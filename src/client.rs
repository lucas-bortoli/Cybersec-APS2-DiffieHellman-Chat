use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use uuid::Uuid;

use crate::diffie_hellman::{
    Base, Modulus, Public, Secret, compute_shared_secret, make_keypair, rand_prime,
};
use crate::protocol::{ClientId, Packet, Roundtrip};

mod diffie_hellman;
mod protocol;

#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub p: Modulus,
    pub g: Base,
    pub their_public: Public,
    pub my_public: Public,
    pub my_secret: Secret,
}

/// Rastreia outros clientes localmente.
#[derive(Debug, Clone)]
pub struct OtherClient {
    pub id: Uuid,
    pub nickname: String,
    pub key_info: Option<KeyInfo>,
}

async fn handle_packet(
    my_id: &Uuid,
    nickname: &str,
    roundtrip: &mut Roundtrip,
    other_clients: &tokio::sync::RwLock<HashMap<ClientId, OtherClient>>,
    packet: Packet,
) {
    match packet {
        Packet::Join { sender, nickname } => {
            let mut map = other_clients.write().await;
            map.insert(
                sender,
                OtherClient {
                    id: sender,
                    nickname,
                    key_info: None,
                },
            );
        }
        Packet::Leave { sender } => {
            let mut map = other_clients.write().await;
            map.remove(&sender);
        }
        Packet::KeyUpdateStart {
            sender,
            modulus,
            base,
            public: their_new_public,
        } => {
            let mut clients = other_clients.write().await;
            match clients.get_mut(&sender) {
                Some(sender_info) => {
                    let (my_public, my_secret) = make_keypair(modulus, base);

                    let our_secret = compute_shared_secret(modulus, my_secret, their_new_public);

                    println!(
                        "Aceitando renegociação da chave com o cliente {}: p={}, g={}, their_new_public={}, my_public={}, our_secret={}",
                        sender, modulus, base, their_new_public, my_public, our_secret
                    );

                    // ... armazenar novos valores
                    sender_info.key_info = Some(KeyInfo {
                        p: modulus,
                        g: base,
                        their_public: their_new_public,
                        my_public: my_public,
                        my_secret: my_secret,
                    });

                    // ... enviar nossa nova publica pra ele
                    roundtrip
                        .send_simple_packet(Packet::KeyUpdateReply {
                            sender: my_id.clone(),
                            intended_receiver: sender,
                            public: my_public,
                        })
                        .await;
                }
                None => {
                    // o cliente não existe, ignorar
                    eprintln!(
                        "recebi um pacote KeyUpdateStart de um cliente que não estava no mapa. packet={:?}, clientes={:?}",
                        packet, other_clients
                    );
                }
            }
        }
        Packet::KeyUpdateReply {
            sender,
            intended_receiver,
            public: new_public,
        } => {
            if intended_receiver != *my_id {
                // mensagem não é direcionada a nós
                return;
            }

            let mut clients = other_clients.write().await;
            if let Some(sender_info) = clients.get_mut(&sender) {
                if let Some(key_info) = &mut sender_info.key_info {
                    key_info.their_public = new_public;
                    println!("Nova chave pública de {}: {}", sender, new_public);
                }
            }
        }
        Packet::CipheredMessage {
            sender,
            nickname,
            intended_receiver,
            content_blob,
        } => {
            if intended_receiver != *my_id {
                // mensagem não é direcionada a nós
                return;
            }

            //let map = other_clients.lock().await;
            println!(
                "[{}]: {}",
                nickname,
                String::from_utf8(content_blob).unwrap()
            );
        }
    }
}

async fn handle_message_send(
    my_id: &Uuid,
    nickname: &str,
    roundtrip: &mut Roundtrip,
    other_clients: &tokio::sync::RwLock<HashMap<ClientId, OtherClient>>,
    message: &str,
) {
    let (p, g) = (diffie_hellman::rand_prime(), diffie_hellman::rand_prime());

    // aqui precisamos cumprir o requisito da atividade:
    // 1. decidir novos parâmetros de p e g (módulo e base, respectivamente)
    // 2. computar uma nova chave pública e privada
    // 3. computar uma chave secreta coordenada (...que será a chave da cifra de César)
    // 4. finalmente, encodar a mensagem com a chave secreta coordenada e enviar cifrada.
    // o problema é que temos um "handshake" aqui. aí é foda.

    // problema autal: other_clients é sempre vazio, já que não tem mecanismo para discovery ainda...

    for client in other_clients.read().await.values() {
        println!("Enviando para {}", client.id);
        let (my_public, my_secret) = make_keypair(p, g);

        roundtrip
            .send_simple_packet(Packet::KeyUpdateStart {
                sender: *my_id,
                modulus: p,
                base: g,
                public: my_public,
            })
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        roundtrip
            .send_simple_packet(Packet::CipheredMessage {
                sender: *my_id,
                nickname: nickname.to_string(),
                intended_receiver: client.id,
                content_blob: message.as_bytes().to_vec(),
            })
            .await;
    }

    roundtrip
        .send_simple_packet(Packet::CipheredMessage {
            sender: *my_id,
            nickname: nickname.to_string(),
            intended_receiver: Uuid::new_v4(),
            content_blob: message.as_bytes().to_vec(),
        })
        .await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // gerar um UUIDv4 para esse cliente
    let my_id = Uuid::new_v4();
    let nickname = args.get(1).cloned().unwrap_or(my_id.to_string());

    let mut roundtrip = Roundtrip::open(my_id, "127.0.0.1:8080").await?;

    roundtrip
        .send_simple_packet(Packet::Join {
            sender: my_id,
            nickname: nickname.clone(),
        })
        .await;

    // coisas para ler stdin
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut line = String::new();

    let other_clients = tokio::sync::RwLock::new(HashMap::<ClientId, OtherClient>::new());

    loop {
        tokio::select! {
            Some(packet) = roundtrip.poll(|_| true) => { handle_packet(&my_id, &nickname, &mut roundtrip, &other_clients, packet).await; },
            res = reader.read_line(&mut line) => {
                if res.unwrap() == 0 {
                    break;
                }

                line = line.trim().to_string();
                handle_message_send(&my_id, &nickname, &mut roundtrip, &other_clients, &line).await;
                line.clear();
            }
        }
    }

    println!("Fechando.");
    Ok(())
}
