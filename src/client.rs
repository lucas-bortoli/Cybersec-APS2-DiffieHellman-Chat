use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

use crate::caesar_cipher::Caesar;
use crate::diffie_hellman::{Base, Modulus, Public, Secret, compute_shared_secret, make_keypair};
use crate::protocol::{ClientId, Packet, Roundtrip};

mod caesar_cipher;
mod diffie_hellman;
mod protocol;

/// Rastreia outros clientes localmente.
#[derive(Debug, Clone)]
pub struct OtherClient {
    pub id: Uuid,
    pub nickname: String,
    pub my_keys: (Modulus, Base, Public, Secret),
    pub their_pub: Option<Public>,
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
            if sender == *my_id {
                return;
            }

            eprintln!("Join: {}", sender);

            let (modulus, base) = (diffie_hellman::rand_prime(), diffie_hellman::rand_prime());
            let (my_public, my_secret) = diffie_hellman::make_keypair(modulus, base);

            let mut map = other_clients.write().await;
            map.insert(
                sender,
                OtherClient {
                    id: sender,
                    nickname,
                    my_keys: (modulus, base, my_public, my_secret),
                    their_pub: None,
                },
            );
        }
        Packet::Leave { sender } => {
            if sender == *my_id {
                return;
            }

            eprintln!("Leave: {}", sender);

            let mut map = other_clients.write().await;
            map.remove(&sender);
        }
        Packet::KeyUpdateStart {
            sender,
            modulus,
            base,
            public: their_new_public,
        } => {
            if sender == *my_id {
                return;
            }

            eprintln!("KeyUpdateStart: {}", sender);
            // First phase: compute values and update local state without awaiting.
            let my_public = {
                let mut clients = other_clients.write().await;

                match clients.get_mut(&sender) {
                    Some(sender_info) => {
                        let (my_public, my_secret) = make_keypair(modulus, base);
                        let our_secret =
                            compute_shared_secret(modulus, my_secret, their_new_public);

                        sender_info.my_keys = (modulus, base, my_public, my_secret);
                        sender_info.their_pub = Some(their_new_public);

                        println!(
                            "renegociação da chave aceita {}: p={}, g={}, their_new_public={}, my_public={}, our_secret={}",
                            sender, modulus, base, their_new_public, my_public, our_secret
                        );

                        my_public
                    }
                    None => {
                        eprintln!(
                            "recebi um pacote KeyUpdateStart de um cliente que não estava no mapa. packet={:?}",
                            packet
                        );
                        return;
                    }
                }
            };

            // enviar pacote de resposta. já atualizamos nosso estado, agora é trabalho do remetente atualizar seu estado com nossas novas informações.
            roundtrip
                .send_simple_packet(Packet::KeyUpdateReply {
                    sender: my_id.clone(),
                    intended_receiver: sender,
                    public: my_public,
                })
                .await;
        }
        Packet::KeyUpdateReply {
            sender,
            intended_receiver,
            public: new_public,
        } => {
            if sender == *my_id || intended_receiver != *my_id {
                // mensagem não é direcionada a nós
                return;
            }

            eprintln!("KeyUpdateReply: {}", sender);

            let mut clients = other_clients.write().await;
            if let Some(sender_info) = clients.get_mut(&sender) {
                println!("nova chave pública de {}: {}", sender, new_public);
                sender_info.their_pub = Some(new_public);
            }
        }
        Packet::CipheredMessage {
            sender,
            nickname,
            intended_receiver,
            content_blob,
        } => {
            if sender == *my_id || intended_receiver != *my_id {
                // mensagem não é direcionada a nós
                return;
            }

            eprintln!("CipheredMessage: {}", sender);

            let clients = other_clients.read().await;

            if let Some(sender) = clients.get(&sender) {
                if let Some(their_pub) = sender.their_pub {
                    println!("recebimento: {:?}, their_pub={}", sender.my_keys, their_pub);

                    let (modulus, _, _, my_secret) = sender.my_keys;

                    let our_shared_secret =
                        diffie_hellman::compute_shared_secret(modulus, my_secret, their_pub);

                    let k = (our_shared_secret % 26).try_into().unwrap();
                    println!("decode key={}", our_shared_secret);
                    let decoded = Caesar::decrypt(k, &content_blob);

                    println!("[{}]: {}", sender.nickname, decoded);
                } else {
                    // a mensagem foi recebida, mas NÃO HOUVE um handshake de senhas. então o conteúdo da mensagem é desconhecido.
                    // mostrar o conteúdo desconhecido, mesmo assim.
                    eprintln!("[{}] (???): {:?}", sender.nickname, content_blob);
                }
            } else {
                eprintln!(
                    "Mensagem recebida, de um remetente desconhecido: {:?}",
                    sender
                );
            }
        }
    }
}

async fn handle_message_send(
    my_id: &Uuid,
    nickname: &str,
    tx: UnboundedSender<Packet>,
    other_clients: Arc<tokio::sync::RwLock<HashMap<ClientId, OtherClient>>>,
    message: &str,
) {
    let (p, g) = (diffie_hellman::rand_prime(), diffie_hellman::rand_prime());

    let clients = other_clients.read().await;
    let clients_copy = clients.clone();
    drop(clients);

    for client in clients_copy.values() {
        // criar um novo keypar para esse handshake
        let (my_public, my_secret) = make_keypair(p, g);

        // ... e armazenar os valores, antes mesmo de enviar o pacote
        {
            let mut clients_w = other_clients.write().await;
            if let Some(entry) = clients_w.get_mut(&client.id) {
                entry.my_keys = (p, g, my_public, my_secret);
                entry.their_pub = None; // invalidar qualquer chave publica anterior; iremos aguardar uma nova
            } else {
                // cliente desapareceu entre a cópia e o write..???
                continue;
            }
        }

        if let Err(_) = tx.send(Packet::KeyUpdateStart {
            sender: *my_id,
            modulus: p,
            base: g,
            public: my_public,
        }) {
            // envio falhou; ignorar
            continue;
        }

        // aguardar até que o outro cliente responda com sua public key
        let mut counter_ms = 0u64;
        let timeout_max_ms = 3000u64;

        loop {
            // checar se o outro cliente setou their_pub
            if let Some(entry) = other_clients.read().await.get(&client.id) {
                if entry.their_pub.is_some() {
                    break; // handshake concluído
                }
            } else {
                // cliente saiu
                break;
            }

            if counter_ms >= timeout_max_ms {
                eprintln!("timeout aguardando KeyUpdateReply de {}", client.id);
                break;
            }

            tokio::time::sleep(Duration::from_millis(50u64)).await;
            counter_ms += 50u64;
        }

        // se o handshake concluiu, finalmente enviar mensagem cifrada
        if let Some(entry) = other_clients.read().await.get(&client.id) {
            if let Some(their_pub) = entry.their_pub {
                let (modulus, _, _, my_secret) = entry.my_keys;
                let our_shared_secret =
                    diffie_hellman::compute_shared_secret(modulus, my_secret, their_pub);

                let k = (our_shared_secret % 26).try_into().unwrap();
                println!("encode key={}", our_shared_secret);
                let encoded_message = Caesar::encrypt(k, &message.to_string());

                println!("envio: {:?}, their_pub={}", entry.my_keys, their_pub);

                let _ = tx.send(Packet::CipheredMessage {
                    sender: *my_id,
                    nickname: nickname.to_string(),
                    intended_receiver: client.id,
                    content_blob: encoded_message,
                });
            } else {
                eprintln!(
                    "não posso enviar ao cliente {}, as chaves não foram negociadas.",
                    client.id
                );
            }
        }
    }
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

    let other_clients = Arc::new(tokio::sync::RwLock::new(
        HashMap::<ClientId, OtherClient>::new(),
    ));

    loop {
        tokio::select! {
            Some(packet) = roundtrip.poll(|_| true) => { handle_packet(&my_id, &nickname, &mut roundtrip, &other_clients, packet).await; },
            res = reader.read_line(&mut line) => {
                if res.unwrap() == 0 {
                    break;
                }

                let s = line.trim().to_string();
                // spawn the send work so that the select continues to poll roundtrip
                let tx_clone = roundtrip.ch_sender.clone();
                let other_clients_clone = other_clients.clone();
                let my_id_clone = my_id.clone();
                let nickname_clone = nickname.clone();
                tokio::spawn(async move {
                    handle_message_send(&my_id_clone, &nickname_clone, tx_clone, other_clients_clone, &s).await;
                });

                line.clear();
            }
        }
    }

    println!("Fechando.");
    Ok(())
}
