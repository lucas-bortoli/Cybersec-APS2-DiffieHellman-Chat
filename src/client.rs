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
use crate::protocol::{ClientId, Packet};

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

async fn setup_connection(
    addr: &str,
) -> anyhow::Result<(UnboundedSender<Packet>, UnboundedReceiver<Packet>)> {
    let stream = TcpStream::connect(addr).await?;
    let (socket_reader, mut socket_writer) = stream.into_split();

    // task de escrita no canal
    let (sent_messages_tx, mut sent_messages_rx) = mpsc::unbounded_channel::<Packet>();
    tokio::spawn(async move {
        while let Some(packet) = sent_messages_rx.recv().await {
            if let Ok(line) = serde_json::to_string(&packet) {
                if let Err(e) = socket_writer.write_all(line.as_bytes()).await {
                    eprintln!("Write error: {:?}", e);
                    break;
                }
                if let Err(e) = socket_writer.write_all(b"\n").await {
                    eprintln!("Write newline error: {:?}", e);
                    break;
                }
            }
        }

        sent_messages_rx.close();
    });

    let (received_msgs_tx, received_msgs_rx) = mpsc::unbounded_channel::<Packet>();
    {
        let mut lines = BufReader::new(socket_reader).lines();
        tokio::spawn(async move {
            while let Some(line) = lines.next_line().await.unwrap_or(None) {
                if line.trim().is_empty() {
                    continue;
                }

                if let Ok(received_packet) = serde_json::from_str::<Packet>(&line) {
                    // pacote válido recebido
                    if received_msgs_tx.send(received_packet).is_err() {
                        break;
                    }
                }
            }
        });
    }

    Ok((sent_messages_tx, received_msgs_rx))
}

async fn ui_thread(
    my_client_id: ClientId,
    my_nickname: String,
    p: Modulus,
    g: Base,
    packet_tx: mpsc::UnboundedSender<Packet>,
    other_clients: Arc<Mutex<HashMap<ClientId, OtherClient>>>,
) -> anyhow::Result<()> {
    println!("Bem-vindo! Você pode enviar mensagens. Ctrl+C para sair.");
    let stdin = io::stdin();
    loop {
        print!("> ");
        io::stdout().flush()?;
        let mut input = String::new();
        stdin.read_line(&mut input)?;
        if input.is_empty() {
            // EOF
            break;
        }
        let msg = input.trim_end().to_string();
        if msg.is_empty() {
            continue;
        }

        // problema autal: other_clients é sempre vazio, já que não tem mecanismo para discovery ainda...

        for client in other_clients.lock().await.values() {
            println!("Enviando para {}", client.id);
            let (my_public, my_secret) = make_keypair(p, g);

            packet_tx
                .send(Packet::KeyUpdateStart {
                    sender: my_client_id,
                    modulus: p,
                    base: g,
                    public: my_public,
                })
                .ok();

            tokio::time::sleep(Duration::from_millis(100)).await;

            packet_tx
                .send(Packet::CipheredMessage {
                    sender: my_client_id,
                    nickname: my_nickname.clone(),
                    intended_receiver: client.id,
                    content_blob: msg.as_bytes().to_vec(),
                })
                .ok();
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = "127.0.0.1:8080";

    // gerar um UUIDv4 para esse cliente
    let my_id = Uuid::new_v4();
    let nickname = args.get(1).cloned().unwrap_or(my_id.to_string());
    let (p, g): (Modulus, Base) = (26, rand_prime());

    println!("connect id={} nick={:?}, p={}, g={}", my_id, nickname, p, g);

    let (packet_tx, mut packet_rx) = setup_connection(addr).await?;

    // mapa de outros clientes
    let other_clients: Arc<Mutex<HashMap<ClientId, OtherClient>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let ui_other_clients = other_clients.clone();

    // enviar pacote Join inicial
    packet_tx
        .send(Packet::Join {
            sender: my_id.clone(),
            nickname: nickname.clone(),
        })
        .ok();

    // task de processamento de packets do servidor
    let packet_tx_t = packet_tx.clone();
    tokio::spawn(async move {
        while let Some(pkt) = packet_rx.recv().await {
            //  println!("{:?}", pkt);
            match pkt {
                Packet::Join { sender, nickname } => {
                    // significa que outro client acabou de conectar
                    let mut map = other_clients.lock().await;
                    let other_client = OtherClient {
                        id: sender,
                        nickname,
                        key_info: None,
                    };
                    map.insert(sender, other_client);
                }
                Packet::Leave { sender } => {
                    let mut map = other_clients.lock().await;
                    map.remove(&sender);
                }
                Packet::KeyUpdateStart {
                    sender,
                    modulus,
                    base,
                    public: their_public,
                } => {
                    let mut clients = other_clients.lock().await;

                    match clients.get_mut(&sender) {
                        Some(sender_info) => {
                            let (my_public, my_secret) = make_keypair(modulus, base);

                            let our_secret =
                                compute_shared_secret(modulus, my_secret, their_public);

                            println!(
                                "Aceitando renegociação da chave com o cliente {}: p={}, g={}, their_public={}, my_public={}, our_secret={}",
                                sender, modulus, base, their_public, my_public, our_secret
                            );

                            // ... armazenar novos valores
                            sender_info.key_info = Some(KeyInfo {
                                p: modulus,
                                g: base,
                                their_public: their_public,
                                my_public: my_public,
                                my_secret: my_secret,
                            });

                            // ... enviar nossa nova public   pra ele
                            packet_tx_t
                                .send(Packet::KeyUpdateReply {
                                    sender: my_id,
                                    intended_receiver: sender,
                                    public: my_public,
                                })
                                .ok();
                        }
                        None => {}
                    }
                }
                Packet::KeyUpdateReply {
                    sender,
                    intended_receiver,
                    public: new_public,
                } => {
                    if intended_receiver != my_id {
                        // mensagem não é direcionada a nós
                        continue;
                    }

                    let mut clients = other_clients.lock().await;
                    if let Some(sender_info) = clients.get_mut(&sender) {
                        if let Some(key_info) = &mut sender_info.key_info {
                            key_info.their_public = new_public;
                            println!("Nova chave pública de {}: {}", sender, new_public);
                        }
                    }
                }
                Packet::CipheredMessage {
                    sender: _,
                    nickname,
                    intended_receiver,
                    content_blob,
                } => {
                    if intended_receiver != my_id {
                        // mensagem não é direcionada a nós
                        continue;
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
    });

    // loop principal: ler do stdin e enviar mensagens;
    ui_thread(
        my_id.clone(),
        nickname.clone(),
        p,
        g,
        packet_tx.clone(),
        ui_other_clients,
    )
    .await?;

    println!("Fechando.");
    Ok(())
}
