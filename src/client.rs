use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use uuid::Uuid;

use chrono::Utc;

use crate::protocol::{Message, Packet};

mod diffie_hellman;
mod protocol;

/// Rastreia outros clientes localmente.
#[derive(Debug, Clone)]
pub struct OtherClient {
    pub id: Uuid,
    pub nickname: Option<String>,
    pub is_online: bool,
}

#[derive(Debug, Clone)]
pub struct LocalClient {
    pub id: Uuid,
    pub nickname: Option<String>,
    pub dh_public: diffie_hellman::Public,
    pub dh_secret: diffie_hellman::Secret,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = "127.0.0.1:8080";
    let nickname = args.get(1).cloned();

    // gerar um UUIDv4 para esse cliente
    let id = Uuid::new_v4();

    let p: diffie_hellman::Modulus = 26;
    let g: diffie_hellman::Base = diffie_hellman::rand_g();

    let (dh_public, dh_secret) = diffie_hellman::make_keypair(p, g);

    let local_client = LocalClient {
        id,
        nickname: nickname.clone(),
        dh_public,
        dh_secret,
    };

    println!(
        "Connecting to {} with id {} nickname {:?}. Choosing public={}, secret={}",
        addr, id, nickname, dh_public, dh_secret
    );

    let (packet_tx, mut packet_rx) = setup_connection(addr).await?;

    // mapa de outros clientes
    let other_clients: Arc<Mutex<HashMap<Uuid, OtherClient>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // task de leitura de linhas do socket
    let others_for_read = other_clients.clone();

    // enviar pacote Join inicial
    packet_tx
        .send(Packet::Join {
            id: local_client.id.clone(),
            nickname: local_client.nickname.clone(),
        })
        .ok();

    // task de processamento de packets do servidor
    let others_handler = others_for_read.clone();
    tokio::spawn(async move {
        while let Some(pkt) = packet_rx.recv().await {
            match pkt {
                Packet::ClientList { clients } => {
                    // popular mapa de clientes, marcando-os online
                    let mut map = others_handler.lock().await;
                    for c in clients {
                        map.entry(c.id)
                            .or_insert(OtherClient {
                                id: c.id,
                                nickname: c.nickname.clone(),
                                is_online: true,
                            })
                            .is_online = true;
                    }
                    print_known_clients(&map);
                }
                Packet::ClientStatus { client, is_online } => {
                    let mut map = others_handler.lock().await;
                    let entry = map.entry(client.id).or_insert(OtherClient {
                        id: client.id,
                        nickname: client.nickname.clone(),
                        is_online,
                    });
                    // atualizar nickname (o servidor sempre o reenvia)
                    entry.nickname = client.nickname.clone();
                    entry.is_online = is_online;
                    println!(
                        "ClientStatus: {} is_online={}",
                        entry.nickname.clone().unwrap_or_default(),
                        is_online
                    );
                }
                Packet::Chat { message } => {
                    let map = others_handler.lock().await;
                    let nick = map
                        .get(&message.author)
                        .and_then(|c| c.nickname.clone())
                        .unwrap_or_else(|| message.author.to_string());
                    println!(
                        "[{}] {}: {}",
                        message.send_date.to_rfc3339(),
                        nick,
                        message.content
                    );
                }
                Packet::Error { reason } => {
                    eprintln!("Server error: {}", reason);
                    // o motivo pode variar... por enquanto, apenas printar
                }
                Packet::StartKeyUpdate {
                    modulus: _,
                    base: _,
                    public: _,
                } => {
                    // o servidor nunca enviará esse pacote para um cliente; ignorar
                }
                Packet::Join { .. } => {
                    // o servidor nunca enviará esse pacote para um cliente; ignorar
                }
            }
        }
    });

    // loop principal: ler do stdin e enviar mensagens
    let my_id = id;

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
        let message = Message {
            content: msg,
            author: my_id,
            send_date: Utc::now(),
        };

        if let Err(e) = packet_tx.send(Packet::Chat { message }) {
            println!("Erro ao enviar mensagem: {}", e);
            break;
        }
    }

    println!("Fechando.");
    Ok(())
}

fn print_known_clients(map: &HashMap<Uuid, OtherClient>) {
    println!("Outros usuários ({}):", map.len());
    for (_, c) in map.iter() {
        println!(
            " - {} [{}] online={}",
            c.nickname.clone().unwrap_or_else(|| c.id.to_string()),
            c.id,
            c.is_online
        );
    }
}
