use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::protocol::{ClientId, Packet};

mod diffie_hellman;
mod protocol;

/// representação no lado servidor para um cliente conectado.
struct ServerClient {
    id: ClientId,
    nickname: String,
    /// `tx` é usado para enviar linhas JSON para esse cliente
    tx: mpsc::UnboundedSender<Packet>,
}

/// estado do server: mapa de UUID para ServerClient.
type SharedState = Arc<Mutex<HashMap<Uuid, ServerClient>>>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = "0.0.0.0:8080";
    println!("Server ativo em {}", addr);
    let listener = TcpListener::bind(addr).await?;
    let state: SharedState = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (socket, peer) = listener.accept().await?;
        let state = state.clone();
        println!("Conexão incoming de {}", peer);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, state).await {
                eprintln!("Erro no handler de conexão: {:?}", e);
            }
        });
    }
}

/// Lida com uma conexão de cliente.
async fn handle_connection(stream: TcpStream, state: SharedState) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();

    // canal de envio de mensagens ao cliente
    let (write_queue_tx, mut write_queue_rx) = mpsc::unbounded_channel::<Packet>();
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = write_queue_rx.recv().await {
            match serde_json::to_string(&pkt) {
                Ok(msg) => {
                    if let Err(e) = writer.write_all(msg.as_bytes()).await {
                        eprintln!("Erro escrevendo dados para cliente: {:?}", e);
                        break;
                    }
                    if let Err(e) = writer.write_all(b"\n").await {
                        eprintln!("Erro escrevendo nova linha para cliente: {:?}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Erro serializando pacote para cliente: {:?}", e);
                    // If serialization fails, skip this packet and continue
                    continue;
                }
            }
        }
    });

    // canal de recebimento de mensagens do cliente
    let (read_queue_tx, mut read_queue_rx) = mpsc::unbounded_channel::<Packet>();
    let reader_task = tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }

                    match serde_json::from_str::<Packet>(&line) {
                        Ok(pkt) => {
                            if read_queue_tx.send(pkt).is_err() {
                                // receiver dropped -> stop reading
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("Pacote quebrado recebido: {:?}", e);
                            continue;
                        }
                    }
                }
                Ok(None) => {
                    // EOF from client
                    break;
                }
                Err(e) => {
                    eprintln!("Erro lendo do socket: {:?}", e);
                    break;
                }
            }
        }
    });

    handle_connection_2(&write_queue_tx, &mut read_queue_rx, state).await?;

    // dropar tx para que a writer_task finalize
    drop(write_queue_tx);
    writer_task.await.ok();
    reader_task.await.ok();

    Ok(())
}

async fn handle_connection_2(
    write_packet: &mpsc::UnboundedSender<Packet>,
    read_packet: &mut mpsc::UnboundedReceiver<Packet>,
    state: SharedState,
) -> anyhow::Result<()> {
    let (client_id, nickname) = match read_packet.recv().await {
        Some(Packet::Join { sender, nickname }) => (sender, nickname),
        Some(other) => {
            println!("Primeiro pacote inesperado do cliente: {:?}", other);
            return Ok(());
        }
        None => {
            // client closed immediately
            println!("Cliente desconectou antes de enviar Join.");
            return Ok(());
        }
    };

    // registrar esse cliente no mapa global
    {
        let mut map = state.lock().await;

        if map.len() == 2 {
            map.clear();
            // TODO remover
        }

        let sc = ServerClient {
            id: client_id.clone(),
            nickname: nickname.clone(),
            tx: write_packet.clone(),
        };

        // anunciar a conexão para os outros clients
        for other_client in map.values() {
            // inform other clients that this new client has joined
            other_client
                .tx
                .send(Packet::Join {
                    sender: client_id.clone(),
                    nickname: nickname.clone(),
                })
                .ok();

            // send an existing-client Join to the new client so it knows who's in the room
            write_packet
                .send(Packet::Join {
                    sender: other_client.id.clone(),
                    nickname: other_client.nickname.clone(),
                })
                .ok();
        }

        // Insert using a clone so we can still use client_id afterwards
        map.insert(client_id.clone(), sc);
    }

    println!("Conectado: {} ({})", nickname, client_id);

    while let Some(packet) = read_packet.recv().await {
        println!("Pacote de {}: {:?}", client_id, packet);
        broadcast(&state, packet).await;
    }

    // este cliente desconectou: remover do estado...
    {
        let mut map = state.lock().await;
        map.remove(&client_id);
    }

    broadcast(
        &state,
        Packet::Leave {
            sender: client_id.clone(),
        },
    )
    .await;

    println!("Cliente desconectou: {} ({})", nickname, client_id);

    Ok(())
}

/// faz o broadcast de um pacote a todos os clientes conectados
async fn broadcast(state: &SharedState, packet: Packet) {
    let map = state.lock().await;
    for (_id, sc) in map.iter() {
        // it's fine if send fails (client writer closed), ignore.
        let _ = sc.tx.send(packet.clone());
    }
}
