use std::any;
use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::protocol::{ClientInfo, Packet};

mod diffie_hellman;
mod protocol;

/// representação no lado servidor para um cliente conectado.
struct ServerClient {
    info: ClientInfo,
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
/// 1. ler a primeira linha (JSON) esperando um Packet::Join
/// 2. se o UUID for duplicado, enviar Packet::Error e fechar conexão.
/// 3. caso contrário:
///    - cria uma tarefa de escrita que consome um canal mpsc
///      e escreve linhas JSON para o socket
///    - envia o Packet::ClientList com todos os clientes conectados atualmente
///    - adiciona esse cliente ao estado compartilhado
///    - transmite o Packet::ClientStatus (is_online=true) para os outros clientes
///    - Lê linhas vindas do cliente: espera por Packet::Chat e retransmite para
///      os demais.
async fn handle_connection(stream: TcpStream, state: SharedState) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();

    // canal de envio de mensagens ao cliente
    let (write_queue_tx, mut write_queue_rx) = mpsc::unbounded_channel::<Packet>();
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = write_queue_rx.recv().await {
            if let Ok(msg) = serde_json::to_string(&pkt) {
                if let Err(e) = writer.write_all(msg.as_bytes()).await {
                    eprintln!("Erro escrevendo dados para cliente: {:?}", e);
                    break;
                }
                if let Err(e) = writer.write_all(b"\n").await {
                    eprintln!("Erro escrevendo nova linha para cliente: {:?}", e);
                    break;
                }
            }
        }
    });

    // canal de recebimento de mensagens do cliente
    let (read_queue_tx, mut read_queue_rx) = mpsc::unbounded_channel::<Packet>();
    let reader_task = tokio::spawn(async move {
        let mut lines = BufReader::new(reader).lines();

        // loop de leitura de pacotes vindos deste cliente
        while let Ok(read_buf) = lines.next_line().await {
            if let Some(line) = read_buf {
                // ignorar linhas vazias
                if line.trim().is_empty() {
                    continue;
                }

                let pkt: Packet = match serde_json::from_str(&line) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Pacote quebrado recebido: {:?}", e);
                        continue;
                    }
                };

                if let Err(_) = read_queue_tx.send(pkt) {
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
    let join_info = match read_packet.recv().await {
        Some(Packet::Join { id, nickname }) => ClientInfo { id, nickname },
        _ => {
            // Unexpected first packet
            let _ = write_packet.send(Packet::Error {
                reason: "Expected Join packet as first packet".into(),
            });
            return Ok(());
        }
    };

    println!("Conectado: {:?} ({})", join_info.nickname, join_info.id);

    // enviar lista atual de clientes antes de anunciar o novo clientet
    {
        let map = state.lock().await;
        let clients: Vec<ClientInfo> = map.values().map(|c| c.info.clone()).collect();
        write_packet.send(Packet::ClientList { clients }).ok();
    }

    // registrar esse cliente no mapa global
    {
        let mut map = state.lock().await;
        let sc = ServerClient {
            info: join_info.clone(),
            tx: write_packet.clone(),
        };
        map.insert(join_info.id, sc);
    }

    // notificar a todos a entrada deste cliente
    broadcast(
        &state,
        Packet::ClientStatus {
            client: join_info.clone(),
            is_online: true,
        },
    )
    .await;

    while let Some(packet) = read_packet.recv().await {
        match packet {
            Packet::Chat { message } => {
                // validação básica: garantir que message.author == join_info.id
                if message.author != join_info.id {
                    eprintln!(
                        "Id do remetente inválido: esperava {}, recebeyu {}",
                        join_info.id, message.author
                    );
                    // ignorar mensagem
                    continue;
                }
                // enviar mensagem a todos, inclusive o remetente original
                broadcast(&state, Packet::Chat { message }).await;
            }
            _ => {
                eprintln!(
                    "Pacote inesperado do cliente {}: {:?}",
                    join_info.id, packet
                );
            }
        }
    }

    // este cliente desconectou: remover do estado...
    {
        let mut map = state.lock().await;
        map.remove(&join_info.id);
    }

    // ...e notificar todos os outros clientes
    broadcast(
        &state,
        Packet::ClientStatus {
            client: join_info.clone(),
            is_online: false,
        },
    )
    .await;

    println!(
        "Cliente desconectou: {} ({})",
        join_info.nickname.unwrap_or_default(),
        join_info.id
    );

    Ok(())
}

/// Faz o broadcast de um pacote a todos os clientes conectados
async fn broadcast(state: &SharedState, packet: Packet) {
    let map = state.lock().await;
    for (_id, sc) in map.iter() {
        // It's fine if send fails (client writer closed), ignore.
        let _ = sc.tx.send(packet.clone());
    }
}
