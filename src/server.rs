use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::protocol::{ClientInfo, Packet};

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
    let mut lines = BufReader::new(reader).lines();

    // ler a primeira linha; obrigatoriamente deve ser um Join
    let first_line = match lines.next_line().await? {
        Some(l) => l,
        None => {
            return Ok(());
        }
    };

    let packet: Packet = match serde_json::from_str(&first_line) {
        Ok(p) => p,
        Err(_) => {
            // erro ao parsear, fechar conex'ao
            let mut w = writer;
            let err = Packet::Error {
                reason: "Invalid initial packet".into(),
            };
            let s = serde_json::to_string(&err)?;
            w.write_all(s.as_bytes()).await?;
            w.write_all(b"\n").await?;
            return Ok(());
        }
    };

    let join_info = match packet {
        Packet::Join { client } => client,
        _ => {
            // Unexpected first packet
            let mut w = writer;
            let err = Packet::Error {
                reason: "Expected Join packet as first packet".into(),
            };
            let s = serde_json::to_string(&err)?;
            w.write_all(s.as_bytes()).await?;
            w.write_all(b"\n").await?;
            return Ok(());
        }
    };

    // checar UUID duplicado
    {
        let map = state.lock().await;
        if map.contains_key(&join_info.id) {
            // duplicado, enviar um Error e fechar conex'ao
            let mut w = writer;
            let err = Packet::Error {
                reason: "UUID already connected".into(),
            };
            let s = serde_json::to_string(&err)?;
            w.write_all(s.as_bytes()).await?;
            w.write_all(b"\n").await?;
            println!("UUID duplicado rejeitado: {}", join_info.id);
            return Ok(());
        }
    }

    // canal de envio de mensagens ao cliente
    let (tx, mut rx) = mpsc::unbounded_channel::<Packet>();

    // tarefa writer_task
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = rx.recv().await {
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

    // enviar lista atual de clientes antes de anunciar o novo clientet
    {
        let map = state.lock().await;
        let clients: Vec<ClientInfo> = map.values().map(|c| c.info.clone()).collect();
        tx.send(Packet::ClientList { clients }).ok();
    }

    // registrar esse cliente no mapa global
    {
        let mut map = state.lock().await;
        let sc = ServerClient {
            info: join_info.clone(),
            tx: tx.clone(),
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

    println!("Conectado: {:?} ({})", join_info.nickname, join_info.id);

    // loop de leitura de pacotes vindos deste cliente
    while let Some(line) = lines.next_line().await? {
        // ignorar linhas vazias
        if line.trim().is_empty() {
            continue;
        }

        let pkt: Packet = match serde_json::from_str(&line) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("Pacote quebrado recebido de {}: {:?}", join_info.id, e);
                continue;
            }
        };

        match pkt {
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
                eprintln!("Pacote inesperado do cliente {}: {:?}", join_info.id, pkt);
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

    // dropar tx para que a writer_task finalize
    drop(tx);
    writer_task.await.ok();

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
