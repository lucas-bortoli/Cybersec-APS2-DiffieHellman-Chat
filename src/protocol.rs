use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{self, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
};
use uuid::Uuid;

use crate::diffie_hellman;

pub type ClientId = Uuid;

/// Estrutura de uma mensagem de chat: conteúdo, id do autor e data de envio (UTC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub content: String,
    pub author: ClientId,
    pub send_date: DateTime<Utc>,
}

/// Pacotes de dados formatados em JSON, linha a linha.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "data")]
pub enum Packet {
    Join {
        sender: ClientId,
        nickname: String,
    },

    Leave {
        sender: ClientId,
    },

    KeyUpdateStart {
        sender: ClientId,
        modulus: diffie_hellman::Modulus, // p
        base: diffie_hellman::Base,       // g
        public: diffie_hellman::Public, // a chave pública do remetent--- public = (g^(secret)) % p
    },

    KeyUpdateReply {
        sender: ClientId,
        intended_receiver: ClientId,
        public: diffie_hellman::Public,
    },

    /// Mensagem de chat de outro cliente.
    CipheredMessage {
        sender: ClientId,
        nickname: String,
        intended_receiver: ClientId,
        content_blob: Vec<u8>,
    },
}

#[derive(Error, Debug)]
pub enum RoundtripError {
    #[error("connection failed")]
    Connection(#[from] io::Error),

    #[error("packet parsing failed")]
    ProtocolError(),
}

pub struct Roundtrip {
    pub my_id: ClientId,

    ch_sender: mpsc::UnboundedSender<Packet>,
    ch_receiver: mpsc::UnboundedReceiver<Packet>,

    sender_task_handle: Option<JoinHandle<Result<(), RoundtripError>>>,
    receiver_task_handle: Option<JoinHandle<Result<(), RoundtripError>>>,
}

impl Roundtrip {
    pub async fn open(id: ClientId, address: &str) -> Result<Roundtrip, RoundtripError> {
        println!("connecting to {}, with client_id={}", address, id);

        let stream = TcpStream::connect(address).await;

        if let Err(error) = stream {
            return Err(RoundtripError::Connection { 0: error });
        }

        let stream = stream.unwrap();
        let (socket_reader, mut socket_writer) = stream.into_split();

        // task de escrita no canal
        let (sent_messages_tx, mut sent_messages_rx) = mpsc::unbounded_channel::<Packet>();
        let sender_task_handle = tokio::spawn(async move {
            while let Some(packet) = sent_messages_rx.recv().await {
                println!("Sending {:?}", packet);
                match serde_json::to_string(&packet) {
                    Ok(line) => {
                        if let Err(e) = socket_writer.write_all(line.as_bytes()).await {
                            eprintln!("Write error: {:?}", e);
                            return Err(RoundtripError::Connection(e));
                        }
                        if let Err(e) = socket_writer.write_all(b"\n").await {
                            eprintln!("Write newline error: {:?}", e);
                            return Err(RoundtripError::Connection(e));
                        }
                    }
                    Err(e) => {
                        eprintln!("Malformed packet: {:?}", e);
                        return Err(RoundtripError::ProtocolError());
                    }
                }
            }

            Ok(())
        });

        let (received_msgs_tx, received_msgs_rx) = mpsc::unbounded_channel::<Packet>();
        let receiver_task_handle = tokio::spawn(async move {
            let mut lines = BufReader::new(socket_reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    return Err(RoundtripError::ProtocolError());
                }

                println!("Received {:?}", line);

                if let Ok(received_packet) = serde_json::from_str::<Packet>(&line) {
                    // pacote válido recebido
                    if let Err(_) = received_msgs_tx.send(received_packet) {
                        return Err(RoundtripError::ProtocolError());
                    }
                }
            }

            Ok(())
        });

        Ok(Roundtrip {
            my_id: id,
            ch_sender: sent_messages_tx,
            ch_receiver: received_msgs_rx,
            sender_task_handle: Some(sender_task_handle),
            receiver_task_handle: Some(receiver_task_handle),
        })
    }

    pub async fn send_simple_packet(&self, packet: Packet) {
        let _ = self.ch_sender.send(packet);
    }

    pub async fn poll(&mut self, matcher: impl Fn(&Packet) -> bool) -> Option<Packet> {
        if let Some(p) = self.ch_receiver.recv().await {
            if matcher(&p) {
                return Some(p);
            }
        }

        None
    }
}

impl Drop for Roundtrip {
    fn drop(&mut self) {
        eprintln!("Roundtrip::drop");

        self.ch_receiver.close();

        if let Some(handle) = self.sender_task_handle.take() {
            handle.abort();
        }

        if let Some(handle) = self.receiver_task_handle.take() {
            handle.abort();
        }
    }
}
