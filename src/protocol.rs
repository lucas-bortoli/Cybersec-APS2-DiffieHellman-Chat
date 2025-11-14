use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
