use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Informação pública sobre um cliente compartilhada com os demais.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub id: Uuid,
    pub nickname: Option<String>,
}

/// Estrutura de uma mensagem de chat: conteúdo, id do autor e data de envio (UTC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub content: String,
    pub author: Uuid,
    pub send_date: DateTime<Utc>,
}

/// Pacotes de dados formatados em JSON, linha a linha.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "data")]
pub enum Packet {
    /// Cliente envia essa mensagem ao se conectar. Um handshake.
    Join { client: ClientInfo },

    /// Servidor envia a lista de clientes atuais após aceitar conexão.
    ClientList { clients: Vec<ClientInfo> },

    /// Servidor retransmite quando o status de um cliente muda.
    /// `is_online = true` para quando o cliente entra,
    /// `false` para quando o cliente se desconecta.
    ClientStatus { client: ClientInfo, is_online: bool },

    /// Mensagem de chat de um cliente ou encaminhada pelo servidor.
    Chat { message: Message },

    /// Servidor pode enviar uma mensagem de erro e então fechar a conexão.
    Error { reason: String },
}
