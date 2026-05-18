use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum CoreError {
    #[error("invalid peer ID: {0}")]
    InvalidPeerId(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("handshake frame error: {0}")]
    HandshakeFrame(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("protocol version mismatch: local={local}, remote={remote}")]
    VersionMismatch { local: u8, remote: u8 },
}
