use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("invalid peer ID: {0}")]
    InvalidPeerId(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("protocol version mismatch: local={local}, remote={remote}")]
    VersionMismatch { local: u8, remote: u8 },
}
