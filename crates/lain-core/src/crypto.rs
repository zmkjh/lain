use crate::error::CoreError;
use crate::peer::PeerId;

/// Noise 握手状态
pub trait NoiseHandshake: Send {
    fn write_message(&mut self, peer_id: &PeerId) -> Result<Vec<u8>, CoreError>;
    fn read_message(&mut self, data: &[u8]) -> Result<PeerId, CoreError>;
    fn into_transport(self: Box<Self>) -> Result<Box<dyn NoiseTransport>, CoreError>;
    fn remote_pubkey(&self) -> Option<[u8; 32]>;
}

/// Noise 传输模式（握手完成后的加解密）
pub trait NoiseTransport: Send {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CoreError>;
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError>;
}

/// Noise 工厂 — 由 daemon 注入 transport，消除 crate 间直接依赖
pub trait CryptoProvider: Send + Sync {
    fn new_initiator(&self, remote_pubkey: &[u8; 32]) -> Result<Box<dyn NoiseHandshake>, CoreError>;
    fn new_responder(&self) -> Result<Box<dyn NoiseHandshake>, CoreError>;
    fn local_pubkey(&self) -> [u8; 32];
}
