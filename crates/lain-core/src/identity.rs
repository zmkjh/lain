use crate::peer::PeerId;

pub type Ed25519PublicKey = [u8; 32];
pub type X25519PublicKey = [u8; 32];
pub type Ed25519Signature = [u8; 64];

/// 设备级永久身份
pub trait IdentityProvider: Send + Sync {
    fn peer_id(&self) -> PeerId;
    fn public_key(&self) -> &Ed25519PublicKey;
    fn sign(&self, data: &[u8]) -> Ed25519Signature;
}
