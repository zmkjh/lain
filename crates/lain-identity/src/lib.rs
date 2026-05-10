#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use lain_core::identity::{Ed25519PublicKey, Ed25519Signature, IdentityProvider};
use lain_core::peer::PeerId;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use tracing;

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("failed to serialize identity: {0}")]
    Serialize(String),
    #[error("failed to deserialize identity: {0}")]
    Deserialize(String),
    #[error("failed to read identity file: {0}")]
    ReadFile(String),
    #[error("failed to write identity file: {0}")]
    WriteFile(String),
    #[error("failed to determine home directory")]
    NoHomeDir,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredIdentity {
    secret_key_bytes: [u8; 32],
    public_key: Ed25519PublicKey,
    peer_id_bytes: [u8; 32],
}

pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    public_key: Ed25519PublicKey,
    peer_id: PeerId,
}

impl Identity {
    pub fn generate() -> Result<Self, IdentityError> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes();
        let peer_id = Self::compute_peer_id(&public_key);
        tracing::info!("generated new identity: {peer_id}");
        Ok(Self { signing_key, verifying_key, public_key, peer_id })
    }

    /// 导出用于 Noise IK 的 X25519 密钥对
    pub fn noise_keypair(&self) -> ([u8; 32], [u8; 32]) {
        let scalar = self.signing_key.to_scalar();
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&scalar.to_bytes());
        let public = self.verifying_key.to_montgomery().to_bytes();
        (secret, public)
    }

    /// 导出 Ed25519 签名种子（用于 DHT RPC 签名）
    pub fn signing_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn load_or_generate() -> Result<Self, IdentityError> {
        match Self::identity_path() {
            Some(path) if path.exists() => {
                tracing::info!("loading identity from {}", path.display());
                Self::load_from_file(&path)
            }
            Some(path) => {
                let id = Self::generate()?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| IdentityError::WriteFile(e.to_string()))?;
                }
                id.save_to_file(&path)?;
                Ok(id)
            }
            None => {
                tracing::warn!("no home directory, using ephemeral identity");
                Self::generate()
            }
        }
    }

    fn load_from_file(path: &PathBuf) -> Result<Self, IdentityError> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| IdentityError::ReadFile(e.to_string()))?;
        let stored: StoredIdentity = serde_json::from_str(&data)
            .map_err(|e| IdentityError::Deserialize(e.to_string()))?;

        let secret_bytes: [u8; 32] = stored.secret_key_bytes;
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let computed_peer_id = Self::compute_peer_id(&stored.public_key);

        if computed_peer_id.0 != stored.peer_id_bytes {
            tracing::error!("identity file corrupted: PeerID mismatch");
            return Err(IdentityError::Deserialize("PeerID mismatch".into()));
        }

        Ok(Self {
            signing_key,
            verifying_key,
            public_key: stored.public_key,
            peer_id: computed_peer_id,
        })
    }

    fn save_to_file(&self, path: &PathBuf) -> Result<(), IdentityError> {
        let stored = StoredIdentity {
            secret_key_bytes: self.signing_key.to_bytes(),
            public_key: self.public_key,
            peer_id_bytes: self.peer_id.0,
        };
        let json = serde_json::to_string_pretty(&stored)
            .map_err(|e| IdentityError::Serialize(e.to_string()))?;
        std::fs::write(path, json)
            .map_err(|e| IdentityError::WriteFile(e.to_string()))?;
        tracing::info!("saved identity to {}", path.display());
        Ok(())
    }

    fn compute_peer_id(pubkey: &Ed25519PublicKey) -> PeerId {
        PeerId::from_pubkey(pubkey)
    }

    fn identity_path() -> Option<PathBuf> {
        dirs_next().map(|d| d.join(".lain").join("identity.json"))
    }
}

impl IdentityProvider for Identity {
    fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    fn sign(&self, data: &[u8]) -> Ed25519Signature {
        self.signing_key.sign(data).to_bytes()
    }
}

fn dirs_next() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("LAIN_HOME") {
        return Some(PathBuf::from(home));
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return Some(PathBuf::from(profile));
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return Some(PathBuf::from(home));
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::VerifyingKey;

    #[test]
    fn test_generate_identity() {
        let id = Identity::generate().unwrap();
        let pid = id.peer_id();
        assert_eq!(pid.0.len(), 32);
        assert_eq!(*id.public_key(), id.signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let id = Identity::generate().unwrap();
        let data = b"hello lain";
        let signature = id.sign(data);

        let vk = VerifyingKey::from_bytes(&id.public_key).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&signature);
        assert!(vk.verify_strict(data, &sig).is_ok());
    }

    #[test]
    fn test_peer_id_deterministic() {
        let id = Identity::generate().unwrap();
        let computed = Identity::compute_peer_id(&id.public_key);
        assert_eq!(id.peer_id(), computed);
    }

    #[test]
    fn test_noise_keypair_conversion() {
        let id = Identity::generate().unwrap();
        let (secret, public) = id.noise_keypair();
        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);
        // Key should be non-zero
        assert!(secret.iter().any(|&b| b != 0));
        assert!(public.iter().any(|&b| b != 0));
    }
}
