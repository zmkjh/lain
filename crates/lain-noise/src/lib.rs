#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::crypto::{CryptoProvider, NoiseHandshake, NoiseTransport};
use lain_core::error::CoreError;
use lain_core::peer::PeerId;
use snow::{Builder, HandshakeState, TransportState};
use snow::params::NoiseParams;

const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

struct Handshake {
    state: HandshakeState,
    finished: bool,
}

impl NoiseHandshake for Handshake {
    fn write_message(&mut self, peer_id: &PeerId) -> Result<Vec<u8>, CoreError> {
        let mut buf = vec![0u8; 4096];
        let len = self.state.write_message(&peer_id.0, &mut buf)
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        buf.truncate(len);
        self.finished = self.state.is_handshake_finished();
        Ok(buf)
    }

    fn read_message(&mut self, data: &[u8]) -> Result<PeerId, CoreError> {
        let mut buf = vec![0u8; 4096];
        let len = self.state.read_message(data, &mut buf)
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        if len < 32 {
            return Err(CoreError::InvalidEndpoint("payload too short for PeerID".into()));
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&buf[..32]);
        self.finished = self.state.is_handshake_finished();
        Ok(PeerId(id))
    }

    fn into_transport(self: Box<Self>) -> Result<Box<dyn NoiseTransport>, CoreError> {
        if !self.finished {
            return Err(CoreError::InvalidEndpoint("handshake not finished".into()));
        }
        let t = self.state.into_transport_mode()
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        Ok(Box::new(Session { transport: t }))
    }

    fn remote_pubkey(&self) -> Option<[u8; 32]> {
        self.state.get_remote_static().and_then(|k| {
            if k.len() != 32 {
                return None;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(k);
            Some(pk)
        })
    }
}

struct Session {
    transport: TransportState,
}

impl NoiseTransport for Session {
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut out = vec![0u8; plaintext.len() + 16];
        let len = self.transport.write_message(plaintext, &mut out)
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        out.truncate(len);
        Ok(out)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut out = vec![0u8; ciphertext.len()];
        let len = self.transport.read_message(ciphertext, &mut out)
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        out.truncate(len);
        Ok(out)
    }
}

pub struct NoiseProvider {
    secret: [u8; 32],
}

impl NoiseProvider {
    pub fn new(secret: [u8; 32]) -> Self {
        Self { secret }
    }
}

impl CryptoProvider for NoiseProvider {
    fn local_pubkey(&self) -> [u8; 32] {
        let secret = x25519_dalek::StaticSecret::from(self.secret);
        let public = x25519_dalek::PublicKey::from(&secret);
        public.to_bytes()
    }

    fn new_initiator(&self, remote_pubkey: &[u8; 32]) -> Result<Box<dyn NoiseHandshake>, CoreError> {
        let params: NoiseParams = PATTERN.parse()
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(&self.secret)
            .remote_public_key(remote_pubkey)
            .build_initiator()
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        Ok(Box::new(Handshake { state, finished: false }))
    }

    fn new_responder(&self) -> Result<Box<dyn NoiseHandshake>, CoreError> {
        let params: NoiseParams = PATTERN.parse()
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(&self.secret)
            .build_responder()
            .map_err(|e: snow::error::Error| CoreError::InvalidEndpoint(e.to_string()))?;
        Ok(Box::new(Handshake { state, finished: false }))
    }
}


#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_with_peer_id() {
        let local = PeerId([1u8; 32]);
        let remote = PeerId([2u8; 32]);

        let pa = NoiseProvider::new([3u8; 32]);
        let pb = NoiseProvider::new([4u8; 32]);
        let b_pk = pb.local_pubkey();

        let mut init = pa.new_initiator(&b_pk).unwrap();
        let mut resp = pb.new_responder().unwrap();

        let msg1 = init.write_message(&local).unwrap();
        assert_eq!(resp.read_message(&msg1).unwrap(), local);

        let msg2 = resp.write_message(&remote).unwrap();
        assert_eq!(init.read_message(&msg2).unwrap(), remote);

        let mut is = init.into_transport().unwrap();
        let mut rs = resp.into_transport().unwrap();
        let ct = is.encrypt(b"hello").unwrap();
        assert_eq!(rs.decrypt(&ct).unwrap(), b"hello");
    }

    #[test]
    fn test_local_pubkey_is_static() {
        let pa = NoiseProvider::new([5u8; 32]);
        assert_eq!(pa.local_pubkey(), pa.local_pubkey());
    }
}
