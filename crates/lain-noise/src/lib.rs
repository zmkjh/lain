#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::peer::PeerId;
use snow::{Builder, HandshakeState, TransportState};
use snow::params::NoiseParams;
use std::cmp::Ordering;
use thiserror::Error;
use tracing;

#[derive(Error, Debug)]
pub enum NoiseError {
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("protocol error: {0}")]
    ProtocolError(String),
}

pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

const MAGIC: [u8; 3] = [0x4C, 0x41, 0x49]; // "LAI"
const VERSION: u8 = 0x01;

/// Noise IK 握手的角色
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

impl NoiseRole {
    /// PeerID 小的一方为 Initiator，大的为 Responder
    pub fn from_peer_ids(a: &PeerId, b: &PeerId) -> (Self, Self) {
        match a.0.cmp(&b.0) {
            Ordering::Less => (Self::Initiator, Self::Responder),
            Ordering::Greater => (Self::Responder, Self::Initiator),
            Ordering::Equal => {
                tracing::warn!("identical PeerID, both acting as initiator");
                (Self::Initiator, Self::Initiator)
            }
        }
    }

    pub fn is_initiator(self) -> bool {
        matches!(self, Self::Initiator)
    }
}

/// 完整的 Noise IK 会话
pub struct NoiseSession {
    transport: TransportState,
    role: NoiseRole,
}

/// Noise IK 握手状态机
pub struct NoiseHandshake {
    state: HandshakeState,
    role: NoiseRole,
    finished: bool,
}

impl NoiseHandshake {
    /// 创建 Initiator 握手（知道 Responder 公钥）
    pub fn new_initiator(
        local_secret: &[u8; 32],
        remote_pubkey: &[u8; 32],
    ) -> Result<Self, NoiseError> {
        let params: NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|e| NoiseError::HandshakeFailed(format!("invalid pattern: {e}")))?;

        let handshake = Builder::new(params)
            .local_private_key(local_secret)
            .remote_public_key(remote_pubkey)
            .build_initiator()
            .map_err(|e| NoiseError::HandshakeFailed(format!("initiator build: {e}")))?;

        tracing::debug!("Noise IK initiator handshake started");
        Ok(Self {
            state: handshake,
            role: NoiseRole::Initiator,
            finished: false,
        })
    }

    /// 创建 Responder 握手（使用自身密钥）
    pub fn new_responder(local_secret: &[u8; 32]) -> Result<Self, NoiseError> {
        let params: NoiseParams = NOISE_PATTERN
            .parse()
            .map_err(|e| NoiseError::HandshakeFailed(format!("invalid pattern: {e}")))?;

        let handshake = Builder::new(params)
            .local_private_key(local_secret)
            .build_responder()
            .map_err(|e| NoiseError::HandshakeFailed(format!("responder build: {e}")))?;

        tracing::debug!("Noise IK responder handshake started");
        Ok(Self {
            state: handshake,
            role: NoiseRole::Responder,
            finished: false,
        })
    }

    pub fn role(&self) -> NoiseRole {
        self.role
    }

    /// Initiator: 写第一帧消息 (IK msg 1)
    /// 返回应发送给 Responder 的数据，或 None 表示已无消息
    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.finished {
            return Err(NoiseError::InvalidState("handshake already finished".into()));
        }
        let mut buf = vec![0u8; 4096];
        let len = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);

        if self.state.is_handshake_finished() {
            self.finished = true;
        }

        Ok(buf)
    }

    /// 读对方发来的握手消息，返回解出的 payload
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if self.finished {
            return Err(NoiseError::InvalidState("handshake already finished".into()));
        }
        let mut buf = vec![0u8; 4096];
        let len = self
            .state
            .read_message(message, &mut buf)
            .map_err(|e| NoiseError::HandshakeFailed(e.to_string()))?;
        buf.truncate(len);

        if self.state.is_handshake_finished() {
            self.finished = true;
        }

        Ok(buf)
    }

    /// 握手是否完成
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// 转换为传输模式
    pub fn into_transport(self) -> Result<NoiseSession, NoiseError> {
        if !self.finished {
            return Err(NoiseError::InvalidState("handshake not finished".into()));
        }
        let transport = self
            .state
            .into_transport_mode()
            .map_err(|e| NoiseError::HandshakeFailed(format!("transport mode: {e}")))?;

        tracing::info!("Noise IK handshake completed");
        Ok(NoiseSession {
            transport,
            role: self.role,
        })
    }

    /// 获取对端的远程公钥（握手完成后可用）
    pub fn remote_pubkey(&self) -> Option<[u8; 32]> {
        if !self.finished {
            return None;
        }
        self.state.get_remote_static().map(|key| {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&key[..32.min(key.len())]);
            pk
        })
    }
}

impl NoiseSession {
    pub fn role(&self) -> NoiseRole {
        self.role
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut output = vec![0u8; plaintext.len() + 16]; // AEAD overhead
        let len = self
            .transport
            .write_message(plaintext, &mut output)
            .map_err(|e| NoiseError::EncryptionFailed(e.to_string()))?;
        output.truncate(len);
        Ok(output)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let mut output = vec![0u8; ciphertext.len()];
        let len = self
            .transport
            .read_message(ciphertext, &mut output)
            .map_err(|e| NoiseError::DecryptionFailed(e.to_string()))?;
        output.truncate(len);
        Ok(output)
    }
}

/// 执行完整的 Noise IK 握手
/// Initiator: write msg1 → Responder: read msg1 + write msg2 → Initiator: read msg2
pub fn perform_full_handshake(
    mut initiator: NoiseHandshake,
    mut responder: NoiseHandshake,
) -> Result<(NoiseSession, NoiseSession), NoiseError> {
    // IK Message 1: initiator → responder (e, es, s, ss)
    let msg1 = initiator.write_message(&[])?;

    // Responder processes msg1, gets msg2 payload
    let _resp_payload = responder.read_message(&msg1)?;

    // IK Message 2: responder → initiator (e, ee, se)
    let msg2 = responder.write_message(&[])?;

    // Initiator processes msg2
    let _init_payload = initiator.read_message(&msg2)?;

    // Now both sides should be finished
    let init_session = initiator.into_transport()?;
    let resp_session = responder.into_transport()?;

    Ok((init_session, resp_session))
}

/// 编码 Noise 握手帧
pub fn encode_handshake_frame(step: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(8 + len);
    frame.extend_from_slice(&MAGIC);
    frame.push(VERSION);
    frame.push(step);
    frame.push(((len >> 16) & 0xFF) as u8);
    frame.push(((len >> 8) & 0xFF) as u8);
    frame.push((len & 0xFF) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// 解析 Noise 握手帧头
pub struct FrameHeader {
    pub handshake_step: u8,
    pub payload_len: usize,
}

pub fn parse_frame_header(data: &[u8]) -> Result<FrameHeader, NoiseError> {
    if data.len() < 7 {
        return Err(NoiseError::ProtocolError("frame too short".into()));
    }
    if data[0..3] != MAGIC {
        return Err(NoiseError::ProtocolError("invalid magic".into()));
    }
    if data[3] != VERSION {
        return Err(NoiseError::ProtocolError(format!(
            "unsupported version: {}",
            data[3]
        )));
    }
    let step = data[4];
    let payload_len =
        ((data[5] as usize) << 16) | ((data[6] as usize) << 8) | (data[7] as usize);
    Ok(FrameHeader {
        handshake_step: step,
        payload_len,
    })
}

/// 编码 Lain 数据帧（握手完成后）
pub fn encode_frame(stream_id: u64, frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&MAGIC);
    encode_varint(stream_id, &mut frame);
    encode_varint(frame_type, &mut frame);
    encode_varint(payload.len() as u64, &mut frame);
    frame.extend_from_slice(payload);
    frame
}

fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    if value <= 63 {
        buf.push(value as u8);
    } else if value <= 16383 {
        buf.push(0x40 | ((value >> 8) as u8 & 0x3F));
        buf.push(value as u8);
    } else if value <= 1073741823 {
        buf.push(0x80 | ((value >> 24) as u8 & 0x3F));
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(0xC0 | ((value >> 56) as u8 & 0x3F));
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

/// 生成 Noise 临时密钥对（用于 IK 模式中的 e）
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .expect("valid pattern");
    let builder = Builder::new(params);
    let kp = builder.generate_keypair().expect("keygen");
    let mut secret = [0u8; 32];
    let mut public = [0u8; 32];
    secret.copy_from_slice(&kp.private[..32]);
    public.copy_from_slice(&kp.public[..32]);
    (secret, public)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_handshake_frame() {
        let payload = b"test";
        let frame = encode_handshake_frame(0, payload);
        assert_eq!(&frame[0..3], b"LAI");
        assert_eq!(frame[3], 1);
        assert_eq!(frame[4], 0);
        assert_eq!(frame[7], 4);
        assert_eq!(&frame[8..], payload);
    }

    #[test]
    fn test_parse_frame_header() {
        let payload = vec![1u8, 2, 3];
        let frame = encode_handshake_frame(1, &payload);
        let header = parse_frame_header(&frame).unwrap();
        assert_eq!(header.handshake_step, 1);
        assert_eq!(header.payload_len, 3);
    }

    #[test]
    fn test_parse_invalid_frame() {
        assert!(parse_frame_header(&[]).is_err());
        assert!(parse_frame_header(&[0; 10]).is_err());
    }

    #[test]
    fn test_role_assignment() {
        let a = PeerId([2u8; 32]);
        let b = PeerId([1u8; 32]);
        let (role_a, role_b) = NoiseRole::from_peer_ids(&a, &b);
        assert!(role_b.is_initiator()); // smaller is initiator
        assert!(!role_a.is_initiator());
    }

    #[test]
    fn test_full_handshake() {
        // Generate two independent keypairs
        let (init_secret, init_public) = generate_keypair();
        let (resp_secret, resp_public) = generate_keypair();

        // Initiator knows responder's public key
        let init = NoiseHandshake::new_initiator(&init_secret, &resp_public).unwrap();
        let resp = NoiseHandshake::new_responder(&resp_secret).unwrap();

        let (init_session, resp_session) = perform_full_handshake(init, resp).unwrap();

        // Test encryption/decryption
        let plaintext = b"hello noise ik";
        let mut sender = init_session;
        let mut receiver = resp_session;

        let ciphertext = sender.encrypt(plaintext).unwrap();
        let decrypted = receiver.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);

        // Reverse direction
        let ciphertext = receiver.encrypt(b"world").unwrap();
        let decrypted = sender.decrypt(&ciphertext).unwrap();
        assert_eq!(&decrypted, b"world");
    }

    #[test]
    fn test_varint_encoding() {
        let test_cases = vec![
            (0u64, vec![0x00]),
            (63, vec![0x3F]),
            (64, vec![0x40, 0x40]),
            (16383, vec![0x7F, 0xFF]),
            (16384, vec![0x80, 0x00, 0x40, 0x00]),
        ];
        for (value, expected) in test_cases {
            let mut buf = Vec::new();
            encode_varint(value, &mut buf);
            assert_eq!(buf, expected, "varint encode {value}");
        }
    }
}
