//! # Noise 加密层 — trait contract（边界模块）
//!
//! ## 模块角色
//! 本模块定义 Noise Protocol 抽象接口，供 transport（调用方）和 lain-noise（实现方）使用。
//!
//! ## Noise IK 模式契约
//!
//! ### Initiator（主动连接方）
//! - `CryptoProvider::new_initiator(remote_pubkey)`：预载对端的 X25519 静态公钥
//!   - 调用方必须传入对端的 X25519 公钥（来自 invite code、DHT 记录等）
//!   - IK pre-message: `<- s` 表示 initiator 已知道 responder 的静态公钥
//! - `write_message(&self_peer_id)`：发送 IK message 1
//!   - payload 为发起方的 PeerId（未经 Ed25519 签名，仅 Noise 加密）
//! - `read_message(&data)`：读取 IK message 2，返回对端 PeerId（来自 payload）
//! - `remote_pubkey()`：握手完成后，返回验证后的对端 X25519 公钥
//!
//! ### Responder（被动接受方）
//! - `CryptoProvider::new_responder()`：**不**预载远端公钥
//!   - IK message 1 中包含 initiator 的 X25519 静态公钥（加密传输）
//! - `read_message(&data)`：读取 IK message 1，返回对端 PeerId
//! - `remote_pubkey()`：提取并返回从 message 1 解密出的对端 X25519 公钥
//! - `write_message(&self_peer_id)`：发送 IK message 2
//!
//! ### 关键安全属性
//! - Noise IK 仅验证 X25519 密钥对的持有权，**不**验证 PeerId 与 Ed25519 的绑定
//! - 调用方必须在上层验证 PeerId 的合法性（invite code 签名 / DHT 记录校验）
//! - `X25519 密钥对` 由 `Ed25519 seed` 通过 SHA256("lain-noise-x25519-v1" || seed) 派生
//!
//! ### 生命周期
//! - `NoiseHandshake` → `into_transport()` → `NoiseTransport`
//! - 握手完成后必须调用 `into_transport()` 转换到传输模式
//! - 传输模式使用 `encrypt`/`decrypt` 进行对称加密

use crate::error::CoreError;
use crate::peer::PeerId;

/// Noise 握手状态
pub trait NoiseHandshake: Send {
    fn write_message(&mut self, peer_id: &PeerId) -> Result<Vec<u8>, CoreError>;
    fn read_message(&mut self, data: &[u8]) -> Result<PeerId, CoreError>;
    fn into_transport(self: Box<Self>) -> Result<Box<dyn NoiseTransport>, CoreError>;
    /// 握手完成后返回验证后的对端 X25519 公钥。
    /// Initiator: 返回与预载值相同（握手加密验证后）。
    /// Responder: 返回从 IK message 1 解密出的 initiator 公钥。
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
