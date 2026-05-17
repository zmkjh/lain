//! # Transport layer — trait contract (边界模块)
//!
//! ## 模块角色
//! 本模块定义传输层抽象接口，供 daemon（调用方）和 lain-transport（实现方）使用。
//! `lain-core` 不实现任何 I/O，仅定义类型和 trait。
//!
//! ## 两条连接路径
//!
//! ### QUIC 连接（`connect`）
//! - 调用方提供 `noise_pubkey: &[u8; 32]`（目标的 X25519 公钥）
//! - 实现方向对端发起 Noise IK 握手，`noise_pubkey` 作为 IK 模式的 pre-message
//! - 返回的 `Connection` 必须提供 `noise_pubkey()` 返回握手验证后的远端 X25519 公钥
//! - 对端 PeerId 经过 Noise payload 传递，**不**附加 Ed25519 签名验证
//!
//! ### TSO 连接（`connect_tso`）
//! - **不**接受 `noise_pubkey` 参数
//! - TSO 握手在 TCP 上自行完成 Noise IK，认证依赖 Noise payload 中的 PeerId
//! - 调用方（daemon）必须自行验证 TSO 连接的身份（通过 invite code 签名或 DHT 记录）
//! - `port_delta`: 0 表示不追加随机端口；非零值用于对称 NAT 的端口预测
//! - `mappable_port_start/end`: 对端可映射端口范围，用于生成额外的随机端口探测
//!
//! ## 调用方约定
//! - daemon 是唯一的调用方
//! - daemon 必须将从 `connect`/`connect_tso`/`accept` 获取的 `Connection` 插入 `connected` map
//! - daemon 负责连接生命周期管理：spawn reader/reconnect，处理旧条目替换，发送事件

use crate::endpoint::Endpoint;
use crate::error::CoreError;
use crate::frame::FrameType;
use crate::peer::PeerId;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PathType {
    Direct = 0,
    TSO = 1,
}

#[async_trait::async_trait]
pub trait Connection: Send + Sync {
    fn peer_id(&self) -> PeerId;
    /// X25519 远端公钥（Noise IK 握手验证后的值）。
    /// QUIC 路径返回 `Some(verified_key)`；TSO 路径返回 `None`。
    fn noise_pubkey(&self) -> Option<[u8; 32]> { None }
    async fn send(&self, ft: FrameType, data: &[u8]) -> Result<(), CoreError>;
    async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError>;
    fn close(&self);
    fn path(&self) -> PathType;
    fn rtt_ms(&self) -> Option<u64> { None }
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// QUIC 连接。`noise_pubkey` 是对端的 X25519 公钥，作为 Noise IK pre-message。
    /// 返回的 Connection 应提供握手验证后的远端 X25519 公钥。
    async fn connect(&self, peer_id: PeerId, noise_pubkey: &[u8; 32], endpoints: &[Endpoint]) -> Result<Box<dyn Connection>, CoreError>;
    /// TSO 连接（TCP 端口映射穿透）。**不**接受 noise_pubkey 参数；
    /// TSO 握手在 TCP 上独立完成 Noise IK，身份由 Noise payload 中的 PeerId 认证。
    async fn connect_tso(&self, peer_id: PeerId, tso_endpoints: &[SocketAddr], port_delta: Option<u16>, stun_rtt_ms: Option<u64>, mappable_port_start: u16, mappable_port_end: u16) -> Result<Box<dyn Connection>, CoreError>;
    async fn accept(&self) -> Result<Box<dyn Connection>, CoreError>;
    fn local_addr(&self) -> Result<SocketAddr, CoreError>;
}
