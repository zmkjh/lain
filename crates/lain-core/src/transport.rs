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
    async fn send(&self, data: &[u8]) -> Result<(), CoreError>;
    /// 返回 (FrameType, payload)。Data 帧的 payload 是应用数据，
    /// RelayConnect 等控制帧由调用方自行处理。
    async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError>;
    fn close(&self);
    fn path(&self) -> PathType;
    fn rtt_ms(&self) -> Option<u64> { None }
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, peer_id: PeerId, noise_pubkey: &[u8; 32], endpoints: &[Endpoint]) -> Result<Box<dyn Connection>, CoreError>;
    async fn connect_tso(&self, peer_id: PeerId, tso_endpoints: &[SocketAddr], port_delta: Option<u16>, stun_rtt_ms: Option<u64>) -> Result<Box<dyn Connection>, CoreError>;
    async fn accept(&self) -> Result<Box<dyn Connection>, CoreError>;
    fn local_addr(&self) -> Result<SocketAddr, CoreError>;
}
