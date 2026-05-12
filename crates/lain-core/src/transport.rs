use crate::endpoint::Endpoint;
use crate::error::CoreError;
use crate::identity::Ed25519PublicKey;
use crate::peer::PeerId;

/// QUIC stream 句柄（由具体实现提供）
pub struct QuicStream;

/// QUIC datagram 发送器（由具体实现提供）
pub struct QuicDatagramSender;

/// 已建立的连接
pub struct Connection {
    pub peer_id: PeerId,
    pub peer_pubkey: Ed25519PublicKey,
    pub stream: QuicStream,
    pub datagram: QuicDatagramSender,
}

/// 入站连接（Noise IK 已完成）
pub struct IncomingConnection {
    pub peer_id: PeerId,
    pub peer_pubkey: Ed25519PublicKey,
    pub stream: QuicStream,
}

/// 穿透路径类型
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PathType {
    IPv6 = 0,
    STUN = 1,
    Relay = 2,
    WebSocket = 3,
    TSO = 4,
}

/// 传输层接口
#[async_trait::async_trait]
pub trait TransportLayer: Send + Sync {
    /// 主动连接 peer（执行完整穿透流程）
    async fn connect(
        &self,
        peer_id: &PeerId,
        pubkey: &Ed25519PublicKey,
        endpoints: &[Endpoint],
    ) -> Result<Connection, CoreError>;

    /// 处理入站连接
    async fn accept(&self) -> Result<IncomingConnection, CoreError>;

    /// 通知地址变更
    fn on_endpoints_changed(&self, peer_id: &PeerId, endpoints: Vec<Endpoint>);
}
