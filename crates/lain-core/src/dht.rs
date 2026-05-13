use std::net::SocketAddr;

use crate::capabilities::Capabilities;
use crate::endpoint::Endpoint;
use crate::error::CoreError;
use crate::identity::{Ed25519PublicKey, Ed25519Signature};
use crate::peer::PeerId;

/// Relay 候选节点
#[derive(Clone, Debug)]
pub struct RelayInfo {
    pub node_id: PeerId,
    pub address: SocketAddr,
    pub noise_pubkey: [u8; 32],
}

/// DHT 中存储的 peer 记录
#[derive(Clone, Debug)]
pub struct PeerRecord {
    pub pubkey: Ed25519PublicKey,
    pub noise_pubkey: Ed25519PublicKey,  // X25519 for Noise IK
    pub endpoints: Vec<Endpoint>,
    pub capabilities: Capabilities,
    pub ttl_remaining: u32,
}

/// DHT 事件
#[derive(Clone, Debug)]
pub enum DhtEvent {
    PeerDiscovered(PeerId, PeerRecord),
    PeerExpired(PeerId),
    PeerUpdated(PeerId, PeerRecord),
    RoutingTableChanged,
}

/// DHT 消息类型
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DhtMsgType {
    Ping = 0x00,
    Store = 0x01,
    FindValue = 0x02,
    FindNode = 0x03,
    RelayNeeded = 0x04,
    Error = 0x05,
    AddrReflect = 0x06,
}

impl DhtMsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x7F {
            0x00 => Some(Self::Ping),
            0x01 => Some(Self::Store),
            0x02 => Some(Self::FindValue),
            0x03 => Some(Self::FindNode),
            0x04 => Some(Self::RelayNeeded),
            0x05 => Some(Self::Error),
            0x06 => Some(Self::AddrReflect),
            _ => None,
        }
    }

    pub fn is_response(v: u8) -> bool {
        v & 0x80 != 0
    }
}

/// DHT RPC 消息
#[derive(Clone, Debug)]
pub struct DhtMessage {
    pub version: u8,
    pub message_id: [u8; 16],
    pub msg_type: DhtMsgType,
    pub is_response: bool,
    pub sender_id: PeerId,
    pub payload: Vec<u8>,
    pub signature: Option<Ed25519Signature>,
}

/// DHT 错误码
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DhtErrorCode {
    UnsupportedVersion = 1,
    InvalidSignature = 2,
    MessageTooLarge = 3,
    InternalError = 4,
}

impl DhtErrorCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::UnsupportedVersion),
            2 => Some(Self::InvalidSignature),
            3 => Some(Self::MessageTooLarge),
            4 => Some(Self::InternalError),
            _ => None,
        }
    }
}

/// DHT 目录服务接口 — 供 daemon 和 test mock 使用
#[async_trait::async_trait]
pub trait DhtBackend: Send + Sync {
    async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), CoreError>;
    async fn store_self(&self, pubkey: &[u8; 32], noise_pubkey: &[u8; 32], endpoints: &[Endpoint], capabilities: Capabilities) -> Result<(), CoreError>;
    async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<PeerRecord>, CoreError>;
    async fn find_relays(&self) -> Result<Vec<RelayInfo>, CoreError>;
    async fn routing_table_size(&self) -> usize;
}
