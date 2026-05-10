#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use lain_core::capabilities::Capabilities;
use lain_core::dht::{DhtMsgType, NodeInfo};
use lain_core::dht::DhtEvent as CoreDhtEvent;
use lain_core::endpoint::Endpoint;
use lain_core::peer::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing;

mod message;
mod routing;

use self::routing::{BucketEntry, RoutingTable};
use self::message::{self as msg_codec};

#[derive(Error, Debug)]
pub enum DhtError {
    #[error("bootstrap failed after {attempts} attempts: {last_error}")]
    BootstrapFailed { attempts: u8, last_error: String },
    #[error("RPC timeout for {rpc_type} to {peer_id}")]
    RpcTimeout { rpc_type: &'static str, peer_id: PeerId },
    #[error("signature verification failed for {peer_id}")]
    InvalidSignature { peer_id: PeerId },
    #[error("routing table corrupted: {detail}")]
    RoutingTableCorrupted { detail: String },
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("network error: {0}")]
    Network(String),
}

#[derive(Clone, Debug)]
pub struct DhtConfig {
    pub k: usize,
    pub alpha: usize,
    pub ttl_seconds: u32,
    pub heartbeat_interval_secs: u64,
    pub republish_interval_secs: u64,
    pub idle_peer_timeout_secs: u64,
    pub local_addr: SocketAddr,
    pub bootstrap_nodes: Vec<SocketAddr>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            k: lain_core::DHT_K,
            alpha: lain_core::DHT_ALPHA,
            ttl_seconds: lain_core::DHT_TTL_SECS,
            heartbeat_interval_secs: lain_core::DHT_HEARTBEAT_SECS,
            republish_interval_secs: lain_core::DHT_REPUBLISH_SECS,
            idle_peer_timeout_secs: 900,
            local_addr: "0.0.0.0:0".parse().unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
            bootstrap_nodes: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerRecord {
    pub pubkey: [u8; 32],
    pub endpoints: Vec<Endpoint>,
    pub capabilities: Capabilities,
    pub ttl_remaining: u32,
    pub expires_at: std::time::Instant,
}

pub struct DhtHandle {
    pub peer_id: PeerId,
    pub public_key: [u8; 32],
    config: DhtConfig,
    routing_table: Arc<RwLock<RoutingTable>>,
    peer_records: Arc<RwLock<HashMap<PeerId, PeerRecord>>>,
    event_tx: broadcast::Sender<CoreDhtEvent>,
    socket: Arc<UdpSocket>,
}

#[derive(Serialize, Deserialize)]
struct RoutesEntry {
    node_id_hex: String,
    addr: String,
}

impl DhtHandle {
    pub fn new(
        peer_id: PeerId,
        public_key: [u8; 32],
        config: DhtConfig,
    ) -> Result<Self, DhtError> {
        let routing_table = Arc::new(RwLock::new(RoutingTable::new(peer_id, config.k)));
        let peer_records = Arc::new(RwLock::new(HashMap::new()));
        let (event_tx, _rx) = broadcast::channel(64);
        // Socket will be bound later
        let std_socket = std::net::UdpSocket::bind(config.local_addr)
            .map_err(|e| DhtError::Network(e.to_string()))?;
        let _ = std_socket.set_nonblocking(true);
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| DhtError::Network(e.to_string()))?;

        Ok(Self {
            peer_id,
            public_key,
            config,
            routing_table,
            peer_records,
            event_tx,
            socket: Arc::new(socket),
        })
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<CoreDhtEvent> {
        self.event_tx.subscribe()
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Bootstrap 到已知节点
    pub async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), DhtError> {
        let mut attempted: u8 = 0;
        let mut last_err = String::new();
        for seed in seeds {
            attempted += 1;
            tracing::info!("bootstrapping via {seed}");
            let msg_id = rand::random::<u128>().to_be_bytes();
            let ping = msg_codec::encode_ping_request(self.peer_id, msg_id);
            if let Err(e) = self.socket.send_to(&ping, *seed).await {
                last_err = e.to_string();
                continue;
            }
            let msg_id = rand::random::<u128>().to_be_bytes();
            let find_node = msg_codec::encode_find_node_request(self.peer_id, msg_id, self.peer_id);
            if let Err(e) = self.socket.send_to(&find_node, *seed).await {
                last_err = e.to_string();
                continue;
            }
            return Ok(());
        }
        Err(DhtError::BootstrapFailed { attempts: attempted, last_error: last_err })
    }

    /// STORE 自身到最近的 k 个节点
    pub async fn store_self(
        &self,
        pubkey: &[u8; 32],
        endpoints: &[Endpoint],
        capabilities: Capabilities,
    ) -> Result<(), DhtError> {
        let closest = {
            let rt = self.routing_table.read().await;
            rt.closest_nodes(&self.peer_id, self.config.k)
        };
        let msg = msg_codec::encode_store_request(
            self.peer_id,
            &self.peer_id.0,
            self.config.ttl_seconds,
            pubkey,
            endpoints,
        );
        for node in &closest {
            let _ = self.socket.send_to(&msg, node.address).await;
        }
        // Save locally
        let record = PeerRecord {
            pubkey: *pubkey,
            endpoints: endpoints.to_vec(),
            capabilities,
            ttl_remaining: self.config.ttl_seconds,
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_secs(self.config.ttl_seconds as u64),
        };
        self.peer_records.write().await.insert(self.peer_id, record);
        Ok(())
    }

    /// FIND_VALUE 查找 peer
    pub async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<PeerRecord>, DhtError> {
        // Check cache
        {
            let records = self.peer_records.read().await;
            if let Some(r) = records.get(peer_id) {
                if r.expires_at > std::time::Instant::now() {
                    return Ok(Some(r.clone()));
                }
            }
        }
        // Iterative lookup to alpha closest nodes
        let closest = {
            let rt = self.routing_table.read().await;
            rt.closest_nodes(peer_id, self.config.alpha)
        };
        for node in &closest {
            let msg_id = rand::random::<u128>().to_be_bytes();
            let req = msg_codec::encode_find_value_request(self.peer_id, msg_id, &peer_id.0);
            let _ = self.socket.send_to(&req, node.address).await;
        }
        // Response comes via handle_incoming
        let records = self.peer_records.read().await;
        Ok(records.get(peer_id).cloned().filter(|r| r.expires_at > std::time::Instant::now()))
    }

    /// 序列化路由表到文件
    pub async fn save_routes(&self, path: &std::path::Path) -> Result<(), DhtError> {
        let rt = self.routing_table.read().await;
        let nodes: Vec<RoutesEntry> = rt.all_nodes().into_iter().map(|n| RoutesEntry {
            node_id_hex: n.node_id.to_hex(),
            addr: n.address.to_string(),
        }).collect();
        let data = serde_json::to_vec(&nodes)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        std::fs::write(path, data)
            .map_err(|e| DhtError::Network(e.to_string()))?;
        tracing::info!("saved {} routes to {}", nodes.len(), path.display());
        Ok(())
    }

    /// 从文件加载路由表
    pub async fn load_routes(&self, path: &std::path::Path) -> Result<usize, DhtError> {
        if !path.exists() {
            return Ok(0);
        }
        let data = std::fs::read(path)
            .map_err(|e| DhtError::Network(e.to_string()))?;
        let entries: Vec<RoutesEntry> = serde_json::from_slice(&data)
            .map_err(|e| DhtError::Serialization(e.to_string()))?;
        let mut count = 0usize;
        let mut rt = self.routing_table.write().await;
        for entry in entries {
            if let (Ok(peer_id), Ok(addr)) = (
                PeerId::from_hex(&entry.node_id_hex),
                entry.addr.parse::<SocketAddr>(),
            ) {
                rt.insert_or_update(BucketEntry {
                    node_id: peer_id,
                    address: addr,
                    last_seen: std::time::Instant::now(),
                });
                count += 1;
            }
        }
        tracing::info!("loaded {count} routes from {}", path.display());
        Ok(count)
    }

    /// 查找 relay 候选
    pub async fn find_relays(&self) -> Result<Vec<NodeInfo>, DhtError> {
        let rt = self.routing_table.read().await;
        Ok(rt.all_nodes().into_iter()
            .filter(|n| n.node_id != self.peer_id)
            .map(|n| NodeInfo { node_id: n.node_id, address: n.address })
            .collect())
    }

    /// 处理入站 DHT 消息，必要时通过 socket 回复
    pub async fn handle_incoming(&self, data: &[u8], src: SocketAddr) -> Result<(), DhtError> {
        let msg = msg_codec::decode_message(data)
            .ok_or_else(|| DhtError::Serialization("decode failed".into()))?;

        // 更新路由表
        {
            let mut rt = self.routing_table.write().await;
            rt.insert_or_update(BucketEntry {
                node_id: msg.sender_id,
                address: src,
                last_seen: std::time::Instant::now(),
            });
        }

        if msg.is_response {
            return self.handle_response(msg, src).await;
        }
        self.handle_request(msg, src).await
    }

    async fn handle_request(&self, msg: lain_core::dht::DhtMessage, src: SocketAddr) -> Result<(), DhtError> {
        match msg.msg_type {
            DhtMsgType::Ping => {
                let closest = {
                    let rt = self.routing_table.read().await;
                    rt.closest_nodes(&msg.sender_id, self.config.k)
                };
                let resp = msg_codec::encode_ping_response(self.peer_id, msg.message_id, &closest);
                let _ = self.socket.send_to(&resp, src).await;
            }
            DhtMsgType::FindNode => {
                if msg.payload.len() >= 32 {
                    let target = PeerId(msg.payload[..32].try_into().unwrap_or([0u8; 32]));
                    let closest = {
                        let rt = self.routing_table.read().await;
                        rt.closest_nodes(&target, self.config.k)
                    };
                    let resp = msg_codec::encode_find_node_response(self.peer_id, msg.message_id, &closest);
                    let _ = self.socket.send_to(&resp, src).await;
                }
            }
            DhtMsgType::Store => {
                if msg.payload.len() >= 36 {
                    let key = PeerId(msg.payload[..32].try_into().unwrap_or([0u8; 32]));
                    let ttl = u32::from_be_bytes([msg.payload[32], msg.payload[33], msg.payload[34], msg.payload[35]]);
                    let _ = ttl;
                    // Store the record locally (parse pubkey + endpoints)
                    if msg.payload.len() >= 68 {
                        let mut pubkey = [0u8; 32];
                        pubkey.copy_from_slice(&msg.payload[36..68]);
                        let record = PeerRecord {
                            pubkey,
                            endpoints: vec![],
                            capabilities: Capabilities::new(),
                            ttl_remaining: 300,
                            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(300),
                        };
                        self.peer_records.write().await.insert(key, record);
                        let _ = self.event_tx.send(CoreDhtEvent::PeerDiscovered(key, PeerRecord {
                            pubkey,
                            endpoints: vec![],
                            capabilities: Capabilities::new(),
                            ttl_remaining: 300,
                            expires_at: std::time::Instant::now(),
                        }.into_core(&key)));
                    }
                }
                // ACK
                let resp = msg_codec::encode_store_ack(self.peer_id, msg.message_id);
                let _ = self.socket.send_to(&resp, src).await;
            }
            DhtMsgType::FindValue => {
                if msg.payload.len() >= 32 {
                    let key = PeerId(msg.payload[..32].try_into().unwrap_or([0u8; 32]));
                    let record = {
                        let records = self.peer_records.read().await;
                        records.get(&key).cloned()
                    };
                    if let Some(ref rec) = record {
                        if rec.expires_at > std::time::Instant::now() {
                            let resp = msg_codec::encode_find_value_response_with_record(
                                self.peer_id, msg.message_id, &rec,
                            );
                            let _ = self.socket.send_to(&resp, src).await;
                            return Ok(());
                        }
                    }
                    // Not found: return k-closest
                    let closest = {
                        let rt = self.routing_table.read().await;
                        rt.closest_nodes(&key, self.config.k)
                    };
                    let resp = msg_codec::encode_find_value_response_not_found(
                        self.peer_id, msg.message_id, &closest,
                    );
                    let _ = self.socket.send_to(&resp, src).await;
                }
            }
            DhtMsgType::AddrReflect => {
                let resp = msg_codec::encode_addr_reflect_response(
                    self.peer_id, msg.message_id, &src,
                );
                let _ = self.socket.send_to(&resp, src).await;
            }
            DhtMsgType::RelayNeeded => {
                let relays = {
                    let rt = self.routing_table.read().await;
                    rt.all_nodes().into_iter()
                        .filter(|n| n.node_id != self.peer_id && n.node_id != msg.sender_id)
                        .take(8)
                        .collect::<Vec<_>>()
                };
                let resp = msg_codec::encode_relay_needed_response(
                    self.peer_id, msg.message_id, &relays,
                );
                let _ = self.socket.send_to(&resp, src).await;
            }
            DhtMsgType::Error => {}
        }
        Ok(())
    }

    async fn handle_response(&self, msg: lain_core::dht::DhtMessage, _src: SocketAddr) -> Result<(), DhtError> {
        match msg.msg_type {
            DhtMsgType::Ping => {
                // Parse k-closest nodes from response, add to routing table
                if let Some(nodes) = msg_codec::parse_nodes_from_payload(&msg.payload) {
                    let mut rt = self.routing_table.write().await;
                    for (node_id, addr) in nodes {
                        rt.insert_or_update(BucketEntry {
                            node_id,
                            address: addr,
                            last_seen: std::time::Instant::now(),
                        });
                    }
                }
            }
            DhtMsgType::FindNode => {
                if let Some(nodes) = msg_codec::parse_nodes_from_payload(&msg.payload) {
                    let mut rt = self.routing_table.write().await;
                    for (node_id, addr) in nodes {
                        rt.insert_or_update(BucketEntry {
                            node_id,
                            address: addr,
                            last_seen: std::time::Instant::now(),
                        });
                    }
                }
            }
            DhtMsgType::FindValue => {
                // Parse response: either value or k-closest
                let payload = &msg.payload;
                if !payload.is_empty() && payload[0] == 1 {
                    // Has value: parse PeerRecord
                    if let Some(record) = msg_codec::parse_record_from_payload(&payload[1..]) {
                        let peer_id = PeerId(msg.sender_id.0);
                        let _ = self.event_tx.send(CoreDhtEvent::PeerDiscovered(
                            peer_id,
                            record.into_core(&peer_id),
                        ));
                    }
                } else {
                    // k-closest nodes
                    if let Some(nodes) = msg_codec::parse_nodes_from_payload(
                        if payload.len() > 1 { &payload[1..] } else { &[] }
                    ) {
                        let mut rt = self.routing_table.write().await;
                        for (node_id, addr) in nodes {
                            rt.insert_or_update(BucketEntry {
                                node_id,
                                address: addr,
                                last_seen: std::time::Instant::now(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

// Convert local PeerRecord ↔ core PeerRecord
impl crate::PeerRecord {
    fn into_core(&self, _peer_id: &PeerId) -> lain_core::dht::PeerRecord {
        lain_core::dht::PeerRecord {
            pubkey: self.pubkey,
            endpoints: self.endpoints.clone(),
            capabilities: self.capabilities,
            ttl_remaining: self.ttl_remaining,
        }
    }
}
