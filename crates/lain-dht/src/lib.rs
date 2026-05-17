#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use lain_core::capabilities::Capabilities;
use lain_core::dht::{DhtBackend, DhtMessage, DhtMsgType, RelayInfo};
use lain_core::dht::DhtEvent as CoreDhtEvent;
use lain_core::endpoint::Endpoint;
use lain_core::error::CoreError;
use lain_core::peer::PeerId;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tracing;

pub mod message;
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
    pub noise_pubkey: [u8; 32],   // X25519 public key for Noise IK
    pub endpoints: Vec<Endpoint>,
    pub capabilities: Capabilities,
    pub ttl_remaining: u32,
    pub expires_at: std::time::Instant,
}

pub struct DhtHandle {
    peer_id: PeerId,
    config: DhtConfig,
    routing_table: Arc<RwLock<RoutingTable>>,
    peer_records: Arc<RwLock<HashMap<PeerId, PeerRecord>>>,
    event_tx: broadcast::Sender<CoreDhtEvent>,
    socket: Arc<UdpSocket>,
    signing_key: Option<[u8; 32]>,
    pending_queries: Arc<RwLock<HashMap<[u8; 16], tokio::sync::oneshot::Sender<Option<PeerRecord>>>>>,
    peer_ratelimit: Arc<RwLock<HashMap<PeerId, (u128, u32)>>>,
}

#[derive(Serialize, Deserialize)]
struct RoutesEntry {
    node_id_hex: String,
    addr: String,
}

impl DhtHandle {
    pub fn new(
        peer_id: PeerId,
        _public_key: [u8; 32],
        config: DhtConfig,
    ) -> Result<Self, DhtError> {
        let routing_table = Arc::new(RwLock::new(RoutingTable::new(peer_id, config.k)));
        let peer_records = Arc::new(RwLock::new(HashMap::new()));
        let (event_tx, _rx) = broadcast::channel(64);
        let std_socket = std::net::UdpSocket::bind(config.local_addr)
                .map_err(|e| DhtError::Network(e.to_string()))?;
            let _ = std_socket.set_nonblocking(true);
        let socket = UdpSocket::from_std(std_socket)
            .map_err(|e| DhtError::Network(e.to_string()))?;

        Ok(Self {
            peer_id,
            config,
            routing_table,
            peer_records,
            event_tx,
            socket: Arc::new(socket),
            signing_key: None,
            pending_queries: Arc::new(RwLock::new(HashMap::new())),
            peer_ratelimit: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<CoreDhtEvent> {
        self.event_tx.subscribe()
    }

    /// 设置 Ed25519 签名密钥（32 字节 seed）
    pub fn set_signer(&mut self, secret: [u8; 32]) {
        self.signing_key = Some(secret);
    }

    /// 内部签名方法：有密钥则签名，无密钥则返回零占位
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Bootstrap 到已知节点并递归填充路由表
    pub async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), DhtError> {
        let mut attempted: u8 = 0;
        let mut last_err = String::new();
        for seed in seeds {
            attempted += 1;
            tracing::info!("bootstrapping via {seed}");
            let msg_id = rand::random::<u128>().to_be_bytes();
            let ping = self.encode_ping(msg_id);
            if let Err(e) = self.socket.send_to(&ping, *seed).await {
                last_err = e.to_string();
                continue;
            }
            let msg_id = rand::random::<u128>().to_be_bytes();
            let find_node = self.encode_find_node(msg_id, self.peer_id);
            if let Err(e) = self.socket.send_to(&find_node, *seed).await {
                last_err = e.to_string();
                continue;
            }
            // Recursively fill routing table: FIND_NODE(self.id) from each newly discovered node
            // Let in-flight responses populate the table; just need one successful contact
            return Ok(());
        }
        Err(DhtError::BootstrapFailed { attempts: attempted, last_error: last_err })
    }

    /// Bootstrap 后递归填满路由表（后台运行）
    pub fn spawn_bucket_refresh(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            // Give initial responses time to arrive
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            // Iterate over all buckets and refresh each
            for bucket_idx in 0..lain_core::DHT_BUCKET_COUNT {
                // Generate a random ID in this bucket's range
                let target = this.random_id_in_bucket(bucket_idx);
                let msg_id = rand::random::<u128>().to_be_bytes();
                let req = this.encode_find_node(msg_id, target);
                let closest = {
                    let rt = this.routing_table.read().await;
                    rt.closest_nodes(&target, 3)
                };
                for node in &closest {
                    this.send_msg(&req, node.address).await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            tracing::info!("bootstrap bucket refresh complete, {} nodes in routing table",
                this.routing_table.read().await.size());
        });
    }

    /// Generate a random PeerID in the given bucket's XOR range
    pub(crate) fn random_id_in_bucket(&self, bucket_idx: usize) -> PeerId {
        let mut id = self.peer_id.0;
        if bucket_idx < 256 {
            // Flip the defining bit for this bucket (first non-zero XOR bit)
            let byte_idx = bucket_idx / 8;
            let bit_idx = 7 - (bucket_idx % 8);
            id[byte_idx] ^= 1u8 << bit_idx;
            // Randomize less significant bits for query diversity
            for b in (bucket_idx + 1)..256 {
                let byte_idx = b / 8;
                let bit_idx = 7 - (b % 8);
                if rand::random::<bool>() {
                    id[byte_idx] ^= 1u8 << bit_idx;
                }
            }
        }
        PeerId(id)
    }

    fn encode_ping(&self, message_id: [u8; 16]) -> Vec<u8> {
        msg_codec::encode_ping_request_signed(self.peer_id, message_id, self.signing_key.as_ref())
    }

    fn encode_find_node(&self, message_id: [u8; 16], target_id: PeerId) -> Vec<u8> {
        msg_codec::encode_find_node_request_signed(self.peer_id, message_id, target_id, self.signing_key.as_ref())
    }

    fn encode_store(&self, key: &[u8; 32], message_id: [u8; 16], ttl: u32, pubkey: &[u8; 32], noise_pubkey: &[u8; 32], capabilities: Capabilities, endpoints: &[Endpoint]) -> Vec<u8> {
        msg_codec::encode_store_request_signed(self.peer_id, message_id, key, ttl, pubkey, noise_pubkey, capabilities, endpoints, self.signing_key.as_ref())
    }

    fn encode_find_value(&self, message_id: [u8; 16], key: &[u8; 32]) -> Vec<u8> {
        msg_codec::encode_find_value_request_signed(self.peer_id, message_id, key, self.signing_key.as_ref())
    }

    /// STORE 自身到最近的 k 个节点
    pub async fn store_self(
        &self,
        pubkey: &[u8; 32],
        noise_pubkey: &[u8; 32],
        endpoints: &[Endpoint],
        capabilities: Capabilities,
    ) -> Result<(), DhtError> {
        let closest = {
            let rt = self.routing_table.read().await;
            rt.closest_nodes(&self.peer_id, self.config.k)
        };
        let msg_id: [u8; 16] = rand::random::<u128>().to_be_bytes();
        let msg = self.encode_store(
            &self.peer_id.0,
            msg_id,
            self.config.ttl_seconds,
            pubkey,
            noise_pubkey,
            capabilities,
            endpoints,
        );
        for node in &closest {
            self.send_msg(&msg, node.address).await;
        }
        // Save locally
        let record = PeerRecord {
            pubkey: *pubkey,
            noise_pubkey: *noise_pubkey,
            endpoints: endpoints.to_vec(),
            capabilities,
            ttl_remaining: self.config.ttl_seconds,
            expires_at: std::time::Instant::now()
                + std::time::Duration::from_secs(self.config.ttl_seconds as u64),
        };
        self.peer_records.write().await.insert(self.peer_id, record);
        Ok(())
    }

    /// Cache-only lookup of a peer record (no DHT query).
    pub async fn get_peer_record(&self, peer_id: &PeerId) -> Option<PeerRecord> {
        let records = self.peer_records.read().await;
        records.get(peer_id)
            .filter(|r| r.expires_at > std::time::Instant::now())
            .cloned()
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

        // Create oneshot channel for the response
        let (tx, rx) = tokio::sync::oneshot::channel();
        let msg_id = rand::random::<u128>().to_be_bytes();

        // Register pending query
        self.pending_queries.write().await.insert(msg_id, tx);

        // Send FIND_VALUE to alpha closest nodes
        let closest = {
            let rt = self.routing_table.read().await;
            rt.closest_nodes(peer_id, self.config.alpha)
        };
        for node in &closest {
            let req = self.encode_find_value(msg_id, &peer_id.0);
            self.send_msg(&req, node.address).await;
        }

        // Wait for response with timeout
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(record)) => Ok(record),
            _ => {
                self.pending_queries.write().await.remove(&msg_id);
                Ok(None)
            }
        }
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
    pub async fn find_relays(&self) -> Result<Vec<RelayInfo>, DhtError> {
        let records = self.peer_records.read().await;
        let rt = self.routing_table.read().await;
        Ok(rt.all_nodes().into_iter()
            .filter(|n| n.node_id != self.peer_id)
            .map(|n| {
                let npk = records.get(&n.node_id).map(|r| r.noise_pubkey).unwrap_or([0u8; 32]);
                RelayInfo { node_id: n.node_id, address: n.address, noise_pubkey: npk }
            })
            .collect())
    }

    /// 获取当前路由表大小（用于判断是否需要 bootstrap）
    pub async fn routing_table_size(&self) -> usize {
        self.routing_table.read().await.size()
    }

    /// Add a node to the routing table (for cross-layer bridging, e.g. QUIC→DHT).
    pub async fn add_node(&self, node_id: PeerId, address: SocketAddr) {
        self.routing_table.write().await.insert_or_update(BucketEntry {
            node_id,
            address,
            last_seen: std::time::Instant::now(),
        });
    }

    /// Per-peer 限速：每秒最多 20 条消息
    async fn check_rate_limit(&self, peer_id: &PeerId) -> bool {
        let mut limits = self.peer_ratelimit.write().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let entry = limits.entry(*peer_id).or_insert((now, 0));
        if now.saturating_sub(entry.0) > 1000 {
            entry.0 = now;
            entry.1 = 1;
            true
        } else if entry.1 >= 20 {
            false
        } else {
            entry.1 += 1;
            true
        }
    }

    /// Verify Ed25519 signature on a DHT message.
    /// Returns Ok if the signature is cryptographically valid, Err otherwise.
    /// For STORE messages from unknown peers, extracts the pubkey from the payload.
    async fn verify_signature(&self, msg: &DhtMessage, body: &[u8]) -> Result<(), DhtError> {
        let sig = match msg.signature {
            Some(ref s) => s,
            None => return Err(DhtError::InvalidSignature { peer_id: msg.sender_id }),
        };

        // Try known peer records first
        let records = self.peer_records.read().await;
        if let Some(rec) = records.get(&msg.sender_id) {
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&rec.pubkey) {
                let s = ed25519_dalek::Signature::from_bytes(sig);
                if vk.verify_strict(body, &s).is_err() {
                    tracing::warn!("bad signature from {}", msg.sender_id);
                    return Err(DhtError::InvalidSignature { peer_id: msg.sender_id });
                }
                return Ok(());
            }
        }
        drop(records);

        // For STORE requests from unknown peers: extract pubkey from payload and verify
        if msg.msg_type == DhtMsgType::Store && !msg.is_response && msg.payload.len() >= 101 {
            let mut store_pk = [0u8; 32];
            store_pk.copy_from_slice(&msg.payload[36..68]);
            if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&store_pk) {
                let s = ed25519_dalek::Signature::from_bytes(sig);
                if vk.verify_strict(body, &s).is_err() {
                    tracing::warn!("bad STORE signature from unknown {}", msg.sender_id);
                    return Err(DhtError::InvalidSignature { peer_id: msg.sender_id });
                }
                return Ok(());
            }
        }

        // Unknown peer, can't verify
        Err(DhtError::InvalidSignature { peer_id: msg.sender_id })
    }

    /// 后台清理：每 10 分钟移除过期 peer_records
    pub fn spawn_cleanup(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(600));
            loop {
                tick.tick().await;
                let now = std::time::Instant::now();
                let mut records = this.peer_records.write().await;
                let before = records.len();
                records.retain(|_k, v| v.expires_at > now);
                if before != records.len() {
                    tracing::debug!("DHT cleanup: removed {} expired", before - records.len());
                }
            }
        });
    }

    /// 处理入站 DHT 消息，必要时通过 socket 回复
    pub async fn send_msg(&self, data: &[u8], addr: SocketAddr) {
        if let Err(e) = self.socket.send_to(data, addr).await {
            tracing::debug!("DHT send to {addr}: {e}");
        }
    }

    pub async fn handle_incoming(&self, data: &[u8], src: SocketAddr) -> Result<(), DhtError> {
        let msg = msg_codec::decode_message(data)
            .ok_or_else(|| DhtError::Serialization("decode failed".into()))?;

        // Rate limit applies to requests only
        if !msg.is_response {
            if !self.check_rate_limit(&msg.sender_id).await {
                tracing::debug!("DHT rate limit: dropping from {}", msg.sender_id);
                return Ok(());
            }
        }

        // Verify Ed25519 signatures for requests and FIND_VALUE responses
        if !msg.is_response || msg.msg_type == DhtMsgType::FindValue {
            let has_sig = msg.signature.as_ref().map_or(false, |s| s.iter().any(|&b| b != 0));
            if has_sig && data.len() >= 64 {
                let body = &data[..data.len().saturating_sub(64)];
                let verified = self.verify_signature(&msg, body).await;
                match verified {
                    Ok(()) => {} // signature valid
                    Err(e) => {
                        if !msg.is_response && msg.msg_type == DhtMsgType::Store {
                            // STORE from unknown peer with unverifiable signature: REJECT
                            return Err(e);
                        }
                        if msg.is_response {
                            // FIND_VALUE response from unknown sender: cannot verify, silently drop
                            tracing::debug!("FIND_VALUE response from {}: signature not verifiable, dropping", msg.sender_id);
                            return Ok(());
                        }
                        // Non-STORE request (PING/FIND_NODE) from unknown peer: accept (deferred)
                    }
                }
            }
        }

        // Reject unsigned FindValue responses unless they match a pending query
        if msg.is_response && msg.msg_type == DhtMsgType::FindValue {
            if let Some(ref sig) = msg.signature {
                if sig.iter().all(|&b| b == 0)
                    && !self.pending_queries.read().await.contains_key(&msg.message_id)
                {
                    return Ok(());
                }
            }
        }

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
        let seed = self.signing_key.as_ref();
        match msg.msg_type {
            DhtMsgType::Ping => {
                let closest = {
                    let rt = self.routing_table.read().await;
                    rt.closest_nodes(&msg.sender_id, self.config.k)
                };
                let resp = msg_codec::encode_ping_response(self.peer_id, msg.message_id, &closest, seed);
                self.send_msg(&resp, src).await;
            }
            DhtMsgType::FindNode => {
                if msg.payload.len() >= 32 {
                    let target = PeerId(msg.payload[..32].try_into().unwrap_or([0u8; 32]));
                    let closest = {
                        let rt = self.routing_table.read().await;
                        rt.closest_nodes(&target, self.config.k)
                    };
                    let resp = msg_codec::encode_find_node_response(self.peer_id, msg.message_id, &closest, seed);
                    self.send_msg(&resp, src).await;
                }
            }
            DhtMsgType::Store => {
                if msg.payload.len() >= 37 {
                    let key = PeerId(msg.payload[..32].try_into().unwrap_or([0u8; 32]));
                    let ttl = u32::from_be_bytes([msg.payload[32], msg.payload[33], msg.payload[34], msg.payload[35]]);
                    let effective_ttl = if ttl == 0 || ttl > 3600 { 300 } else { ttl };
                    // Store the record locally (parse pubkey + noise_pubkey + capabilities + endpoints)
                    if msg.payload.len() >= 101 {
                        let mut pubkey = [0u8; 32];
                        pubkey.copy_from_slice(&msg.payload[36..68]);
                        let mut noise_pubkey = [0u8; 32];
                        noise_pubkey.copy_from_slice(&msg.payload[68..100]);
                        let cap_bits = msg.payload[100];
                        let capabilities = Capabilities { bits: cap_bits };

                        // Verify pubkey matches PeerID (SHA256(pubkey) == key)
                        let expected_id = PeerId(sha2::Sha256::digest(&pubkey).into());
                        if expected_id != key {
                            tracing::warn!("STORE from {}: pubkey doesn't match PeerID", msg.sender_id);
                            return Err(DhtError::InvalidSignature { peer_id: msg.sender_id });
                        }

                        // Parse endpoints from remaining payload
                        let eps = if msg.payload.len() >= 103 {
                            let ep_len = u16::from_be_bytes([msg.payload[101], msg.payload[102]]) as usize;
                            msg_codec::parse_endpoints(&msg.payload[103..], ep_len)
                        } else {
                            vec![]
                        };

                        let record = PeerRecord {
                            pubkey,
                            noise_pubkey,
                            endpoints: eps.clone(),
                            capabilities,
                            ttl_remaining: effective_ttl,
                            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(effective_ttl as u64),
                        };
                        self.peer_records.write().await.insert(key, record);
                        let _ = self.event_tx.send(CoreDhtEvent::PeerDiscovered(key, PeerRecord {
                            pubkey,
                            noise_pubkey,
                            endpoints: eps,
                            capabilities,
                            ttl_remaining: effective_ttl,
                            expires_at: std::time::Instant::now() + std::time::Duration::from_secs(effective_ttl as u64),
                        }.into_core(&key)));
                    }
                }
                // ACK
                let resp = msg_codec::encode_store_ack(self.peer_id, msg.message_id, seed);
                self.send_msg(&resp, src).await;
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
                                self.peer_id, msg.message_id, rec, seed,
                            );
                            self.send_msg(&resp, src).await;
                            return Ok(());
                        }
                    }
                    // Not found: return k-closest
                    let closest = {
                        let rt = self.routing_table.read().await;
                        rt.closest_nodes(&key, self.config.k)
                    };
                    let resp = msg_codec::encode_find_value_response_not_found(
                        self.peer_id, msg.message_id, &closest, seed,
                    );
                    self.send_msg(&resp, src).await;
                }
            }
            DhtMsgType::AddrReflect => {
                let resp = msg_codec::encode_addr_reflect_response(
                    self.peer_id, msg.message_id, &src, seed,
                );
                self.send_msg(&resp, src).await;
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
                    self.peer_id, msg.message_id, &relays, seed,
                );
                self.send_msg(&resp, src).await;
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
                // Forward to pending query if we have one
                if let Some(tx) = self.pending_queries.write().await.remove(&msg.message_id) {
                    let payload = &msg.payload;
                    let record = if !payload.is_empty() && payload[0] == 1 {
                        msg_codec::parse_record_from_payload(&payload[1..])
                    } else {
                        None
                    };
                    let _ = tx.send(record);
                }

                // Also update routing table from k-closest nodes
                let payload = &msg.payload;
                if !payload.is_empty() && payload[0] == 1 {
                    if let Some(record) = msg_codec::parse_record_from_payload(&payload[1..]) {
                        let peer_id = PeerId(sha2::Sha256::digest(&record.pubkey).into());
                        let _ = self.event_tx.send(CoreDhtEvent::PeerDiscovered(
                            peer_id,
                            record.into_core(&peer_id),
                        ));
                    }
                } else {
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
            noise_pubkey: self.noise_pubkey,
            endpoints: self.endpoints.clone(),
            capabilities: self.capabilities,
            ttl_remaining: self.ttl_remaining,
        }
    }
}

#[async_trait::async_trait]
impl DhtBackend for DhtHandle {
    async fn bootstrap(&self, seeds: &[SocketAddr]) -> Result<(), CoreError> {
        self.bootstrap(seeds).await.map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn store_self(&self, pubkey: &[u8; 32], noise_pubkey: &[u8; 32], endpoints: &[Endpoint], capabilities: Capabilities) -> Result<(), CoreError> {
        self.store_self(pubkey, noise_pubkey, endpoints, capabilities).await.map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn find_peer(&self, peer_id: &PeerId) -> Result<Option<lain_core::dht::PeerRecord>, CoreError> {
        self.find_peer(peer_id).await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
            .map(|opt| opt.map(|r| r.into_core(peer_id)))
    }

    async fn find_relays(&self) -> Result<Vec<RelayInfo>, CoreError> {
        self.find_relays().await.map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn routing_table_size(&self) -> usize {
        self.routing_table_size().await
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod handler_tests;
