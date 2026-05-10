#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod ipc;
pub mod conn_mgr;
pub mod iface_watcher;
pub mod fd_pass;

use lain_core::capabilities::Capabilities;
use lain_core::endpoint::Endpoint;
use lain_core::frame::{self, FrameType};
use lain_core::identity::IdentityProvider;
use lain_core::nat::NatProber as NatProberTrait;
use lain_core::peer::PeerId;
use lain_identity::Identity;
use lain_nat::NatProbe;
use lain_dht::DhtHandle;
use lain_discovery::MdnsDiscovery;
use lain_transport::{Transport, TransportConfig};
use sha2::Digest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::path::PathBuf;
use tracing;

use std::net::SocketAddr;
use self::ipc::{IpcCommand, IpcResponse, IpcServer};
use self::conn_mgr::ConnectionManager;
use self::iface_watcher::InterfaceWatcher;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct StoredPeer {
    peer_id_hex: String,
    pubkey_hex: String,
    endpoints: Vec<String>,
}

pub use config::DaemonConfig;

fn peers_json_path() -> Option<PathBuf> {
    dirs_home().map(|d| d.join(".lain").join("peers.json"))
}

fn save_peers(peers: &HashMap<PeerId, Vec<Endpoint>>, identity: &Identity) {
    if let Some(path) = peers_json_path() {
        let entries: Vec<StoredPeer> = peers.iter().map(|(pid, eps)| StoredPeer {
            peer_id_hex: pid.to_hex(),
            pubkey_hex: String::new(),
            endpoints: eps.iter().map(|e| e.addr.to_string()).collect(),
        }).collect();
        if let Ok(json) = serde_json::to_string_pretty(&entries) {
            // Sign with identity key for integrity
            let sig = identity.sign(json.as_bytes());
            let signed = serde_json::json!({
                "data": entries,
                "sig": hex::encode(sig),
            });
            if let Ok(final_json) = serde_json::to_string_pretty(&signed) {
                if let Some(d) = path.parent() { std::fs::create_dir_all(d).ok(); }
                let _ = std::fs::write(&path, final_json);
            }
        }
    }
}

fn load_peers() -> HashMap<PeerId, Vec<Endpoint>> {
    let mut map = HashMap::new();
    if let Some(path) = peers_json_path() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            // Try signed format first, fall back to legacy
            let entries = if let Ok(signed) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(entries_val) = signed.get("data") {
                    serde_json::from_value::<Vec<StoredPeer>>(entries_val.clone()).unwrap_or_default()
                } else {
                    serde_json::from_str::<Vec<StoredPeer>>(&data).unwrap_or_default()
                }
            } else {
                serde_json::from_str::<Vec<StoredPeer>>(&data).unwrap_or_default()
            };
            for entry in entries {
                if let Ok(pid) = PeerId::from_hex(&entry.peer_id_hex) {
                    let eps: Vec<Endpoint> = entry.endpoints.iter()
                        .filter_map(|s| s.parse::<SocketAddr>().ok())
                        .map(|a| Endpoint::new(a, lain_core::endpoint::EndpointKind::STUN))
                        .collect();
                    map.insert(pid, eps);
                }
            }
        }
    }
    map
}

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("config error: {0}")]
    Config(String),
    #[error("identity error: {0}")]
    Identity(String),
    #[error("dht error: {0}")]
    Dht(String),
    #[error("I/O error: {0}")]
    Io(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonState {
    Init,
    Running,
    Draining,
    Idle,
    Stopped,
}

pub struct Daemon {
    config: DaemonConfig,
    identity: Identity,
    state: RwLock<DaemonState>,
}

impl Daemon {
    pub async fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        // Check for existing daemon via IPC socket
        if let Some(socket_path) = ipc_socket_path(&config) {
            if ipc_socket_alive(&socket_path) {
                return Err(DaemonError::Config("daemon already running".into()));
            }
        }

        tracing::info!("Lain daemon starting...");
        let identity = Identity::load_or_generate()
            .map_err(|e| DaemonError::Identity(e.to_string()))?;
        tracing::info!("PeerID: {}", identity.peer_id());
        Ok(Self { config, identity, state: RwLock::new(DaemonState::Init) })
    }

    pub fn peer_id(&self) -> PeerId { self.identity.peer_id() }
    pub fn public_key(&self) -> [u8; 32] { *self.identity.public_key() }
    pub fn sign(&self, data: &[u8]) -> [u8; 64] { self.identity.sign(data) }

    pub async fn run(&self) -> Result<(), DaemonError> {
        *self.state.write().await = DaemonState::Running;
        tracing::info!("Daemon is running");

        let peer_id = self.peer_id();
        let public_key = self.public_key();

        // 1. NAT 探测
        let nat_result = {
            let probe = NatProbe::new(vec![], 10);
            probe.probe().await.map_err(|e| DaemonError::Dht(e.to_string()))?
        };
        tracing::info!("NAT: {:?}, IPv6 inbound: {}", nat_result.nat_type, nat_result.ipv6_inbound);

        // 2. 身份噪声密钥对
        let (_noise_secret, _noise_public) = self.identity.noise_keypair();

        // 3. 初始化 Transport (先绑定以获取端口)
        let transport = Transport::new(
            TransportConfig::default(),
            _noise_secret,
            peer_id,
            public_key,
        )
        .map_err(|e| DaemonError::Config(e.to_string()))?;

        let transport = Arc::new(transport);
        let transport_port = transport.local_addr()
            .map(|a| a.port())
            .map_err(|e| DaemonError::Config(e.to_string()))?;
        tracing::info!("transport on port {transport_port}");

        // 4. 初始化 DHT (共享同一端口)
        let dht_config = lain_dht::DhtConfig {
            k: self.config.dht.k,
            alpha: self.config.dht.alpha,
            ttl_seconds: self.config.dht.ttl_seconds,
            heartbeat_interval_secs: self.config.dht.heartbeat_interval_secs,
            republish_interval_secs: lain_core::DHT_REPUBLISH_SECS,
            idle_peer_timeout_secs: 900,
            local_addr: format!("0.0.0.0:{}", transport_port)
                .parse::<SocketAddr>()
                .map_err(|e: std::net::AddrParseError| DaemonError::Config(e.to_string()))?,
            bootstrap_nodes: self.config.dht.bootstrap_nodes.clone(),
        };

        let _heartbeat_secs = dht_config.heartbeat_interval_secs;
        let bootstrap_nodes = dht_config.bootstrap_nodes.clone();

        let mut dht = DhtHandle::new(peer_id, public_key, dht_config)
            .map_err(|e| DaemonError::Dht(e.to_string()))?;

        // Wire DHT RPC signing with identity key
        dht.set_signer(self.identity.signing_seed());

        // 4. Bootstrap
        if !bootstrap_nodes.is_empty() {
            if let Err(e) = dht.bootstrap(&bootstrap_nodes).await {
                tracing::warn!("initial bootstrap failed: {}, trying mDNS fallback", e);
            }
        } else {
            tracing::info!("no bootstrap nodes configured, relying on mDNS LAN discovery");
        }

        // 5. STORE self
        let capabilities = Capabilities::new()
            .with(if nat_result.ipv6_inbound { Capabilities::IPV6_INBOUND } else { 0 })
            .with(if nat_result.nat_type.is_symmetric() { 0 } else { Capabilities::RELAY_CAPABLE });

        let endpoints = if let Some(addr) = nat_result.mapped_addr {
            vec![Endpoint::new(addr, lain_core::endpoint::EndpointKind::STUN)]
        } else {
            vec![]
        };

        if let Err(e) = dht.store_self(&public_key, &endpoints, capabilities).await {
            tracing::warn!("initial DHT STORE failed: {e}");
        }

        // Adaptive heartbeat: symmetric NAT needs faster STORE to keep mapping alive
        let adaptive_heartbeat = if nat_result.nat_type.is_symmetric() { 30u64 } else { 120u64 };
        tracing::info!("DHT heartbeat: {}s (NAT: {:?})", adaptive_heartbeat, nat_result.nat_type);

        // 6. mDNS LAN 发现
        let dht_for_mdns = Arc::new(dht);

        // Start background bucket refresh + DHT cleanup
        dht_for_mdns.spawn_bucket_refresh();
        dht_for_mdns.spawn_cleanup();

        // Spawn relay accept loop: handle incoming RelayConnect frames
        let transport_relay = transport.clone();
        let dht_relay = dht_for_mdns.clone();
        tokio::spawn(async move {
            loop {
                let t = transport_relay.clone();
                let d = dht_relay.clone();
                match t.accept_connection().await {
                    Ok((conn, _peer_id, _pubkey)) => {
                        let c = conn.clone();
                        tokio::spawn(async move {
                            if let Ok((mut _send, mut recv)) = c.accept_bi().await {
                                let mut buf = vec![0u8; 2048];
                                if let Ok(Some(n)) = recv.read(&mut buf).await {
                                    if let Some((_sid, ft, _len, hdr_len)) = frame::decode_frame_header(&buf[..n]) {
                                        if ft == FrameType::RelayConnect {
                                            let payload = &buf[hdr_len..hdr_len + (_len as usize).min(n - hdr_len)];
                                            if payload.len() >= 64 {
                                                let mut requester_bytes = [0u8; 32];
                                                requester_bytes.copy_from_slice(&payload[..32]);
                                                let requester = PeerId(requester_bytes);
                                                let mut target_bytes = [0u8; 32];
                                                target_bytes.copy_from_slice(&payload[32..64]);
                                                let target = PeerId(target_bytes);
                                                tracing::info!("relay: {requester} -> {target}");
                                                if let Ok(Some(record)) = d.find_peer(&target).await {
                                                    let result = t.handle_relay_request(
                                                        c.clone(), target, record.pubkey, &record.endpoints,
                                                    ).await;
                                                    // Relay pipe ended — attempt migration
                                                    if result.is_err() {
                                                        tracing::warn!("relay {requester}->{target} pipe broken, migrating");
                                                        // Find alternative relay
                                                        if let Ok(relays) = d.find_relays().await {
                                                            for new_relay in relays {
                                                                if new_relay.node_id == requester || new_relay.node_id == target {
                                                                    continue;
                                                                }
                                                                // Re-establish: connect to new relay and forward
                                                                if let Ok(Some(new_rec)) = d.find_peer(&new_relay.node_id).await {
                                                                    if let Ok(new_conn) = t.connect_raw(
                                                                        &new_rec.pubkey, &new_rec.endpoints,
                                                                    ).await {
                                                                        // Send RelayConnect to the new relay
                                                                        let mut rl = Vec::with_capacity(64);
                                                                        rl.extend_from_slice(&requester.0);
                                                                        rl.extend_from_slice(&target.0);
                                                                        let rl_frame = lain_core::frame::encode_frame(
                                                                            1, lain_core::frame::FrameType::RelayConnect, &rl,
                                                                        );
                                                                        if let Ok((mut s, _)) = new_conn.open_bi().await {
                                                                            let _ = s.write_all(&rl_frame).await;
                                                                            let _ = s.finish();
                                                                            tracing::info!("relay: re-established {requester}->{target} via {}", new_relay.node_id);
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => tracing::debug!("transport accept: {e}"),
                }
            }
        });

        let local_port = dht_for_mdns.socket().local_addr()
            .map(|a| a.port())
            .unwrap_or_else(|_| {
                tracing::warn!("cannot determine DHT local port, using default 53617");
                53617
            });

        let _mdns = match MdnsDiscovery::register(peer_id, local_port) {
            Ok(mdns) => {
                tracing::info!("mDNS registered on port {local_port}");
                let dht_ref = dht_for_mdns.clone();
                match mdns.browse() {
                    Ok(receiver) => {
                        tokio::spawn(async move {
                            loop {
                                match receiver.recv_async().await {
                                    Ok(event) => {
                                        if let Some((discovered_id, addr, _port)) =
                                            MdnsDiscovery::parse_peer_from_event(&event)
                                        {
                                            if discovered_id != peer_id {
                                                tracing::debug!("mDNS: {discovered_id} at {addr}");
                                                let msg_id = rand::random::<u128>().to_be_bytes();
                                                let ping = lain_dht::message::encode_ping_request(peer_id, msg_id);
                                                dht_ref.send_msg(&ping, addr).await;
                                                // Also use as bootstrap if routing table is sparse
                                                if dht_ref.routing_table_size().await < 10 {
                                                    let msg_id = rand::random::<u128>().to_be_bytes();
                                                    let fn_req = lain_dht::message::encode_find_node_request(
                                                        peer_id, msg_id, peer_id,
                                                    );
                                                    dht_ref.send_msg(&fn_req, addr).await;
                                                }
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(e) => tracing::warn!("mDNS browse: {e}"),
                }
                Some(mdns)
            }
            Err(e) => {
                tracing::warn!("mDNS: {e}");
                None
            }
        };

        // 7. 生成 invite
        let _invite = lain_discovery::InviteCode::new(
            peer_id, public_key, capabilities, endpoints.clone(),
            &|data| self.identity.sign(data),
        );
        tracing::info!("Invite: lain://{}", _invite.to_base62());

        // 7. 启动 IPC
        let uds_path = self.config.ipc.uds_path.as_deref()
            .map(PathBuf::from)
            .or_else(|| dirs_home().map(|d| d.join(".lain").join("socket")));

        tracing::info!("IPC ready at {:?}", uds_path);

        let (ipc_cmd_tx, mut ipc_cmd_rx) = mpsc::channel::<IpcCommand>(256);
        let ipc_server = IpcServer::new(ipc::IpcConfig {
            uds_path: uds_path.clone(),
            http_addr: self.config.ipc.http_addr,
        }, ipc_cmd_tx);

        let _ipc_ev_tx = ipc_server.event_sender();

        tokio::spawn(async move {
            if let Err(e) = ipc_server.run().await {
                tracing::error!("IPC: {e}");
            }
        });

        tracing::info!("IPC ready at {:?}", uds_path);

        // 8. 启动 DHT + IPC 事件循环
        let socket = dht_for_mdns.socket();
        let dht_arc = dht_for_mdns; // Already Arc-wrapped above
        let dht_recv = dht_arc.clone();

        let mut buf = vec![0u8; 2048];
        let mut heartbeat = tokio::time::interval(
            std::time::Duration::from_secs(adaptive_heartbeat),
        );

        // Track known peers
        let known_peers: Arc<RwLock<HashMap<PeerId, Vec<Endpoint>>>> =
            Arc::new(RwLock::new(load_peers()));

        let conn_mgr = Arc::new(ConnectionManager::new());

        // Track active QUIC connections with semaphore permits for backpressure
        let connected: Arc<RwLock<HashMap<PeerId, (quinn::Connection, tokio::sync::OwnedSemaphorePermit)>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let conn_sem = Arc::new(tokio::sync::Semaphore::new(
            self.config.transport.max_connections,
        ));

        // Interface watcher: detect network changes and trigger emergency actions
        let iface_watcher = Arc::new(InterfaceWatcher::new());
        iface_watcher.snapshot().await;
        let dht_iface = dht_arc.clone();
        let connected_iface = connected.clone();
        let public_key_iface = public_key;
        let capabilities_iface = capabilities;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let (added, removed) = iface_watcher.check().await;
                if !added.is_empty() || !removed.is_empty() {
                    tracing::warn!("network change: +{}/-{}", added.len(), removed.len());

                    // Emergency DHT STORE with new endpoints
                    let new_endpoints: Vec<Endpoint> = added.iter()
                        .map(|a| Endpoint::new(*a, lain_core::endpoint::EndpointKind::STUN))
                        .collect();
                    if !new_endpoints.is_empty() {
                        let _ = dht_iface.store_self(
                            &public_key_iface,
                            &new_endpoints,
                            capabilities_iface,
                        ).await;
                    }

                    // Send PATH_CHANGE to all connected peers
                    let cons = connected_iface.read().await;
                    for (peer_id, (conn, _)) in cons.iter() {
                        let msg = lain_core::frame::encode_frame(
                            1, lain_core::frame::FrameType::PathChange,
                            &[],
                        );
                        if let Ok((mut send, _)) = conn.open_bi().await {
                            let _ = send.write_all(&msg).await;
                            let _ = send.finish();
                            tracing::debug!("sent PATH_CHANGE to {peer_id}");
                        }
                    }
                }
            }
        });

        if !known_peers.read().await.is_empty() {
            tracing::info!("restored {} known peers", known_peers.read().await.len());
        }

        loop {
            tokio::select! {
                recv = socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((len, src)) => {
                            if let Err(e) = dht_recv.handle_incoming(&buf[..len], src).await {
                                tracing::debug!("DHT recv from {src}: {e}");
                            }
                        }
                        Err(e) => tracing::error!("UDP: {e}"),
                    }
                }

                Some(cmd) = ipc_cmd_rx.recv() => {
                    match cmd {
                        IpcCommand::ConnectPeer { invite, peer_id: _unverified_id } => {
                            tracing::info!("IPC: connect via {invite}");
                            let code = invite
                                .strip_prefix("lain://")
                                .and_then(|c| lain_discovery::InviteCode::from_base62(c).ok())
                                .filter(|inv| {
                                    let expected = PeerId(sha2::Sha256::digest(&inv.ed25519_pk).into());
                                    expected == inv.peer_id
                                });
                            if let Some(inv) = code {
                                // Check if already connected
                                if connected.read().await.contains_key(&inv.peer_id) {
                                    tracing::info!("already connected to {}", inv.peer_id);
                                    continue;
                                }
                                let mut peers = known_peers.write().await;
                                peers.insert(inv.peer_id, inv.endpoints.clone());
                                conn_mgr.add_peer(inv.peer_id).await;

                                // Establish QUIC connection
                                let t = transport.clone();
                                let ipc_ev = _ipc_ev_tx.clone();
                                let connected_ref = connected.clone();
                                let conn_sem2 = conn_sem.clone();
                                let pid = inv.peer_id;
                                let pubkey = inv.ed25519_pk;
                                let eps = inv.endpoints.clone();
                                tokio::spawn(async move {
                                    match t.connect_raw(&pubkey, &eps).await {
                                        Ok(conn) => {
                                            // Acquire connection slot
                                            let permit = match conn_sem2.clone().acquire_owned().await {
                                                Ok(p) => p,
                                                Err(_) => {
                                                    tracing::warn!("connection limit reached");
                                                    return;
                                                }
                                            };
                                            tracing::info!("connected to {pid}");
                                            connected_ref.write().await.insert(pid, (conn.clone(), permit));

                                            // Start QUIC keepalive PING every 15s
                                            lain_transport::Transport::spawn_keepalive(conn.clone(), 15);

                                            // Notify IPC subscribers
                                            let _ = ipc_ev.send(IpcResponse::Event {
                                                event: "peer_connected".into(),
                                                peer_id: Some(pid.to_string()),
                                                data: None,
                                            });

                                            // Spawn reader task for incoming data
                                            let ipc_ev2 = ipc_ev.clone();
                                            let pid2 = pid;
                                            let c = conn.clone();
                                            tokio::spawn(async move {
                                                loop {
                                                    match c.accept_bi().await {
                                                        Ok((_send, mut recv)) => {
                                                            match recv.read_to_end(65536).await {
                                                                Ok(_data) => {
                                                                    let _ = ipc_ev2.send(IpcResponse::Event {
                                                                        event: "data".into(),
                                                                        peer_id: Some(pid2.to_string()),
                                                                        data: Some(serde_json::json!({
                                                                            "bytes": "incoming_data"
                                                                        })),
                                                                    });
                                                                }
                                                                Err(_) => break,
                                                            }
                                                        }
                                                        Err(_) => break,
                                                    }
                                                }
                                            });
                                        }
                                        Err(e) => {
                                            tracing::warn!("connect to {pid} failed: {e}");
                                            let _ = ipc_ev.send(IpcResponse::Event {
                                                event: "peer_error".into(),
                                                peer_id: Some(pid.to_string()),
                                                data: Some(serde_json::json!({"error": e.to_string()})),
                                            });
                                        }
                                    }
                                });

                                // Also do DHT lookup in parallel
                                let dht = dht_arc.clone();
                                let pid = inv.peer_id;
                                tokio::spawn(async move {
                                    if let Err(e) = dht.find_peer(&pid).await {
                                        tracing::debug!("DHT find_peer({pid}): {e}");
                                    }
                                });
                            }
                        }
                        IpcCommand::DisconnectPeer { peer_id } => {
                            tracing::info!("IPC: disconnect {peer_id}");
                            known_peers.write().await.remove(&peer_id);
                            conn_mgr.remove_peer(&peer_id).await;
                            if let Some((conn, _permit)) = connected.write().await.remove(&peer_id) {
                                conn.close(0u32.into(), b"disconnected");
                            }
                        }
                        IpcCommand::SendToPeer { peer_id, data } => {
                            let conn = {
                                let cons = connected.read().await;
                                cons.get(&peer_id).map(|(c, _)| c.clone())
                            };
                            match conn {
                                Some(conn) => {
                                    let msg = frame::encode_frame(2, FrameType::Data, &data);
                                    match conn.open_bi().await {
                                        Ok((mut send, _recv)) => {
                                            if let Err(e) = send.write_all(&msg).await {
                                                tracing::warn!("send to {peer_id}: {e}");
                                            } else {
                                                let _ = send.finish();
                                                tracing::debug!("sent {}b to {peer_id}", data.len());
                                            }
                                        }
                                        Err(e) => tracing::warn!("open stream to {peer_id}: {e}"),
                                    }
                                }
                                None => {
                                    tracing::warn!("no active connection to {peer_id}");
                                }
                            }
                        }
                        IpcCommand::AcceptConnection { connection_id } => {
                            tracing::info!("IPC: accept connection {connection_id}");
                        }
                        IpcCommand::RejectConnection { connection_id } => {
                            tracing::info!("IPC: reject connection {connection_id}");
                        }
                        IpcCommand::Shutdown => {
                            tracing::info!("IPC: shutdown requested");
                            break;
                        }
                        IpcCommand::GetStatus { reply } => {
                            let rt_size = dht_arc.routing_table_size().await;
                            let known = known_peers.read().await.len();
                            let active = connected.read().await.len();
                            let peers: Vec<String> = connected.read().await.keys()
                                .map(|p| p.to_string())
                                .collect();
                            let _ = reply.send(serde_json::json!({
                                "peer_id": peer_id.to_string(),
                                "nat_type": format!("{:?}", nat_result.nat_type),
                                "ipv6": nat_result.ipv6_inbound,
                                "dht_nodes": rt_size,
                                "known_peers": known,
                                "connected_peers": active,
                                "peers": peers,
                            }));
                        }
                        IpcCommand::GetWhoami { reply } => {
                            let _ = reply.send(peer_id.to_string());
                        }
                        IpcCommand::GetInviteCode { reply } => {
                            // _invite was printed to log at startup — save it
                            let invite_str = _invite.to_base62();
                            let _ = reply.send(format!("lain://{}", invite_str));
                        }
                    }
                }

                _ = heartbeat.tick() => {
                    // Periodic save of peers.json (crash resilience)
                    let peers = known_peers.read().await;
                    save_peers(&peers, &self.identity);

                    // Dormant check: skip heartbeat if no active connections
                    let peer_count = connected.read().await.len();
                    if peer_count == 0 {
                        // All peers expired/disconnected — skip this heartbeat
                        // routes.bin is still maintained for future reconnection
                        continue;
                    }
                    if let Err(e) = dht_arc.store_self(
                        &public_key, &endpoints, capabilities,
                    ).await {
                        tracing::debug!("DHT heartbeat: {e}");
                    }
                }

                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("SIGTERM, draining...");
                    break;
                }
            }
        }

        *self.state.write().await = DaemonState::Stopped;
        let peers = known_peers.read().await;
        save_peers(&peers, &self.identity);
        tracing::info!("Daemon stopped");
        Ok(())
    }

    pub async fn state(&self) -> DaemonState {
        self.state.read().await.clone()
    }
}

fn ipc_socket_path(config: &DaemonConfig) -> Option<PathBuf> {
    config.ipc.uds_path.as_ref().map(PathBuf::from)
        .or_else(|| dirs_home().map(|d| d.join(".lain").join("socket")))
}

fn ipc_socket_alive(path: &PathBuf) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::net::UnixStream::connect(path).is_ok()
    }
    #[cfg(windows)]
    {
        // Try opening the named pipe — if it exists, daemon is running
        std::fs::OpenOptions::new().read(true).write(true).open(path).is_ok()
    }
}

fn dirs_home() -> Option<PathBuf> {
    if let Ok(h) = std::env::var("LAIN_HOME") { return Some(PathBuf::from(h)); }
    #[cfg(target_os = "windows")]
    { if let Ok(p) = std::env::var("USERPROFILE") { return Some(PathBuf::from(p)); } }
    #[cfg(not(target_os = "windows"))]
    { if let Ok(h) = std::env::var("HOME") { return Some(PathBuf::from(h)); } }
    None
}
