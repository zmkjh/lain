#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod ipc;

use lain_core::capabilities::Capabilities;
use lain_core::endpoint::Endpoint;
use lain_core::identity::IdentityProvider;
use lain_core::nat::NatProber as NatProberTrait;
use lain_core::peer::PeerId;
use lain_identity::Identity;
use lain_nat::NatProbe;
use lain_dht::DhtHandle;
use lain_discovery::MdnsDiscovery;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use std::sync::Arc;
use std::path::PathBuf;
use tracing;

use std::net::SocketAddr;
use self::ipc::{IpcCommand, IpcServer};

#[derive(Serialize, Deserialize, Clone, Debug)]
struct StoredPeer {
    peer_id_hex: String,
    pubkey_hex: String,
    endpoints: Vec<String>,
}

fn peers_json_path() -> Option<PathBuf> {
    dirs_home().map(|d| d.join(".lain").join("peers.json"))
}

fn save_peers(peers: &HashMap<PeerId, Vec<Endpoint>>) {
    if let Some(path) = peers_json_path() {
        let entries: Vec<StoredPeer> = peers.iter().map(|(pid, eps)| StoredPeer {
            peer_id_hex: pid.to_hex(),
            pubkey_hex: String::new(),
            endpoints: eps.iter().map(|e| e.addr.to_string()).collect(),
        }).collect();
        if let Ok(json) = serde_json::to_string_pretty(&entries) {
            if let Some(d) = path.parent() { std::fs::create_dir_all(d).ok(); }
            let _ = std::fs::write(&path, json);
            tracing::info!("saved {} peers to {}", entries.len(), path.display());
        }
    }
}

fn load_peers() -> HashMap<PeerId, Vec<Endpoint>> {
    let mut map = HashMap::new();
    if let Some(path) = peers_json_path() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(entries) = serde_json::from_str::<Vec<StoredPeer>>(&data) {
                for entry in entries {
                    if let Ok(pid) = PeerId::from_hex(&entry.peer_id_hex) {
                        let eps: Vec<Endpoint> = entry.endpoints.iter()
                            .filter_map(|s| s.parse::<SocketAddr>().ok())
                            .map(|a| Endpoint::new(a, lain_core::endpoint::EndpointKind::STUN))
                            .collect();
                        map.insert(pid, eps);
                    }
                }
                tracing::info!("loaded {} peers from {}", map.len(), path.display());
            }
        }
    }
    map
}

pub use config::DaemonConfig;

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

        // 3. 初始化 DHT
        let dht_config = lain_dht::DhtConfig {
            k: self.config.dht.k,
            alpha: self.config.dht.alpha,
            ttl_seconds: self.config.dht.ttl_seconds,
            heartbeat_interval_secs: self.config.dht.heartbeat_interval_secs,
            republish_interval_secs: lain_core::DHT_REPUBLISH_SECS,
            idle_peer_timeout_secs: 900,
            local_addr: self.config.dht.local_addr.unwrap_or("0.0.0.0:0".parse().unwrap()),
            bootstrap_nodes: self.config.dht.bootstrap_nodes.clone(),
        };

        let heartbeat_secs = dht_config.heartbeat_interval_secs;
        let bootstrap_nodes = dht_config.bootstrap_nodes.clone();

        let mut dht = DhtHandle::new(peer_id, public_key, dht_config)
            .map_err(|e| DaemonError::Dht(e.to_string()))?;

        // Wire DHT RPC signing with identity key
        dht.set_signer(self.identity.signing_seed());

        // 4. Bootstrap
        if !bootstrap_nodes.is_empty() {
            if let Err(e) = dht.bootstrap(&bootstrap_nodes).await {
                tracing::warn!("initial bootstrap failed: {e}");
            }
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

        let _ = dht.store_self(&public_key, &endpoints, capabilities).await;

        // 6. mDNS LAN 发现
        let dht_for_mdns = Arc::new(dht);
        let local_port = dht_for_mdns.socket().local_addr()
            .map(|a| a.port())
            .unwrap_or(53617);

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
            std::time::Duration::from_secs(heartbeat_secs),
        );

        // Track known peers
        let known_peers: Arc<RwLock<HashMap<PeerId, Vec<Endpoint>>>> =
            Arc::new(RwLock::new(load_peers()));

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
                        IpcCommand::ConnectPeer { invite, .. } => {
                            tracing::info!("IPC: connect via {invite}");
                            // Parse invite to get PeerID and endpoints
                            let code = invite
                                .strip_prefix("lain://")
                                .and_then(|c| lain_discovery::InviteCode::from_base62(c).ok());
                            if let Some(inv) = code {
                                let mut peers = known_peers.write().await;
                                peers.insert(inv.peer_id, inv.endpoints.clone());
                                tracing::info!("added peer {} ({} endpoints)",
                                    inv.peer_id, inv.endpoints.len());
                                // Initiate DHT lookup
                                let dht = dht_arc.clone();
                                let pid = inv.peer_id;
                                tokio::spawn(async move {
                                    if let Err(e) = dht.find_peer(&pid).await {
                                        tracing::debug!("DHT find_peer({pid}): {e}");
                                    }
                                });
                            } else {
                                tracing::warn!("invalid invite: {invite}");
                            }
                        }
                        IpcCommand::DisconnectPeer { peer_id } => {
                            tracing::info!("IPC: disconnect {peer_id}");
                            known_peers.write().await.remove(&peer_id);
                        }
                        IpcCommand::SendToPeer { peer_id, data } => {
                            tracing::info!("IPC: send {}b to {peer_id}", data.len());
                            let peers = known_peers.read().await;
                            if let Some(endpoints) = peers.get(&peer_id) {
                                // Try each endpoint
                                for ep in endpoints {
                                    let msg = lain_core::frame::encode_frame(
                                        2, lain_core::frame::FrameType::Data, &data,
                                    );
                                    let _ = socket.send_to(&msg, ep.addr).await;
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
                    }
                }

                _ = heartbeat.tick() => {
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
        save_peers(&peers);
        tracing::info!("Daemon stopped");
        Ok(())
    }

    pub async fn state(&self) -> DaemonState {
        self.state.read().await.clone()
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
