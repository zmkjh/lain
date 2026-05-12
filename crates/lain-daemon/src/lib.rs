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
        if let Some(ref socket_path) = ipc_socket_path(&config) {
            if ipc_socket_alive(socket_path) {
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
        // Ensure rustls crypto provider is installed before QUIC/Transport init
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        *self.state.write().await = DaemonState::Running;
        tracing::info!("Daemon is running");

        let peer_id = self.peer_id();
        let public_key = self.public_key();

        // Start IPC early so CLI can connect immediately (before slow STUN probe)
        let uds_path = self.config.ipc.uds_path.as_deref()
            .map(PathBuf::from)
            .or_else(|| dirs_home().map(|d| d.join(".lain").join("socket")));

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

        // VPN/TUN detection: warn if virtual adapters may interfere with STUN
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in &ifaces {
                let name_lower = iface.name.to_lowercase();
                if name_lower.contains("vpn") || name_lower.contains("tun")
                    || name_lower.contains("tap") || name_lower.contains("virtual")
                    || name_lower.contains("wintun") || name_lower.contains("wireguard")
                    || name_lower.contains("openvpn") || name_lower.contains("nord")
                    || name_lower.contains("proton") || name_lower.contains("surf")
                {
                    tracing::warn!("VPN/TUN interface '{}' detected — STUN may return wrong public IP.\
                        Consider disabling VPN for accurate NAT detection.", iface.name);
                }
            }
        }

        // 1. NAT 探测 (resolve STUN hostnames to addresses)
        let stun_addrs: Vec<std::net::SocketAddr> = {
            let mut addrs = Vec::new();
            for host in &self.config.stun_servers {
                match tokio::net::lookup_host(host).await {
                    Ok(iter) => {
                        for addr in iter { addrs.push(addr); }
                    }
                    Err(e) => tracing::debug!("STUN lookup {host}: {e}"),
                }
            }
            addrs
        };
        let nat_result = {
            let probe = NatProbe::new(stun_addrs, 10);
            probe.probe().await.map_err(|e| DaemonError::Dht(e.to_string()))?
        };
        tracing::info!("NAT: {:?}, mapped addr: {:?}, IPv6: {}", nat_result.nat_type, nat_result.mapped_addr, nat_result.ipv6_inbound);

        // 2. Purity under NAT: detect IPv6 global address for direct P2P
        let bind_addr = if nat_result.ipv6_inbound {
            "[::]:0".parse::<SocketAddr>()
                .map_err(|e: std::net::AddrParseError| DaemonError::Config(e.to_string()))?
        } else {
            "0.0.0.0:0".parse::<SocketAddr>()
                .map_err(|e: std::net::AddrParseError| DaemonError::Config(e.to_string()))?
        };
        let ipv6_addr: Option<std::net::SocketAddr> = if nat_result.ipv6_inbound {
            if_addrs::get_if_addrs().ok().and_then(|ifs| {
                ifs.into_iter().find_map(|i| {
                    match i.addr {
                        if_addrs::IfAddr::V6(v6)
                            if !v6.ip.is_loopback() && !v6.ip.is_unspecified()
                               && (v6.ip.segments()[0] & 0xE000) == 0x2000 => // 2000::/3 global unicast
                            Some(SocketAddr::new(std::net::IpAddr::V6(v6.ip), 0)),
                        _ => None,
                    }
                })
            })
        } else { None };
        if let Some(ref addr) = ipv6_addr {
            tracing::info!("IPv6 global: {}", addr.ip());
        }

        // 3. 身份噪声密钥对
        let (_noise_secret, noise_pubkey) = self.identity.noise_keypair();

        // 3. 初始化 Transport (dual-stack when IPv6 available)
        let transport = Transport::new(
            TransportConfig { bind_addr, ..Default::default() },
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

        // 4. 初始化 DHT (separate UDP socket, not shared with QUIC transport)
        let dht_config = lain_dht::DhtConfig {
            k: self.config.dht.k,
            alpha: self.config.dht.alpha,
            ttl_seconds: self.config.dht.ttl_seconds,
            heartbeat_interval_secs: self.config.dht.heartbeat_interval_secs,
            republish_interval_secs: lain_core::DHT_REPUBLISH_SECS,
            idle_peer_timeout_secs: 900,
            local_addr: bind_addr,
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

        // Load saved routes from previous session (crash recovery)
        if let Some(routes_path) = dirs_home().map(|d| d.join(".lain").join("routes.json")) {
            if let Err(e) = dht.load_routes(&routes_path).await {
                tracing::debug!("no saved routes to load ({}), starting fresh", e);
            }
        }

        // 5. STORE self — build endpoint list including DHT port so peers can discover it
        let capabilities = Capabilities::new()
            .with(if nat_result.ipv6_inbound { Capabilities::IPV6_INBOUND } else { 0 })
            .with(if nat_result.nat_type.is_symmetric() { 0 } else { Capabilities::RELAY_CAPABLE });

        let local_dht_addr = dht.socket().local_addr()
            .map_err(|e| DaemonError::Config(format!("DHT addr: {e}")))?;
        // Build endpoint list: IPv6 (direct P2P, pure), STUN (NAT-piercing), DHT
        let mut endpoints: Vec<Endpoint> = Vec::new();
        if let Some(addr) = ipv6_addr {
            // IPv6 is pure — no NAT, globally routable from the start
            endpoints.push(Endpoint::new(
                SocketAddr::new(addr.ip(), transport_port),
                lain_core::endpoint::EndpointKind::IPv6,
            ));
        }
        if let Some(stun) = nat_result.mapped_addr {
            // STUN gives us the public IP, but the port is for the probe socket.
            // Combine STUN IP with our actual QUIC transport port.
            endpoints.push(Endpoint::new(
                SocketAddr::new(stun.ip(), transport_port),
                lain_core::endpoint::EndpointKind::STUN,
            ));
        }
        // Include DHT UDP ports so peers can reach our DHT socket
        if let Some(ref addr) = ipv6_addr {
            let ipv6_dht = SocketAddr::new(addr.ip(), local_dht_addr.port());
            endpoints.push(Endpoint::new(ipv6_dht, lain_core::endpoint::EndpointKind::IPv6));
        }
        // IPv4 DHT: use STUN IP + DHT port for routability behind NAT
        let public_dht_addr = if let Some(stun) = nat_result.mapped_addr {
            SocketAddr::new(stun.ip(), local_dht_addr.port())
        } else {
            local_dht_addr
        };
        endpoints.push(Endpoint::new(public_dht_addr, lain_core::endpoint::EndpointKind::STUN));

        // TSO TCP ports: bind N sockets for birthday-attack-style TSO,
        // increasing probability of TCP simultaneous open through APDF NAT.
        const TSO_PORTS: u16 = 16;
        for _ in 0..TSO_PORTS {
            let tso_listener = tokio::net::TcpListener::bind(bind_addr).await
                .map_err(|e| DaemonError::Config(format!("TSO bind: {e}")))?;
            let tso_port = tso_listener.local_addr()
                .map_err(|e| DaemonError::Config(format!("TSO addr: {e}")))?
                .port();
            if let Some(stun) = nat_result.mapped_addr {
                endpoints.push(Endpoint::new(
                    SocketAddr::new(stun.ip(), tso_port),
                    lain_core::endpoint::EndpointKind::TSO,
                ));
            }
            let tso_noise_secret = _noise_secret;
            let tso_peer_id = peer_id;
            let tso_noise_pk = noise_pubkey;
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                use lain_noise::{NoiseHandshake, encode_handshake_frame, parse_frame_header};
                loop {
                    match tso_listener.accept().await {
                        Ok((mut stream, _)) => {
                            // TSO handshake: exchange [PeerID:32 + noise_pk:32] → Role → Noise IK
                            let mut our_info = [0u8; 64];
                            our_info[..32].copy_from_slice(&tso_peer_id.0);
                            our_info[32..].copy_from_slice(&tso_noise_pk);
                            stream.write_all(&our_info).await.ok();

                            let mut their_info = [0u8; 64];
                            if stream.read_exact(&mut their_info).await.is_err() { continue; }
                            let their_id: [u8; 32] = their_info[..32].try_into().unwrap();
                            let their_pk: &[u8; 32] = &their_info[32..].try_into().unwrap();
                            let we_initiate = tso_peer_id.0 < their_id;

                            let noise_result = if we_initiate {
                                NoiseHandshake::new_initiator(&tso_noise_secret, their_pk)
                            } else {
                                NoiseHandshake::new_responder(&tso_noise_secret)
                            };
                            if let Ok(mut noise) = noise_result {
                                if we_initiate {
                                    if let Ok(ik1) = noise.write_message(&[]) {
                                        stream.write_all(&encode_handshake_frame(0, &ik1)).await.ok();
                                        let mut buf = vec![0u8; 4096];
                                        if let Ok(n) = stream.read(&mut buf).await {
                                            if let Ok(h) = parse_frame_header(&buf[..n]) {
                                                noise.read_message(&buf[8..8+h.payload_len.min(n-8)]).ok();
                                            }
                                        }
                                    }
                                } else {
                                    let mut buf = vec![0u8; 4096];
                                    if let Ok(n) = stream.read(&mut buf).await {
                                        if let Ok(h) = parse_frame_header(&buf[..n]) {
                                            if noise.read_message(&buf[8..8+h.payload_len.min(n-8)]).is_ok() {
                                                if let Ok(ik2) = noise.write_message(&[]) {
                                                    stream.write_all(&encode_handshake_frame(0, &ik2)).await.ok();
                                                }
                                            }
                                        }
                                    }
                                }
                                let _session = noise.into_transport();
                                tracing::info!("TSO accepted from peer");
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        tracing::info!("TSO TCP: {TSO_PORTS} ports");

        if let Err(e) = dht.store_self(&public_key, &noise_pubkey, &endpoints, capabilities).await {
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
        let public_dht = public_dht_addr;
        tokio::spawn(async move {
            loop {
                let t = transport_relay.clone();
                let d = dht_relay.clone();
                match t.accept_connection().await {
                    Ok((conn, _peer_id, _pubkey)) => {
                        let c = conn.clone();
                        let my_id = peer_id;
                        let my_dht_addr = public_dht;
                        tokio::spawn(async move {
                            if let Ok((mut _send, mut recv)) = c.accept_bi().await {
                                let mut buf = vec![0u8; 2048];
                                if let Ok(Some(n)) = recv.read(&mut buf).await {
                                    // DHT address exchange + PeerID: non-frame plaintext stream
                                    // Format: "DHT_ADDR:ip:port:PeerIDhex"
                                    if buf[..n].starts_with(b"DHT_ADDR:") {
                                        let parts: Vec<&str> = std::str::from_utf8(&buf[7..n])
                                            .unwrap_or("").trim().split(':').collect();
                                        if parts.len() >= 3 {
                                            if let Ok(peer_dht) = format!("{}:{}", parts[0], parts[1]).parse::<SocketAddr>() {
                                                let correct_peer_id = if parts.len() >= 4 {
                                                    PeerId::from_hex(parts[3]).unwrap_or(_peer_id)
                                                } else {
                                                    _peer_id
                                                };
                                                d.add_node(correct_peer_id, peer_dht).await;
                                                // Respond with our DHT addr (public IP + DHT port) + PeerID
                                                let resp = format!("DHT_ADDR:{my_dht_addr}:{}", my_id);
                                                _send.write_all(resp.as_bytes()).await.ok();
                                                _send.finish().ok();
                                            }
                                        }
                                        return;
                                    }

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
                                                        c.clone(), target, record.noise_pubkey, &record.endpoints,
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

        // 7. Store invite state for on-demand regeneration
        let invite_state = Arc::new(RwLock::new((
            peer_id, public_key, noise_pubkey, capabilities, endpoints.clone(),
        )));

        // Log initial invite
        let init_invite = lain_discovery::InviteCode::new(
            peer_id, public_key, noise_pubkey, capabilities, endpoints.clone(),
            &|data| self.identity.sign(data),
        );
        tracing::info!("Invite: lain://{}", init_invite.to_base62());

        // 7. (IPC was started early at the top of run())

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
                            &noise_pubkey,
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
                                    expected == inv.peer_id && inv.noise_pk.iter().any(|&b| b != 0)
                                });
                            if let Some(inv) = code {
                                if inv.is_expired() {
                                    tracing::warn!("invite expired for {}", inv.peer_id);
                                    let _ = _ipc_ev_tx.send(IpcResponse::Event {
                                        event: "peer_error".into(),
                                        peer_id: Some(inv.peer_id.to_string()),
                                        data: Some(serde_json::json!({"error": "invite expired"})),
                                    });
                                    continue;
                                }
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
                                let noise_pk = inv.noise_pk;
                                let eps = inv.endpoints.clone();
                                let dht = dht_arc.clone();
                                let my_id = peer_id;
                                let my_dht = endpoints.last().map(|e| e.addr);
                                let my_endpoints = endpoints.clone();
                                let my_pubkey = public_key;
                                let my_noise_pk = noise_pubkey;
                                let my_caps = capabilities;
                                tokio::spawn(async move {
                                    match t.connect_raw(&noise_pk, &eps).await {
                                        Ok(conn) => {
                                            // Bridge QUIC → DHT: exchange DHT addresses
                                            // via a QUIC stream so both sides learn the
                                            // correct DHT port (not the QUIC port).
                                            if let Some(dht_addr) = my_dht {
                                                if let Ok((mut s, mut r)) = conn.open_bi().await {
                                                    let msg = format!("DHT_ADDR:{dht_addr}:{my_id}");
                                                    if s.write_all(msg.as_bytes()).await.is_ok() {
                                                        s.finish().ok();
                                                        let mut buf = vec![0u8; 128];
                                                        if let Ok(Some(n)) = r.read(&mut buf).await {
                                                            if buf[..n].starts_with(b"DHT_ADDR:") {
                                                                let parts: Vec<&str> = std::str::from_utf8(&buf[7..n])
                                                                    .unwrap_or("").trim().split(':').collect();
                                                                if parts.len() >= 2 {
                                                                    if let Ok(peer_dht) = format!("{}:{}", parts[0], parts[1]).parse::<SocketAddr>() {
                                                                        let correct_pid = if parts.len() >= 3 {
                                                                            PeerId::from_hex(parts[2]).unwrap_or(pid)
                                                                        } else { pid };
                                                                        dht.add_node(correct_pid, peer_dht).await;
                                                                        tracing::info!("DHT bridged: {correct_pid} @ {peer_dht}");
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                // Also send PING to peer DHT once we have its addr
                                                let ping = lain_dht::message::encode_ping_request(
                                                    my_id,
                                                    rand::random::<u128>().to_be_bytes(),
                                                );
                                                // Try both STUN endpoint and DHT endpoint
                                                for ep in &eps {
                                                    dht.send_msg(&ping, ep.addr).await;
                                                }
                                                dht.send_msg(&ping, dht_addr).await;
                                            }

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

                                            // Immediately push our record to the DHT so
                                            // the new peer (and their neighbors) can find us
                                            // without waiting for the next heartbeat.
                                            let _ = dht.store_self(
                                                &my_pubkey, &my_noise_pk, &my_endpoints, my_caps,
                                            ).await;

                                            // Spawn reader task for incoming data
                                            let ipc_ev2 = ipc_ev.clone();
                                            let pid2 = pid;
                                            let c = conn.clone();
                                            tokio::spawn(async move {
                                                loop {
                                                    match c.accept_bi().await {
                                                        Ok((_send, mut recv)) => {
                                                            match recv.read_to_end(65536).await {
                                                                Ok(data) => {
                                                                    use base64::Engine;
                                                                    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                                                                    let _ = ipc_ev2.send(IpcResponse::Event {
                                                                        event: "data".into(),
                                                                        peer_id: Some(pid2.to_string()),
                                                                        data: Some(serde_json::json!({
                                                                            "bytes": b64
                                                                        })),
                                                                    });
                                                                }
                                                                Err(_) => break,
                                                            }
                                                        }
                                                        Err(_) => break,
                                                    }
                                                }
                                                // Connection lost — notify subscribers
                                                let _ = ipc_ev2.send(IpcResponse::Event {
                                                    event: "peer_disconnected".into(),
                                                    peer_id: Some(pid2.to_string()),
                                                    data: None,
                                                });
                                            });
                                        }
                                        Err(e) => {
                                            tracing::warn!("direct connect to {pid} failed: {e}, trying relay");
                                            // Fallback: relay through any reachable peer
                                            if let Ok(relays) = dht.find_relays().await {
                                                for relay in relays {
                                                    if relay.node_id == my_id || relay.node_id == pid {
                                                        continue;
                                                    }
                                                    if let Ok(Some(rec)) = dht.find_peer(&relay.node_id).await {
                                                        if let Ok(relay_conn) = t.connect_raw(&rec.noise_pubkey, &rec.endpoints).await {
                                                            let mut rl = Vec::with_capacity(64);
                                                            rl.extend_from_slice(&my_id.0);
                                                            rl.extend_from_slice(&pid.0);
                                                            let rl_frame = lain_core::frame::encode_frame(
                                                                1, lain_core::frame::FrameType::RelayConnect, &rl,
                                                            );
                                                            if let Ok((mut s, _)) = relay_conn.open_bi().await {
                                                                s.write_all(&rl_frame).await.ok();
                                                                s.finish().ok();
                                                                tracing::info!("relay: {my_id} -> {pid} via {}", relay.node_id);
                                                                // Connected via relay — same as direct
                                                                connected_ref.write().await.insert(pid, (relay_conn, {
                                                                    let permit = conn_sem2.clone().acquire_owned().await.unwrap();
                                                                    permit
                                                                }));
                                                                let _ = ipc_ev.send(IpcResponse::Event {
                                                                    event: "peer_connected".into(),
                                                                    peer_id: Some(pid.to_string()),
                                                                    data: Some(serde_json::json!({"via": "relay"})),
                                                                });
                                                                return;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            // TSO fallback: try TCP simultaneous open
                                            let tso_eps: Vec<SocketAddr> = eps.iter()
                                                .filter(|ep| ep.kind == lain_core::endpoint::EndpointKind::TSO)
                                                .map(|ep| ep.addr).collect();
                                            if !tso_eps.is_empty() {
                                                match t.ts_connect(&pid, &noise_pk, &tso_eps).await {
                                                    Ok((_stream, _session, _peer)) => {
                                                        let _ = ipc_ev.send(IpcResponse::Event {
                                                            event: "peer_connected".into(),
                                                            peer_id: Some(pid.to_string()),
                                                            data: Some(serde_json::json!({"via": "tso"})),
                                                        });
                                                        return;
                                                    }
                                                    Err(e) => tracing::debug!("TSO to {pid}: {e}"),
                                                }
                                            }
                                            // All paths exhausted
                                            let _ = ipc_ev.send(IpcResponse::Event {
                                                event: "peer_error".into(),
                                                peer_id: Some(pid.to_string()),
                                                data: Some(serde_json::json!({"error": format!("{e} (all paths exhausted)")})),
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
                            } else {
                                tracing::warn!("invalid invite: {invite}");
                                let _ = _ipc_ev_tx.send(IpcResponse::Event {
                                    event: "peer_error".into(),
                                    peer_id: None,
                                    data: Some(serde_json::json!({"error": "invalid invite code"})),
                                });
                            }
                        }
                        IpcCommand::TsoPeer { invite } => {
                            tracing::info!("IPC: TSO via {invite}");
                            let code = invite.strip_prefix("lain://")
                                .and_then(|c| lain_discovery::InviteCode::from_base62(c).ok());
                            if let Some(inv) = code {
                                let t = transport.clone();
                                let ipc_ev = _ipc_ev_tx.clone();
                                let pid = inv.peer_id;
                                let noise_pk = inv.noise_pk;
                                let tso_eps: Vec<SocketAddr> = inv.endpoints.iter()
                                    .filter(|e| e.kind == lain_core::endpoint::EndpointKind::TSO)
                                    .map(|e| e.addr)
                                    .collect();
                                tokio::spawn(async move {
                                    match t.ts_connect(&pid, &noise_pk, &tso_eps).await {
                                        Ok((_stream, _session, peer)) => {
                                            let _ = ipc_ev.send(IpcResponse::Event {
                                                event: "peer_connected".into(),
                                                peer_id: Some(pid.to_string()),
                                                data: Some(serde_json::json!({"via": "TSO"})),
                                            });
                                            tracing::info!("TSO connected: {pid} via {peer}");
                                        }
                                        Err(e) => {
                                            let _ = ipc_ev.send(IpcResponse::Event {
                                                event: "peer_error".into(),
                                                peer_id: Some(pid.to_string()),
                                                data: Some(serde_json::json!({"error": format!("TSO: {e}")})),
                                            });
                                        }
                                    }
                                });
                            } else {
                                let _ = _ipc_ev_tx.send(IpcResponse::Event {
                                    event: "peer_error".into(),
                                    peer_id: None,
                                    data: Some(serde_json::json!({"error": "invalid invite code"})),
                                });
                            }
                        }
                        IpcCommand::FindPeer { peer_id } => {
                            tracing::info!("IPC: find {peer_id}");
                            let dht = dht_arc.clone();
                            let t = transport.clone();
                            let ipc_ev = _ipc_ev_tx.clone();
                            let connected_ref = connected.clone();
                            let conn_sem2 = conn_sem.clone();
                            tokio::spawn(async move {
                                if let Ok(pid) = PeerId::from_hex(&peer_id) {
                                    match dht.find_peer(&pid).await {
                                        Ok(Some(record)) => {
                                            tracing::info!("found {pid} via DHT, connecting...");
                                            let eps = record.endpoints.clone();
                                            let npk = record.noise_pubkey;
                                            let conn_result = t.connect_raw(&npk, &eps).await;
                                            match conn_result {
                                                Ok(conn) => {
                                                    connected_ref.write().await.insert(pid, (conn, conn_sem2.acquire_owned().await.unwrap()));
                                                    let _ = ipc_ev.send(IpcResponse::Event {
                                                        event: "peer_connected".into(),
                                                        peer_id: Some(pid.to_string()),
                                                        data: Some(serde_json::json!({"via": "dht"})),
                                                    });
                                                }
                                                Err(e) => {
                                                    // Relay fallback
                                                    tracing::warn!("direct connect to {pid} failed: {e}, trying relay");
                                                    if let Ok(relays) = dht.find_relays().await {
                                                        for relay in relays {
                                                            if relay.node_id == pid { continue; }
                                                            if let Ok(Some(rec)) = dht.find_peer(&relay.node_id).await {
                                                                if let Ok(relay_conn) = t.connect_raw(&rec.noise_pubkey, &rec.endpoints).await {
                                                                    let mut rl = Vec::new();
                                                                    rl.extend_from_slice(&PeerId::from_hex(&peer_id).unwrap_or(PeerId([0;32])).0);
                                                                    rl.extend_from_slice(&pid.0);
                                                                    let rl_frame = lain_core::frame::encode_frame(1, lain_core::frame::FrameType::RelayConnect, &rl);
                                                                    if let Ok((mut s, _)) = relay_conn.open_bi().await {
                                                                        s.write_all(&rl_frame).await.ok();
                                                                        s.finish().ok();
                                                                        connected_ref.write().await.insert(pid, (relay_conn, conn_sem2.acquire_owned().await.unwrap()));
                                                                        let _ = ipc_ev.send(IpcResponse::Event {
                                                                            event: "peer_connected".into(),
                                                                            peer_id: Some(pid.to_string()),
                                                                            data: Some(serde_json::json!({"via": "dht+relay"})),
                                                                        });
                                                                        return;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    // TSO fallback
                                                    let tso_eps: Vec<_> = eps.iter().filter(|ep| ep.kind == lain_core::endpoint::EndpointKind::TSO).map(|ep| ep.addr).collect();
                                                    if !tso_eps.is_empty() {
                                                        match t.ts_connect(&pid, &npk, &tso_eps).await {
                                                            Ok((_stream, _session, _peer)) => {
                                                                let _ = ipc_ev.send(IpcResponse::Event {
                                                                    event: "peer_connected".into(),
                                                                    peer_id: Some(pid.to_string()),
                                                                    data: Some(serde_json::json!({"via": "dht+tso"})),
                                                                });
                                                                return;
                                                            }
                                                            Err(e) => tracing::debug!("TSO to {pid}: {e}"),
                                                        }
                                                    }
                                                    let _ = ipc_ev.send(IpcResponse::Event {
                                                        event: "peer_error".into(),
                                                        peer_id: Some(pid.to_string()),
                                                        data: Some(serde_json::json!({"error": format!("{e} (all paths exhausted)")})),
                                                    });
                                                    return;
                                                }
                                            }
                                        }
                                        _ => {
                                            let _ = ipc_ev.send(IpcResponse::Event {
                                                event: "peer_error".into(),
                                                peer_id: Some(peer_id.clone()),
                                                data: Some(serde_json::json!({"error": "peer not found in DHT — connect to someone first to build the network"})),
                                            });
                                        }
                                    }
                                }
                            });
                        }
                        IpcCommand::DisconnectPeer { peer_id } => {
                            tracing::info!("IPC: disconnect {peer_id}");
                            known_peers.write().await.remove(&peer_id);
                            conn_mgr.remove_peer(&peer_id).await;
                            if let Some((conn, _permit)) = connected.write().await.remove(&peer_id) {
                                conn.close(0u32.into(), b"disconnected");
                            }
                            let _ = _ipc_ev_tx.send(IpcResponse::Event {
                                event: "peer_disconnected".into(),
                                peer_id: Some(peer_id.to_string()),
                                data: None,
                            });
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
                            let (pid, pk, npk, caps, eps) = invite_state.read().await.clone();
                            let inv = lain_discovery::InviteCode::new(
                                pid, pk, npk, caps, eps,
                                &|data| self.identity.sign(data),
                            );
                            let _ = reply.send(format!("lain://{}", inv.to_base62()));
                        }
                    }
                }

                _ = heartbeat.tick() => {
                    // Periodic save of peers.json (crash resilience)
                    let peers = known_peers.read().await;
                    save_peers(&peers, &self.identity);

                    // Also save DHT routes for crash recovery
                    if let Some(routes_path) = dirs_home().map(|d| d.join(".lain").join("routes.json")) {
                        let _ = dht_arc.save_routes(&routes_path).await;
                    }

                    // Update invite with latest endpoints (NAT may have changed)
                    let mut inv = invite_state.write().await;
                    inv.4 = endpoints.clone();

                    // Always propagate STORE to maintain DHT presence (even idle)
                    // so other peers can discover this node via find_peer.
                    if let Err(e) = dht_arc.store_self(
                        &public_key, &noise_pubkey, &endpoints, capabilities,
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
        .or_else(|| {
            #[cfg(windows)] { Some(PathBuf::from(r"\\.\pipe\lain")) }
            #[cfg(unix)] { dirs_home().map(|d| d.join(".lain").join("socket")) }
        })
}

fn ipc_socket_alive(path: &PathBuf) -> bool {
    #[cfg(unix)]
    { std::os::unix::net::UnixStream::connect(path).is_ok() }
    #[cfg(windows)]
    {
        // Try opening as client — succeeds only if a server is listening
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x40000000) // FILE_FLAG_OVERLAPPED for async pipe
            .open(path)
            .is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use lain_identity::Identity;

    // Test the stored peer format used by save_peers/load_peers
    #[test]
    fn test_peer_json_roundtrip() {
        let id = Identity::generate().ok().unwrap();
        let pid = id.peer_id();

        // Create a stored peer list (same format as save_peers writes)
        let entries = vec![StoredPeer {
            peer_id_hex: pid.to_hex(),
            pubkey_hex: String::new(),
            endpoints: vec!["127.0.0.1:8080".to_string()],
        }];

        // Sign and wrap (same as save_peers does)
        let sig = id.sign(serde_json::to_string(&entries).unwrap().as_bytes());
        let signed = serde_json::json!({
            "data": entries,
            "sig": hex::encode(sig),
        });

        let json = serde_json::to_string(&signed).unwrap();

        // Parse back (same logic as load_peers)
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let loaded: Vec<StoredPeer> = serde_json::from_value(parsed["data"].clone()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].peer_id_hex, pid.to_hex());
        assert_eq!(loaded[0].endpoints[0], "127.0.0.1:8080");
    }

    #[test]
    fn test_peer_json_load_legacy_format() {
        let id = Identity::generate().ok().unwrap();
        let pid = id.peer_id();

        // Legacy format: just the array, no signature wrapper
        let entries = vec![StoredPeer {
            peer_id_hex: pid.to_hex(),
            pubkey_hex: String::new(),
            endpoints: vec!["10.0.0.1:443".to_string()],
        }];
        let json = serde_json::to_string(&entries).unwrap();

        // Parse as legacy (load_peers fallback path)
        let parsed: Vec<StoredPeer> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].peer_id_hex, pid.to_hex());
    }
}
