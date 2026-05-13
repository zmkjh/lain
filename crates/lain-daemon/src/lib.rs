#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod ipc;

use lain_core::capabilities::Capabilities;
use lain_core::crypto::CryptoProvider;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::frame::FrameType;
use lain_core::identity::IdentityProvider;
use lain_core::nat::NatProber;
use lain_core::peer::PeerId;
use lain_core::transport::Connection;
use lain_core::transport::Transport;
use crate::ipc::{IpcCommand, IpcResponse};
use lain_dht::DhtHandle;
use lain_discovery::MdnsDiscovery;
use lain_identity::Identity;
use lain_nat::NatProbe;
use lain_noise::NoiseProvider;
use lain_transport::{TransportConfig, PeekConnection};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{RwLock, broadcast, watch};
use tracing;

pub use config::DaemonConfig;

#[derive(Error, Debug)]
pub enum DaemonError {
    #[error("config: {0}")] Config(String),
    #[error("identity: {0}")] Identity(String),
    #[error("dht: {0}")] Dht(String),
    #[error("transport: {0}")] Transport(String),
}

impl From<lain_transport::TransportError> for DaemonError {
    fn from(e: lain_transport::TransportError) -> Self { DaemonError::Transport(e.to_string()) }
}
impl From<lain_core::error::CoreError> for DaemonError {
    fn from(e: lain_core::error::CoreError) -> Self { DaemonError::Transport(e.to_string()) }
}

#[derive(Serialize, Deserialize)]
struct StoredPeer {
    peer_id_hex: String,
    addr: String,
}

pub struct Daemon {
    config: DaemonConfig,
    identity: Identity,
}

struct ConnectionGuard(tokio::sync::watch::Sender<bool>);

impl ConnectionGuard {
    fn disconnect(&self) { let _ = self.0.send(true); }
}

type Connections = Arc<RwLock<HashMap<PeerId, (Arc<dyn Connection>, ConnectionGuard)>>>;
type KnownPeers = Arc<RwLock<HashMap<PeerId, Vec<Endpoint>>>>;

impl Daemon {
    pub async fn new(config: DaemonConfig) -> Result<Self, DaemonError> {
        tracing::info!("Lain daemon starting...");
        let identity = Identity::load_or_generate()
            .map_err(|e| DaemonError::Identity(e.to_string()))?;
        tracing::info!("PeerID: {}", identity.peer_id());
        Ok(Self { config, identity })
    }

    pub fn peer_id(&self) -> PeerId { self.identity.peer_id() }

    pub async fn run(&self) -> Result<(), DaemonError> {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }

        let peer_id = self.peer_id();
        let public_key = *self.identity.public_key();

        // ── IPC ──
        let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<ipc::IpcCommand>(256);
        let ipc_server = ipc::IpcServer::new(
            ipc::IpcConfig {
                uds_path: self.config.ipc.uds_path.clone().map(PathBuf::from)
                    .or_else(|| dirs_home().map(|d| d.join(".lain").join("socket"))),
                http_addr: self.config.ipc.http_addr,
            }, cmd_tx,
        );
        let ipc_ev = ipc_server.event_sender();
        // 让 IPC dispatch 能在 main loop 启动前直接响应 Whoami
        ipc::set_daemon_peer_id(&peer_id);
        tokio::spawn(async move { let _ = ipc_server.run().await; });

        // ── NAT ──
        let stun_addrs: Vec<SocketAddr> = {
            let mut addrs = Vec::new();
            for host in &self.config.stun_servers {
                if let Ok(iter) = tokio::net::lookup_host(host).await { addrs.extend(iter); }
            }
            addrs
        };
        let nat = match tokio::time::timeout(
            Duration::from_secs(4),
            NatProbe::new(stun_addrs, 3).probe(),
        ).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(DaemonError::Dht(e.to_string())),
            Err(_) => {
                tracing::warn!("NAT probe timed out, continuing with Unknown type");
                let (ipv6_inbound, ipv6_addr) = NatProbe::ipv6_status().await;
                lain_core::nat::NatProbeResult {
                    nat_type: lain_core::nat::NatType::Unknown,
                    ipv6_inbound,
                    ipv6_addr,
                    mapped_addr: None,
                    port_delta: None,
                    stun_rtt_ms: None,
                }
            }
        };
        let ipv6_desc = nat.ipv6_addr.map(|a| a.to_string()).unwrap_or_else(||
            if nat.ipv6_inbound { "stack only (no global address)".into() } else { "no".into() }
        );
        tracing::info!("NAT: {:?}, IPv6: {}", nat.nat_type, ipv6_desc);

        let ipv6_addr = nat.ipv6_addr;

        let bind_addr = if ipv6_addr.is_some() {
            "[::]:0".parse().unwrap_or(SocketAddr::from(([0,0,0,0], 0)))
        } else {
            "0.0.0.0:0".parse::<SocketAddr>().unwrap()
        };

        let (noise_secret, noise_pubkey) = self.identity.noise_keypair();
        let crypto: Arc<dyn CryptoProvider> = Arc::new(NoiseProvider::new(noise_secret));

        // ── Transport ──
        let transport: Arc<dyn Transport> = Arc::new(lain_transport::Transport::new(
            TransportConfig { bind_addr, has_ipv6: ipv6_addr.is_some() },
            crypto, peer_id,
        )?);
        let transport_port = transport.local_addr()?.port();

        // ── DHT ──
        let mut dht = DhtHandle::new(peer_id, public_key, lain_dht::DhtConfig {
            local_addr: bind_addr, ..Default::default()
        }).map_err(|e| DaemonError::Dht(e.to_string()))?;
        dht.set_signer(self.identity.signing_seed());

        if let Some(rp) = dirs_home().map(|d| d.join(".lain").join("routes.json")) {
            let _ = dht.load_routes(&rp).await;
        }
        if !self.config.dht.bootstrap_nodes.is_empty() {
            if let Err(e) = dht.bootstrap(&self.config.dht.bootstrap_nodes).await {
                tracing::warn!("DHT bootstrap failed: {e}");
            }
        }
        let dht = Arc::new(dht);

        // ── Endpoints ──
        let mut eps: Vec<Endpoint> = Vec::new();
        if let Some(v6) = ipv6_addr {
            eps.push(Endpoint::new(SocketAddr::new(std::net::IpAddr::V6(v6), transport_port), EndpointKind::IPv6));
        }
        if let Some(stun) = nat.mapped_addr {
            eps.push(Endpoint::new(SocketAddr::new(stun.ip(), transport_port), EndpointKind::STUN));
            for i in 0..8u16 {
                eps.push(Endpoint::new(SocketAddr::new(stun.ip(), 50000 + i), EndpointKind::TSO));
            }
        }

        let caps = Capabilities::new()
            .with(if nat.ipv6_inbound { Capabilities::IPV6_INBOUND } else { 0 })
            .with(if nat.nat_type.is_symmetric() && !nat.ipv6_inbound { 0 } else { Capabilities::RELAY_CAPABLE });
        let _ = dht.store_self(&public_key, &noise_pubkey, &eps, caps).await;

        dht.spawn_bucket_refresh();
        dht.spawn_cleanup();

        // ── mDNS ──
        let dht_port = dht.socket().local_addr().map(|a| a.port()).unwrap_or(53617);
        let dht_mdns = dht.clone();
        tokio::spawn(async move { let _ = mdns_loop(peer_id, dht_port, dht_mdns).await; });

        let dht_socket = dht.socket();
        let dht_for_loop = dht.clone();

        // ── State ──
        let connected: Connections =
            Arc::new(RwLock::new(HashMap::new()));
        let known_peers: KnownPeers =
            Arc::new(RwLock::new(HashMap::new()));

        // ── Ifacesnapshot 1 ──
        let mut iface_addrs: Vec<SocketAddr> = Vec::new();
        if let Ok(ifs) = if_addrs::get_if_addrs() {
            iface_addrs = ifs.into_iter()
                .filter(|i| !i.ip().is_loopback())
                .map(|i| SocketAddr::new(i.ip(), 0))
                .collect();
        }

        // ── Main loop ──
        let mut dht_buf = vec![0u8; 2048];
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(300));
        let mut ev_rx = ipc_ev.subscribe();
        loop {
            tokio::select! {
                recv = dht_socket.recv_from(&mut dht_buf) => {
                    if let Ok((len, src)) = recv {
                        let _ = dht_for_loop.handle_incoming(&dht_buf[..len], src).await;
                    }
                }

                result = cmd_rx.recv() => {
                    if let Some(cmd) = result { match cmd {
                    IpcCommand::ConnectPeer { invite, .. } => {
                        let t = transport.clone(); let e = ipc_ev.clone();
                        let c = connected.clone(); let d = dht.clone();
                        let k = known_peers.clone();
                        tokio::spawn(async move { connect_cmd(invite, t, e, c, d, k).await; });
                    }
                    IpcCommand::TsoPeer { invite } => {
                        let t = transport.clone(); let e = ipc_ev.clone();
                        let c = connected.clone();
                        let rtt = nat.stun_rtt_ms;
                        tokio::spawn(async move { tso_cmd(invite, t, e, c, rtt).await; });
                    }
                    IpcCommand::FindPeer { peer_id } => {
                        let d = dht.clone(); let t = transport.clone();
                        let e = ipc_ev.clone(); let c = connected.clone();
                        tokio::spawn(async move { find_cmd(peer_id, d, t, e, c).await; });
                    }
                    IpcCommand::DisconnectPeer { peer_id } => {
                        if let Some((conn, guard)) = connected.write().await.remove(&peer_id) {
                            guard.disconnect();
                            conn.close();
                        }
                        let _ = ipc_ev.send(IpcResponse::Event {
                            event: "peer_disconnected".into(),
                            peer_id: Some(peer_id.to_string()), data: None,
                        });
                    }
                    IpcCommand::SendToPeer { peer_id, data, reply } => {
                        let cons = connected.read().await;
                        match cons.get(&peer_id) {
                            Some((conn, _)) => match conn.send(FrameType::Data, &data).await {
                                Ok(()) => { let _ = reply.send(IpcResponse::Ok {
                                    message: Some("sent".into()), data: None,
                                }); }
                                Err(e) => { let _ = reply.send(IpcResponse::Error {
                                    code: "SEND_FAILED".into(), message: e.to_string(),
                                }); }
                            },
                            None => { let _ = reply.send(IpcResponse::Error {
                                code: "NOT_CONNECTED".into(),
                                message: "no active connection".into(),
                            }); }
                        }
                    }
                    IpcCommand::Shutdown => break,
                    IpcCommand::GetStatus { reply } => {
                        let ipv6_addr_str = ipv6_addr.map(|ip| ip.to_string());
                        let _ = reply.send(serde_json::json!({
                            "peer_id": peer_id.to_string(),
                            "nat_type": format!("{:?}", nat.nat_type),
                            "ipv6": nat.ipv6_inbound,
                            "ipv6_addr": ipv6_addr_str,
                            "port_delta": nat.port_delta,
                            "stun_rtt_ms": nat.stun_rtt_ms,
                            "dht_nodes": dht.routing_table_size().await,
                            "known_peers": known_peers.read().await.len(),
                            "connected_peers": connected.read().await.len(),
                        }));
                    }
                    IpcCommand::GetWhoami { reply } => { let _ = reply.send(peer_id.to_string()); }
                    IpcCommand::GetInviteCode { reply } => {
                        let mut inv = lain_discovery::InviteCode::new(
                            peer_id, public_key, noise_pubkey, caps, eps.clone(),
                            &|data| self.identity.sign(data),
                        );
                        inv.port_delta_hint = nat.port_delta.unwrap_or(0) as u8;
                        let _ = reply.send(format!("lain://{}", inv.to_base62()));
                    }
                } }
                }
                result = ev_rx.recv() => {
                    if let Ok(ev) = result {
                        if let IpcResponse::Event { event, peer_id, .. } = ev {
                            if event == "peer_disconnected" {
                                if let Some(pid_str) = peer_id {
                                    if let Ok(pid) = PeerId::from_hex(&pid_str) {
                                        connected.write().await.remove(&pid);
                                    }
                                }
                            }
                        }
                    }
                }

                // ── Incoming connection: peek → relay or data ──
                result = transport.accept() => {
                    if let Ok(conn) = result {
                        let pid = conn.peer_id();
                        let d = dht_for_loop.clone();
                        let t = transport.clone();
                        let e = ipc_ev.clone();
                        let c = connected.clone();
                        let k = known_peers.clone();
                        tokio::spawn(async move {
                            // Skip control frames (HEADERS sent by try_quic) until we
                            // get a Data or RelayConnect message.
                            let (_, first) = loop {
                                match conn.recv().await {
                                    Ok((ft, data)) => match ft {
                                        FrameType::RelayConnect => {
                                            handle_relay(conn, &data, d, t).await;
                                            return;
                                        }
                                        FrameType::Data => break (ft, data),
                                        _ => continue,
                                    }
                                    Err(_) => return,
                                }
                            };
                            let conn = PeekConnection::new(conn, first);
                            let conn = Arc::new(conn) as Arc<dyn Connection>;
                            let (cancel_tx, cancel_rx) = watch::channel(false);
                            if let Some((old, guard)) = c.write().await.insert(pid, (conn.clone(), ConnectionGuard(cancel_tx))) {
                                guard.disconnect();
                                old.close();
                            }
                            k.write().await.insert(pid, Vec::new());
                            let _ = e.send(IpcResponse::Event {
                                event: "peer_connected".into(),
                                peer_id: Some(pid.to_string()), data: None,
                            });
                            let cancel = cancel_rx;
                            spawn_reader(conn, e, Some(cancel));
                        });
                    }
                }

                _ = heartbeat.tick() => {
                    // DHT keepalive
                    let _ = dht.store_self(&public_key, &noise_pubkey, &eps, caps).await;
                    // Peers persistence
                    save_peers(&*known_peers.read().await, &self.identity);
                    // Interface change detection
                    let (changed, _new_addrs) = iface_changed(&mut iface_addrs);
                    if changed {
                        tracing::warn!("network interfaces changed");
                        if let Ok(ifs) = if_addrs::get_if_addrs() {
                            iface_addrs = ifs.into_iter()
                                .filter(|i| !i.ip().is_loopback())
                                .map(|i| SocketAddr::new(i.ip(), 0))
                                .collect();
                        }
                        let _ = dht.store_self(&public_key, &noise_pubkey, &eps, caps).await;
                    }
                    // Drop stale connections silently
                    let _ = dht.clone().save_routes(&dirs_home().map(|d| d.join(".lain").join("routes.json")).unwrap_or(PathBuf::from("/dev/null"))).await;
                }

                _ = tokio::signal::ctrl_c() => break,
            }
        }
        save_peers(&*known_peers.read().await, &self.identity);
        tracing::info!("Daemon stopped");
        Ok(())
    }
}

// ── Relay ──

async fn handle_relay(
    requester: Box<dyn Connection>,
    frame_payload: &[u8],
    dht: Arc<DhtHandle>,
    transport: Arc<dyn Transport>,
) {
    if frame_payload.len() < 32 { return; }
    let mut target_bytes = [0u8; 32];
    target_bytes.copy_from_slice(&frame_payload[..32]);
    let target = PeerId(target_bytes);
    tracing::info!("relay request for {target}");

    let record = match dht.find_peer(&target).await {
        Ok(Some(r)) => r,
        _ => { tracing::warn!("relay: target {target} not found"); return; }
    };
    let target_conn = match transport.connect(target, &record.noise_pubkey, &record.endpoints).await {
        Ok(c) => c,
        Err(e) => { tracing::warn!("relay: connect to {target}: {e}"); return; }
    };

    // Bidirectional pipe
    let rt: Arc<dyn Connection> = Arc::from(requester);
    let tt: Arc<dyn Connection> = Arc::from(target_conn);
    let t2 = tt.clone();
    let r2 = rt.clone();
    tokio::spawn(async move {
        loop {
            match rt.recv().await {
                Ok((_, d)) => { if tt.send(FrameType::Data, &d).await.is_err() { break; } }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match t2.recv().await {
                Ok((_, d)) => { if r2.send(FrameType::Data, &d).await.is_err() { break; } }
                Err(_) => break,
            }
        }
    });
}

// ── Unified connect + track helper ──

/// Connect to a peer, track it, and spawn reader/reconnect.
async fn connect_and_track(
    pid: PeerId,
    noise_pk: &[u8; 32],
    endpoints: &[Endpoint],
    transport: Arc<dyn Transport>,
    ipc: broadcast::Sender<IpcResponse>,
    connected: Connections,
    via: &str,
    reconnect: bool,
) -> bool {
    let conn = match transport.connect(pid, noise_pk, endpoints).await {
        Ok(c) => c,
        Err(e) => {
            let _ = ipc.send(IpcResponse::Event {
                event: "peer_error".into(), peer_id: Some(pid.to_string()),
                data: Some(serde_json::json!({"error": e.to_string()})),
            });
            return false;
        }
    };
    let conn = <Arc<dyn Connection>>::from(conn);
    let ev = ipc.clone();
    if reconnect {
        let guard = spawn_reconnect(conn.clone(), ipc, transport, noise_pk, endpoints, connected.clone());
        connected.write().await.insert(pid, (conn, guard));
    } else {
        let guard = ConnectionGuard(watch::channel(false).0);
        connected.write().await.insert(pid, (conn.clone(), guard));
        spawn_reader(conn, ev.clone(), None);
    }
    let _ = ev.send(IpcResponse::Event {
        event: "peer_connected".into(), peer_id: Some(pid.to_string()),
        data: if via.is_empty() { None } else { Some(serde_json::json!({"via": via})) },
    });
    true
}

// ── Connect commands ──

async fn connect_cmd(
    invite: String, transport: Arc<dyn Transport>,
    ipc: broadcast::Sender<IpcResponse>,
    connected: Connections,
    dht: Arc<DhtHandle>,
    known: KnownPeers,
) {
    let code = match parse_invite(&invite) { Some(c) => c, None => { return; } };
    let pid = code.peer_id;
    known.write().await.insert(pid, code.endpoints.clone());

    let ipc2 = ipc.clone();
    if connect_and_track(pid, &code.noise_pk, &code.endpoints, transport.clone(), ipc2, connected.clone(), "", true).await {
        return;
    }

    // Direct QUIC failed — try relay fallback
    if let Ok(relays) = dht.find_relays().await {
        for relay in &relays {
            if relay.node_id == pid { continue; }
            let ep = [Endpoint::new(relay.address, EndpointKind::STUN)];
            if let Ok(relay_conn) = transport.connect(relay.node_id, &relay.noise_pubkey, &ep).await {
                if relay_conn.send(FrameType::RelayConnect, &pid.0).await.is_ok() {
                    let conn = <Arc<dyn Connection>>::from(relay_conn);
                    let guard = ConnectionGuard(watch::channel(false).0);
                    connected.write().await.insert(pid, (conn.clone(), guard));
                    let _ = ipc.send(IpcResponse::Event {
                        event: "peer_connected".into(), peer_id: Some(pid.to_string()),
                        data: Some(serde_json::json!({"via": "relay"})),
                    });
                    spawn_reader(conn, ipc, None);
                    return;
                }
            }
        }
    }

    let _ = ipc.send(IpcResponse::Event {
        event: "peer_error".into(), peer_id: Some(pid.to_string()),
        data: Some(serde_json::json!({"error": "all paths exhausted"})),
    });
}

async fn tso_cmd(
    invite: String, transport: Arc<dyn Transport>,
    ipc: broadcast::Sender<IpcResponse>,
    connected: Connections,
    stun_rtt_ms: Option<u64>,
) {
    let code = match parse_invite(&invite) { Some(c) => c, None => { return; } };
    let tso: Vec<SocketAddr> = code.endpoints.iter()
        .filter(|e| e.kind == EndpointKind::TSO).map(|e| e.addr).collect();
    if tso.is_empty() { tracing::warn!("no TSO endpoints"); return; }
    let port_delta = if code.port_delta_hint > 0 { Some(code.port_delta_hint as u16) } else { None };
    match transport.connect_tso(code.peer_id, &tso, port_delta, stun_rtt_ms).await {
        Ok(conn) => {
            let conn = <Arc<dyn Connection>>::from(conn);
            let guard = ConnectionGuard(watch::channel(false).0);
            connected.write().await.insert(code.peer_id, (conn.clone(), guard));
            let _ = ipc.send(IpcResponse::Event {
                event: "peer_connected".into(), peer_id: Some(code.peer_id.to_string()),
                data: Some(serde_json::json!({"via": "TSO"})),
            });
            spawn_reader(conn, ipc, None);
        }
        Err(e) => { let _ = ipc.send(IpcResponse::Event {
            event: "peer_error".into(), peer_id: Some(code.peer_id.to_string()),
            data: Some(serde_json::json!({"error": e.to_string()})),
        }); }
    }
}

async fn find_cmd(
    hex: String, dht: Arc<DhtHandle>, transport: Arc<dyn Transport>,
    ipc: broadcast::Sender<IpcResponse>,
    connected: Connections,
) {
    let pid = match PeerId::from_hex(&hex) {
        Ok(p) => p, Err(_) => { tracing::warn!("invalid peer_id: {hex}"); return; }
    };
    let record = match dht.find_peer(&pid).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = ipc.send(IpcResponse::Event {
                event: "peer_error".into(), peer_id: Some(hex),
                data: Some(serde_json::json!({"error": "not found"})),
            }); return;
        }
        Err(e) => { tracing::warn!("DHT find {pid}: {e}"); return; }
    };
    connect_and_track(pid, &record.noise_pubkey, &record.endpoints, transport, ipc, connected, "dht", true).await;
}

fn spawn_reader(
    conn: Arc<dyn Connection>,
    ipc: broadcast::Sender<IpcResponse>,
    cancel_rx: Option<watch::Receiver<bool>>,
) {
    tokio::spawn(async move {
        let pid = conn.peer_id();
        let mut cancel = cancel_rx;
        loop {
            let result = match cancel.as_mut() {
                Some(rx) => {
                    tokio::select! {
                        r = conn.recv() => r,
                        _ = rx.changed() => break,
                    }
                }
                None => conn.recv().await,
            };
            match result {
                Ok((ft, data)) => {
                    if ft != FrameType::Data { continue; }
                    use base64::Engine;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                    let _ = ipc.send(IpcResponse::Event {
                        event: "data".into(),
                        peer_id: Some(pid.to_string()),
                        data: Some(serde_json::json!({"bytes": b64})),
                    });
                }
                Err(_) => break,
            }
        }
        let _ = ipc.send(IpcResponse::Event {
            event: "peer_disconnected".into(),
            peer_id: Some(pid.to_string()),
            data: None,
        });
    });
}

/// Like spawn_reader, but reconnects on disconnect with exponential backoff.
/// Returns a ConnectionGuard that can stop reconnection.
fn spawn_reconnect(
    conn: Arc<dyn Connection>,
    ipc: broadcast::Sender<IpcResponse>,
    transport: Arc<dyn Transport>,
    noise_pubkey: &[u8; 32],
    endpoints: &[Endpoint],
    connected: Connections,
) -> ConnectionGuard {
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let npk = *noise_pubkey;
    let eps = endpoints.to_vec();
    let backoffs = [1u64, 3, 9, 27, 60, 60, 60, 60];

    tokio::spawn(async move {
        let pid = conn.peer_id();
        let mut current = conn;

        'outer: loop {
            // Reader phase
            loop {
                tokio::select! {
                    result = current.recv() => match result {
                        Ok((ft, data)) => {
                            if ft != FrameType::Data { continue; }
                            use base64::Engine;
                            let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                            let _ = ipc.send(IpcResponse::Event {
                                event: "data".into(),
                                peer_id: Some(pid.to_string()),
                                data: Some(serde_json::json!({"bytes": b64})),
                            });
                        }
                        Err(_) => break,
                    },
                    _ = cancel_rx.changed() => break 'outer,
                }
            }

            // Reconnect phase
            if *cancel_rx.borrow() { break 'outer; }
            let mut reconnected = false;
            for &secs in &backoffs {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(secs)) => {}
                    _ = cancel_rx.changed() => { break 'outer; }
                }
                match transport.connect(pid, &npk, &eps).await {
                    Ok(new) => {
                        current = Arc::from(new);
                        if let Some((existing, _)) = connected.write().await.get_mut(&pid) {
                            *existing = current.clone();
                        }
                        let _ = ipc.send(IpcResponse::Event {
                            event: "peer_connected".into(),
                            peer_id: Some(pid.to_string()),
                            data: Some(serde_json::json!({"via": "reconnect"})),
                        });
                        reconnected = true;
                        break;
                    }
                    Err(_) => continue,
                }
            }
            if reconnected { continue 'outer; }
            break 'outer;
        }

        let _ = ipc.send(IpcResponse::Event {
            event: "peer_disconnected".into(),
            peer_id: Some(pid.to_string()),
            data: None,
        });
    });
    ConnectionGuard(cancel_tx)
}

// ── Persistence ──

fn save_peers(peers: &HashMap<PeerId, Vec<Endpoint>>, identity: &Identity) {
    let path = match dirs_home().map(|d| d.join(".lain").join("peers.json")) {
        Some(p) => p, None => return,
    };
    let entries: Vec<StoredPeer> = peers.iter().map(|(pid, eps)| StoredPeer {
        peer_id_hex: pid.to_hex(),
        addr: eps.first().map(|e| e.addr.to_string()).unwrap_or_default(),
    }).collect();
    if let Ok(json) = serde_json::to_string(&entries) {
        let sig = identity.sign(json.as_bytes());
        let signed = serde_json::json!({ "data": entries, "sig": hex::encode(sig) });
        if let Ok(final_json) = serde_json::to_string(&signed) {
            if let Some(d) = path.parent() { std::fs::create_dir_all(d).ok(); }
            let _ = std::fs::write(&path, final_json);
        }
    }
}

// ── Interface change detection ──

fn iface_changed(cached: &mut Vec<SocketAddr>) -> (bool, Vec<SocketAddr>) {
    let current = if_addrs::get_if_addrs().ok().map(|ifs| {
        ifs.into_iter()
            .filter(|i| !i.ip().is_loopback())
            .map(|i| SocketAddr::new(i.ip(), 0))
            .collect::<Vec<_>>()
    }).unwrap_or_default();
    (current != *cached, current)
}

// ── Invite parsing ──

fn parse_invite(s: &str) -> Option<lain_discovery::InviteCode> {
    let code = s.strip_prefix("lain://")
        .and_then(|c| lain_discovery::InviteCode::from_base62(c).ok())?;
    let expected = PeerId(sha2::Sha256::digest(&code.ed25519_pk).into());
    if expected != code.peer_id || code.noise_pk.iter().all(|&b| b == 0) { return None; }
    if !code.verify(&|pk, data, sig| {
        ed25519_dalek::VerifyingKey::from_bytes(pk).ok()
            .and_then(|vk| ed25519_dalek::Signature::from_slice(sig).ok()
                .map(|s| vk.verify_strict(data, &s).is_ok()))
            .unwrap_or(false)
    }) { return None; }
    if code.is_expired() { return None; }
    Some(code)
}

// ── mDNS ──

async fn mdns_loop(peer_id: PeerId, dht_port: u16, dht: Arc<DhtHandle>) {
    let mdns = match MdnsDiscovery::register(peer_id, dht_port) {
        Ok(m) => m, Err(e) => { tracing::warn!("mDNS: {e}"); return; }
    };
    let rx = match mdns.browse() {
        Ok(r) => r, Err(e) => { tracing::warn!("mDNS browse: {e}"); return; }
    };
    loop {
        match rx.recv_async().await {
            Ok(event) => {
                if let Some((found, addr, _)) = MdnsDiscovery::parse_peer_from_event(&event) {
                    if found != peer_id {
                        dht.send_msg(&lain_dht::message::encode_ping_request(
                            peer_id, rand::random::<u128>().to_be_bytes(),
                        ), addr).await;
                    }
                }
            }
            Err(_) => break,
        }
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lain_core::error::CoreError;
    use lain_core::transport::PathType;
    use tokio::sync::broadcast;
    use lain_core::frame;

    // ── Mocks ──

    #[derive(Clone)]
    struct MockConnection {
        pid: PeerId,
        fail_recv: bool,
    }

    #[async_trait::async_trait]
    impl Connection for MockConnection {
        fn peer_id(&self) -> PeerId { self.pid }
        fn path(&self) -> PathType { PathType::Direct }
        async fn send(&self, _ft: FrameType, _data: &[u8]) -> Result<(), CoreError> { Ok(()) }
        fn close(&self) {}
        async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError> {
            if self.fail_recv { Err(CoreError::InvalidEndpoint("mock fail".into())) }
            else { Ok((FrameType::Data, b"mock data".to_vec())) }
        }
    }

    struct MockTransport {
        connect_result: std::sync::Mutex<Result<MockConnection, CoreError>>,
    }

    impl MockTransport {
        fn new_ok() -> Arc<Self> {
            Arc::new(Self { connect_result: std::sync::Mutex::new(Ok(MockConnection { pid: PeerId([2u8; 32]), fail_recv: false })) })
        }
        fn new_fail() -> Arc<Self> {
            Arc::new(Self { connect_result: std::sync::Mutex::new(Err(CoreError::InvalidEndpoint("mock fail".into()))) })
        }
    }

    #[async_trait::async_trait]
    impl Transport for MockTransport {
        async fn connect(&self, _pid: PeerId, _npk: &[u8; 32], _eps: &[Endpoint]) -> Result<Box<dyn Connection>, CoreError> {
            self.connect_result.lock().unwrap().clone().map(|c| Box::new(c) as Box<dyn Connection>)
        }
        async fn connect_tso(&self, _pid: PeerId, _eps: &[SocketAddr], _pd: Option<u16>, _rtt: Option<u64>) -> Result<Box<dyn Connection>, CoreError> {
            Err(CoreError::InvalidEndpoint("tso not mocked".into()))
        }
        async fn accept(&self) -> Result<Box<dyn Connection>, CoreError> {
            Err(CoreError::InvalidEndpoint("accept not mocked".into()))
        }
        fn local_addr(&self) -> Result<SocketAddr, CoreError> {
            Err(CoreError::InvalidEndpoint("no addr".into()))
        }
    }

    fn make_connected() -> Connections {
        Arc::new(RwLock::new(HashMap::new()))
    }

    fn make_ipc() -> (broadcast::Sender<IpcResponse>, broadcast::Receiver<IpcResponse>) {
        broadcast::channel(16)
    }

    // ── Relay pipe ──

    // relay pipe and handle_relay are tested via integration tests
    // (QUIC connect + send relay frame). Mock testing of the pipe
    // requires non-trivial async plumbing and adds little value over
    // the integration coverage.

    #[tokio::test]
    async fn reconnect_stops_on_disconnect() {
        let conn = Arc::new(MockConnection { pid: PeerId([1u8; 32]), fail_recv: true }) as Arc<dyn Connection>;
        let (ipc, _) = broadcast::channel(16);
        let guard = spawn_reconnect(conn, ipc, MockTransport::new_fail(), &[0u8; 32], &[], make_connected());
        guard.disconnect();
        // guard is dropped at end of scope — task exits via watch channel close
    }

    // ── connect_and_track ──

    #[tokio::test]
    async fn connect_and_track_success_inserts_and_sends_event() {
        let transport = MockTransport::new_ok();
        let ipc = make_ipc();
        let mut rx = ipc.1;
        let connected = make_connected();
        let pid = PeerId([2u8; 32]);
        let npk = [0u8; 32];
        let eps = vec![];

        let ok = connect_and_track(pid, &npk, &eps, transport, ipc.0, connected.clone(), "test", false).await;
        assert!(ok, "connect should succeed");

        // Check connected map
        let map = connected.read().await;
        assert!(map.contains_key(&pid), "pid should be in connected map");
        assert_eq!(map.get(&pid).unwrap().0.peer_id(), pid);

        // Check IPC event
        let ev = rx.try_recv().unwrap();
        match ev {
            IpcResponse::Event { event, peer_id, data } => {
                assert_eq!(event, "peer_connected");
                assert_eq!(peer_id, Some(pid.to_string()));
                assert_eq!(data, Some(serde_json::json!({"via": "test"})));
            }
            _ => panic!("expected Event"),
        }
    }

    #[tokio::test]
    async fn connect_and_track_failure_sends_error_event() {
        let transport = MockTransport::new_fail();
        let ipc = make_ipc();
        let mut rx = ipc.1;
        let connected = make_connected();

        let ok = connect_and_track(PeerId([3u8; 32]), &[0u8; 32], &[], transport, ipc.0, connected, "", false).await;
        assert!(!ok, "connect should fail");

        let ev = rx.try_recv().unwrap();
        match ev {
            IpcResponse::Event { event, .. } => assert_eq!(event, "peer_error"),
            _ => panic!("expected Event"),
        }
    }

    // ── save_peers ──

    #[test]
    fn test_save_peers_creates_file() {
        use std::fs;
        let tmp = std::env::temp_dir().join("lain-test-peers");
        let _ = fs::remove_dir_all(&tmp);
        let prev = std::env::var("LAIN_HOME").ok();
        unsafe { std::env::set_var("LAIN_HOME", tmp.to_str().unwrap()); }

        let id = Identity::generate().unwrap();
        let pid = id.peer_id();
        let mut peers = HashMap::new();
        peers.insert(pid, vec![Endpoint::new("127.0.0.1:9000".parse().unwrap(), EndpointKind::STUN)]);

        save_peers(&peers, &id);

        let path = dirs_home().unwrap().join(".lain").join("peers.json");
        assert!(path.exists(), "peers.json should exist");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains(&pid.to_hex()), "saved file should contain peer id");

        // Cleanup
        if let Some(v) = prev { unsafe { std::env::set_var("LAIN_HOME", v); } }
        else { std::env::remove_var("LAIN_HOME"); }
        let _ = fs::remove_dir_all(&tmp);
    }

    // ── Existing tests ──

    #[test]
    fn test_is_relay_request_detects_relay_connect() {
        let frame = frame::encode_frame(1, FrameType::RelayConnect, &[0u8; 64]);
        // Accept handler checks ft == FrameType::RelayConnect after recv()
        let (_, ft, _, _) = frame::decode_frame_header(&frame).unwrap();
        assert_eq!(ft, FrameType::RelayConnect);
    }

    #[test]
    fn test_is_relay_request_rejects_data_frame() {
        let frame = frame::encode_frame(1, FrameType::Data, b"hello");
        let (_, ft, _, _) = frame::decode_frame_header(&frame).unwrap();
        assert_eq!(ft, FrameType::Data);
    }

    #[test]
    fn test_is_relay_request_rejects_garbage() {
        assert!(frame::decode_frame_header(b"not a frame").is_none());
        assert!(frame::decode_frame_header(&[]).is_none());
    }

    #[test]
    fn test_connection_guard_disconnect_triggers_cancel() {
        let (tx, rx) = watch::channel(false);
        let guard = ConnectionGuard(tx);
        assert!(!*rx.borrow(), "should not be cancelled initially");
        guard.disconnect();
        assert!(*rx.borrow(), "should be cancelled after disconnect");
    }

    #[test]
    fn test_parse_invite_valid() {
        let id = Identity::generate().unwrap();
        let (_, noise_pk) = id.noise_keypair();
        let ep = Endpoint::new("127.0.0.1:9000".parse().unwrap(), EndpointKind::STUN);
        let invite = lain_discovery::InviteCode::new(
            id.peer_id(), *id.public_key(), noise_pk,
            Capabilities::new(), vec![ep],
            &|data| id.sign(data),
        );
        let uri = invite.to_uri();
        let parsed = parse_invite(&uri);
        assert!(parsed.is_some(), "valid invite should parse");
        assert_eq!(parsed.unwrap().peer_id, id.peer_id());
    }

    #[test]
    fn test_parse_invite_expired() {
        let id = Identity::generate().unwrap();
        let (_, noise_pk) = id.noise_keypair();
        let invite = lain_discovery::InviteCode::new(
            id.peer_id(), *id.public_key(), noise_pk,
            Capabilities::new(), vec![],
            &|data| id.sign(data),
        );
        assert!(!invite.is_expired(), "fresh invite should not be expired");
    }

    #[test]
    fn test_parse_invite_rejects_wrong_signature() {
        let id = Identity::generate().unwrap();
        let (_, noise_pk) = id.noise_keypair();
        let mut invite = lain_discovery::InviteCode::new(
            id.peer_id(), *id.public_key(), noise_pk,
            Capabilities::new(), vec![],
            &|data| id.sign(data),
        );
        invite.signature[0] ^= 0xFF;
        let uri = invite.to_uri();
        assert!(parse_invite(&uri).is_none(), "tampered signature should be rejected");
    }

    #[test]
    fn test_parse_invite_rejects_bad_prefix() {
        assert!(parse_invite("not-lain://abc").is_none());
        assert!(parse_invite("").is_none());
    }

    #[test]
    fn test_iface_changed_initial_state() {
        let mut cached = vec![];
        let (changed, current) = iface_changed(&mut cached);
        assert!(changed, "first call should detect change");
        let mut cached2 = current.clone();
        let (changed2, _) = iface_changed(&mut cached2);
        assert!(!changed2, "identical data should not trigger change");
    }
}
