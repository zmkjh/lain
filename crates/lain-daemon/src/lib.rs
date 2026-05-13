#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod ipc;

use lain_core::capabilities::Capabilities;
use lain_core::crypto::CryptoProvider;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::frame::{self, FrameType};
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
        tokio::spawn(async move { let _ = ipc_server.run().await; });

        // ── NAT ──
        let stun_addrs: Vec<SocketAddr> = {
            let mut addrs = Vec::new();
            for host in &self.config.stun_servers {
                if let Ok(iter) = tokio::net::lookup_host(host).await { addrs.extend(iter); }
            }
            addrs
        };
        let nat = NatProbe::new(stun_addrs, 10).probe().await?;
        tracing::info!("NAT: {:?}, IPv6: {}", nat.nat_type, nat.ipv6_inbound);

        let ipv6_addr = if nat.ipv6_inbound {
            if_addrs::get_if_addrs().ok().and_then(|ifs| {
                ifs.into_iter().find_map(|i| match i.addr {
                    if_addrs::IfAddr::V6(v6) if !v6.ip.is_loopback() && !v6.ip.is_unspecified()
                        && (v6.ip.segments()[0] & 0xE000) == 0x2000 =>
                        Some(v6.ip),
                    _ => None,
                })
            })
        } else { None };

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
            let _ = dht.bootstrap(&self.config.dht.bootstrap_nodes).await;
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
                        tokio::spawn(async move { tso_cmd(invite, t, e, c).await; });
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
                            Some((conn, _)) => match conn.send(&data).await {
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
                        let inv = lain_discovery::InviteCode::new(
                            peer_id, public_key, noise_pubkey, caps, eps.clone(),
                            &|data| self.identity.sign(data),
                        );
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
                            let first = match conn.recv().await {
                                Ok(d) => d, Err(_) => return,
                            };
                            if is_relay_request(&first) {
                                handle_relay(conn, &first[8..], d, t).await;
                                return;
                            }
                            let conn = PeekConnection::new(conn, first);
                            let conn = Arc::new(conn) as Arc<dyn Connection>;
                            let (cancel_tx, cancel_rx) = watch::channel(false);
                            c.write().await.insert(pid, (conn.clone(), ConnectionGuard(cancel_tx)));
                            k.write().await.insert(pid, Vec::new());
                            let _ = e.send(IpcResponse::Event {
                                event: "peer_connected".into(),
                                peer_id: Some(pid.to_string()), data: None,
                            });
                            let mut cancel = cancel_rx;
                            tokio::spawn(async move {
                                let pid = conn.peer_id();
                                loop {
                                    tokio::select! {
                                        data = conn.recv() => match data {
                                            Ok(data) => {
                                                use base64::Engine;
                                                let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                                                let _ = e.send(IpcResponse::Event {
                                                    event: "data".into(),
                                                    peer_id: Some(pid.to_string()),
                                                    data: Some(serde_json::json!({"bytes": b64})),
                                                });
                                            }
                                            Err(_) => break,
                                        },
                                        _ = cancel.changed() => break,
                                    }
                                }
                                let _ = e.send(IpcResponse::Event {
                                    event: "peer_disconnected".into(),
                                    peer_id: Some(pid.to_string()),
                                    data: None,
                                });
                            });
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

fn is_relay_request(data: &[u8]) -> bool {
    frame::decode_frame_header(data)
        .map(|(_, ft, _, _)| ft == FrameType::RelayConnect)
        .unwrap_or(false)
}

async fn handle_relay(
    requester: Box<dyn Connection>,
    frame_payload: &[u8],
    dht: Arc<DhtHandle>,
    transport: Arc<dyn Transport>,
) {
    if frame_payload.len() < 64 { return; }
    let mut target_bytes = [0u8; 32];
    target_bytes.copy_from_slice(&frame_payload[32..64]);
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
                Ok(d) => { if tt.send(&d).await.is_err() { break; } }
                Err(_) => break,
            }
        }
    });
    tokio::spawn(async move {
        loop {
            match t2.recv().await {
                Ok(d) => { if r2.send(&d).await.is_err() { break; } }
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
        let guard = spawn_reconnect(conn.clone(), ipc, transport, noise_pk, endpoints);
        connected.write().await.insert(pid, (conn, guard));
    } else {
        let guard = ConnectionGuard(watch::channel(false).0);
        connected.write().await.insert(pid, (conn.clone(), guard));
        spawn_reader(conn, ev.clone());
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
                let mut payload = Vec::with_capacity(64);
                payload.extend_from_slice(&code.peer_id.0);
                payload.extend_from_slice(&pid.0);
                let frame = frame::encode_frame(1, FrameType::RelayConnect, &payload);
                if relay_conn.send(&frame).await.is_ok() {
                    let conn = <Arc<dyn Connection>>::from(relay_conn);
                    let guard = ConnectionGuard(watch::channel(false).0);
                    connected.write().await.insert(pid, (conn.clone(), guard));
                    let _ = ipc.send(IpcResponse::Event {
                        event: "peer_connected".into(), peer_id: Some(pid.to_string()),
                        data: Some(serde_json::json!({"via": "relay"})),
                    });
                    spawn_reader(conn, ipc);
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
) {
    let code = match parse_invite(&invite) { Some(c) => c, None => { return; } };
    let tso: Vec<SocketAddr> = code.endpoints.iter()
        .filter(|e| e.kind == EndpointKind::TSO).map(|e| e.addr).collect();
    if tso.is_empty() { tracing::warn!("no TSO endpoints"); return; }
    match transport.connect_tso(code.peer_id, &tso, None, None).await {
        Ok(conn) => {
            let conn = <Arc<dyn Connection>>::from(conn);
            let guard = ConnectionGuard(watch::channel(false).0);
            connected.write().await.insert(code.peer_id, (conn.clone(), guard));
            let _ = ipc.send(IpcResponse::Event {
                event: "peer_connected".into(), peer_id: Some(code.peer_id.to_string()),
                data: Some(serde_json::json!({"via": "TSO"})),
            });
            spawn_reader(conn, ipc);
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
) {
    tokio::spawn(async move {
        let pid = conn.peer_id();
        loop {
            match conn.recv().await {
                Ok(data) => {
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
                    data = current.recv() => match data {
                        Ok(data) => {
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
            let mut reconnected = false;
            for &secs in &backoffs {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(secs)) => {}
                    _ = cancel_rx.changed() => break 'outer,
                }
                match transport.connect(pid, &npk, &eps).await {
                    Ok(new) => {
                        current = Arc::from(new);
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
