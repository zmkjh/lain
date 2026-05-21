#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

//! # Lain Transport — Transport + Connection 实现
//!
//! ## 模块角色
//! 实现 `lain_core::transport::Transport` 和 `Connection` trait。
//! 提供两条传输路径：QUIC（Universal）和 TSO（TCP 端口预测）。
//!
//! ## 连接类型
//!
//! ### QuicConnection（QUIC + Noise IK）
//! - QUIC TLS 使用 `NoVerify`（不验证证书，所有身份由 Noise 层处理）
//! - Noise IK handshake over QUIC bi-directional stream:
//!   - Initiator: 预载对端 X25519 公钥 → send ik1 → recv ik2 → `remote_pubkey()`
//!   - Responder: recv ik1 → `remote_pubkey()` → send ik2
//! - `noise_pubkey()` 返回 `try_quic` 中 `noise.remote_pubkey()` 的返回值（握手验证后的 X25519 公钥）
//! - 数据帧走 QUIC 流，使用 `lain_core::frame` 编解码
//!
//! ### TcpConnection（TSO + Noise IK）
//! - TCP connect via mapped port prediction（多对 (local_ip:port, remote_ip:port) 并行探测）
//! - Noise IK handshake over TCP:
//!   - 先交换明文 identity claim（PeerId + X25519 pk，64 字节）
//!   - 根据 PeerId 字典序决定 initiator/responder 角色
//!   - 握手完成后验证 Noise payload 中的 PeerId 匹配
//! - `noise_pubkey()` 返回 `None`（TSO 不暴露 X25519 公钥给上层）
//! - 内置 TCP keepalive（Noise 空消息加密发送）
//!
//! ## 与上层模块的契约
//! - `Transport::connect(pid, noise_pk, endpoints)`: 调用方提供待连接端点的 X25519 公钥
//!   - 实现方用其作为 Noise IK pre-message，握手加密验证
//!   - 返回的 Connection 的 `noise_pubkey()` 为 `verified_pk`（握手验证后的值）
//! - `Transport::connect_tso(pid, ..., mappable_port_start, mappable_port_end)`:
//!   - **不**接受 noise_pubkey 参数
//!   - 实现方在 TCP 上独立完成 Noise IK，身份仅由 PeerId 认证
//! - `Transport::accept()`: 返回的 QuicConnection 包含 Noise IK 握手解密出的 X25519 公钥
//!
//! ## 导出类型
//! - `Transport` — Transport trait 实现
//! - `TransportConfig` — QUIC 绑定地址 + TSO 端口配置
//! - `PeekConnection` — 缓冲首条消息的 Connection 包装器
//! - `TransportError` — 传输层错误（可实现 From for CoreError）

use lain_core::crypto::{CryptoProvider, NoiseHandshake, NoiseTransport};
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::error::CoreError;
use lain_core::frame::{self, encode_handshake_frame, parse_handshake_frame_header as parse_frame_header, FrameType};
use lain_core::peer::PeerId;
use lain_core::transport::{Connection, PathType, Transport as TransportTrait};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use thiserror::Error;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{Mutex, watch};

mod port_predict;
pub use port_predict::LinearPredictor;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("connect: {0}")]
    Connect(String),
    #[error("noise: {0}")]
    Noise(String),
    #[error("io: {0}")]
    Io(String),
    #[error("no path")]
    NoPath,
}

impl From<TransportError> for CoreError {
    fn from(e: TransportError) -> Self { CoreError::InvalidEndpoint(e.to_string()) }
}

// ── QuicConnection ──

struct QuicConnection {
    peer_id: PeerId,
    quic: quinn::Connection,
    noise_pubkey: Option<[u8; 32]>,
}

#[async_trait::async_trait]
impl Connection for QuicConnection {
    fn peer_id(&self) -> PeerId { self.peer_id }
    fn noise_pubkey(&self) -> Option<[u8; 32]> { self.noise_pubkey }
    fn path(&self) -> PathType { PathType::Direct }

    async fn send(&self, ft: FrameType, data: &[u8]) -> Result<(), CoreError> {
        let msg = frame::encode_frame(2, ft, data);
        let (mut s, _) = self.quic.open_bi().await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
        s.write_all(&msg).await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
        s.finish().ok();
        Ok(())
    }

    async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError> {
        loop {
            let (_, mut recv) = self.quic.accept_bi().await
                .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
            let data = recv.read_to_end(lain_core::frame::MAX_PAYLOAD_SIZE as usize).await
                .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
            if data.is_empty() { continue; }
            if let Some((_, ft, plen, hlen)) = frame::decode_frame_header(&data) {
                // Skip control frames; the caller only sees Data/application frames.
                if matches!(ft, FrameType::Headers) {
                    continue;
                }
                let payload = data.get(hlen..hlen + plen as usize)
                    .unwrap_or(&[]).to_vec();
                return Ok((ft, payload));
            }
            // Legacy: raw data without frame header — treat as Data
            return Ok((FrameType::Data, data));
        }
    }

    fn close(&self) {
        self.quic.close(0u32.into(), b"bye");
    }

    fn rtt_ms(&self) -> Option<u64> {
        Some(self.quic.rtt().as_millis() as u64)
    }
}

// ── TcpConnection ──

struct TcpInner {
    read: Mutex<OwnedReadHalf>,
    write: Mutex<OwnedWriteHalf>,
    noise: Mutex<Box<dyn NoiseTransport>>,
}

struct TcpConnection {
    peer_id: PeerId,
    inner: Arc<TcpInner>,
    keepalive_alive: Arc<AtomicBool>,
}

impl TcpConnection {
    async fn new(
        stream: tokio::net::TcpStream,
        noise: Box<dyn NoiseTransport>,
        peer_id: PeerId,
        keepalive_secs: u64,
    ) -> Self {
        let (read, write) = stream.into_split();
        let inner = Arc::new(TcpInner {
            read: Mutex::new(read),
            write: Mutex::new(write),
            noise: Mutex::new(noise),
        });
        let keepalive_alive = Arc::new(AtomicBool::new(true));
        let ka_alive = keepalive_alive.clone();
        let ka = inner.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(keepalive_secs));
            loop {
                interval.tick().await;
                if !ka_alive.load(Ordering::Relaxed) {
                    break;
                }
                let ct = {
                    let mut n = ka.noise.lock().await;
                    match n.encrypt(b"") {
                        Ok(c) => c,
                        Err(_) => break,
                    }
                };
                let frame = encode_handshake_frame(0, &ct);
                let mut w = ka.write.lock().await;
                if w.write_all(&frame).await.is_err() {
                    break;
                }
            }
        });
        Self { peer_id, inner, keepalive_alive }
    }
}

#[async_trait::async_trait]
impl Connection for TcpConnection {
    fn peer_id(&self) -> PeerId { self.peer_id }
    fn path(&self) -> PathType { PathType::TSO }

    async fn send(&self, _ft: FrameType, data: &[u8]) -> Result<(), CoreError> {
        let ct = {
            let mut noise = self.inner.noise.lock().await;
            noise.encrypt(data)?
        };
        let frame = encode_handshake_frame(0, &ct);
        let mut write = self.inner.write.lock().await;
        match write.write_all(&frame).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Must close: Noise has advanced but peer never received this frame.
                drop(write);
                self.close();
                Err(CoreError::InvalidEndpoint(e.to_string()))
            }
        }
    }

    async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError> {
        loop {
            let mut r = self.inner.read.lock().await;
            let mut header = [0u8; 8];
            r.read_exact(&mut header).await
                .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
            let plen = ((header[5] as usize) << 16) | ((header[6] as usize) << 8) | (header[7] as usize);
            let mut payload = vec![0u8; plen];
            if plen > 0 {
                r.read_exact(&mut payload).await
                    .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
            }
            drop(r);
            let data = { let mut n = self.inner.noise.lock().await; n.decrypt(&payload)? };
            if data.is_empty() { continue; }
            return Ok((FrameType::Data, data));
        }
    }

    fn close(&self) {
        self.keepalive_alive.store(false, Ordering::Relaxed);
        let inner = self.inner.clone();
        tokio::spawn(async move {
            let mut w = inner.write.lock().await;
            let _ = w.shutdown().await;
        });
    }
}

// ── Transport ──

pub struct TransportConfig {
    pub bind_addr: SocketAddr,
    pub has_ipv6: bool,
    pub tso_port_start: u16,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self { bind_addr: SocketAddr::from(([0u8; 4], 0)), has_ipv6: false, tso_port_start: 50000 }
    }
}

pub struct Transport {
    endpoint: quinn::Endpoint,
    crypto: Arc<dyn CryptoProvider>,
    peer_id: PeerId,
    tso_port_start: u16,
}

impl Transport {
    pub fn new(
        config: TransportConfig,
        crypto: Arc<dyn CryptoProvider>,
        peer_id: PeerId,
    ) -> Result<Self, TransportError> {
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let cert_params = rcgen::CertificateParams::new(vec!["lain".into()])
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let cert = cert_params.self_signed(&key_pair)
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let key_der = rustls::pki_types::PrivateKeyDer::from(pkcs8);

        let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| TransportError::Io(e.to_string()))?;

        let mut transport_cfg = quinn::TransportConfig::default();
        transport_cfg.keep_alive_interval(Some(std::time::Duration::from_secs(lain_core::KEEP_ALIVE_SECS)));

        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
                .map_err(|e| TransportError::Io(e.to_string()))?
        ));
        server_cfg.transport = Arc::new(transport_cfg);

        let socket = std::net::UdpSocket::bind(config.bind_addr)
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let runtime = quinn::default_runtime()
            .ok_or_else(|| TransportError::Io("no runtime".into()))?;

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(), Some(server_cfg), socket, runtime,
        ).map_err(|e| TransportError::Io(e.to_string()))?;

        Ok(Self { endpoint, crypto, peer_id, tso_port_start: config.tso_port_start })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr().map_err(|e| TransportError::Io(e.to_string()))
    }

    pub async fn accept(&self) -> Result<Box<dyn Connection>, TransportError> {
        let incoming = self.endpoint.accept().await
            .ok_or_else(|| TransportError::Connect("endpoint closed".into()))?;
        let conn = incoming.await
            .map_err(|e| TransportError::Connect(e.to_string()))?;

        let (mut send, mut recv) = conn.accept_bi().await
            .map_err(|e| TransportError::Connect(e.to_string()))?;

        let mut header = [0u8; 8];
        recv.read_exact(&mut header).await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
        let hdr = parse_frame_header(&header)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        if hdr.payload_len > 65536 {
            return Err(TransportError::Noise("ik1 payload too large".into()));
        }
        let mut payload = vec![0u8; hdr.payload_len];
        if hdr.payload_len > 0 {
            recv.read_exact(&mut payload).await
                .map_err(|e| TransportError::Connect(e.to_string()))?;
        }
        let mut noise = self.crypto.new_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let remote_id = noise.read_message(&payload)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let remote_pk = noise.remote_pubkey();

        let ik2 = noise.write_message(&self.peer_id)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        send.write_all(&encode_handshake_frame(1, &ik2)).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        send.finish().ok();
        // Snow requires into_transport_mode to finalize the handshake
        let _noise = noise.into_transport()
            .map_err(|e| TransportError::Noise(e.to_string()))?;

        // HEADERS
        if let Ok((mut hd_s, _)) = conn.clone().accept_bi().await {
            hd_s.write_all(&frame::encode_frame(1, FrameType::Headers, b"{}")).await.ok();
            hd_s.finish().ok();
        }

        Ok(Box::new(QuicConnection { peer_id: remote_id, quic: conn, noise_pubkey: remote_pk }))
    }

    pub async fn connect(
        &self,
        peer_id: PeerId,
        noise_pubkey: &[u8; 32],
        endpoints: &[Endpoint],
    ) -> Result<Box<dyn Connection>, TransportError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Box<dyn Connection>, TransportError>>(16);

        for ep in endpoints {
            if !matches!(ep.kind, EndpointKind::IPv6 | EndpointKind::STUN) { continue; }
            let tx = tx.clone(); let addr = ep.addr;
            let npk = *noise_pubkey; let cry = self.crypto.clone(); let my = self.peer_id;
            let qep = self.endpoint.clone();
            tokio::spawn(async move {
                let r = try_quic(addr, npk, cry, my, qep).await;
                tx.send(r.map(|(pid, q, verified_pk)| Box::new(QuicConnection { peer_id: pid, quic: q, noise_pubkey: verified_pk }) as Box<dyn Connection>)).await.ok();
            });
        }
        drop(tx);

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(lain_core::TRAVERSAL_TIMEOUT_SECS));
        tokio::pin!(deadline);
        while let Some(r) = tokio::select! { r = rx.recv() => r, _ = &mut deadline => None } {
            if let Ok(c) = r {
                if c.peer_id() == peer_id {
                    return Ok(c);
                }
                c.close();
            }
        }
        Err(TransportError::NoPath)
    }

    pub async fn connect_tso(
        &self,
        peer_id: PeerId,
        tso_endpoints: &[SocketAddr],
        port_delta: Option<u16>,
        stun_rtt_ms: Option<u64>,
        mappable_port_start: u16,
        mappable_port_end: u16,
        predictor: Arc<dyn lain_core::PortPredictor>,
    ) -> Result<Box<dyn Connection>, TransportError> {
        const TSO_DEADLINE_SECS: u64 = 102;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(TSO_DEADLINE_SECS);
        let bind_ip = self.endpoint.local_addr()
            .map(|a| a.ip()).unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        let is_pp = port_delta == Some(1);
        let rtt = stun_rtt_ms.unwrap_or(200);
        let local_ports: u16 = if is_pp { 4 } else { 8 };

        // Per-connect timeout: 20×RTT clamped to [5s, 10s].
        // This gives TCP at least one full retransmission cycle (SYN → 1s → SYN-RTX)
        // instead of killing the attempt before the first retry.
        let connect_timeout_ms: u64 = (rtt * 20).clamp(5000, 10000);

        // Stagger spawns at ~25 connects/sec — well below typical CGNAT
        // SYN-flood thresholds (50-100/sec on China Mobile NAT4 devices).
        let stagger_ms: u64 = 40;

        // ── Build remote address list ──
        //
        // Strategy (Yamada 2008 / N4 2024):
        //   1. Retain TSO endpoints as-is (for Cone NAT fallback; those ports may
        //      accept packets from any remote source).
        //   2. Use PortPredictor to generate predicted external ports for the NEXT
        //      destination on a symmetric NAT (i.e., ports the NAT will allocate
        //      for a connection TO this peer — NOT the STUN server).
        //   3. If port_delta is None (unpredictable allocation), fall back to a
        //      wider random scan of the mappable_port_range, but acknowledge that
        //      APDF × APDF success probability is low; relay is the real fallback.

        let mut remote_addrs: Vec<SocketAddr> = tso_endpoints.to_vec();

        // Predicted ports for symmetric NAT (next-destination prediction)
        let remote_ip = tso_endpoints.first().map(|a| a.ip());
        if let Some(ip) = remote_ip {
            let base_ports: Vec<u16> = tso_endpoints.iter().map(|a| a.port()).collect();
            let predicted = predictor.predict(&base_ports, port_delta, stun_rtt_ms);
            for &p in &predicted {
                remote_addrs.push(SocketAddr::new(ip, p));
            }

            // ── Random fallback for unpredictable NAT ──
            //
            // When port_delta is None (APDF with random port allocation), the
            // linear predictor returns empty.  We widen the random scan to 32
            // ports from mappable_range as a last-ditch effort.  Success rate
            // is low (~1-2% per pair), but the low cost makes it worth trying
            // before relay.
            if port_delta.is_none() {
                let range = mappable_port_start.saturating_sub(128)..mappable_port_end.saturating_add(128);
                let range_len = (range.end - range.start).max(1) as u32;
                for _ in 0..32 {
                    let offset = rand::random::<u32>() % range_len;
                    remote_addrs.push(SocketAddr::new(ip, range.start + offset as u16));
                }
            }
        }
        // Deduplicate by SocketAddr
        remote_addrs.sort_by_key(|a| a.port());
        remote_addrs.dedup();

        let random_count = if port_delta.is_none() { 32u64 } else { 0 };
        let predicted_count = remote_addrs.len()
            .saturating_sub(tso_endpoints.len() + random_count as usize);
        tracing::info!(
            "TSO: {} targets ({} invite + {} predicted + {} random), {} local ports",
            remote_addrs.len(), tso_endpoints.len(), predicted_count, random_count, local_ports,
        );

        // ── Build (local_addr, remote_addr) pairs ──
        let pairs: Vec<(SocketAddr, SocketAddr)> = (0..local_ports)
            .flat_map(|i| {
                let la = SocketAddr::new(bind_ip, self.tso_port_start + i);
                remote_addrs.iter().map(move |&ra| (la, ra))
            })
            .collect();

        let stream_result: Arc<Mutex<Option<tokio::net::TcpStream>>> =
            Arc::new(Mutex::new(None));

        // Track which (local_port, remote_addr) pairs are currently in-flight
        // to avoid spawning duplicate 4-tuple connections.
        let in_flight: Arc<Mutex<HashSet<(u16, SocketAddr)>>> =
            Arc::new(Mutex::new(HashSet::new()));

        // ── Cancellation signal ──
        // When connect_tso returns (success or timeout), the sender is dropped
        // and all spawned tasks receive the cancellation signal.
        let (cancel_tx, cancel_rx) = watch::channel(false);

        // ── Continuous staggered flow ──
        // Instead of burst-sleep rounds, we keep ~all pairs continuously alive:
        // each spawn is staggered by stagger_ms, each lives for connect_timeout_ms,
        // and as one dies it is immediately re-spawned.  No dead zones.
        while std::time::Instant::now() < deadline {
            if stream_result.lock().await.is_some() {
                break;
            }

            // Pick a random free pair (not currently in-flight).
            let pair = {
                let locked = in_flight.lock().await;
                let free: Vec<_> = pairs
                    .iter()
                    .filter(|(la, ra)| !locked.contains(&(la.port(), *ra)))
                    .copied()
                    .collect();
                if free.is_empty() {
                    // All pairs busy — wait a bit for some to complete, then retry.
                    drop(locked);
                    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                    continue;
                }
                let idx = rand::thread_rng().gen_range(0..free.len());
                free[idx]
            };

            let (la, ra) = pair;

            // Mark this pair as in-flight *before* spawning.
            in_flight.lock().await.insert((la.port(), ra));

            let sr = stream_result.clone();
            let infl = in_flight.clone();
            let mut cancel_rx_clone = cancel_rx.clone();
            tokio::spawn(async move {
                // Quick bail if another task already won.
                if sr.lock().await.is_some() {
                    infl.lock().await.remove(&(la.port(), ra));
                    return;
                }

                let s = if ra.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()
                } else {
                    tokio::net::TcpSocket::new_v6()
                };

                if let Ok(s) = s {
                    s.set_reuseaddr(true).ok();
                    if s.bind(la).is_ok() {
                        let connect_fut = tokio::time::timeout(
                            std::time::Duration::from_millis(connect_timeout_ms),
                            s.connect(ra),
                        );
                        tokio::select! {
                            biased;
                            _ = cancel_rx_clone.changed() => {
                                // Cancellation: parent returned, stop immediately
                            }
                            result = connect_fut => {
                                if let Ok(Ok(stream)) = result {
                                    // Verify connected address matches target
                                    if stream.peer_addr().ok() != Some(ra) {
                                        infl.lock().await.remove(&(la.port(), ra));
                                        return;
                                    }
                                    let mut res = sr.lock().await;
                                    if res.is_none() {
                                        *res = Some(stream);
                                    }
                                }
                            }
                        }
                    }
                }

                // Always release the in-flight slot on completion.
                infl.lock().await.remove(&(la.port(), ra));
            });

            // Stagger the next spawn.
            tokio::time::sleep(std::time::Duration::from_millis(stagger_ms)).await;
        }

        // Drop cancel_tx to signal all remaining spawned tasks to stop.
        drop(cancel_tx);

        if let Some(stream) = stream_result.lock().await.take() {
            tracing::info!("TSO connected, starting handshake");
            return tso_handshake(stream, peer_id, &self.crypto, &self.peer_id, 15).await;
        }

        Err(TransportError::Connect("TSO timeout".into()))
    }
}

// ── Free functions ──

/// Try a single QUIC connection attempt. Uses a pre-existing endpoint
/// (cheaply cloned from Transport's endpoint) instead of creating a new one.
async fn try_quic(
    addr: SocketAddr, noise_pubkey: [u8; 32], crypto: Arc<dyn CryptoProvider>, my_id: PeerId,
    endpoint: quinn::Endpoint,
) -> Result<(PeerId, quinn::Connection, Option<[u8; 32]>), TransportError> {
    let client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(lain_core::KEEP_ALIVE_SECS)));
    let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
            .map_err(|e| TransportError::Io(e.to_string()))?
    ));
    quic_cfg.transport_config(Arc::new(transport_config));

    let conn = endpoint.connect_with(quic_cfg, addr, "lain")
        .map_err(|e| TransportError::Connect(e.to_string()))?
        .await
        .map_err(|e| TransportError::Connect(e.to_string()))?;

    let (mut send, mut recv) = conn.open_bi().await
        .map_err(|e| TransportError::Connect(e.to_string()))?;

    let mut noise = crypto.new_initiator(&noise_pubkey)
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    let ik1 = noise.write_message(&my_id)
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    send.write_all(&encode_handshake_frame(0, &ik1)).await
        .map_err(|e| TransportError::Io(e.to_string()))?;

    let mut header = [0u8; 8];
    recv.read_exact(&mut header).await
        .map_err(|e| TransportError::Connect(e.to_string()))?;
    let hdr = parse_frame_header(&header)
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    if hdr.payload_len > 65536 {
        return Err(TransportError::Noise("ik2 payload too large".into()));
    }
    let mut payload = vec![0u8; hdr.payload_len];
    if hdr.payload_len > 0 {
        recv.read_exact(&mut payload).await
            .map_err(|e| TransportError::Connect(e.to_string()))?;
    }
    let pid = noise.read_message(&payload)
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    let verified_pk = noise.remote_pubkey();
    // Snow requires into_transport_mode to finalize the handshake,
    // even though QUIC handles encryption after this point.
    let _sess = noise.into_transport()
        .map_err(|e| TransportError::Noise(e.to_string()))?;

    let (mut ctrl, _) = conn.open_bi().await
        .map_err(|e| TransportError::Connect(e.to_string()))?;
    ctrl.write_all(&frame::encode_frame(1, FrameType::Headers, b"{}")).await.ok();
    ctrl.finish().ok();
    Ok((pid, conn, verified_pk))
}

async fn tso_handshake(
    mut stream: tokio::net::TcpStream,
    peer_id: PeerId,
    crypto: &Arc<dyn CryptoProvider>,
    my_id: &PeerId,
    keepalive_secs: u64,
) -> Result<Box<dyn Connection>, TransportError> {
    let our_pk = crypto.local_pubkey();
    let mut info = [0u8; 64];
    info[..32].copy_from_slice(&my_id.0);
    info[32..].copy_from_slice(&our_pk);
    tokio::time::timeout(std::time::Duration::from_secs(15), stream.write_all(&info)).await
        .map_err(|_| TransportError::Connect("tso_handshake timeout sending identity".into()))?
        .map_err(|e| TransportError::Io(e.to_string()))?;

    let mut their_info = [0u8; 64];
    tokio::time::timeout(std::time::Duration::from_secs(15), stream.read_exact(&mut their_info)).await
        .map_err(|_| TransportError::Connect("tso_handshake timeout reading peer info".into()))?
        .map_err(|e| TransportError::Io(e.to_string()))?;

    let their_id = PeerId(match <[u8; 32]>::try_from(&their_info[..32]) {
        Ok(id) => id,
        Err(_) => return Err(TransportError::Connect("invalid peer info".into())),
    });
    let their_pk: &[u8; 32] = match <&[u8; 32]>::try_from(&their_info[32..]) {
        Ok(pk) => pk,
        Err(_) => return Err(TransportError::Connect("invalid peer info".into())),
    };
    let we_init = my_id.0 < their_id.0;

    let mut noise: Box<dyn NoiseHandshake> = if we_init {
        crypto.new_initiator(their_pk)
            .map_err(|e| TransportError::Noise(e.to_string()))?
    } else {
        crypto.new_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?
    };

    let remote_id = if we_init {
        let ik1 = noise.write_message(my_id)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        stream.write_all(&encode_handshake_frame(0, &ik1)).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let mut header = [0u8; 8];
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut header)).await
            .map_err(|_| TransportError::Connect("tso_handshake timeout reading ik2 header".into()))?
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let h = parse_frame_header(&header)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        if h.payload_len > 65536 {
            return Err(TransportError::Noise("ik2 payload too large".into()));
        }
        let mut payload = vec![0u8; h.payload_len];
        if h.payload_len > 0 {
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut payload)).await
                .map_err(|_| TransportError::Connect("tso_handshake timeout reading ik2 payload".into()))?
                .map_err(|e| TransportError::Io(e.to_string()))?;
        }
        noise.read_message(&payload)
            .map_err(|e| TransportError::Noise(e.to_string()))?
    } else {
        let mut header = [0u8; 8];
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut header)).await
            .map_err(|_| TransportError::Connect("tso_handshake timeout reading ik1 header".into()))?
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let h = parse_frame_header(&header)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        if h.payload_len > 65536 {
            return Err(TransportError::Noise("ik1 payload too large".into()));
        }
        let mut payload = vec![0u8; h.payload_len];
        if h.payload_len > 0 {
            tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut payload)).await
                .map_err(|_| TransportError::Connect("tso_handshake timeout reading ik1 payload".into()))?
                .map_err(|e| TransportError::Io(e.to_string()))?;
        }
        let rid = noise.read_message(&payload)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let ik2 = noise.write_message(my_id)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        stream.write_all(&encode_handshake_frame(0, &ik2)).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        rid
    };
    if remote_id != peer_id {
        return Err(TransportError::Connect("peer_id mismatch".into()));
    }

    let session = noise.into_transport()
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    Ok(Box::new(TcpConnection::new(stream, session, remote_id, keepalive_secs).await))
}

// ── Helpers ──

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

// ── PeekConnection: wrap a Connection, buffer the first recv'd message ──

pub struct PeekConnection {
    inner: Arc<dyn Connection>,
    peek: Mutex<Option<Vec<u8>>>,
}

impl PeekConnection {
    pub fn new(inner: Box<dyn Connection>, first: Vec<u8>) -> Self {
        Self { inner: Arc::from(inner), peek: Mutex::new(Some(first)) }
    }

    /// Take ownership of the inner connection (consuming the peek buffer).
    pub fn into_inner(self) -> Arc<dyn Connection> { self.inner }
}

#[async_trait::async_trait]
impl Connection for PeekConnection {
    fn peer_id(&self) -> PeerId { self.inner.peer_id() }
    fn noise_pubkey(&self) -> Option<[u8; 32]> { self.inner.noise_pubkey() }
    fn path(&self) -> PathType { self.inner.path() }
    fn rtt_ms(&self) -> Option<u64> { self.inner.rtt_ms() }

    async fn send(&self, ft: FrameType, data: &[u8]) -> Result<(), CoreError> { self.inner.send(ft, data).await }
    fn close(&self) { self.inner.close() }

    async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError> {
        if let Some(data) = self.peek.lock().await.take() {
            return Ok((FrameType::Data, data));
        }
        self.inner.recv().await
    }
}

// ── Trait impl ──

#[async_trait::async_trait]
impl TransportTrait for Transport {
    async fn connect(&self, peer_id: PeerId, noise_pubkey: &[u8; 32], endpoints: &[Endpoint]) -> Result<Box<dyn Connection>, CoreError> {
        Transport::connect(self, peer_id, noise_pubkey, endpoints).await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn connect_tso(&self, peer_id: PeerId, tso_endpoints: &[SocketAddr], port_delta: Option<u16>, stun_rtt_ms: Option<u64>, mappable_port_start: u16, mappable_port_end: u16, predictor: std::sync::Arc<dyn lain_core::PortPredictor>) -> Result<Box<dyn Connection>, CoreError> {
        Transport::connect_tso(self, peer_id, tso_endpoints, port_delta, stun_rtt_ms, mappable_port_start, mappable_port_end, predictor).await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn accept(&self) -> Result<Box<dyn Connection>, CoreError> {
        Transport::accept(self).await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    fn local_addr(&self) -> Result<SocketAddr, CoreError> {
        Transport::local_addr(self)
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use lain_core::peer::PeerId;

    struct MockConnection {
        pid: PeerId,
        messages: tokio::sync::Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Connection for MockConnection {
        fn peer_id(&self) -> PeerId { self.pid }
        fn path(&self) -> PathType { PathType::Direct }
        async fn send(&self, _ft: FrameType, _data: &[u8]) -> Result<(), CoreError> { Ok(()) }
        fn close(&self) {}

        async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError> {
            let mut msgs = self.messages.lock().await;
            if msgs.is_empty() {
                return Err(CoreError::InvalidEndpoint("no more messages".into()));
            }
            Ok((FrameType::Data, msgs.remove(0)))
        }
    }

    #[tokio::test]
    async fn peek_returns_buffered_first() {
        let data = vec![b"first".to_vec(), b"second".to_vec()];
        let inner = Box::new(MockConnection { pid: PeerId([1u8; 32]), messages: tokio::sync::Mutex::new(data) }) as Box<dyn Connection>;
        let peek = PeekConnection::new(inner, b"buffered".to_vec());

        // First recv returns the buffered message
        assert_eq!(peek.recv().await.unwrap(), (FrameType::Data, b"buffered".to_vec()));
        // Second recv delegates to inner
        assert_eq!(peek.recv().await.unwrap(), (FrameType::Data, b"first".to_vec()));
        // Third recv delegates to inner
        assert_eq!(peek.recv().await.unwrap(), (FrameType::Data, b"second".to_vec()));
        // Fourth recv fails (no more messages)
        assert!(peek.recv().await.is_err());
    }

    #[tokio::test]
    async fn peek_delegates_send_close_and_metadata() {
        let inner = Box::new(MockConnection { pid: PeerId([2u8; 32]), messages: tokio::sync::Mutex::new(vec![]) }) as Box<dyn Connection>;
        let peek = PeekConnection::new(inner, b"x".to_vec());

        assert_eq!(peek.peer_id(), PeerId([2u8; 32]));
        assert_eq!(peek.path(), PathType::Direct);
        assert!(peek.send(FrameType::Data, b"test").await.is_ok());
        peek.close();
    }

    #[tokio::test]
    async fn peek_into_inner_recovers_arc() {
        let inner = Box::new(MockConnection { pid: PeerId([3u8; 32]), messages: tokio::sync::Mutex::new(vec![b"data".to_vec()]) }) as Box<dyn Connection>;
        let peek = PeekConnection::new(inner, b"x".to_vec());
        let recovered = peek.into_inner();
        assert_eq!(recovered.recv().await.unwrap(), (FrameType::Data, b"data".to_vec()));
    }
}
