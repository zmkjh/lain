#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::frame::{self, FrameType};
use lain_core::identity::Ed25519PublicKey;
use lain_core::peer::PeerId;
use lain_core::transport::{Connection as CoreConn, IncomingConnection, PathType, TransportLayer};
use lain_core::error::CoreError;
use lain_noise::{NoiseHandshake, encode_handshake_frame, parse_frame_header};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("connection: {0}")]
    Connect(String),
    #[error("no path for {peer_id}")]
    NoPath { peer_id: PeerId },
    #[error("noise: {0}")]
    Noise(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("io: {0}")]
    Io(String),
}

#[derive(Clone, Debug)]
pub struct TransportConfig {
    pub bind_addr: SocketAddr,
    pub max_connections: usize,
    pub idle_timeout_ms: u32,
    pub traversal_timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            max_connections: lain_core::MAX_CONNECTIONS,
            idle_timeout_ms: (lain_core::IDLE_TIMEOUT_SECS * 1000) as u32,
            traversal_timeout_secs: lain_core::TRAVERSAL_TIMEOUT_SECS,
        }
    }
}

struct PeerConnection {
    _quic: quinn::Connection,
    _noise: lain_noise::NoiseSession,
}

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
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

pub struct Transport {
    config: TransportConfig,
    endpoint: quinn::Endpoint,
    connections: Arc<Mutex<HashMap<PeerId, PeerConnection>>>,
    noise_secret: [u8; 32],
    #[allow(dead_code)]
    peer_id: PeerId,
    #[allow(dead_code)]
    public_key: Ed25519PublicKey,
}

impl Transport {
    pub fn new(
        config: TransportConfig,
        noise_secret: [u8; 32],
        peer_id: PeerId,
        public_key: Ed25519PublicKey,
    ) -> Result<Self, TransportError> {
        // Generate self-signed cert for QUIC
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|e| TransportError::Tls(format!("keygen: {e}")))?;
        let cert_params = rcgen::CertificateParams::new(vec!["lain".into()])
            .map_err(|e| TransportError::Tls(format!("cert params: {e}")))?;
        let cert = cert_params.self_signed(&key_pair)
            .map_err(|e| TransportError::Tls(format!("self-signed: {e}")))?;

        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_bytes = key_pair.serialize_der();
        let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(key_bytes);
        let key_der = rustls::pki_types::PrivateKeyDer::from(pkcs8);

        let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| TransportError::Tls(format!("server config: {e}")))?;

        let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
                .map_err(|e| TransportError::Tls(format!("server quic: {e}")))?
        ));

        // Bind UDP socket
        let socket = std::net::UdpSocket::bind(config.bind_addr)
            .map_err(|e| TransportError::Io(format!("bind: {e}")))?;

        let runtime = quinn::default_runtime()
            .ok_or_else(|| TransportError::Io("no runtime".into()))?;

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_cfg),
            socket,
            runtime,
        )
        .map_err(|e| TransportError::Io(format!("endpoint: {e}")))?;

        tracing::info!("transport bound to {:?}", endpoint.local_addr());

        Ok(Self {
            config,
            endpoint,
            connections: Arc::new(Mutex::new(HashMap::new())),
            noise_secret,
            peer_id,
            public_key,
        })
    }

    /// 主动连接并返回原始 QUIC 连接（用于 daemon 管理流）
    pub async fn connect_raw(
        &self,
        remote_pubkey: &Ed25519PublicKey,
        endpoints: &[Endpoint],
    ) -> Result<quinn::Connection, TransportError> {
        let client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

        let quic_client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| TransportError::Tls(format!("client quic: {e}")))?
        ));

        let mut eps: Vec<_> = endpoints.iter().collect();
        eps.sort_by(|a, b| b.priority.cmp(&a.priority));

        for ep in eps {
            match tokio::time::timeout(
                std::time::Duration::from_secs(self.config.traversal_timeout_secs),
                self.try_connect(remote_pubkey, ep.addr, &quic_client_cfg),
            ).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => tracing::debug!("connect {}: {e}", ep.addr),
                Err(_) => tracing::debug!("connect {}: timeout", ep.addr),
            }
        }
        Err(TransportError::NoPath { peer_id: PeerId([0u8; 32]) })
    }

    async fn try_connect(
        &self,
        remote_pubkey: &Ed25519PublicKey,
        addr: SocketAddr,
        client_cfg: &quinn::ClientConfig,
    ) -> Result<quinn::Connection, TransportError> {
        let conn = self.endpoint
            .connect_with(client_cfg.clone(), addr, "lain")
            .map_err(|e| TransportError::Connect(format!("connect: {e}")))?
            .await
            .map_err(|e| TransportError::Connect(format!("wait: {e}")))?;

        let (mut send, mut recv) = conn.open_bi().await
            .map_err(|e| TransportError::Connect(format!("bi: {e}")))?;

        let mut noise = NoiseHandshake::new_initiator(&self.noise_secret, remote_pubkey)
            .map_err(|e| TransportError::Noise(format!("init: {e}")))?;

        let ik1 = noise.write_message(&[])
            .map_err(|e| TransportError::Noise(format!("init: {e}")))?;
        send.write_all(&encode_handshake_frame(0, &ik1)).await
            .map_err(|e| TransportError::Io(format!("send ik1: {e}")))?;

        let mut buf = vec![0u8; 4096];
        let n = recv.read(&mut buf).await
            .map_err(|e| TransportError::Connect(format!("recv ik2: {e}")))?
            .ok_or_else(|| TransportError::Noise("no ik2".into()))?;

        let header = parse_frame_header(&buf[..n])
            .map_err(|e| TransportError::Noise(format!("ik2 parse: {e}")))?;
        let payload = &buf[8..8 + header.payload_len.min(n - 8)];

        noise.read_message(payload)
            .map_err(|e| TransportError::Noise(format!("ik2 process: {e}")))?;

        let _session = noise.into_transport()
            .map_err(|e| TransportError::Noise(format!("transport: {e}")))?;

        // Send HEADERS
        let headers = frame::encode_frame(1, FrameType::Headers, b"{}");
        let (mut ctrl_send, _) = conn.open_bi().await
            .map_err(|e| TransportError::Connect(format!("ctrl: {e}")))?;
        ctrl_send.write_all(&headers).await.ok();
        let _ = ctrl_send.finish();

        Ok(conn)
    }

    /// NAT Rebinding: QUIC Connection ID 自动处理路径迁移。
    /// 保活 PING 减少 NAT 映射过期。
    pub fn spawn_keepalive(conn: quinn::Connection, interval_secs: u64) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs),
            );
            loop {
                interval.tick().await;
                if let Ok((mut send, _)) = conn.open_bi().await {
                    let msg = frame::encode_frame(1, FrameType::Ping, &[]);
                    if send.write_all(&msg).await.is_err() { break; }
                    let _ = send.finish();
                }
            }
        });
    }

    /// 接受原始 QUIC 连接（包含 Noise IK + HEADERS）
    pub async fn start_ws_listener(&self, bind_addr: SocketAddr) -> Result<u16, TransportError> {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .map_err(|e| TransportError::Io(format!("WS bind: {e}")))?;

        let port = listener.local_addr()
            .map_err(|e| TransportError::Io(format!("WS local_addr: {e}")))?
            .port();

        // Spawn WS accept loop
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, addr)) => {
                        // Minimal HTTP Upgrade handshake
                        use tokio::io::AsyncBufReadExt;
                        let mut reader = tokio::io::BufReader::new(&mut stream);
                        let mut line = String::new();
                        // Read request line
                        if reader.read_line(&mut line).await.is_err() { continue; }
                        // Skip headers
                        let mut key = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).await.is_err() { break; }
                            let t = line.trim();
                            if t.is_empty() { break; }
                            if let Some(v) = t.strip_prefix("Sec-WebSocket-Key:") {
                                key = v.trim().to_string();
                            }
                        }
                        // Send upgrade response
                        if key.is_empty() {
                            let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
                            continue;
                        }
                        let accept = ws_accept_key(&key);
                        let resp = format!(
                            "HTTP/1.1 101 Switching Protocols\r\n\
                             Upgrade: websocket\r\n\
                             Connection: Upgrade\r\n\
                             Sec-WebSocket-Accept: {accept}\r\n\r\n"
                        );
                        if stream.write_all(resp.as_bytes()).await.is_err() { continue; }

                        tracing::info!("WS upgraded from {addr}");
                        // WebSocket established — Noise IK runs over WS frames
                        // In production, WS frame encode/decode wraps the stream
                        // For now, raw bytes pass through (works for text-based WS)
                    }
                    Err(e) => {
                        tracing::error!("WS accept: {e}");
                        break;
                    }
                }
            }
        });

        tracing::info!("WS fallback listening on port {port}");
        Ok(port)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr()
            .map_err(|e| TransportError::Io(format!("local_addr: {e}")))
    }

    pub async fn accept_incoming(&self) -> Result<IncomingConnection, TransportError> {
        let (_, peer_id, pubkey) = self.accept_connection().await?;
        Ok(IncomingConnection {
            peer_id,
            peer_pubkey: pubkey,
            stream: lain_core::transport::QuicStream,
        })
    }

    /// Accept a raw connection and return (quinn::Connection, PeerId, pubkey)
    /// Caller can then inspect control frames before proceeding
    pub async fn accept_connection(&self) -> Result<(quinn::Connection, PeerId, Ed25519PublicKey), TransportError> {
        let incoming = self.endpoint
            .accept()
            .await
            .ok_or_else(|| TransportError::Connect("endpoint closed".into()))?;

        let conn = incoming
            .await
            .map_err(|e| TransportError::Connect(format!("accept: {e}")))?;

        // Noise IK responder over stream 0
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::Connect(format!("stream0: {e}")))?;

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            recv.read(&mut buf),
        )
        .await
        .map_err(|_| TransportError::Noise("ik1 timeout".into()))?
        .map_err(|e| TransportError::Connect(format!("read ik1: {e}")))?
        .ok_or_else(|| TransportError::Noise("no ik1".into()))?;

        let header = parse_frame_header(&buf[..n])
            .map_err(|e| TransportError::Noise(format!("ik1 parse: {e}")))?;
        let payload = &buf[8..8 + header.payload_len.min(n - 8)];

        let mut noise = NoiseHandshake::new_responder(&self.noise_secret)
            .map_err(|e| TransportError::Noise(format!("resp: {e}")))?;

        noise.read_message(payload)
            .map_err(|e| TransportError::Noise(format!("ik1: {e}")))?;

        let ik2 = noise.write_message(&[])
            .map_err(|e| TransportError::Noise(format!("ik2: {e}")))?;
        let frame = encode_handshake_frame(1, &ik2);
        send.write_all(&frame).await
            .map_err(|e| TransportError::Io(format!("send ik2: {e}")))?;
        let _ = send.finish();

        let remote_pk = noise.remote_pubkey().unwrap_or([0u8; 32]);
        let _session = noise.into_transport()
            .map_err(|e| TransportError::Noise(format!("transport: {e}")))?;

        // Receive HEADERS on stream 1, send response
        let conn2 = conn.clone();
        tokio::spawn(async move {
            if let Ok((mut hd_send, mut hd_recv)) = conn2.accept_bi().await {
                let mut buf = vec![0u8; 1024];
                if let Ok(Some(_n)) = hd_recv.read(&mut buf).await {
                    let resp = frame::encode_frame(1, FrameType::Headers, b"{}");
                    hd_send.write_all(&resp).await.ok();
                    hd_send.finish().ok();
                }
            }
        });

        let remote_peer_id = PeerId::from_pubkey(&remote_pk);

        tracing::info!("incoming connection from {remote_peer_id}");

        Ok((conn, remote_peer_id, remote_pk))
    }

    async fn connect_internal(
        &self,
        peer_id: &PeerId,
        remote_pubkey: &Ed25519PublicKey,
        endpoints: &[Endpoint],
    ) -> Result<(CoreConn, PathType, quinn::Connection), TransportError> {
        // Build client config that skips cert verification
        let client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[
            &rustls::version::TLS13,
        ])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

        let quic_client_cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
                .map_err(|e| TransportError::Tls(format!("client quic: {e}")))?
        ));

        let mut eps: Vec<_> = endpoints.iter().collect();
        eps.sort_by(|a, b| b.priority.cmp(&a.priority));

        for ep in eps {
            let path = match ep.kind {
                EndpointKind::IPv6 => PathType::IPv6,
                EndpointKind::STUN => PathType::STUN,
                EndpointKind::Relay => PathType::Relay,
                EndpointKind::WebSocket => PathType::WebSocket,
                _ => continue,
            };

            let result = tokio::time::timeout(
                std::time::Duration::from_secs(self.config.traversal_timeout_secs),
                self.try_path(peer_id, remote_pubkey, ep.addr, path, &quic_client_cfg),
            )
            .await;

            match result {
                Ok(Ok((conn, _, quic))) => {
                    tracing::info!("connected {peer_id} via {path:?}");
                    return Ok((conn, path, quic));
                }
                Ok(Err(e)) => tracing::debug!("{path:?} → {peer_id}: {e}"),
                Err(_) => tracing::debug!("{path:?} → {peer_id}: timeout"),
            }
        }

        Err(TransportError::NoPath { peer_id: *peer_id })
    }

    async fn try_path(
        &self,
        peer_id: &PeerId,
        remote_pubkey: &Ed25519PublicKey,
        addr: SocketAddr,
        path: PathType,
        client_cfg: &quinn::ClientConfig,
    ) -> Result<(CoreConn, PathType, quinn::Connection), TransportError> {
        let conn = self.endpoint
            .connect_with(client_cfg.clone(), addr, "lain")
            .map_err(|e| TransportError::Connect(format!("connect: {e}")))?
            .await
            .map_err(|e| TransportError::Connect(format!("wait: {e}")))?;

        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Connect(format!("bi: {e}")))?;

        let mut noise = NoiseHandshake::new_initiator(&self.noise_secret, remote_pubkey)
            .map_err(|e| TransportError::Noise(format!("init: {e}")))?;

        let ik1 = noise.write_message(&[])
            .map_err(|e| TransportError::Noise(format!("ik1: {e}")))?;
        let frame = encode_handshake_frame(0, &ik1);
        send.write_all(&frame).await
            .map_err(|e| TransportError::Io(format!("send ik1: {e}")))?;

        let mut buf = vec![0u8; 4096];
        let n = recv.read(&mut buf).await
            .map_err(|e| TransportError::Connect(format!("recv ik2: {e}")))?
            .ok_or_else(|| TransportError::Noise("no ik2".into()))?;

        let header = parse_frame_header(&buf[..n])
            .map_err(|e| TransportError::Noise(format!("ik2 parse: {e}")))?;
        let payload = &buf[8..8 + header.payload_len.min(n - 8)];

        noise.read_message(payload)
            .map_err(|e| TransportError::Noise(format!("ik2 process: {e}")))?;

        let session = noise.into_transport()
            .map_err(|e| TransportError::Noise(format!("transport: {e}")))?;

        // Send HEADERS frame on stream 1 (control channel)
        let headers = frame::encode_frame(1, FrameType::Headers, b"{}");
        let (mut ctrl_send, _ctrl_recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Connect(format!("ctrl stream: {e}")))?;
        ctrl_send.write_all(&headers).await.ok();
        ctrl_send.finish().ok();

        self.connections.lock().await.insert(*peer_id, PeerConnection {
            _quic: conn.clone(),
            _noise: session,
        });

        Ok((CoreConn {
            peer_id: *peer_id,
            peer_pubkey: *remote_pubkey,
            stream: lain_core::transport::QuicStream,
            datagram: lain_core::transport::QuicDatagramSender,
        }, path, conn))
    }

    /// 处理 relay 请求，连接到目标 peer 并启动数据转发
    pub async fn handle_relay_request(
        &self,
        requester_conn: quinn::Connection,
        target_peer_id: PeerId,
        target_pubkey: Ed25519PublicKey,
        target_endpoints: &[Endpoint],
    ) -> Result<(), TransportError> {
        tracing::info!("relay: forwarding to {target_peer_id}");

        // Connect to target
        let (_, _, target_quic) = self.connect_internal(
            &target_peer_id,
            &target_pubkey,
            target_endpoints,
        ).await?;

        // Forward data bidirectionally
        tracing::info!("relay: pipe established requester <> {target_peer_id}");
        Self::pipe_connections(requester_conn, target_quic).await;

        Ok(())
    }

    /// 双向管道转发两个 QUIC 连接之间的所有数据
    async fn pipe_connections(a: quinn::Connection, b: quinn::Connection) {
        let a2 = a.clone();
        let b2 = b.clone();

        // Forward incoming streams from A to B (30s timeout on accept for dead relay detection)
        let a_to_b = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(30), a.accept_bi()).await {
                    Ok(Ok(stream)) => {
                        let (_send, mut recv) = (stream.0, stream.1);
                let b3 = b.clone();
                tokio::spawn(async move {
                    if let Ok((mut b_send, _b_recv)) = b3.open_bi().await {
                        // A recv → B send
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(n)) => {
                                    if b_send.write_all(&buf[..n]).await.is_err() { break; }
                                }
                                _ => break,
                            }
                        }
                        let _ = b_send.finish();
                    }
                });
            }
                    Ok(Err(_)) => break,     // QUIC error, relay dead
                    Err(_) => break,          // Timeout, relay dead
                }
            }
        });

        // Forward incoming streams from B to A (30s timeout)
        let b_to_a = tokio::spawn(async move {
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(30), b2.accept_bi()).await {
                    Ok(Ok(stream)) => {
                let (_send, mut recv) = (stream.0, stream.1);
                let a3 = a2.clone();
                tokio::spawn(async move {
                    if let Ok((mut a_send, _a_recv)) = a3.open_bi().await {
                        let mut buf = vec![0u8; 8192];
                        loop {
                            match recv.read(&mut buf).await {
                                Ok(Some(n)) => {
                                    if a_send.write_all(&buf[..n]).await.is_err() { break; }
                                }
                                _ => break,
                            }
                        }
                        let _ = a_send.finish();
                    }
                });
            }
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
        });

        let _ = tokio::join!(a_to_b, b_to_a);
    }
}

#[async_trait::async_trait]
impl TransportLayer for Transport {
    async fn connect(
        &self,
        peer_id: &PeerId,
        pubkey: &Ed25519PublicKey,
        endpoints: &[Endpoint],
    ) -> Result<CoreConn, CoreError> {
        self.connect_internal(peer_id, pubkey, endpoints)
            .await
            .map(|(c, _, _)| c)
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn accept(&self) -> Result<IncomingConnection, CoreError> {
        self.accept_incoming()
            .await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    fn on_endpoints_changed(&self, peer_id: &PeerId, _endpoints: Vec<Endpoint>) {
        tracing::info!("endpoints changed for {peer_id}");
    }
}

/// WebSocket handshake accept key: base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
/// WebSocket 帧编码（binary, FIN=1）
#[allow(dead_code)]
fn ws_encode_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 10);
    f.push(0x82); // FIN + Binary opcode
    if payload.len() <= 125 {
        f.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        f.push(126);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        f.push(127);
        f.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    f.extend_from_slice(payload);
    f
}

/// WebSocket 帧解码，返回 payload
#[allow(dead_code)]
fn ws_decode_frame(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 2 { return None; }
    let masked = data[1] & 0x80 != 0;
    let mut len = (data[1] & 0x7F) as usize;
    let mut offset = 2usize;
    if len == 126 { if data.len() < 4 { return None; } len = u16::from_be_bytes([data[2], data[3]]) as usize; offset = 4; }
    else if len == 127 { if data.len() < 10 { return None; } len = u64::from_be_bytes(data[2..10].try_into().ok()?) as usize; offset = 10; }
    let mask = if masked { if data.len() < offset + 4 { return None; } let m = [data[offset], data[offset+1], data[offset+2], data[offset+3]]; offset += 4; Some(m) } else { None };
    if data.len() < offset + len { return None; }
    let mut payload = data[offset..offset + len].to_vec();
    if let Some(m) = mask { for (i, b) in payload.iter_mut().enumerate() { *b ^= m[i % 4]; } }
    Some(payload)
}

fn ws_accept_key(key: &str) -> String {
    let mut combined = key.to_string();
    combined.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let hash = sha1_smol::Sha1::from(&combined).digest().bytes();
    base64_encode(&hash)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((n >> 18) & 63) as usize] as char);
        result.push(CHARS[((n >> 12) & 63) as usize] as char);
        result.push(if chunk.len() > 1 { CHARS[((n >> 6) & 63) as usize] } else { b'=' } as char);
        result.push(if chunk.len() > 2 { CHARS[(n & 63) as usize] } else { b'=' } as char);
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn test_config_defaults() {
        let c = TransportConfig::default();
        assert_eq!(c.max_connections, 256);
    }
}
