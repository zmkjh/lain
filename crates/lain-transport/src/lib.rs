#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::crypto::{CryptoProvider, NoiseHandshake, NoiseTransport};
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::error::CoreError;
use lain_core::frame::{self, encode_handshake_frame, parse_handshake_frame_header as parse_frame_header, FrameType};
use lain_core::peer::PeerId;
use lain_core::transport::{Connection, PathType, Transport as TransportTrait};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

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
}

#[async_trait::async_trait]
impl Connection for QuicConnection {
    fn peer_id(&self) -> PeerId { self.peer_id }
    fn path(&self) -> PathType { PathType::Direct }

    async fn send(&self, data: &[u8]) -> Result<(), CoreError> {
        let msg = frame::encode_frame(2, FrameType::Data, data);
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
            let data = recv.read_to_end(4 * 65536).await
                .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
            if data.is_empty() { continue; }
            if let Some((_, ft, plen, hlen)) = frame::decode_frame_header(&data) {
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
    stream: Mutex<tokio::net::TcpStream>,
    noise: Mutex<Box<dyn NoiseTransport>>,
}

struct TcpConnection {
    peer_id: PeerId,
    inner: Arc<TcpInner>,
}

impl TcpConnection {
    async fn new(
        stream: tokio::net::TcpStream,
        noise: Box<dyn NoiseTransport>,
        peer_id: PeerId,
        keepalive_secs: u64,
    ) -> Self {
        let inner = Arc::new(TcpInner {
            stream: Mutex::new(stream),
            noise: Mutex::new(noise),
        });
        let ka = inner.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(keepalive_secs));
            loop {
                interval.tick().await;
                let ct = {
                    let mut n = ka.noise.lock().await;
                    match n.encrypt(b"") { Ok(c) => c, Err(_) => break }
                };
                let frame = encode_handshake_frame(0, &ct);
                let mut s = ka.stream.lock().await;
                if s.write_all(&frame).await.is_err() { break; }
            }
        });
        Self { peer_id, inner }
    }
}

#[async_trait::async_trait]
impl Connection for TcpConnection {
    fn peer_id(&self) -> PeerId { self.peer_id }
    fn path(&self) -> PathType { PathType::TSO }

    async fn send(&self, data: &[u8]) -> Result<(), CoreError> {
        let mut noise = self.inner.noise.lock().await;
        let mut stream = self.inner.stream.lock().await;
        let ct = noise.encrypt(data)?;
        let frame = encode_handshake_frame(0, &ct);
        stream.write_all(&frame).await
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))
    }

    async fn recv(&self) -> Result<(FrameType, Vec<u8>), CoreError> {
        loop {
            let mut header = [0u8; 8];
            { let mut s = self.inner.stream.lock().await;
              s.read_exact(&mut header).await
                .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?; }
            let plen = ((header[5] as usize) << 16) | ((header[6] as usize) << 8) | (header[7] as usize);
            let mut payload = vec![0u8; plen];
            if plen > 0 {
                let mut s = self.inner.stream.lock().await;
                s.read_exact(&mut payload).await
                    .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
            }
            let data = { let mut n = self.inner.noise.lock().await; n.decrypt(&payload)? };
            if data.is_empty() { continue; }
            return Ok((FrameType::Data, data));
        }
    }

    fn close(&self) {}
}

// ── Transport ──

pub struct TransportConfig {
    pub bind_addr: SocketAddr,
    pub has_ipv6: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self { bind_addr: "0.0.0.0:0".parse().unwrap(), has_ipv6: false }
    }
}

pub struct Transport {
    endpoint: quinn::Endpoint,
    crypto: Arc<dyn CryptoProvider>,
    peer_id: PeerId,
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

        Ok(Self { endpoint, crypto, peer_id })
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

        let mut buf = vec![0u8; 4096];
        let n = recv.read(&mut buf).await
            .map_err(|e| TransportError::Connect(e.to_string()))?
            .ok_or_else(|| TransportError::Noise("no ik1".into()))?;

        let hdr = parse_frame_header(&buf[..n])
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let mut noise = self.crypto.new_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let remote_id = noise.read_message(&buf[8..8 + hdr.payload_len.min(n - 8)])
            .map_err(|e| TransportError::Noise(e.to_string()))?;

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

        Ok(Box::new(QuicConnection { peer_id: remote_id, quic: conn }))
    }

    pub async fn connect(
        &self,
        _peer_id: PeerId,
        noise_pubkey: &[u8; 32],
        endpoints: &[Endpoint],
    ) -> Result<Box<dyn Connection>, TransportError> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Box<dyn Connection>, TransportError>>(4);

        for ep in endpoints {
            if !matches!(ep.kind, EndpointKind::IPv6 | EndpointKind::STUN) { continue; }
            let tx = tx.clone(); let addr = ep.addr;
            let npk = *noise_pubkey; let cry = self.crypto.clone(); let my = self.peer_id;
            let qep = self.endpoint.clone();
            tokio::spawn(async move {
                let r = try_quic(addr, npk, cry, my, qep).await;
                tx.send(r.map(|(pid, q)| Box::new(QuicConnection { peer_id: pid, quic: q }) as Box<dyn Connection>)).await.ok();
            });
        }
        drop(tx);

        let deadline = tokio::time::sleep(std::time::Duration::from_secs(lain_core::TRAVERSAL_TIMEOUT_SECS));
        tokio::pin!(deadline);
        while let Some(r) = tokio::select! { r = rx.recv() => r, _ = &mut deadline => None } {
            if let Ok(c) = r { return Ok(c); }
        }
        Err(TransportError::NoPath)
    }

    pub async fn connect_tso(
        &self,
        peer_id: PeerId,
        tso_endpoints: &[SocketAddr],
        port_delta: Option<u16>,
        stun_rtt_ms: Option<u64>,
    ) -> Result<Box<dyn Connection>, TransportError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(102);
        let bind_ip = self.endpoint.local_addr()
            .map(|a| a.ip()).unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        let is_pp = port_delta == Some(1);
        let rtt = stun_rtt_ms.unwrap_or(200);
        let ports: u16 = if is_pp { 4 } else { 8 };
        let per_attempt = if rtt < 100 { 200 } else if rtt < 300 { 400 } else { 600 };
        let inter_round = if is_pp { 200 } else { 300 };

        while std::time::Instant::now() < deadline {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<tokio::net::TcpStream>(1);
            for i in 0..ports {
                let la = SocketAddr::new(bind_ip, 50000 + i);
                for &ra in tso_endpoints {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let s = if ra.is_ipv4() {
                            tokio::net::TcpSocket::new_v4()
                        } else {
                            tokio::net::TcpSocket::new_v6()
                        };
                        if let Ok(s) = s {
                            s.set_reuseaddr(true).ok();
                            if s.bind(la).is_ok() {
                                if let Ok(Ok(s)) = tokio::time::timeout(
                                    std::time::Duration::from_millis(per_attempt), s.connect(ra),
                                ).await { tx.send(s).await.ok(); }
                            }
                        }
                    });
                }
            }
            drop(tx);
            if let Some(stream) = rx.recv().await {
                return tso_handshake(stream, peer_id, &self.crypto, &self.peer_id, 15).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(inter_round)).await;
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
) -> Result<(PeerId, quinn::Connection), TransportError> {
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

    let mut buf = vec![0u8; 4096];
    let n = recv.read(&mut buf).await
        .map_err(|e| TransportError::Connect(e.to_string()))?
        .ok_or_else(|| TransportError::Noise("no ik2".into()))?;
    let hdr = parse_frame_header(&buf[..n])
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    let pid = noise.read_message(&buf[8..8 + hdr.payload_len.min(n - 8)])
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    // Snow requires into_transport_mode to finalize the handshake,
    // even though QUIC handles encryption after this point.
    let _sess = noise.into_transport()
        .map_err(|e| TransportError::Noise(e.to_string()))?;

    let (mut ctrl, _) = conn.open_bi().await
        .map_err(|e| TransportError::Connect(e.to_string()))?;
    ctrl.write_all(&frame::encode_frame(1, FrameType::Headers, b"{}")).await.ok();
    ctrl.finish().ok();
    Ok((pid, conn))
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
    stream.write_all(&info).await
        .map_err(|e| TransportError::Io(e.to_string()))?;

    let mut their_info = [0u8; 64];
    stream.read_exact(&mut their_info).await
        .map_err(|e| TransportError::Io(e.to_string()))?;

    let their_id = PeerId(their_info[..32].try_into().unwrap_or([0u8; 32]));
    let their_pk: &[u8; 32] = their_info[32..].try_into().unwrap_or(&[0u8; 32]);
    let we_init = my_id.0 < their_id.0;

    let mut noise: Box<dyn NoiseHandshake> = if we_init {
        crypto.new_initiator(their_pk)
            .map_err(|e| TransportError::Noise(e.to_string()))?
    } else {
        crypto.new_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?
    };

    if we_init {
        let ik1 = noise.write_message(my_id)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        stream.write_all(&encode_handshake_frame(0, &ik1)).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let h = parse_frame_header(&buf[..n])
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        noise.read_message(&buf[8..8 + h.payload_len.min(n - 8)])
            .map_err(|e| TransportError::Noise(e.to_string()))?;
    } else {
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let h = parse_frame_header(&buf[..n])
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        noise.read_message(&buf[8..8 + h.payload_len.min(n - 8)])
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        let ik2 = noise.write_message(my_id)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        stream.write_all(&encode_handshake_frame(0, &ik2)).await
            .map_err(|e| TransportError::Io(e.to_string()))?;
    }

    let session = noise.into_transport()
        .map_err(|e| TransportError::Noise(e.to_string()))?;
    Ok(Box::new(TcpConnection::new(stream, session, peer_id, keepalive_secs).await))
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
    fn path(&self) -> PathType { self.inner.path() }
    fn rtt_ms(&self) -> Option<u64> { self.inner.rtt_ms() }

    async fn send(&self, data: &[u8]) -> Result<(), CoreError> { self.inner.send(data).await }
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

    async fn connect_tso(&self, peer_id: PeerId, tso_endpoints: &[SocketAddr], port_delta: Option<u16>, stun_rtt_ms: Option<u64>) -> Result<Box<dyn Connection>, CoreError> {
        Transport::connect_tso(self, peer_id, tso_endpoints, port_delta, stun_rtt_ms).await
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
        async fn send(&self, _data: &[u8]) -> Result<(), CoreError> { Ok(()) }
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
        assert!(peek.send(b"test").await.is_ok());
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
