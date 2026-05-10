#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::identity::Ed25519PublicKey;
use lain_core::peer::PeerId;
use lain_core::transport::{Connection as CoreConn, IncomingConnection, PathType, TransportLayer};
use lain_core::error::CoreError;
use lain_noise::{NoiseHandshake, encode_handshake_frame, parse_frame_header};
use sha2::Digest;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
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

    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint.local_addr()
            .map_err(|e| TransportError::Io(format!("local_addr: {e}")))
    }

    pub async fn accept_incoming(&self) -> Result<IncomingConnection, TransportError> {
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
        let n = recv.read(&mut buf).await
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
        send.finish().ok();

        let remote_pk = noise.remote_pubkey().unwrap_or([0u8; 32]);
        let _session = noise.into_transport()
            .map_err(|e| TransportError::Noise(format!("transport: {e}")))?;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&remote_pk);
        let hash = hasher.finalize();
        let mut pid = [0u8; 32];
        pid.copy_from_slice(&hash);

        Ok(IncomingConnection {
            peer_id: PeerId(pid),
            peer_pubkey: remote_pk,
            stream: lain_core::transport::QuicStream,
        })
    }

    async fn connect_internal(
        &self,
        peer_id: &PeerId,
        remote_pubkey: &Ed25519PublicKey,
        endpoints: &[Endpoint],
    ) -> Result<(CoreConn, PathType), TransportError> {
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
                Ok(Ok(conn)) => {
                    tracing::info!("connected {peer_id} via {path:?}");
                    return Ok((conn, path));
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
        _path: PathType,
        client_cfg: &quinn::ClientConfig,
    ) -> Result<CoreConn, TransportError> {
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

        self.connections.lock().await.insert(*peer_id, PeerConnection {
            _quic: conn,
            _noise: session,
        });

        Ok(CoreConn {
            peer_id: *peer_id,
            peer_pubkey: *remote_pubkey,
            stream: lain_core::transport::QuicStream,
            datagram: lain_core::transport::QuicDatagramSender,
        })
    }

    /// 处理 relay 请求，连接到目标 peer 并启动数据转发
    pub async fn handle_relay_request(
        &self,
        _requester_conn: quinn::Connection,
        target_peer_id: PeerId,
    ) -> Result<(), TransportError> {
        tracing::info!("relay: forwarding to target {target_peer_id}");
        // Full implementation requires:
        // 1. Query DHT for target's endpoints
        // 2. Connect to target via try_path
        // 3. Pipe data between the two connections
        // For now, plumbing is ready but data relay needs target endpoint info
        Err(TransportError::Connect(format!("relay target {target_peer_id}: not yet connected")))
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
            .map(|(c, _)| c)
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
