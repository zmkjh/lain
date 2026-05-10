#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::endpoint::Endpoint;
use lain_core::identity::Ed25519PublicKey;
use lain_core::peer::PeerId;
use lain_core::transport::{Connection, IncomingConnection, PathType, TransportLayer};
use lain_core::error::CoreError;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing;

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("QUIC error: {0}")]
    QuicError(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("no viable path for {peer_id}")]
    NoViablePath { peer_id: PeerId },
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

pub struct TransportConfig {
    pub bind_addr: std::net::SocketAddr,
    pub max_connections: usize,
    pub idle_timeout_secs: u64,
    pub keep_alive_secs: u64,
    pub traversal_timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:0".parse().unwrap_or(([0, 0, 0, 0], 0).into()),
            max_connections: lain_core::MAX_CONNECTIONS,
            idle_timeout_secs: lain_core::IDLE_TIMEOUT_SECS,
            keep_alive_secs: lain_core::KEEP_ALIVE_SECS,
            traversal_timeout_secs: lain_core::TRAVERSAL_TIMEOUT_SECS,
        }
    }
}

pub struct Transport {
    config: TransportConfig,
    pending_connections: Arc<Mutex<Vec<PendingConnection>>>,
}

struct PendingConnection {
    peer_id: PeerId,
    path_type: PathType,
}

impl Transport {
    pub fn new(config: TransportConfig) -> Self {
        Self {
            config,
            pending_connections: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 尝试 Layer 1: IPv6 直连
    async fn try_ipv6_direct(
        &self,
        peer_id: &PeerId,
        endpoints: &[Endpoint],
    ) -> Result<Connection, TransportError> {
        for ep in endpoints {
            if ep.addr.is_ipv6() {
                tracing::debug!("trying IPv6 direct to {peer_id} at {}", ep.addr);
                // In real implementation: QUIC connect
                // For now, placeholder
                let _ = ep;
            }
        }
        Err(TransportError::NoViablePath { peer_id: *peer_id })
    }

    /// 尝试 Layer 2: STUN 打洞
    async fn try_stun_punch(
        &self,
        peer_id: &PeerId,
        endpoints: &[Endpoint],
    ) -> Result<Connection, TransportError> {
        tracing::debug!("trying STUN punch to {peer_id}");
        for ep in endpoints {
            let _ = ep;
        }
        Err(TransportError::NoViablePath { peer_id: *peer_id })
    }

    /// 尝试 Layer 3: P2P Relay
    async fn try_relay(
        &self,
        peer_id: &PeerId,
    ) -> Result<Connection, TransportError> {
        tracing::debug!("trying relay connection to {peer_id}");
        Err(TransportError::NoViablePath { peer_id: *peer_id })
    }
}

#[async_trait::async_trait]
impl TransportLayer for Transport {
    async fn connect(
        &self,
        peer_id: &PeerId,
        pubkey: &Ed25519PublicKey,
        endpoints: &[Endpoint],
    ) -> Result<Connection, CoreError> {
        tracing::info!("connecting to {peer_id}");

        // Layer 1: IPv6 (try first)
        if let Ok(conn) = self.try_ipv6_direct(peer_id, endpoints).await {
            tracing::info!("connected via IPv6 to {peer_id}");
            return Ok(conn);
        }

        // Layer 2: STUN punch
        if let Ok(conn) = self.try_stun_punch(peer_id, endpoints).await {
            tracing::info!("connected via STUN to {peer_id}");
            return Ok(conn);
        }

        // Layer 3: Relay
        if let Ok(conn) = self.try_relay(peer_id).await {
            tracing::info!("connected via relay to {peer_id}");
            return Ok(conn);
        }

        Err(CoreError::InvalidEndpoint(format!(
            "no viable path to {peer_id}"
        )))
    }

    async fn accept(&self) -> Result<IncomingConnection, CoreError> {
        // In real implementation, this would wait for incoming QUIC connections
        // and perform Noise_IK handshake
        Err(CoreError::InvalidEndpoint(
            "no incoming connections available".into(),
        ))
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
        let config = TransportConfig::default();
        assert_eq!(config.max_connections, 256);
        assert_eq!(config.idle_timeout_secs, 30);
    }
}
