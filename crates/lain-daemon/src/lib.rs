#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;

use lain_core::capabilities::Capabilities;
use lain_core::endpoint::Endpoint;
use lain_core::identity::IdentityProvider;
use lain_core::nat::NatProber as NatProberTrait;
use lain_core::peer::PeerId;
use lain_identity::Identity;
use lain_nat::NatProbe;
use lain_dht::DhtHandle;
use thiserror::Error;
use tokio::sync::RwLock;
use std::sync::Arc;
use tracing;

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

        let dht = DhtHandle::new(peer_id, public_key, dht_config)
            .map_err(|e| DaemonError::Dht(e.to_string()))?;

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

        // 6. 生成 invite
        let invite = lain_discovery::InviteCode::new(
            peer_id, public_key, capabilities, endpoints.clone(),
            &|data| self.identity.sign(data),
        );

        // 7. 启动 DHT 接收循环
        let socket = dht.socket();
        let dht_arc = Arc::new(dht);
        let dht_recv = dht_arc.clone();

        let mut buf = vec![0u8; 2048];
        let mut heartbeat = tokio::time::interval(
            std::time::Duration::from_secs(heartbeat_secs),
        );

        loop {
            tokio::select! {
                recv = socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((len, src)) => {
                            if let Err(e) = dht_recv.handle_incoming(&buf[..len], src).await {
                                tracing::debug!("DHT recv error from {src}: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::error!("UDP recv error: {e}");
                        }
                    }
                }

                _ = heartbeat.tick() => {
                    if let Err(e) = dht_arc.store_self(
                        &public_key, &endpoints, capabilities,
                    ).await {
                        tracing::debug!("DHT heartbeat failed: {e}");
                    }
                }

                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Shutting down...");
                    break;
                }
            }
        }

        *self.state.write().await = DaemonState::Stopped;
        Ok(())
    }

    pub async fn state(&self) -> DaemonState {
        self.state.read().await.clone()
    }
}
