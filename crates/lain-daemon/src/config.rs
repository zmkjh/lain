use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default)]
    pub dht: DhtConfigFields,
    #[serde(default)]
    pub transport: TransportConfigFields,
    #[serde(default)]
    pub ipc: IpcConfigFields,
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DhtConfigFields {
    #[serde(default = "default_k")]
    pub k: usize,
    #[serde(default = "default_alpha")]
    pub alpha: usize,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: u32,
    #[serde(default = "default_heartbeat")]
    pub heartbeat_interval_secs: u64,
    #[serde(default, with = "opt_socket_addr")]
    pub local_addr: Option<SocketAddr>,
    #[serde(default, with = "vec_socket_addr")]
    pub bootstrap_nodes: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransportConfigFields {
    #[serde(default = "default_max_conns")]
    pub max_connections: usize,
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_keepalive")]
    pub keep_alive_secs: u64,
    #[serde(default, with = "opt_socket_addr")]
    pub bind_addr: Option<SocketAddr>,
    #[serde(default = "default_tso_port_start")]
    pub tso_port_start: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpcConfigFields {
    #[serde(default)]
    pub uds_path: Option<String>,
    #[serde(default, with = "opt_socket_addr")]
    pub http_addr: Option<SocketAddr>,
}

// serde helpers for SocketAddr
mod opt_socket_addr {
    use std::net::SocketAddr;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(addr: &Option<SocketAddr>, s: S) -> Result<S::Ok, S::Error> {
        match addr {
            Some(a) => s.serialize_str(&a.to_string()),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SocketAddr>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) if !s.is_empty() => s.parse()
                .map(Some)
                .map_err(|_| serde::de::Error::custom("invalid SocketAddr")),
            _ => Ok(None),
        }
    }
}

mod vec_socket_addr {
    use std::net::SocketAddr;
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(addrs: &Vec<SocketAddr>, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(addrs.len()))?;
        for addr in addrs {
            seq.serialize_element(&addr.to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<SocketAddr>, D::Error> {
        let strings: Vec<String> = Vec::deserialize(d)?;
        strings.iter()
            .map(|s| s.parse()
                .map_err(|_| serde::de::Error::custom(format!("invalid SocketAddr: {s}"))))
            .collect()
    }
}

fn default_tso_port_start() -> u16 { 50000 }
fn default_k() -> usize { 20 }
fn default_alpha() -> usize { 3 }
fn default_ttl() -> u32 { 300 }
fn default_heartbeat() -> u64 { 150 }
fn default_max_conns() -> usize { 256 }
fn default_idle() -> u64 { 30 }
fn default_keepalive() -> u64 { 15 }
fn default_stun_servers() -> Vec<String> {
    vec![
        "stun.miwifi.com:3478".to_string(),
        "stun.qq.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
    ]
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            dht: DhtConfigFields::default(),
            transport: TransportConfigFields::default(),
            ipc: IpcConfigFields::default(),
            stun_servers: default_stun_servers(),
        }
    }
}

impl Default for DhtConfigFields {
    fn default() -> Self {
        Self {
            k: default_k(),
            alpha: default_alpha(),
            ttl_seconds: default_ttl(),
            heartbeat_interval_secs: default_heartbeat(),
            local_addr: None,
            bootstrap_nodes: Vec::new(),
        }
    }
}

impl Default for TransportConfigFields {
    fn default() -> Self {
        Self {
            max_connections: default_max_conns(),
            idle_timeout_secs: default_idle(),
            keep_alive_secs: default_keepalive(),
            bind_addr: None,
            tso_port_start: default_tso_port_start(),
        }
    }
}

impl Default for IpcConfigFields {
    fn default() -> Self {
        Self {
            uds_path: None,
            http_addr: None,
        }
    }
}

impl DaemonConfig {
    pub fn load_or_default() -> Result<Self, String> {
        let paths = ["lain.toml", "config.toml"];
        for path in &paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(config) = toml::from_str(&content) {
                    tracing::info!("Loaded config from {path}");
                    return Ok(config);
                }
                tracing::warn!("Failed to parse {path}");
            }
        }
        tracing::info!("No config file found, using defaults");
        Ok(Self::default())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DaemonConfig::default();
        assert_eq!(config.dht.k, 20);
    }

    #[test]
    fn test_config_serialize_deserialize() {
        let config = DaemonConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let decoded: DaemonConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(decoded.dht.k, config.dht.k);
    }
}
