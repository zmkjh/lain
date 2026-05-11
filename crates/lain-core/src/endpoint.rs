use std::net::SocketAddr;

/// 网络端点：地址 + 类型 + 优先级
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    #[serde(with = "serde_socket_addr")]
    pub addr: SocketAddr,
    pub kind: EndpointKind,
    pub priority: u8,
    pub ttl_seconds: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum EndpointKind {
    IPv6 = 0,
    STUN = 1,
    LAN = 2,
    WebSocket = 3,
    Relay = 4,
    TSO = 5,         // TCP Simultaneous Open port
}

mod serde_socket_addr {
    use std::net::SocketAddr;
    use serde::Deserialize;

    pub fn serialize<S: serde::Serializer>(addr: &SocketAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<SocketAddr, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        s.parse::<SocketAddr>()
            .map_err(|_| serde::de::Error::custom("invalid SocketAddr"))
    }
}

impl Endpoint {
    pub fn new(addr: SocketAddr, kind: EndpointKind) -> Self {
        Self { addr, kind, priority: 128, ttl_seconds: 300 }
    }

    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_ttl(mut self, ttl_seconds: u32) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }
}
