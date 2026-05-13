#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum EndpointKind {
    IPv6 = 0,
    STUN = 1,
    LAN = 2,
    WebSocket = 3,
    Relay = 4,
    TSO = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub kind: EndpointKind,
    pub ttl_seconds: u32,
}

impl Endpoint {
    pub fn new(addr: SocketAddr, kind: EndpointKind) -> Self {
        Self { addr, kind, ttl_seconds: 300 }
    }
}
