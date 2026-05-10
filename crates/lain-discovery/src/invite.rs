#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::capabilities::Capabilities;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::peer::PeerId;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DiscoveryError {
    #[error("invite encode error: {0}")]
    Encode(String),
    #[error("invite decode error: {0}")]
    Decode(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invite expired")]
    Expired,
    #[error("mDNS error: {0}")]
    MdnsError(String),
}

#[derive(Clone, Debug)]
pub struct InviteCode {
    pub version: u8,
    pub peer_id: PeerId,
    pub ed25519_pk: [u8; 32],
    pub capabilities: Capabilities,
    pub mappable_port_start: u16,
    pub mappable_port_end: u16,
    pub port_delta_hint: u8,
    pub endpoints: Vec<Endpoint>,
    pub timestamp: u64,
    pub signature: [u8; 64],
}

impl InviteCode {
    pub fn new(
        peer_id: PeerId,
        pubkey: [u8; 32],
        capabilities: Capabilities,
        endpoints: Vec<Endpoint>,
        sign_fn: &dyn Fn(&[u8]) -> [u8; 64],
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut invite = Self {
            version: lain_core::PROTOCOL_VERSION,
            peer_id,
            ed25519_pk: pubkey,
            capabilities,
            mappable_port_start: 1024,
            mappable_port_end: 65535,
            port_delta_hint: 0,
            endpoints,
            timestamp,
            signature: [0u8; 64],
        };

        let data = invite.encode_payload();
        invite.signature = sign_fn(&data);
        invite
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.version);
        data.extend_from_slice(&self.peer_id.0);
        data.extend_from_slice(&self.ed25519_pk);
        data.push(self.capabilities.bits);
        data.extend_from_slice(&self.mappable_port_start.to_be_bytes());
        data.extend_from_slice(&self.mappable_port_end.to_be_bytes());
        data.push(self.port_delta_hint);

        let ep_count = self.endpoints.len().min(255) as u8;
        data.push(ep_count);
        for ep in &self.endpoints {
            encode_endpoint_binary(&mut data, ep);
        }

        data.extend_from_slice(&self.timestamp.to_be_bytes());
        data
    }

    fn decode_payload(data: &[u8]) -> Result<Self, DiscoveryError> {
        if data.len() < 74 {
            return Err(DiscoveryError::Decode("too short".into()));
        }

        let version = data[0];
        if version != lain_core::PROTOCOL_VERSION {
            return Err(DiscoveryError::Decode(format!("unsupported version {version}")));
        }

        let mut peer_id_bytes = [0u8; 32];
        peer_id_bytes.copy_from_slice(&data[1..33]);

        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[33..65]);

        let capabilities = Capabilities { bits: data[65] };

        let mappable_port_start = u16::from_be_bytes([data[66], data[67]]);
        let mappable_port_end = u16::from_be_bytes([data[68], data[69]]);
        let port_delta_hint = data[70];

        let ep_count = data[71] as usize;
        let mut offset = 72usize;
        let mut endpoints = Vec::with_capacity(ep_count);

        for _ in 0..ep_count {
            if let Some(ep) = decode_endpoint_binary(data, &mut offset) {
                endpoints.push(ep);
            }
        }

        let mut timestamp_bytes = [0u8; 8];
        if offset + 8 > data.len() {
            return Err(DiscoveryError::Decode("timestamp missing".into()));
        }
        timestamp_bytes.copy_from_slice(&data[offset..offset + 8]);
        let timestamp = u64::from_be_bytes(timestamp_bytes);
        offset += 8;

        let mut signature = [0u8; 64];
        if offset + 64 <= data.len() {
            signature.copy_from_slice(&data[offset..offset + 64]);
        }

        Ok(InviteCode {
            version,
            peer_id: PeerId(peer_id_bytes),
            ed25519_pk: pk,
            capabilities,
            mappable_port_start,
            mappable_port_end,
            port_delta_hint,
            endpoints,
            timestamp,
            signature,
        })
    }

    pub fn to_base62(&self) -> String {
        let payload = self.encode_payload();
        let mut full = payload;
        full.extend_from_slice(&self.signature);
        encode_base62(&full)
    }

    pub fn from_base62(s: &str) -> Result<Self, DiscoveryError> {
        let data = decode_base62(s)
            .ok_or_else(|| DiscoveryError::Decode("invalid base62".into()))?;
        if data.len() < 74 + 64 {
            return Err(DiscoveryError::Decode("invite too short".into()));
        }
        Self::decode_payload(&data)
    }

    pub fn to_uri(&self) -> String {
        format!("lain://{}", self.to_base62())
    }

    pub fn from_uri(uri: &str) -> Result<Self, DiscoveryError> {
        let code = uri
            .strip_prefix("lain://")
            .ok_or_else(|| DiscoveryError::Decode("invalid URI prefix".into()))?;
        Self::from_base62(code)
    }

    pub fn verify(&self, verify_fn: &dyn Fn(&[u8; 32], &[u8], &[u8; 64]) -> bool) -> bool {
        let payload = self.encode_payload();
        verify_fn(&self.ed25519_pk, &payload, &self.signature)
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window: u64 = 30 * 60;
        if now < self.timestamp {
            return false;
        }
        now - self.timestamp > window
    }
}

fn encode_endpoint_binary(buf: &mut Vec<u8>, ep: &Endpoint) {
    match ep.addr {
        SocketAddr::V4(v4) => {
            buf.push(0);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            buf.push(1);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    buf.push(ep.kind as u8);
    buf.push(ep.priority);
    buf.extend_from_slice(&ep.ttl_seconds.to_be_bytes());
}

fn decode_endpoint_binary(data: &[u8], offset: &mut usize) -> Option<Endpoint> {
    if *offset + 2 > data.len() {
        return None;
    }
    let addr_kind = data[*offset];
    *offset += 1;

    let addr = if addr_kind == 0 {
        if *offset + 6 > data.len() {
            return None;
        }
        let ip = std::net::Ipv4Addr::new(
            data[*offset],
            data[*offset + 1],
            data[*offset + 2],
            data[*offset + 3],
        );
        let port = u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]);
        *offset += 6;
        SocketAddr::new(std::net::IpAddr::V4(ip), port)
    } else {
        if *offset + 18 > data.len() {
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&data[*offset..*offset + 16]);
        let ip = std::net::Ipv6Addr::from(ip_bytes);
        let port = u16::from_be_bytes([data[*offset + 16], data[*offset + 17]]);
        *offset += 18;
        SocketAddr::new(std::net::IpAddr::V6(ip), port)
    };

    if *offset + 7 > data.len() {
        return None;
    }
    let kind_byte = data[*offset];
    *offset += 1;
    let priority = data[*offset];
    *offset += 1;
    let kind = match kind_byte {
        0 => EndpointKind::IPv6,
        1 => EndpointKind::STUN,
        2 => EndpointKind::LAN,
        3 => EndpointKind::WebSocket,
        4 => EndpointKind::Relay,
        _ => EndpointKind::LAN,
    };
    let ttl_bytes = [data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]];
    let ttl_seconds = u32::from_be_bytes(ttl_bytes);
    *offset += 4;

    Some(Endpoint { addr, kind, priority, ttl_seconds })
}

const BASE62_CHARS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn encode_base62(data: &[u8]) -> String {
    let mut result = String::new();
    let mut value = Vec::from(data);
    if value.iter().all(|&b| b == 0) {
        return String::from("0");
    }
    while !value.iter().all(|&b| b == 0) {
        let mut remainder: u16 = 0;
        let mut new_value = Vec::new();
        for &byte in &value {
            let combined = (remainder << 8) | byte as u16;
            new_value.push((combined / 62) as u8);
            remainder = combined % 62;
        }
        result.push(BASE62_CHARS[remainder as usize] as char);
        value = new_value;
    }
    for &byte in data {
        if byte == 0 {
            result.push(BASE62_CHARS[0] as char);
        } else {
            break;
        }
    }
    result.chars().rev().collect()
}

fn decode_base62(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    let mut value = Vec::new();
    value.push(0u8);
    let mut zero_count = 0u32;
    let bytes = s.as_bytes();

    for &ch in bytes {
        let idx = BASE62_CHARS.iter().position(|&c| c == ch)?;
        if idx == 0 && value.len() == 1 && value[0] == 0 {
            zero_count = zero_count.saturating_add(1);
            continue;
        }
        let mut carry: u32 = idx as u32;
        for byte in value.iter_mut().rev() {
            let v = *byte as u32 * 62 + carry;
            *byte = (v & 0xFF) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            value.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    let mut result = vec![0u8; zero_count as usize];
    result.extend_from_slice(&value);
    Some(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_invite() -> InviteCode {
        let peer_id = PeerId([1u8; 32]);
        let pk = [2u8; 32];
        let endpoint = Endpoint {
            addr: "192.168.1.1:8080".parse().unwrap(),
            kind: EndpointKind::LAN,
            priority: 100,
            ttl_seconds: 300,
        };
        let sign_fn = |_data: &[u8]| -> [u8; 64] { [3u8; 64] };
        InviteCode::new(peer_id, pk, Capabilities::new(), vec![endpoint], &sign_fn)
    }

    #[test]
    fn test_invite_encode_decode_base62() {
        let invite = make_invite();
        let b62 = invite.to_base62();
        let decoded = InviteCode::from_base62(&b62).unwrap();
        assert_eq!(invite.peer_id, decoded.peer_id);
        assert_eq!(invite.ed25519_pk, decoded.ed25519_pk);
    }

    #[test]
    fn test_invite_uri_roundtrip() {
        let invite = make_invite();
        let uri = invite.to_uri();
        assert!(uri.starts_with("lain://"));
        let decoded = InviteCode::from_uri(&uri).unwrap();
        assert_eq!(invite.peer_id, decoded.peer_id);
    }

    #[test]
    fn test_invite_not_expired() {
        let invite = make_invite();
        assert!(!invite.is_expired());
    }

    #[test]
    fn test_base62_roundtrip() {
        let data = b"hello world!";
        let encoded = encode_base62(data);
        let decoded = decode_base62(&encoded).unwrap();
        assert_eq!(&decoded[0..data.len()], data);
    }
}
