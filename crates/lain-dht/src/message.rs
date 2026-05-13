use lain_core::capabilities::Capabilities;
use lain_core::dht::{DhtMessage, DhtMsgType};
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::peer::PeerId;
use lain_core::PROTOCOL_VERSION;
use ed25519_dalek::Signer;
use std::net::SocketAddr;

use crate::routing::BucketEntry;
use crate::PeerRecord;

/// Build a PING request message (unsigned)
pub fn encode_ping_request(sender_id: PeerId, message_id: [u8; 16]) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::Ping, false, &[], None)
}

/// Build a signed PING request message
pub fn encode_ping_request_signed(
    sender_id: PeerId,
    message_id: [u8; 16],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::Ping, false, &[], seed)
}

/// Build a signed FIND_NODE request message
pub fn encode_find_node_request_signed(
    sender_id: PeerId,
    message_id: [u8; 16],
    target_id: PeerId,
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::FindNode, false, &target_id.0, seed)
}

/// Build a signed STORE request message
pub fn encode_store_request_signed(
    sender_id: PeerId,
    message_id: [u8; 16],
    key: &[u8; 32],
    ttl: u32,
    pubkey: &[u8; 32],
    noise_pubkey: &[u8; 32],
    capabilities: Capabilities,
    endpoints: &[Endpoint],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(key);
    payload.extend_from_slice(&ttl.to_be_bytes());
    payload.extend_from_slice(pubkey);
    payload.extend_from_slice(noise_pubkey);
    payload.push(capabilities.bits);
    let mut endpoints_data = Vec::new();
    for ep in endpoints {
        encode_endpoint(&mut endpoints_data, ep);
    }
    let val_len = endpoints_data.len() as u16;
    payload.extend_from_slice(&val_len.to_be_bytes());
    payload.extend_from_slice(&endpoints_data);
    encode_message(sender_id, message_id, DhtMsgType::Store, false, &payload, seed)
}

/// Build a signed FIND_VALUE request message
pub fn encode_find_value_request_signed(
    sender_id: PeerId,
    message_id: [u8; 16],
    key: &[u8; 32],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::FindValue, false, key, seed)
}

/// Sign message data with an Ed25519 signing key seed, returns signature
pub fn sign_with_seed(seed: &[u8; 32], data: &[u8]) -> [u8; 64] {
    let key = ed25519_dalek::SigningKey::from_bytes(seed);
    key.sign(data).to_bytes()
}

/// Build a PING response with k-closest nodes
pub fn encode_ping_response(
    sender_id: PeerId,
    message_id: [u8; 16],
    nodes: &[BucketEntry],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    let node_count = nodes.len().min(255) as u8;
    payload.push(node_count);
    for entry in nodes.iter().take(node_count as usize) {
        payload.extend_from_slice(&entry.node_id.0);
        encode_address(&mut payload, &entry.address);
    }
    encode_message(sender_id, message_id, DhtMsgType::Ping, true, &payload, seed)
}

/// Build a STORE request
pub fn encode_store_request(
    sender_id: PeerId,
    key: &[u8; 32],
    ttl: u32,
    pubkey: &[u8; 32],
    noise_pubkey: &[u8; 32],
    capabilities: Capabilities,
    endpoints: &[Endpoint],
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(key);
    payload.extend_from_slice(&ttl.to_be_bytes());
    payload.extend_from_slice(pubkey);
    payload.extend_from_slice(noise_pubkey);
    payload.push(capabilities.bits);

    let mut endpoints_data = Vec::new();
    for ep in endpoints {
        encode_endpoint(&mut endpoints_data, ep);
    }
    let val_len = endpoints_data.len() as u16;
    payload.extend_from_slice(&val_len.to_be_bytes());
    payload.extend_from_slice(&endpoints_data);

    encode_message(sender_id, rand_msg_id(), DhtMsgType::Store, false, &payload, None)
}

/// Build a FIND_VALUE request
pub fn encode_find_value_request(
    sender_id: PeerId,
    message_id: [u8; 16],
    key: &[u8; 32],
) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::FindValue, false, key, None)
}

/// Build a FIND_NODE request
pub fn encode_find_node_request(
    sender_id: PeerId,
    message_id: [u8; 16],
    target_id: PeerId,
) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::FindNode, false, &target_id.0, None)
}

/// Build a FIND_NODE response
pub fn encode_find_node_response(
    sender_id: PeerId,
    message_id: [u8; 16],
    nodes: &[BucketEntry],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    let node_count = nodes.len().min(255) as u8;
    payload.push(node_count);
    for entry in nodes.iter().take(node_count as usize) {
        payload.extend_from_slice(&entry.node_id.0);
        encode_address(&mut payload, &entry.address);
    }
    encode_message(sender_id, message_id, DhtMsgType::FindNode, true, &payload, seed)
}

/// Encode a DHT message to wire format
fn encode_message(
    sender_id: PeerId,
    message_id: [u8; 16],
    msg_type: DhtMsgType,
    is_response: bool,
    payload: &[u8],
    sign_seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(83 + payload.len() + 64);
    msg.push(PROTOCOL_VERSION);
    msg.extend_from_slice(&message_id);
    let type_byte = msg_type as u8 | if is_response { 0x80 } else { 0 };
    msg.push(type_byte);
    msg.extend_from_slice(&sender_id.0);

    let payload_len = payload.len() as u32;
    msg.push(((payload_len >> 16) & 0xFF) as u8);
    msg.push(((payload_len >> 8) & 0xFF) as u8);
    msg.push((payload_len & 0xFF) as u8);
    msg.extend_from_slice(payload);

    let sig = if let Some(seed) = sign_seed {
        sign_with_seed(seed, &msg)
    } else {
        [0u8; 64]
    };
    msg.extend_from_slice(&sig);

    msg
}

/// Decode a DHT message from wire format
pub fn decode_message(data: &[u8]) -> Option<DhtMessage> {
    if data.len() < 53 {
        return None;
    }

    let version = data[0];
    if version != PROTOCOL_VERSION {
        return None;
    }

    let mut message_id = [0u8; 16];
    message_id.copy_from_slice(&data[1..17]);

    let type_byte = data[17];
    let msg_type = DhtMsgType::from_u8(type_byte)?;
    let is_response = DhtMsgType::is_response(type_byte);

    let mut sender_bytes = [0u8; 32];
    sender_bytes.copy_from_slice(&data[18..50]);
    let sender_id = PeerId(sender_bytes);

    let payload_len = ((data[50] as usize) << 16)
        | ((data[51] as usize) << 8)
        | (data[52] as usize);

    let payload_end = 53 + payload_len;
    if data.len() < payload_end {
        return None;
    }
    let payload = data[53..payload_end].to_vec();

    let signature = if data.len() >= payload_end + 64 {
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data[payload_end..payload_end + 64]);
        Some(sig)
    } else {
        None
    };

    Some(DhtMessage {
        version,
        message_id,
        msg_type,
        is_response,
        sender_id,
        payload,
        signature,
    })
}

fn encode_endpoint(buf: &mut Vec<u8>, ep: &Endpoint) {
    encode_address(buf, &ep.addr);
    buf.push(ep.kind as u8);
    buf.extend_from_slice(&ep.ttl_seconds.to_be_bytes());
}

fn encode_address(buf: &mut Vec<u8>, addr: &std::net::SocketAddr) {
    match addr {
        std::net::SocketAddr::V4(v4) => {
            buf.push(0); // IPv4
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        std::net::SocketAddr::V6(v6) => {
            buf.push(1); // IPv6
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
}

fn rand_msg_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    for byte in &mut id {
        *byte = rand::random::<u8>();
    }
    id
}

// ── Additional encode/decode helpers ──

/// STORE ACK response
pub fn encode_store_ack(sender_id: PeerId, message_id: [u8; 16], seed: Option<&[u8; 32]>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0u8); // status = ok
    encode_message(sender_id, message_id, DhtMsgType::Store, true, &payload, seed)
}

/// FIND_VALUE response with record found
pub fn encode_find_value_response_with_record(
    sender_id: PeerId,
    message_id: [u8; 16],
    record: &PeerRecord,
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1u8); // has_value = true
    payload.extend_from_slice(&record.ttl_remaining.to_be_bytes());
    payload.extend_from_slice(&record.pubkey);
    payload.extend_from_slice(&record.noise_pubkey);
    payload.push(record.capabilities.bits);
    let mut ep_data = Vec::new();
    for ep in &record.endpoints {
        encode_endpoint(&mut ep_data, ep);
    }
    let ep_len = ep_data.len() as u16;
    payload.extend_from_slice(&ep_len.to_be_bytes());
    payload.extend_from_slice(&ep_data);
    encode_message(sender_id, message_id, DhtMsgType::FindValue, true, &payload, seed)
}

/// FIND_VALUE response not found (return k-closest)
pub fn encode_find_value_response_not_found(
    sender_id: PeerId,
    message_id: [u8; 16],
    nodes: &[BucketEntry],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(0u8); // has_value = false
    let node_count = nodes.len().min(255) as u8;
    payload.push(node_count);
    for entry in nodes.iter().take(node_count as usize) {
        payload.extend_from_slice(&entry.node_id.0);
        encode_address(&mut payload, &entry.address);
    }
    encode_message(sender_id, message_id, DhtMsgType::FindValue, true, &payload, seed)
}

/// ADDR_REFLECT response
pub fn encode_addr_reflect_response(
    sender_id: PeerId,
    message_id: [u8; 16],
    observed_addr: &SocketAddr,
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    encode_address(&mut payload, observed_addr);
    encode_message(sender_id, message_id, DhtMsgType::AddrReflect, true, &payload, seed)
}

/// RELAY_NEEDED response
pub fn encode_relay_needed_response(
    sender_id: PeerId,
    message_id: [u8; 16],
    relays: &[BucketEntry],
    seed: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    let count = relays.len().min(255) as u8;
    payload.push(count);
    for entry in relays.iter().take(count as usize) {
        payload.extend_from_slice(&entry.node_id.0);
        encode_address(&mut payload, &entry.address);
    }
    encode_message(sender_id, message_id, DhtMsgType::RelayNeeded, true, &payload, seed)
}

/// ADDR_REFLECT request
pub fn encode_addr_reflect_request(sender_id: PeerId, message_id: [u8; 16]) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::AddrReflect, false, &[], None)
}

/// RELAY_NEEDED request
pub fn encode_relay_needed_request(sender_id: PeerId, message_id: [u8; 16]) -> Vec<u8> {
    encode_message(sender_id, message_id, DhtMsgType::RelayNeeded, false, &[], None)
}

/// Parse node list from payload (common pattern in PING/FIND_NODE responses)
/// Returns Vec of (PeedId, SocketAddr)
pub fn parse_nodes_from_payload(payload: &[u8]) -> Option<Vec<(PeerId, SocketAddr)>> {
    if payload.is_empty() {
        return Some(Vec::new());
    }
    let count = payload[0] as usize;
    let mut offset = 1usize;
    let mut nodes = Vec::with_capacity(count);

    for _ in 0..count {
        if offset + 32 > payload.len() {
            break;
        }
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&payload[offset..offset + 32]);
        offset += 32;

        let addr = decode_address(payload, &mut offset)?;
        nodes.push((PeerId(id_bytes), addr));
    }
    Some(nodes)
}

/// Parse a PeerRecord from FIND_VALUE response payload (after has_value byte)
pub fn parse_record_from_payload(payload: &[u8]) -> Option<PeerRecord> {
    if payload.len() < 71 {
        return None; // min: ttl(4) + pubkey(32) + noise_pubkey(32) + capabilities(1) + ep_len(2)
    }
    let ttl_remaining = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&payload[4..36]);
    let mut noise_pubkey = [0u8; 32];
    noise_pubkey.copy_from_slice(&payload[36..68]);
    let capabilities = Capabilities { bits: payload[68] };
    let ep_len = u16::from_be_bytes([payload[69], payload[70]]) as usize;
    let endpoints = parse_endpoints(&payload[71..], ep_len);

    Some(PeerRecord {
        pubkey,
        noise_pubkey,
        endpoints,
        capabilities,
        ttl_remaining,
        expires_at: std::time::Instant::now() + std::time::Duration::from_secs(ttl_remaining as u64),
    })
}

/// Parse endpoints from raw bytes with given byte-length budget.
pub fn parse_endpoints(data: &[u8], ep_data_len: usize) -> Vec<Endpoint> {
    let mut endpoints = Vec::with_capacity(4);
    let ep_data_end = ep_data_len.min(data.len());
    let mut offset = 0usize;
    while offset + 7 <= ep_data_end {
        let addr = match decode_address(data, &mut offset) {
            Some(a) => a,
            None => break,
        };
        if offset + 5 > ep_data_end { break; }
        let kind_byte = data[offset]; offset += 1;
        let kind = match kind_byte {
            0 => EndpointKind::IPv6,
            1 => EndpointKind::STUN,
            2 => EndpointKind::LAN,
            3 => EndpointKind::WebSocket,
            4 => EndpointKind::Relay,
            5 => EndpointKind::TSO,
            _ => EndpointKind::STUN,
        };
        let ttl_bytes = [data[offset], data[offset+1], data[offset+2], data[offset+3]];
        let ttl = u32::from_be_bytes(ttl_bytes);
        offset += 4;
        endpoints.push(Endpoint { addr, kind, ttl_seconds: ttl });
    }
    endpoints
}

fn decode_address(data: &[u8], offset: &mut usize) -> Option<SocketAddr> {
    if *offset >= data.len() {
        return None;
    }
    let kind = data[*offset];
    *offset += 1;

    match kind {
        0 => {
            // IPv4
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
            Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
        }
        1 => {
            // IPv6
            if *offset + 18 > data.len() {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[*offset..*offset + 16]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[*offset + 16], data[*offset + 17]]);
            *offset += 18;
            Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lain_core::capabilities::Capabilities;
    use lain_core::endpoint::{Endpoint, EndpointKind};
    use lain_core::peer::PeerId;
    use lain_core::dht::DhtMsgType;

    #[test]
    fn test_encode_decode_message_roundtrip_ping() {
        let sender = PeerId([1u8; 32]);
        let msg_id = [2u8; 16];
        let encoded = encode_message(sender, msg_id, DhtMsgType::Ping, false, &[], None);
        let decoded = decode_message(&encoded).expect("should decode");
        assert_eq!(decoded.msg_type, DhtMsgType::Ping);
        assert!(!decoded.is_response);
        assert_eq!(decoded.sender_id, sender);
        assert_eq!(decoded.message_id, msg_id);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn test_encode_decode_message_roundtrip_find_node() {
        let sender = PeerId([3u8; 32]);
        let msg_id = [4u8; 16];
        let payload = vec![5u8; 32];
        let encoded = encode_message(sender, msg_id, DhtMsgType::FindNode, false, &payload, None);
        let decoded = decode_message(&encoded).expect("should decode");
        assert_eq!(decoded.msg_type, DhtMsgType::FindNode);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_encode_decode_message_with_signature() {
        let sender = PeerId([6u8; 32]);
        let msg_id = [7u8; 16];
        let seed = [8u8; 32];
        let payload = b"hello".to_vec();
        let encoded = encode_message(sender, msg_id, DhtMsgType::FindValue, false, &payload, Some(&seed));
        let decoded = decode_message(&encoded).expect("should decode");
        assert_eq!(decoded.msg_type, DhtMsgType::FindValue);
        assert!(decoded.signature.is_some());
        assert!(!decoded.signature.unwrap().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_encode_decode_message_response_flag() {
        let sender = PeerId([9u8; 32]);
        let msg_id = [10u8; 16];
        let encoded = encode_message(sender, msg_id, DhtMsgType::Store, true, &[0u8], None);
        let decoded = decode_message(&encoded).expect("should decode");
        assert!(decoded.is_response);
    }

    #[test]
    fn test_decode_message_too_short() {
        assert!(decode_message(&[0u8; 10]).is_none());
        assert!(decode_message(&[0u8; 52]).is_none());
    }

    #[test]
    fn test_decode_message_wrong_version() {
        let mut buf = vec![0u8; 53];
        buf[0] = 0xFF; // wrong version
        assert!(decode_message(&buf).is_none());
    }

    #[test]
    fn test_encode_decode_store_payload_roundtrip() {
        let sender = PeerId([11u8; 32]);
        let key = [12u8; 32];
        let ttl = 600;
        let pubkey = [13u8; 32];
        let noise_pubkey = [14u8; 32];
        let endpoints = vec![
            Endpoint::new("192.168.1.1:8080".parse().unwrap(), EndpointKind::LAN),
            Endpoint::new("10.0.0.1:443".parse().unwrap(), EndpointKind::STUN),
        ];

        let raw = encode_store_request(sender, &key, ttl, &pubkey, &noise_pubkey, Capabilities::new(), &endpoints);
        let msg = decode_message(&raw).expect("should decode STORE");

        assert_eq!(msg.msg_type, DhtMsgType::Store);
        assert!(!msg.is_response);
        assert_eq!(&msg.payload[..32], &key);
        assert_eq!(u32::from_be_bytes([msg.payload[32], msg.payload[33], msg.payload[34], msg.payload[35]]), ttl);
        assert_eq!(&msg.payload[36..68], &pubkey);
        assert_eq!(&msg.payload[68..100], &noise_pubkey);
    }

    #[test]
    fn test_parse_nodes_from_payload() {
        let mut payload = vec![0u8; 1 + 32 + 7]; // count + 1 node
        payload[0] = 1; // 1 node
        payload[1..33].copy_from_slice(&[15u8; 32]); // node_id
        payload[33] = 0; // IPv4
        payload[34..38].copy_from_slice(&[192, 168, 1, 1]); // IP
        payload[38..40].copy_from_slice(&8080u16.to_be_bytes()); // port

        let nodes = parse_nodes_from_payload(&payload).expect("should parse");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, PeerId([15u8; 32]));
        assert_eq!(nodes[0].1.to_string(), "192.168.1.1:8080");
    }

    #[test]
    fn test_parse_nodes_from_empty_payload() {
        let nodes = parse_nodes_from_payload(&[]).expect("should handle empty");
        assert!(nodes.is_empty());
    }

    #[test]
    fn test_peer_record_encode_decode_roundtrip() {
        let pubkey = [16u8; 32];
        let noise_pubkey = [17u8; 32];
        let ttl: u32 = 1200;
        let endpoints = vec![
            Endpoint::new("10.0.0.1:9000".parse().unwrap(), EndpointKind::STUN),
        ];

        let record = PeerRecord {
            pubkey,
            noise_pubkey,
            endpoints,
            capabilities: Capabilities::new(),
            ttl_remaining: ttl,
            expires_at: std::time::Instant::now(),
        };

        let payload = encode_find_value_response_with_record(
            PeerId([0u8; 32]), [0u8; 16], &record, None,
        );

        let msg = decode_message(&payload).expect("should decode");
        assert!(msg.is_response);
        assert_eq!(msg.msg_type, DhtMsgType::FindValue);
        assert_eq!(msg.payload[0], 1); // has_value
        let parsed = parse_record_from_payload(&msg.payload[1..]).expect("should parse record");
        assert_eq!(parsed.pubkey, pubkey);
        assert_eq!(parsed.noise_pubkey, noise_pubkey);
        assert_eq!(parsed.ttl_remaining, ttl);
        assert_eq!(parsed.endpoints.len(), 1);
        assert_eq!(parsed.endpoints[0].addr.to_string(), "10.0.0.1:9000");
    }

    #[test]
    fn test_parse_record_from_payload_rejects_too_short() {
        assert!(parse_record_from_payload(&[0u8; 50]).is_none()); // < 70 bytes
    }
}
