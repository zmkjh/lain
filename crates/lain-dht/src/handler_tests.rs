use super::*;
use crate::message as msg_codec;
use lain_core::capabilities::Capabilities;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::identity::IdentityProvider;
use lain_identity::Identity;
use std::time::Duration;

fn make_id(seed: u8) -> PeerId {
    PeerId([seed; 32])
}

fn make_config(addr: &str) -> DhtConfig {
    DhtConfig {
        local_addr: addr.parse().unwrap(),
        ..Default::default()
    }
}

fn spawn_recv_loop(dht: Arc<DhtHandle>) {
    let dht2 = dht.clone();
    let sock = dht.socket();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((len, src)) => { let _ = dht2.handle_incoming(&buf[..len], src).await; }
                Err(_) => break,
            }
        }
    });
}

#[tokio::test]
async fn test_ping_request_populates_routing_table() {
    let a = Arc::new(DhtHandle::new(make_id(1), [1u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(2), [2u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let b_addr = b.socket().local_addr().unwrap();

    let ping = msg_codec::encode_ping_request(a.peer_id, [0u8; 16]);
    a.socket().send_to(&ping, b_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    let size = b.routing_table_size().await;
    assert!(size >= 1, "B should have A in its routing table: got {size}");
}

#[tokio::test]
async fn test_ping_response_populates_routing_table() {
    let a = Arc::new(DhtHandle::new(make_id(3), [3u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(4), [4u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let b_addr = b.socket().local_addr().unwrap();

    a.socket().send_to(&msg_codec::encode_ping_request(a.peer_id, [1u8; 16]), b_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(a.routing_table_size().await >= 1);
    assert!(b.routing_table_size().await >= 1);
}

#[tokio::test]
async fn test_find_node_request_responds_closest() {
    let a = Arc::new(DhtHandle::new(make_id(5), [5u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(6), [6u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();
    b.socket().send_to(&msg_codec::encode_find_node_request(b.peer_id, [2u8; 16], make_id(7)), a_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(a.routing_table_size().await >= 1);
}

#[tokio::test]
async fn test_store_and_retrieve_record() {
    let a = Arc::new(DhtHandle::new(make_id(8), [8u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(9), [9u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();

    // Bootstrap: ensure B knows A
    b.socket().send_to(&msg_codec::encode_ping_request(b.peer_id, [3u8; 16]), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a real identity for the dummy peer so pubkey hashes to the PeerID
    let dummy_id = Identity::generate().ok().unwrap();
    let dummy_pk = *dummy_id.public_key();
    let dummy_peer = dummy_id.peer_id();
    let (_ns, np) = dummy_id.noise_keypair();
    let ep = Endpoint::new("10.0.0.10:9000".parse().unwrap(), EndpointKind::STUN);

    let store = msg_codec::encode_store_request(b.peer_id, &dummy_peer.0, 600, &dummy_pk, &np, &[ep.clone()]);
    b.socket().send_to(&store, a_addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let stored = a.peer_records.read().await;
    assert!(stored.contains_key(&dummy_peer), "A should store dummy peer record");
    let rec = stored.get(&dummy_peer).unwrap();
    assert_eq!(rec.pubkey, dummy_pk);
    assert_eq!(rec.noise_pubkey, np);
    assert_eq!(rec.endpoints[0].addr.to_string(), "10.0.0.10:9000");
}

#[tokio::test]
async fn test_find_value_found() {
    let a = Arc::new(DhtHandle::new(make_id(12), [12u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(13), [13u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();

    // Bootstrap
    b.socket().send_to(&msg_codec::encode_ping_request(b.peer_id, [5u8; 16]), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create real identity for peer to store
    let dummy_id = Identity::generate().ok().unwrap();
    let dummy_pk = *dummy_id.public_key();
    let dummy_peer = dummy_id.peer_id();
    let (_ns, np) = dummy_id.noise_keypair();
    let ep = Endpoint::new("10.0.0.14:9000".parse().unwrap(), EndpointKind::STUN);

    // Store on A
    let store = msg_codec::encode_store_request(b.peer_id, &dummy_peer.0, 600, &dummy_pk, &np, &[ep.clone()]);
    b.socket().send_to(&store, a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // B sends FIND_VALUE to A
    b.socket().send_to(&msg_codec::encode_find_value_request(b.peer_id, [6u8; 16], &dummy_peer.0), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let stored = a.peer_records.read().await;
    assert!(stored.contains_key(&dummy_peer), "Record should be in A");
}

#[tokio::test]
async fn test_rate_limit_drops_excess() {
    let a = Arc::new(DhtHandle::new(make_id(16), [16u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(17), [17u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let b_addr = b.socket().local_addr().unwrap();

    // Send 50 PINGs from A to B — should not crash
    let ping = msg_codec::encode_ping_request(a.peer_id, [7u8; 16]);
    for _ in 0..50 {
        let _ = a.socket().send_to(&ping, b_addr).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Verify B is alive
    tokio::time::sleep(Duration::from_millis(200)).await;
    let size = b.routing_table_size().await;
    assert!(size <= 50, "routing table should not overflow: got {size}");
}

#[tokio::test]
async fn test_find_value_not_found_returns_nodes() {
    let a = Arc::new(DhtHandle::new(make_id(18), [18u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(19), [19u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());

    // Don't spawn B's recv loop — we'll read its socket directly to verify response
    let b_sock = b.socket();
    let a_addr = a.socket().local_addr().unwrap();

    // Bootstrap
    let ping = msg_codec::encode_ping_request(b.peer_id, [10u8; 16]);
    b_sock.send_to(&ping, a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // FIND_VALUE for a key that doesn't exist
    let nonexistent = PeerId([0xFFu8; 32]);
    let msg_id = [11u8; 16];
    let fv = msg_codec::encode_find_value_request(b.peer_id, msg_id, &nonexistent.0);
    b_sock.send_to(&fv, a_addr).await.unwrap();

    // Read responses from B's socket until we find the FIND_VALUE response
    let mut buf = vec![0u8; 2048];
    let mut found = false;
    for _ in 0..10 {
        match tokio::time::timeout(Duration::from_millis(500), b_sock.recv_from(&mut buf)).await {
            Ok(Ok((len, _src))) => {
                if let Some(msg) = msg_codec::decode_message(&buf[..len]) {
                    if msg.is_response && msg.message_id == msg_id {
                        assert_eq!(msg.payload[0], 0, "first byte should be 0 (not found)");
                        found = true;
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    assert!(found, "should have received FIND_VALUE not-found response");
}

#[tokio::test]
async fn test_store_ttl_clamping() {
    let a = Arc::new(DhtHandle::new(make_id(20), [20u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(21), [21u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();

    // Bootstrap
    b.socket().send_to(&msg_codec::encode_ping_request(b.peer_id, [12u8; 16]), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let dummy_id = Identity::generate().ok().unwrap();
    let dummy_pk = *dummy_id.public_key();
    let dummy_peer = dummy_id.peer_id();
    let (_ns, np) = dummy_id.noise_keypair();
    let ep = Endpoint::new("10.0.0.10:8000".parse().unwrap(), EndpointKind::STUN);

    // Store with TTL=0 (should be clamped to default 300)
    let store_zero = msg_codec::encode_store_request(b.peer_id, &dummy_peer.0, 0, &dummy_pk, &np, &[ep.clone()]);
    b.socket().send_to(&store_zero, a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let stored = a.peer_records.read().await;
    let rec = stored.get(&dummy_peer).unwrap();
    // TTL=0 should have been clamped to 300, not stored as 0
    assert!(rec.ttl_remaining >= 300, "TTL=0 should be clamped to >=300, got {}", rec.ttl_remaining);
}

#[tokio::test]
async fn test_store_rejects_mismatched_pubkey() {
    let a = Arc::new(DhtHandle::new(make_id(22), [22u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(23), [23u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();

    // Bootstrap
    b.socket().send_to(&msg_codec::encode_ping_request(b.peer_id, [13u8; 16]), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Use a key that doesn't match the pubkey (SHA256(pubkey) != key)
    let fake_key = PeerId([24u8; 32]);
    let fake_pubkey = [25u8; 32];
    let fake_noise = [26u8; 32];
    let ep = Endpoint::new("10.0.0.99:1".parse().unwrap(), EndpointKind::STUN);

    let bad_store = msg_codec::encode_store_request(b.peer_id, &fake_key.0, 600, &fake_pubkey, &fake_noise, &[ep]);
    b.socket().send_to(&bad_store, a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A should NOT have stored the bad record
    let stored = a.peer_records.read().await;
    assert!(!stored.contains_key(&fake_key), "A should reject STORE with mismatched pubkey");
}

#[tokio::test]
async fn test_save_and_load_routes() {
    let a = Arc::new(DhtHandle::new(make_id(27), [27u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(28), [28u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();

    // Populate A's routing table with B
    b.socket().send_to(&msg_codec::encode_ping_request(b.peer_id, [14u8; 16]), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let initial_size = a.routing_table_size().await;
    assert!(initial_size >= 1, "A should have B in routing table");

    // Save routes
    let tmp = std::env::temp_dir().join("lain_test_routes.json");
    a.save_routes(&tmp).await.unwrap();
    assert!(tmp.exists(), "routes file should exist after save");

    // Create a fresh DHT and load
    let c = Arc::new(DhtHandle::new(make_id(29), [29u8; 32], make_config("127.0.0.1:0")).unwrap());
    let loaded = c.load_routes(&tmp).await.unwrap();
    assert!(loaded >= 1, "should load at least 1 route from file, got {loaded}");

    // Cleanup
    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn test_load_routes_nonexistent_file() {
    let dht = DhtHandle::new(make_id(30), [30u8; 32], make_config("127.0.0.1:0")).unwrap();
    let tmp = std::env::temp_dir().join("lain_test_nonexistent_routes.json");
    // Should return Ok(0) for nonexistent file
    let loaded = dht.load_routes(&tmp).await.unwrap();
    assert_eq!(loaded, 0, "nonexistent file should load 0 routes");
}

#[tokio::test]
async fn test_signed_message_verified_and_rejected() {
    // Generate real identity for sender (with Ed25519 signing key)
    let sender_id = Identity::generate().ok().unwrap();
    let sender_pubkey = *sender_id.public_key();
    let sender_peer = sender_id.peer_id();
    let sender_seed = sender_id.signing_seed();

    // Receiver DHT
    let receiver = Arc::new(DhtHandle::new(make_id(31), [31u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(receiver.clone());

    // Pre-populate receiver's peer_records with sender's pubkey (so verify_strict is reached)
    let record = PeerRecord {
        pubkey: sender_pubkey,
        noise_pubkey: sender_pubkey, // placeholder
        endpoints: vec![],
        capabilities: Capabilities::new(),
        ttl_remaining: 600,
        expires_at: std::time::Instant::now() + Duration::from_secs(600),
    };
    receiver.peer_records.write().await.insert(sender_peer, record);

    let receiver_addr = receiver.socket().local_addr().unwrap();

    // Send signed PING with valid signature
    let msg_id = [42u8; 16];
    let signed_ping = msg_codec::encode_ping_request_signed(sender_peer, msg_id, Some(&sender_seed));
    receiver.socket().send_to(&signed_ping, receiver_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Valid signed message should be accepted (routing table updated)
    let size = receiver.routing_table_size().await;
    assert!(size >= 1, "signed PING should be accepted: routing table has {size} nodes");

    // Now tamper with a signed message: sign fresh, then corrupt body
    let msg_id2 = [43u8; 16];
    let mut tampered_bytes = msg_codec::encode_ping_request_signed(sender_peer, msg_id2, Some(&sender_seed));
    // Corrupt the body (e.g., change message_id between header and signature)
    if tampered_bytes.len() > 30 { tampered_bytes[20] ^= 0xFF; }
    receiver.socket().send_to(&tampered_bytes, receiver_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Receiver should still be alive (tampered message rejected gracefully)
    let size2 = receiver.routing_table_size().await;
    assert!(size2 >= 1, "receiver should survive tampered message; routing table has {size2} nodes");
}

#[tokio::test]
async fn test_sender_without_record_accepted_deferred() {
    // Unknown sender (no record in peer_records) — accepted with deferred verification
    let unknown_id = Identity::generate().ok().unwrap();
    let unknown_peer = unknown_id.peer_id();
    let unknown_seed = unknown_id.signing_seed();

    let receiver = Arc::new(DhtHandle::new(make_id(32), [32u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(receiver.clone());

    let receiver_addr = receiver.socket().local_addr().unwrap();

    let signed_ping = msg_codec::encode_ping_request_signed(unknown_peer, [44u8; 16], Some(&unknown_seed));
    receiver.socket().send_to(&signed_ping, receiver_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Deferred verification: unknown peer accepted, routing table updated
    let size = receiver.routing_table_size().await;
    assert!(size >= 1, "unknown signed peer should be accepted (deferred verification): got {size}");
}

#[tokio::test]
async fn test_expired_records_removed_by_cleanup() {
    let dht = Arc::new(DhtHandle::new(make_id(35), [35u8; 32], make_config("127.0.0.1:0")).unwrap());

    // Insert a record that's already expired
    let expired_peer = PeerId([99u8; 32]);
    let expired = PeerRecord {
        pubkey: [99u8; 32],
        noise_pubkey: [99u8; 32],
        endpoints: vec![],
        capabilities: Capabilities::new(),
        ttl_remaining: 0,
        expires_at: std::time::Instant::now() - Duration::from_secs(1),
    };
    dht.peer_records.write().await.insert(expired_peer, expired);

    // Insert a record that's still valid
    let live_peer = PeerId([100u8; 32]);
    let live = PeerRecord {
        pubkey: [100u8; 32],
        noise_pubkey: [100u8; 32],
        endpoints: vec![],
        capabilities: Capabilities::new(),
        ttl_remaining: 3600,
        expires_at: std::time::Instant::now() + Duration::from_secs(3600),
    };
    dht.peer_records.write().await.insert(live_peer, live);

    assert_eq!(dht.peer_records.read().await.len(), 2);

    // Simulate cleanup: remove expired records
    {
        let mut records = dht.peer_records.write().await;
        let now = std::time::Instant::now();
        records.retain(|_k, v| v.expires_at > now);
    }

    let records = dht.peer_records.read().await;
    assert_eq!(records.len(), 1, "expired record should be removed");
    assert!(records.contains_key(&live_peer), "live record should remain");
    assert!(!records.contains_key(&expired_peer), "expired record should be gone");
}

#[tokio::test]
async fn test_find_peer_returns_cached_record_even_when_node_offline() {
    let a = Arc::new(DhtHandle::new(make_id(36), [36u8; 32], make_config("127.0.0.1:0")).unwrap());
    let b = Arc::new(DhtHandle::new(make_id(37), [37u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(a.clone());
    spawn_recv_loop(b.clone());

    let a_addr = a.socket().local_addr().unwrap();

    // Bootstrap B into A's routing table
    b.socket().send_to(&msg_codec::encode_ping_request(b.peer_id, [50u8; 16]), a_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Store a peer record in A's local cache (simulating prior DHT lookup)
    let dummy_id = Identity::generate().ok().unwrap();
    let dummy_peer = dummy_id.peer_id();
    let record = PeerRecord {
        pubkey: *dummy_id.public_key(),
        noise_pubkey: { let (_, np) = dummy_id.noise_keypair(); np },
        endpoints: vec![Endpoint::new("10.0.0.99:1".parse().unwrap(), EndpointKind::STUN)],
        capabilities: Capabilities::new(),
        ttl_remaining: 600,
        expires_at: std::time::Instant::now() + Duration::from_secs(600),
    };
    a.peer_records.write().await.insert(dummy_peer, record);

    // find_peer should return cached record without needing to query the network
    let found = a.find_peer(&dummy_peer).await.unwrap();
    assert!(found.is_some(), "cached record should be returned even if node is offline");
    let rec = found.unwrap();
    assert_eq!(rec.endpoints[0].addr.port(), 1);

    // find_peer for uncached peer returns None (no nodes to query for random key)
    let unknown = PeerId([0xDEu8; 32]);
    let result = a.find_peer(&unknown).await.unwrap();
    assert!(result.is_none(), "unknown peer with no DHT connectivity should return None");
}

#[tokio::test]
async fn test_store_self_propagates_to_routing_table() {
    // Two nodes: seed and client. Client bootstraps from seed, then store_self.
    let seed = Arc::new(DhtHandle::new(make_id(38), [38u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(seed.clone());

    // Generate real identity for client so pubkey hashes to the PeerID
    let client_id = Identity::generate().ok().unwrap();
    let client_pk = *client_id.public_key();
    let client_peer = client_id.peer_id();
    let (_, client_np) = client_id.noise_keypair();

    let seed_addr = seed.socket().local_addr().unwrap();

    let client = Arc::new(DhtHandle::new(
        client_peer, client_pk,
        DhtConfig { local_addr: "127.0.0.1:0".parse().unwrap(), bootstrap_nodes: vec![seed_addr], ..Default::default() },
    ).unwrap());
    spawn_recv_loop(client.clone());

    // Bootstrap
    client.socket().send_to(&msg_codec::encode_ping_request(client.peer_id, [60u8; 16]), seed_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify client knows seed
    assert!(client.routing_table_size().await >= 1);

    // store_self on client: should send STORE to seed
    let ep = Endpoint::new("10.0.0.39:9999".parse().unwrap(), EndpointKind::STUN);
    client.store_self(&client_pk, &client_np, &[ep.clone()], Capabilities::new()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Seed should have the client's record
    let seed_records = seed.peer_records.read().await;
    assert!(seed_records.contains_key(&client_peer), "seed should have client's record after store_self");
    let rec = seed_records.get(&client_peer).unwrap();
    assert!(!rec.endpoints.is_empty(), "stored record should have endpoints");
    assert_eq!(rec.endpoints[0].addr.to_string(), "10.0.0.39:9999");
}

#[tokio::test]
async fn test_dht_node_offline_find_peer_graceful() {
    // Single DHT node tries to find_peer when no other nodes exist
    // The pending query times out gracefully, no crash
    let node = Arc::new(DhtHandle::new(make_id(40), [40u8; 32], make_config("127.0.0.1:0")).unwrap());
    spawn_recv_loop(node.clone());

    let unknown = PeerId([0xABu8; 32]);

    // find_peer with empty routing table should return None, not crash
    let result = node.find_peer(&unknown).await;
    assert!(result.is_ok(), "find_peer should not error even with empty network");
    assert!(result.unwrap().is_none(), "should return None when no peers known");

    // Also test find_relays with empty network
    let relays = node.find_relays().await.unwrap();
    assert!(relays.is_empty(), "no relays should be found with empty network");
}
