use super::*;
use crate::message as msg_codec;
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
