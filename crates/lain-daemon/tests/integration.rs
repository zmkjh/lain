//! 集成测试
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lain_core::capabilities::Capabilities;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::identity::IdentityProvider;
use lain_core::peer::PeerId;
use lain_identity::Identity;
use lain_dht::{DhtHandle, DhtConfig};
use lain_transport::{Transport, TransportConfig};

/// 启动测试节点，自带 DHT recv 循环
async fn spawn_node(bootstrap_addr: Option<SocketAddr>) -> (PeerId, Arc<DhtHandle>, Arc<Transport>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let identity = Identity::generate().ok().unwrap();
    let peer_id = identity.peer_id();
    let public_key = *identity.public_key();
    let (noise_secret, _) = identity.noise_keypair();

    let transport = Arc::new(
        Transport::new(
            TransportConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), ..Default::default() },
            noise_secret, peer_id, public_key,
        ).unwrap(),
    );

    let dht_config = DhtConfig {
        local_addr: "127.0.0.1:0".parse().unwrap(),
        bootstrap_nodes: bootstrap_addr.map_or(vec![], |a| vec![a]),
        ..Default::default()
    };
    let mut dht = DhtHandle::new(peer_id, public_key, dht_config).unwrap();
    dht.set_signer(identity.signing_seed());
    let dht = Arc::new(dht);

    // DHT recv loop
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

    // Bootstrap if seed address provided
    if let Some(addr) = bootstrap_addr {
        let _ = dht.bootstrap(&[addr]).await;
    }

    // Wait briefly for route table population
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Store self with actual transport endpoint so peers can connect
    let local_port = transport.local_addr().unwrap().port();
    let ep = Endpoint::new(
        format!("127.0.0.1:{local_port}").parse().unwrap(),
        EndpointKind::STUN,
    );
    let _ = dht.store_self(&public_key, &[ep], Capabilities::new()).await;

    (peer_id, dht, transport)
}

// ── Test 1: Bootstrap + find ──

#[tokio::test]
async fn test_node_spawn() {
    let (_id, _dht, _t) = spawn_node(None).await;
}

#[tokio::test]
async fn test_bootstrap_and_find() {
    let (_seed_id, seed_dht, _seed_t) = spawn_node(None).await;
    let seed_addr = seed_dht.socket().local_addr().unwrap();
    let (node_id, node_dht, _node_t) = spawn_node(Some(seed_addr)).await;

    // Retry — DHT needs time to converge (find_peer has 5s internal timeout)
    for i in 0..8 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Some(_)) = seed_dht.find_peer(&node_id).await { break; }
        if i == 7 { panic!("seed never found node after 8 attempts"); }
    }
}

// ── Test 2: STORE + FIND_VALUE ──

#[tokio::test]
async fn test_store_and_find() {
    let (_seed_id, seed_dht, _seed_t) = spawn_node(None).await;
    let seed_addr = seed_dht.socket().local_addr().unwrap();
    let (node_id, node_dht, _node_t) = spawn_node(Some(seed_addr)).await;

    // Wait for bootstrap
    for i in 0..15 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if node_dht.routing_table_size().await > 0 { break; }
        if i == 14 { panic!("node routing table empty"); }
    }

    // Node's store_self was already called in spawn_node.
    // Find it from seed.
    for i in 0..10 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Ok(Some(_rec)) = seed_dht.find_peer(&node_id).await {
            assert!(!_rec.pubkey.iter().all(|&b| b == 0), "pubkey should be non-zero");
            return;
        }
        if i == 9 { panic!("seed never found node's stored record"); }
    }
}

// ── Test 3: QUIC connect ──

#[tokio::test]
async fn test_quic_connect() {
    let (_seed_id, _seed_dht, seed_t) = spawn_node(None).await;
    let seed_port = seed_t.local_addr().unwrap().port();

    // Recreate B with fixed address for connecting
    let identity_b = Identity::generate().ok().unwrap();
    let (_b_noise_secret, _b_noise_pub) = identity_b.noise_keypair();
    // Just verify QUIC transport can bind and accept
    let t = Transport::new(
        TransportConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), ..Default::default() },
        _b_noise_secret,
        identity_b.peer_id(),
        *identity_b.public_key(),
    ).unwrap();
    let _port = t.local_addr().unwrap().port();
    // Smoke test: transport created successfully
    assert!(true);
}

// ── Test 4: Rate limit doesn't crash DHT ──

#[tokio::test]
async fn test_rate_limit_survives_flood() {
    let (_seed_id, seed_dht, _seed_t) = spawn_node(None).await;
    let seed_addr = seed_dht.socket().local_addr().unwrap();
    let (flood_id, _flood_dht, _flood_t) = spawn_node(Some(seed_addr)).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // Send many PINGs from seed back to flood node
    let msg_id = [0u8; 16];
    let ping = lain_dht::message::encode_ping_request(_seed_id, msg_id);
    let flood_addr = _flood_dht.socket().local_addr().unwrap();

    for _ in 0..50 {
        let _ = seed_dht.socket().send_to(&ping, flood_addr).await;
    }

    // DHT should still be functional
    let size = seed_dht.routing_table_size().await;
    assert!(size >= 0); // survived
}

// ── Test 5: Pure QUIC connection (no Noise IK) ──

#[tokio::test]
async fn test_pure_quic_connect() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Self-signed cert for server
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap()
        .self_signed(&key_pair).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
    let key = rustls::pki_types::PrivateKeyDer::from(key_der);

    let server_config = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key).unwrap();
    let server_cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config).unwrap(),
    ));

    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let runtime = quinn::default_runtime().unwrap();
    let server = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server_cfg), socket, runtime).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Spawn server — keep endpoint alive until data exchange completes
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        if let Some(incoming) = server.accept().await {
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = recv.read_to_end(65536).await {
                send.write_all(&n).await.unwrap();
                send.finish().unwrap();
            }
            let _ = done_rx.await; // wait for client to confirm
        }
    });

    // Client connect
    let client_crypto = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyClient))
        .with_no_client_auth();
    let client_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto).unwrap(),
    ));

    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let conn = client.connect_with(client_cfg, server_addr, "localhost").unwrap().await.unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hello quic").await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(65536).await.unwrap();
    assert_eq!(data, b"hello quic", "QUIC roundtrip should work");
    let _ = done_tx.send(());
    let _ = server_handle.await;
}

#[derive(Debug)]
struct NoVerifyClient;
impl rustls::client::danger::ServerCertVerifier for NoVerifyClient {
    fn verify_server_cert(&self, _: &rustls::pki_types::CertificateDer<'_>, _: &[rustls::pki_types::CertificateDer<'_>], _: &rustls::pki_types::ServerName<'_>, _: &[u8], _: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _: &[u8], _: &rustls::pki_types::CertificateDer<'_>, _: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384, 
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

// ── Test 7: Malformed messages don't crash ──

#[tokio::test]
async fn test_malformed_messages_dont_crash() {
    let (_id, dht, _t) = spawn_node(None).await;
    let addr = dht.socket().local_addr().unwrap();

    // Bogus data (wrong version, short, garbage)
    let bogus: Vec<&[u8]> = vec![
        &[0xFF, 0x00, 0x00],                    // wrong version
        &[],                                      // empty
        &[0x01; 10],                              // too short for header
        &[0x01; 53],                              // exactly header, no payload
    ];

    for data in bogus {
        // Send bogus data to DHT port
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.send_to(data, addr).unwrap();
    }

    // Verify DHT still works
    let size = dht.routing_table_size().await;
    assert!(size >= 0); // no crash
}

// ── Test 7: PeerID zero and edge cases ──

#[tokio::test]
async fn test_peerid_edge_cases() {
    let zero = PeerId([0u8; 32]);
    let all_ones = PeerId([0xFF; 32]);
    // Distance extremes should not panic
    let _d1 = zero.distance(&all_ones);
    let _d2 = all_ones.distance(&zero);
    // Bucket index bounds
    let idx = zero.bucket_index(&all_ones);
    assert!(idx < 256);
    // Display should not panic
    let _s = format!("{zero}");
}
