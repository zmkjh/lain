//! 集成测试：覆盖 QUIC/TCP 连接全路径，确保生产可用。
//! 每个测试启动 2-3 个节点，验证握手、数据收发、并发、断开等场景。

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lain_core::crypto::CryptoProvider;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::frame::FrameType;
use lain_core::identity::IdentityProvider;
use lain_core::peer::PeerId;
use lain_core::transport::{Connection, Transport};
use lain_identity::Identity;
use lain_noise::NoiseProvider;
use lain_transport::{TransportConfig, PeekConnection};

fn init() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct TestNode {
    pub peer_id: PeerId,
    pub noise_pk: [u8; 32],
    pub transport: Arc<dyn Transport>,
}

impl TestNode {
    async fn new() -> Self {
        init();
        let id = Identity::generate().unwrap();
        let peer_id = id.peer_id();
        let (ns, noise_pk) = id.noise_keypair();
        let crypto: Arc<dyn CryptoProvider> = Arc::new(NoiseProvider::new(ns));
        let transport = Arc::new(
            lain_transport::Transport::new(
                TransportConfig { bind_addr: "127.0.0.1:0".parse().unwrap(), ..Default::default() },
                crypto, peer_id,
            ).unwrap()
        );
        Self { peer_id, noise_pk, transport }
    }

    fn endpoint(&self) -> Endpoint {
        let addr = self.transport.local_addr().unwrap();
        Endpoint::new(addr, EndpointKind::STUN)
    }
}

/// 连接两个节点，返回 (conn_a, conn_b)
async fn connect_ab(a: &TestNode, b: &TestNode) -> (Box<dyn Connection>, Box<dyn Connection>) {
    let b_eps = vec![b.endpoint()];
    let b_t = b.transport.clone();
    let b_acc = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(10), b_t.accept()).await.unwrap().unwrap()
    });
    let conn_a = tokio::time::timeout(Duration::from_secs(10),
        a.transport.connect(b.peer_id, &b.noise_pk, &b_eps)
    ).await.unwrap().unwrap();
    let conn_b = b_acc.await.unwrap();
    (conn_a, conn_b)
}

// ── 基础 ──

#[tokio::test]
async fn connect_and_send_one_message() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    conn_a.send(b"ping").await.unwrap();
    let (ft, data) = conn_b.recv().await.unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(data, b"ping");
}

#[tokio::test]
async fn handshake_exchanges_peer_ids() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;
    assert_eq!(conn_a.peer_id(), b.peer_id, "conn_a sees B's PeerID");
    assert_eq!(conn_b.peer_id(), a.peer_id, "conn_b sees A's PeerID");
}

#[tokio::test]
async fn parallel_connect_fallback() {
    // 第一个 endpoint 不可达，第二个可达
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let eps = vec![
        Endpoint::new("127.0.0.1:1".parse().unwrap(), EndpointKind::STUN),
        b.endpoint(),
    ];
    let b_t = b.transport.clone();
    let _h = tokio::spawn(async move { let _ = b_t.accept().await; });
    let conn = a.transport.connect(b.peer_id, &b.noise_pk, &eps).await.unwrap();
    assert_eq!(conn.peer_id(), b.peer_id);
    conn.send(b"ok").await.unwrap();
}

// ── 多消息 ──

#[tokio::test]
async fn multiple_messages_in_order() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    let count = 10;
    for i in 0..count {
        let msg = format!("msg_{i}");
        conn_a.send(msg.as_bytes()).await.unwrap();
    }

    for i in 0..count {
        let (ft, data) = conn_b.recv().await.unwrap();
        assert_eq!(ft, FrameType::Data);
        assert_eq!(data, format!("msg_{i}").as_bytes(), "message {i} in order");
    }
}

#[tokio::test]
async fn large_message_100kb() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    let payload = vec![0xABu8; 102400]; // 100KB
    conn_a.send(&payload).await.unwrap();

    let (ft, data) = conn_b.recv().await.unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(data.len(), 102400);
    assert!(data.iter().all(|&b| b == 0xAB));
}

// ── 双向 ──

#[tokio::test]
async fn bidirectional_messages() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    // 同时发送
    let b_handle = tokio::spawn(async move {
        conn_b.send(b"from B").await.unwrap();
        conn_b.recv().await.unwrap()
    });
    conn_a.send(b"from A").await.unwrap();
    let (ft, data) = conn_a.recv().await.unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(data, b"from B");

    let result = b_handle.await.unwrap();
    assert_eq!(result.0, FrameType::Data);
    assert_eq!(result.1, b"from A");
}

// ── 并发连接 ──

#[tokio::test]
async fn multiple_connections() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let c = TestNode::new().await;

    // A → B 和 A → C 同时进行
    let b_eps = vec![b.endpoint()];
    let c_eps = vec![c.endpoint()];

    let b_t = b.transport.clone();
    let c_t = c.transport.clone();
    let b_acc = tokio::spawn(async move { b_t.accept().await.unwrap() });
    let c_acc = tokio::spawn(async move { c_t.accept().await.unwrap() });

    let conn_ab = a.transport.connect(b.peer_id, &b.noise_pk, &b_eps).await.unwrap();
    let conn_ac = a.transport.connect(c.peer_id, &c.noise_pk, &c_eps).await.unwrap();

    let conn_b = b_acc.await.unwrap();
    let conn_c = c_acc.await.unwrap();

    assert_eq!(conn_ab.peer_id(), b.peer_id);
    assert_eq!(conn_ac.peer_id(), c.peer_id);
    assert_eq!(conn_b.peer_id(), a.peer_id);
    assert_eq!(conn_c.peer_id(), a.peer_id);

    // 各自发一条
    conn_ab.send(b"A->B").await.unwrap();
    conn_ac.send(b"A->C").await.unwrap();
    let (_, d1) = conn_b.recv().await.unwrap();
    let (_, d2) = conn_c.recv().await.unwrap();
    assert_eq!(d1, b"A->B");
    assert_eq!(d2, b"A->C");
}

// ── 关闭 ──

#[tokio::test]
async fn close_terminates_recv() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    conn_a.close();
    // recv 应该很快返回错误
    let result = tokio::time::timeout(Duration::from_secs(5), conn_b.recv()).await;
    assert!(result.is_ok(), "recv should return error quickly after close");
    assert!(result.unwrap().is_err(), "recv should fail after peer closed");
}

// ── 空消息 ──

#[tokio::test]
async fn send_empty_payload() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    conn_a.send(b"").await.unwrap();
    let (ft, data) = conn_b.recv().await.unwrap();
    assert_eq!(ft, FrameType::Data);
    assert!(data.is_empty(), "empty payload should be delivered");
}

// ── PeekConnection ──

#[tokio::test]
async fn peek_connection_buffers_first_message() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    conn_a.send(b"hello peek").await.unwrap();

    let (ft, first) = conn_b.recv().await.unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(first, b"hello peek");

    let peeked = PeekConnection::new(conn_b, first.clone());
    let (ft2, replayed) = peeked.recv().await.unwrap();
    assert_eq!(ft2, FrameType::Data);
    assert_eq!(replayed, first);
}

// ── 生存时间（keepalive）───

#[tokio::test]
async fn connection_survives_idle_period() {
    // 验证连接在无人说话时不会断（QUIC keepalive 15s）
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let (conn_a, conn_b) = connect_ab(&a, &b).await;

    // 等 10s，期间不发任何数据
    tokio::time::sleep(Duration::from_secs(10)).await;

    // 仍然能发数据
    conn_a.send(b"still alive").await.unwrap();
    let (ft, data) = conn_b.recv().await.unwrap();
    assert_eq!(ft, FrameType::Data);
    assert_eq!(data, b"still alive");
}

// ── TSO ──

#[tokio::test]
#[ignore]
async fn tso_handshake() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;

    let tso_eps: Vec<SocketAddr> = (0..8u16).map(|i| {
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 50000 + i)
    }).collect();

    let b_t = b.transport.clone();
    let a_t = a.transport.clone();
    let b_pid = b.peer_id;
    let tso_clone = tso_eps.clone();

    let h = tokio::spawn(async move {
        let _ = tokio::time::timeout(Duration::from_secs(20),
            b_t.connect_tso(a.peer_id, &tso_clone, Some(1), Some(10))
        ).await;
    });

    let conn = match tokio::time::timeout(Duration::from_secs(20),
        a_t.connect_tso(b_pid, &tso_eps, Some(1), Some(10))
    ).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => { h.await.unwrap_or(()); panic!("TSO failed: {e}"); }
        Err(_) => { h.await.unwrap_or(()); panic!("TSO timed out"); }
    };

    assert_eq!(conn.peer_id(), b.peer_id);
    conn.send(b"tso works").await.unwrap();
    h.await.unwrap_or(());
}
