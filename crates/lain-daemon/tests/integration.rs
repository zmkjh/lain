//! 集成测试：测试真实 QUIC/TCP 连接 + Noise 身份验证。
//! 每个测试启动两个节点，验证它们能成功握手并交换数据。

#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use lain_core::crypto::CryptoProvider;
use lain_core::endpoint::{Endpoint, EndpointKind};
use lain_core::identity::IdentityProvider;
use lain_core::peer::PeerId;
use lain_core::transport::{Connection, Transport};
use lain_identity::Identity;
use lain_noise::NoiseProvider;
use lain_transport::{TransportConfig, PeekConnection};

// ── 工具 ──

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

// ── 测试 ──

#[tokio::test]
async fn quic_connect_and_accept() {
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let b_eps = vec![b.endpoint()];

    // B 在后台接受连接
    let b_transport = b.transport.clone();
    let handle = tokio::spawn(async move {
        let conn = tokio::time::timeout(Duration::from_secs(10), b_transport.accept()).await;
        let conn = conn.unwrap().unwrap();
        assert_eq!(conn.peer_id(), a.peer_id, "B receives A's PeerID from handshake");
        conn
    });

    // A 连接 B
    let conn_a = tokio::time::timeout(Duration::from_secs(10),
        a.transport.connect(b.peer_id, &b.noise_pk, &b_eps)
    ).await.unwrap().unwrap();

    assert_eq!(conn_a.peer_id(), b.peer_id, "A receives B's PeerID from handshake");

    // 双向发送数据
    let msg = b"hello quic";
    conn_a.send(msg).await.unwrap();

    let conn_b = handle.await.unwrap();
    let received = conn_b.recv().await.unwrap();
    assert_eq!(received, msg);
}

#[tokio::test]
async fn quic_parallel_connect() {
    // 两个 endpoint，第二个可达 — 验证 parallel select 能选到正确的
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let b_eps = vec![
        Endpoint::new("127.0.0.1:1".parse().unwrap(), EndpointKind::STUN), // unreachable
        b.endpoint(), // reachable
    ];

    let b_t = b.transport.clone();
    let _h = tokio::spawn(async move { let _ = b_t.accept().await; });

    let conn = tokio::time::timeout(Duration::from_secs(10),
        a.transport.connect(b.peer_id, &b.noise_pk, &b_eps)
    ).await.unwrap().unwrap();

    assert_eq!(conn.peer_id(), b.peer_id);
    conn.send(b"parallel").await.unwrap();
}

#[tokio::test]
async fn peek_connection_replays_first_message() {
    // PeekConnection 应该缓存第一次 recv 的消息
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let b_eps = vec![b.endpoint()];

    let b_t = b.transport.clone();
    let h = tokio::spawn(async move {
        let conn = b_t.accept().await.unwrap();
        conn.send(b"hello peek").await.unwrap();
        // Keep connection alive until test completes
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let conn = tokio::time::timeout(Duration::from_secs(10),
        a.transport.connect(b.peer_id, &b.noise_pk, &b_eps)
    ).await.unwrap().unwrap();

    // 模拟 daemon accept handler: 先 recv(), 再 wrap 成 PeekConnection
    let first = conn.recv().await.unwrap();
    assert_eq!(&first, b"hello peek", "first message should be payload, not frame");

    let _peeked = PeekConnection::new(conn, first.clone());
    // peeked 第一次 recv 应该返回缓存的消息
    let replayed = _peeked.recv().await.unwrap();
    assert_eq!(replayed, first);

    h.await.unwrap();
}

/// TSO 需要双方同时 bind+connect，在 localhost 上端口竞争导致不可靠。
/// 在真实网络（不同 IP）上工作正常。
#[tokio::test]
#[ignore]
async fn tso_handshake() {
    // 测试 TSO 连接（TCP simultaneous open）
    let a = TestNode::new().await;
    let b = TestNode::new().await;
    let b_addr = b.transport.local_addr().unwrap();
    let a_addr = a.transport.local_addr().unwrap();

    // TSO 需要双方同时 connect
    let b_t = b.transport.clone();
    let a_t = a.transport.clone();
    let b_pid = b.peer_id;

    tokio::spawn(async move {
        // B 发起到 A 的 TSO
        let _ = tokio::time::timeout(Duration::from_secs(15),
            b_t.connect_tso(a.peer_id, &[a_addr], None, None)
        ).await;
    });

    let conn = tokio::time::timeout(Duration::from_secs(15),
        a_t.connect_tso(b_pid, &[b_addr], None, None)
    ).await.unwrap().unwrap();

    assert_eq!(conn.peer_id(), b.peer_id);
    conn.send(b"tso works").await.unwrap();
}
