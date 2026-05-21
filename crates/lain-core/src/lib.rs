#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

//! lain-core: 核心类型、trait 接口、协议常量。
//!
//! 本 crate 定义所有其他 crate 共享的基础设施，零外部依赖（除了 thiserror）。
//! 所有网络 I/O 相关的 trait 使用 `async_trait`（可选依赖）或返回 `Future`。

pub mod crypto;
pub mod error;
pub mod identity;
pub mod peer;
pub mod endpoint;
pub mod capabilities;
pub mod dht;
pub mod nat;
pub mod transport;
pub mod frame;

// 协议常量
pub const PROTOCOL_VERSION: u8 = 1;
pub use frame::MAGIC;  // re-export from frame.rs (single source of truth)
pub use nat::PortPredictor;

/// DHT 参数默认值
pub const DHT_K: usize = 20;
pub const DHT_ALPHA: usize = 3;
pub const DHT_TTL_SECS: u32 = 300;
pub const DHT_HEARTBEAT_SECS: u64 = 150;
pub const DHT_REPUBLISH_SECS: u64 = 3600;
pub const DHT_BUCKET_COUNT: usize = 256;

/// 连接参数默认值
pub const CONNECT_TIMEOUT_SECS: u64 = 10;
pub const TRAVERSAL_TIMEOUT_SECS: u64 = 30;
pub const IDLE_TIMEOUT_SECS: u64 = 30;
pub const KEEP_ALIVE_SECS: u64 = 15;
pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_STREAMS_PER_CONN: usize = 128;
pub const MAX_RELAY_STREAMS: usize = 32;

/// Noise IK 握手超时
pub const NOISE_HANDSHAKE_TIMEOUT_SECS: u64 = 15;

/// 移动端适配
pub const MOBILE_IDLE_TIMEOUT_SECS: u64 = 120;
pub const MOBILE_KEEP_ALIVE_SECS: u64 = 60;
pub const MOBILE_DHT_K: usize = 8;
pub const MOBILE_MAX_CONNECTIONS: usize = 64;
pub const MOBILE_MAX_STREAMS_PER_CONN: usize = 32;

/// 入站连接等待应用接受的超时
pub const INCOMING_ACCEPT_TIMEOUT_SECS: u64 = 30;
