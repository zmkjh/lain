use crate::error::CoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NatType {
    Unknown = 0,
    Cone = 1,
    ADFSymmetric = 2,
    APDFSymmetric = 3,
}

impl NatType {
    pub fn is_symmetric(self) -> bool {
        matches!(self, NatType::ADFSymmetric | NatType::APDFSymmetric)
    }
    pub fn is_apdf(self) -> bool {
        matches!(self, NatType::APDFSymmetric)
    }
}

/// NAT 类型探测结果
#[derive(Clone, Debug)]
pub struct NatProbeResult {
    pub nat_type: NatType,
    /// IPv6 协议栈是否可用（可绑定 loopback）
    pub ipv6_inbound: bool,
    /// 全局可路由的 IPv6 地址（2000::/3），如果有则 ipv6_inbound 也为 true
    pub ipv6_addr: Option<std::net::Ipv6Addr>,
    pub mapped_addr: Option<std::net::SocketAddr>,
    pub port_delta: Option<u16>,
    pub stun_rtt_ms: Option<u64>,
}

#[async_trait::async_trait]
pub trait NatProber: Send + Sync {
    async fn probe(&self) -> Result<NatProbeResult, CoreError>;
}
