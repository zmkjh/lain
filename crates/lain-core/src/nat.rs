use crate::error::CoreError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum NatType {
    /// 不可达 / 未探测
    Unknown = 0,
    /// Endpoint-Independent Mapping (Cone NAT)
    Cone = 1,
    /// Address-Dependent Filtering + Endpoint-Dependent Mapping
    ADFSymmetric = 2,
    /// Address+Port-Dependent Filtering + Endpoint-Dependent Mapping
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
    pub ipv6_inbound: bool,
    pub mapped_addr: Option<std::net::SocketAddr>,
    /// NAT port delta: difference between mapped ports of adjacent internal ports.
    /// Some(1) means port-preserving (ideal for TSO).
    /// None means couldn't determine.
    pub port_delta: Option<u16>,
    /// STUN round-trip time in milliseconds
    pub stun_rtt_ms: Option<u64>,
}

#[async_trait::async_trait]
pub trait NatProber: Send + Sync {
    async fn probe(&self) -> Result<NatProbeResult, CoreError>;
}
