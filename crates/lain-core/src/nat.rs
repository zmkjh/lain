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

/// 对称 NAT 端口预测器。
///
/// 给定 STUN 探测得到的基础端口序列和端口增量规律，预测 NAT 为
/// "下一个新目标"分配的外部端口候选列表。调用方在所有候选中并发
/// 尝试 TCP 连接（birthday attack），命中的端口对完成 TSO 握手。
///
/// # 预留 ML 扩展
///
/// 当前实现 `LinearPredictor` 基于端口增量线性预测（参考 Yamada 2008
/// 论文及 N4 项目）。未来可替换为基于 ML 的预测器（历史模式学习、
/// RTT 相关性建模等），只需实现本 trait，不影响 TSO 其他逻辑。
///
/// ML 预测器可能需要的输入均已包含在 `predict` 签名中：
/// - `base_ports`：观测到的端口序列（可从中学习分配模式）
/// - `port_delta`：当前增量规律（ML 可忽略，自行从序列推理）
/// - `stun_rtt_ms`：网络延迟（可用于自适应调整扫描参数）
pub trait PortPredictor: Send + Sync {
    /// 预测对端 NAT 为"下一个新目标"分配的外部端口候选列表。
    ///
    /// # 参数
    ///
    /// * `base_ports` — 邀请码中已知的 TSO 端口（对端 STUN 映射端口序列）。
    ///   对于端口保持型 NAT，这些端口 ≈ 本地绑定端口。
    /// * `port_delta` — NAT 每遇到一个新目标时的端口增量。
    ///   `None` 表示端口分配不可预测（此时本方法返回空，调用方退回到 relay）。
    /// * `stun_rtt_ms` — 对端到 STUN 服务器的 RTT（毫秒）。
    ///   用于自适应调整扫描策略（未来 ML 预测器使用）。
    ///
    /// # 返回
    ///
    /// 去重后的预测目标端口列表。这些端口代表 NAT 为"下一个新目标"
    /// 可能分配的外部端口。调用方会在此基础上追加 `base_ports` 自身
    /// 作为 fallback（对 Cone NAT 有效）。
    fn predict(
        &self,
        base_ports: &[u16],
        port_delta: Option<u16>,
        stun_rtt_ms: Option<u64>,
    ) -> Vec<u16>;
}
