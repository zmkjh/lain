#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::nat::PortPredictor;

/// 线性端口预测器：基于 NAT 端口增量规律预测下一目标的外部端口。
///
/// # 算法（参考 Yamada 2008, N4 2024）
///
/// 对称 NAT 为每个新目标 (dst_ip, dst_port) 分配不同的外部端口。
/// 若 STUN 探测到不同服务器获得端口 P、P+d、P+2d，且 d 恒定，
/// 则可推断 NAT 为端口保持型：下一新目标将分配 P+N×d。
///
/// N 代表"本目标在 STUN 之后算第几个新目标"，由于调用方无法确知
/// 对端在 STUN 和 TSO 之间经历了多少次其他连接，本预测器扫描
/// N ∈ [1, max_offset] 的整个范围。
///
/// # 参数选择
///
/// `max_offset` 默认为 20，依据：
/// - N4 项目用 `port_offset=5`，`src_port_count=25` 每轮扫描
/// - Yamada 论文在不可预测时用 ~1000 端口暴力探测
/// - TCP 场景更受限（每连接 5-10s 生命周期，40ms stagger）
/// - 8×21=168 目标端口 + 4~8 本地端口 = 672~1344 对
/// - 102s / 40ms = 2550 spawns — 每对 2~4 次重试，覆盖充分
/// - 远低于 CGNAT flood 阈值（~50-100 SYN/秒 → 25/秒安全）
///
/// # 示例
///
/// ```text
/// base_ports = [50000, 50001, 50002, 50003]  (邀请码中的 4 个 TSO 端口)
/// port_delta = Some(1)
/// max_offset = 20
///
/// 预测输出：
///   50001..50020  (base=50000, N=1..20)
///   50002..50021  (base=50001, N=1..20)
///   50003..50022  (base=50002, N=1..20)
///   50004..50023  (base=50003, N=1..20)
///   去重后约 24 个端口
/// ```
///
/// # 不可预测场景
///
/// `port_delta == None` 时返回空列表。调用方（`connect_tso`）退回到
/// relay fallback；对称 NAT 的随机端口分配在 TCP 层面无法有效暴力探测。
pub struct LinearPredictor {
    /// 预测扫描的最大偏移步数。
    /// N ∈ [1, max_offset] 对应端口 = base_port + N × port_delta。
    max_offset: u16,
}

impl LinearPredictor {
    /// 创建线性预测器。
    ///
    /// `max_offset` 控制每个 base 端口向前扫描的偏移步数。
    /// 默认值 20 适用于大多数场景；降低可减少网络流量，提高可增强覆盖。
    pub fn new(max_offset: u16) -> Self {
        Self { max_offset }
    }
}

impl Default for LinearPredictor {
    fn default() -> Self {
        Self { max_offset: 20 }
    }
}

impl PortPredictor for LinearPredictor {
    fn predict(
        &self,
        base_ports: &[u16],
        port_delta: Option<u16>,
        _stun_rtt_ms: Option<u64>,
    ) -> Vec<u16> {
        let delta = match port_delta {
            Some(d) if d > 0 => d,
            _ => return Vec::new(), // 不可预测 → 返回空，调用方 relay fallback
        };

        let mut predicted = Vec::with_capacity(base_ports.len() * self.max_offset as usize);

        for &base in base_ports {
            for n in 1..=self.max_offset {
                let port = base.wrapping_add(n * delta);
                // 跳过已知的基础端口（避免重复）
                if base_ports.contains(&port) {
                    continue;
                }
                predicted.push(port);
            }
        }

        // 按端口号排序并去重
        predicted.sort();
        predicted.dedup();
        predicted
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn predictable_delta_1() {
        let pred = LinearPredictor::new(5);
        let result = pred.predict(&[50000, 50001], Some(1), None);
        // base=50000: 50001..50005 (skip 50001)
        // base=50001: 50002..50006
        assert_eq!(result, vec![50002, 50003, 50004, 50005, 50006]);
    }

    #[test]
    fn predictable_delta_2() {
        let pred = LinearPredictor::new(3);
        let result = pred.predict(&[50000], Some(2), None);
        assert_eq!(result, vec![50002, 50004, 50006]);
    }

    #[test]
    fn unpredictable_returns_empty() {
        let pred = LinearPredictor::new(10);
        let result = pred.predict(&[50000], None, None);
        assert!(result.is_empty());
    }

    #[test]
    fn delta_zero_returns_empty() {
        let pred = LinearPredictor::new(5);
        let result = pred.predict(&[50000], Some(0), None);
        assert!(result.is_empty());
    }

    #[test]
    fn no_duplicates() {
        let pred = LinearPredictor::new(20);
        let result = pred.predict(&[50000, 50001], Some(1), None);
        let unique: std::collections::HashSet<u16> = result.iter().copied().collect();
        assert_eq!(result.len(), unique.len());
    }
}
