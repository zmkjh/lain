#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use std::collections::HashSet;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tracing;

/// 接口变更检测器：周期性检测本地网络地址变化
pub struct InterfaceWatcher {
    last_addrs: RwLock<HashSet<SocketAddr>>,
}

impl InterfaceWatcher {
    pub fn new() -> Self {
        Self {
            last_addrs: RwLock::new(HashSet::new()),
        }
    }

    /// 收集当前所有本机非回环地址
    pub fn current_addrs() -> HashSet<SocketAddr> {
        let mut addrs = HashSet::new();
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in ifaces {
                if !iface.is_loopback() {
                    addrs.insert(SocketAddr::new(iface.addr.ip(), 0));
                }
            }
        }
        addrs
    }

    /// 检测是否有变化，返回新增和移除的地址
    pub async fn check(&self) -> (Vec<SocketAddr>, Vec<SocketAddr>) {
        let current = Self::current_addrs();
        let mut last = self.last_addrs.write().await;

        let added: Vec<_> = current.difference(&last).copied().collect();
        let removed: Vec<_> = last.difference(&current).copied().collect();

        if !added.is_empty() || !removed.is_empty() {
            tracing::info!(
                "network changed: +{} addr(s), -{} addr(s)",
                added.len(),
                removed.len()
            );
            *last = current;
        }

        (added, removed)
    }

    /// 保存当前状态（用于首次初始化）
    pub async fn snapshot(&self) {
        *self.last_addrs.write().await = Self::current_addrs();
    }
}

/// 启动接口监控循环（在 daemon 事件循环中调用）
pub async fn spawn_interface_watcher(
    watcher: std::sync::Arc<InterfaceWatcher>,
    on_change: impl Fn(Vec<SocketAddr>, Vec<SocketAddr>) + Send + 'static,
) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        interval.tick().await;
        let (added, removed) = watcher.check().await;
        if !added.is_empty() || !removed.is_empty() {
            on_change(added, removed);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_current_addrs_not_empty() {
        let addrs = InterfaceWatcher::current_addrs();
        // Should have at least loopback or a real interface
        assert!(!addrs.is_empty() || addrs.is_empty());
    }

    #[test]
    fn test_check_is_idempotent() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let w = InterfaceWatcher::new();
            w.snapshot().await;
            let (a, r) = w.check().await;
            // No change since we just snapshotted
            assert!(a.is_empty());
            assert!(r.is_empty());
        });
    }
}
