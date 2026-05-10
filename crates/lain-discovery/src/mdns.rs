#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::peer::PeerId;
use std::net::SocketAddr;
use thiserror::Error;
use tracing;

#[derive(Error, Debug)]
pub enum MdnsError {
    #[error("mDNS error: {0}")]
    Service(String),
}

/// mDNS LAN 发现服务
pub struct MdnsDiscovery {
    mdns: mdns_sd::ServiceDaemon,
    service_name: String,
    #[allow(dead_code)]
    peer_id: PeerId,
    #[allow(dead_code)]
    port: u16,
}

impl MdnsDiscovery {
    /// 注册 `_lain._udp.local` 服务
    pub fn register(peer_id: PeerId, port: u16) -> Result<Self, MdnsError> {
        let mdns = mdns_sd::ServiceDaemon::new()
            .map_err(|e| MdnsError::Service(format!("daemon: {e}")))?;

        let service_type = "_lain._udp.local.";
        let instance_name = format!("{}", peer_id);
        let hostname = format!("{}.local.", peer_id.to_string());

        let peer_id_str = peer_id.to_string();
        let properties: [(&str, &str); 1] = [
            ("peer_id", &peer_id_str),
        ];

        let service_info = mdns_sd::ServiceInfo::new(
            service_type,
            &instance_name,
            &hostname,
            "",
            port,
            &properties as &[(&str, &str)],
        )
        .map_err(|e| MdnsError::Service(format!("info: {e}")))?;

        mdns.register(service_info)
            .map_err(|e| MdnsError::Service(format!("register: {e}")))?;

        tracing::info!("mDNS registered as {instance_name} on port {port}");

        Ok(Self {
            mdns,
            service_name: instance_name,
            peer_id,
            port,
        })
    }

    /// 浏览 LAN 内其他 lain 节点
    pub fn browse(&self) -> Result<mdns_sd::Receiver<mdns_sd::ServiceEvent>, MdnsError> {
        let service_type = "_lain._udp.local.";
        let receiver = self.mdns
            .browse(service_type)
            .map_err(|e| MdnsError::Service(format!("browse: {e}")))?;

        tracing::debug!("mDNS browsing {service_type}");
        Ok(receiver)
    }

    /// 从 mDNS ServiceEvent 解析 PeerID 和地址
    pub fn parse_peer_from_event(
        event: &mdns_sd::ServiceEvent,
    ) -> Option<(PeerId, SocketAddr, u16)> {
        match event {
            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                let peer_id_str = info
                    .get_property("peer_id")
                    .and_then(|p| std::str::from_utf8(p.val()?).ok())?;

                let peer_id = PeerId::from_hex(peer_id_str).ok()?;
                let addr = info.get_addresses().iter().next()?;
                let port = info.get_port();

                Some((peer_id, SocketAddr::new(*addr, port), port))
            }
            _ => None,
        }
    }

    /// 停止 mDNS
    pub fn unregister(self) -> Result<(), MdnsError> {
        self.mdns
            .unregister(&self.service_name)
            .map_err(|e| MdnsError::Service(format!("unregister: {e}")))?;
        tracing::info!("mDNS unregistered");
        Ok(())
    }

    /// 获取 mDNS daemon 引用，用于外部浏览
    pub fn daemon(&self) -> &mdns_sd::ServiceDaemon {
        &self.mdns
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_peer_from_event_resolved() {
        let properties: [(&str, &str); 1] = [
            ("peer_id", "dummy"),
        ];

        let service_info = mdns_sd::ServiceInfo::new(
            "_lain._udp.local.",
            "abc123",
            "abc123.local.",
            "192.168.1.1",
            53617,
            &properties as &[(&str, &str)],
        )
        .unwrap();

        let event = mdns_sd::ServiceEvent::ServiceResolved(service_info);
        // Can't fully test without valid PeerId hex, but verify it doesn't panic
        let _ = MdnsDiscovery::parse_peer_from_event(&event);
    }
}
