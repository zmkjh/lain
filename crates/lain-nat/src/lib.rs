#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use async_trait::async_trait;
use lain_core::error::CoreError;
use lain_core::nat::{NatProbeResult, NatProber, NatType};
use std::net::{SocketAddr, UdpSocket};
use thiserror::Error;
use tracing;

#[derive(Error, Debug)]
pub enum NatError {
    #[error("STUN probe failed: {0}")]
    StunProbeFailed(String),
    #[error("DHT reflection failed: {0}")]
    DhtReflectionFailed(String),
    #[error("no STUN servers available")]
    NoStunServers,
    #[error("network error: {0}")]
    NetworkError(String),
}

pub struct NatProbe {
    stun_servers: Vec<SocketAddr>,
    timeout: std::time::Duration,
}

impl NatProbe {
    pub fn new(stun_servers: Vec<SocketAddr>, timeout_secs: u64) -> Self {
        Self {
            stun_servers,
            timeout: std::time::Duration::from_secs(timeout_secs),
        }
    }
}

#[async_trait]
impl NatProber for NatProbe {
    async fn probe(&self) -> Result<NatProbeResult, CoreError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
        socket.set_read_timeout(Some(self.timeout))
            .map_err(|e| CoreError::InvalidEndpoint(format!("set timeout: {e}")))?;

        let result = self.probe_with_socket(&socket)?;

        Ok(result)
    }
}

impl NatProbe {
    fn probe_with_socket(&self, socket: &UdpSocket) -> Result<NatProbeResult, CoreError> {
        if self.stun_servers.is_empty() {
            return Ok(NatProbeResult {
                nat_type: NatType::Unknown,
                ipv6_inbound: false,
                mapped_addr: None,
            });
        }

        // RFC 5780 simplified:
        // 1. Basic Binding Request → (ip, port)
        // 2. CHANGE-REQUEST Binding Request → (ip2, port2)
        // 3. If port == port2 → Cone, else → Symmetric

        let mut nat_type = NatType::Unknown;
        let mut mapped_addr = None;

        // Probe 1: Basic Binding Request
        for stun_addr in &self.stun_servers {
            if let Ok(addr) = self.probe_stun(socket, *stun_addr, false) {
                mapped_addr = Some(addr);
                // Probe 2: CHANGE-REQUEST to the same server
                if let Ok(addr2) = self.probe_stun(socket, *stun_addr, true) {
                    if addr.port() == addr2.port() {
                        nat_type = NatType::Cone;
                    } else {
                        // Different port: Symmetric (EDM)
                        // Try to distinguish ADF vs APDF with a second server
                        nat_type = if self.stun_servers.len() > 1 {
                            let second = self.stun_servers[1];
                            if let Ok(addr3) = self.probe_stun(socket, second, false) {
                                if addr3.port() == addr2.port() {
                                    // Same mapped port to different destination → Cone after all
                                    NatType::Cone
                                } else {
                                    // Cross-server port differs: Symmetric
                                    // Assume ADFSymmetric if single IP pool, else APDFSymmetric
                                    NatType::ADFSymmetric
                                }
                            } else {
                                NatType::ADFSymmetric
                            }
                        } else {
                            // Single server: cannot distinguish, assume APDF (worst case)
                            NatType::APDFSymmetric
                        };
                    }
                } else {
                    // CHANGE-REQUEST rejected → likely Symmetric
                    nat_type = NatType::APDFSymmetric;
                }
                break; // Successfully probed first server
            }
        }

        Ok(NatProbeResult {
            nat_type,
            ipv6_inbound: self.check_ipv6(),
            mapped_addr,
        })
    }

    fn probe_stun(
        &self,
        socket: &UdpSocket,
        stun_addr: SocketAddr,
        change_request: bool,
    ) -> Result<SocketAddr, CoreError> {
        let binding_request = Self::build_binding_request(change_request);

        socket
            .send_to(&binding_request, stun_addr)
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;

        let mut buf = [0u8; 1024];
        let (len, _src) = socket
            .recv_from(&mut buf)
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;

        let addr = Self::parse_binding_response(&buf[..len], stun_addr)
            .ok_or_else(|| CoreError::InvalidEndpoint("STUN parse failed".into()))?;

        Ok(addr)
    }

    fn build_binding_request(change_request: bool) -> Vec<u8> {
        let mut packet = if change_request {
            // With CHANGE-REQUEST attribute (type 0x0003, length 4)
            let mut p = vec![0u8; 28];
            p[20] = 0x00; // CHANGE-REQUEST
            p[21] = 0x03;
            p[22] = 0x00; // length
            p[23] = 0x04;
            p[24] = 0x00; // change IP flag
            p[25] = 0x00;
            p[26] = 0x00;
            p[27] = 0x04; // change port flag
            p
        } else {
            vec![0u8; 20]
        };
        packet[0] = 0x00; // Binding Request
        packet[1] = 0x01;
        packet[4] = 0x21; // Magic cookie
        packet[5] = 0x12;
        packet[6] = 0xA4;
        packet[7] = 0x42;
        for i in 8..20 {
            if i >= packet.len() { break; }
            packet[i] = rand::random::<u8>();
        }
        packet
    }

    fn parse_binding_response(data: &[u8], stun_addr: SocketAddr) -> Option<SocketAddr> {
        if data.len() < 20 {
            return None;
        }
        if data[0] != 0x01 && data[0] != 0x01 {
            return None;
        }
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let mut offset = 20usize;
        let end = (20 + msg_len).min(data.len());

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if attr_type == 0x0001 {
                // MAPPED-ADDRESS
                if offset + 4 > data.len() {
                    break;
                }
                let addr = parse_mapped_address(&data[offset..], attr_len)?;
                return Some(addr);
            } else if attr_type == 0x0020 {
                // XOR-MAPPED-ADDRESS
                if offset + 4 > data.len() {
                    break;
                }
                let cookie = [0x21, 0x12, 0xA4, 0x42];
                let addr = parse_xor_mapped(&data[offset..offset + attr_len], &cookie)?;
                return Some(addr);
            }

            offset += attr_len;
            while offset % 4 != 0 {
                offset += 1;
            }
        }

        // Fallback: if we can't parse, use stun server as reference
        Some(stun_addr)
    }

    fn check_ipv6(&self) -> bool {
        match UdpSocket::bind("[::1]:0") {
            Ok(_) => true,
            Err(_) => {
                tracing::debug!("IPv6 not available on this host");
                false
            }
        }
    }
}

fn parse_mapped_address(data: &[u8], _len: usize) -> Option<SocketAddr> {
    if data.len() < 6 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);
    if family == 0x01 {
        // IPv4
        if data.len() < 8 {
            return None;
        }
        let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
    } else if family == 0x02 {
        // IPv6
        if data.len() < 20 {
            return None;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&data[4..20]);
        let ip = std::net::Ipv6Addr::from(ip_bytes);
        Some(SocketAddr::new(std::net::IpAddr::V6(ip), port))
    } else {
        None
    }
}

fn parse_xor_mapped(data: &[u8], cookie: &[u8; 4]) -> Option<SocketAddr> {
    if data.len() < 6 {
        return None;
    }
    let family = data[1];
    let port_xor = u16::from_be_bytes([data[2], data[3]]);
    let port = port_xor ^ u16::from_be_bytes([cookie[0], cookie[1]]);

    if family == 0x01 {
        if data.len() < 8 {
            return None;
        }
        let mut ip_xor = [data[4], data[5], data[6], data[7]];
        for i in 0..4 {
            ip_xor[i] ^= cookie[i];
        }
        let ip = std::net::Ipv4Addr::new(ip_xor[0], ip_xor[1], ip_xor[2], ip_xor[3]);
        Some(SocketAddr::new(std::net::IpAddr::V4(ip), port))
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let req = NatProbe::build_binding_request(false);
        assert_eq!(req.len(), 20);
        assert_eq!(req[0], 0x00); // Binding Request
        assert_eq!(req[1], 0x01);
    }

    #[test]
    fn test_probe_with_no_servers() {
        let probe = NatProbe::new(vec![], 5);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let result = probe.probe_with_socket(&socket).unwrap();
        assert_eq!(result.nat_type, NatType::Unknown);
    }

    #[test]
    fn test_parse_xor_mapped_basic() {
        // Test XOR-MAPPED-ADDRESS parsing
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        let ip = [192, 168, 1, 1];
        let port: u16 = 1234;
        let port_xor = port ^ u16::from_be_bytes([cookie[0], cookie[1]]);
        let mut data = vec![0u8; 8];
        data[0] = 0;
        data[1] = 0x01; // IPv4
        data[2..4].copy_from_slice(&port_xor.to_be_bytes());
        for i in 0..4 {
            data[4 + i] = ip[i] ^ cookie[i];
        }
        let result = parse_xor_mapped(&data, &cookie).unwrap();
        assert_eq!(result.port(), port);
    }
}
