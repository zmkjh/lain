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
            p[2] = 0x00; // message length = 8
            p[3] = 0x08;
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
        if data[0] != 0x01 || data[1] != 0x01 {
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
    use std::sync::mpsc;

    /// Mock STUN server that responds with configurable XOR-MAPPED-ADDRESS.
    /// - basic_port: mapped port for plain Binding Request
    /// - change_port: mapped port for CHANGE-REQUEST Binding Request
    /// - reject_change: if true, don't respond to CHANGE-REQUEST (simulates rejection)
    fn start_mock_stun(basic_port: u16, change_port: u16, reject_change: bool) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        std::thread::spawn(move || {
            ready_tx.send(()).ok();
            let cookie: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
            let mut buf = [0u8; 1024];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        // Check if it's a valid STUN Binding Request
                        if len < 20 { continue; }
                        let is_stun = buf[0] == 0x00 && buf[1] == 0x01
                            && buf[4..8] == cookie;
                        if !is_stun { continue; }

                        let has_change = len >= 28
                            && buf[20] == 0x00 && buf[21] == 0x03;

                        if has_change && reject_change {
                            continue; // simulate rejection
                        }

                        let mapped_port = if has_change { change_port } else { basic_port };
                        let mapped_ip: [u8; 4] = [10, 0, 0, 1];

                        // Build STUN Binding Success Response
                        let mut resp = vec![0u8; 32];
                        resp[0] = 0x01; resp[1] = 0x01; // type
                        resp[2] = 0x00; resp[3] = 12;   // length
                        resp[4..8].copy_from_slice(&cookie);
                        resp[8..20].copy_from_slice(&buf[8..20]); // transaction ID
                        // XOR-MAPPED-ADDRESS attribute
                        resp[20] = 0x00; resp[21] = 0x20; // type
                        resp[22] = 0x00; resp[23] = 0x08; // length
                        resp[24] = 0x00;                    // reserved
                        resp[25] = 0x01;                    // IPv4
                        let port_xor = mapped_port ^ u16::from_be_bytes([cookie[0], cookie[1]]);
                        resp[26..28].copy_from_slice(&port_xor.to_be_bytes());
                        for i in 0..4 {
                            resp[28 + i] = mapped_ip[i] ^ cookie[i];
                        }
                        socket.send_to(&resp, src).ok();
                    }
                    Err(_) => break,
                }
            }
        });
        ready_rx.recv_timeout(std::time::Duration::from_secs(1)).ok();
        addr
    }

    // ── NAT type tests ──

    #[test]
    fn test_nat_cone_same_mapped_port() {
        let addr = start_mock_stun(10000, 10000, false);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1))).ok();
        let probe = NatProbe::new(vec![addr], 3);
        let result = probe.probe_with_socket(&socket).unwrap();
        assert_eq!(result.nat_type, NatType::Cone,
            "same port for basic and change → Cone");
        assert!(result.mapped_addr.is_some());
    }

    #[test]
    fn test_nat_apdf_symmetric_single_server() {
        // Single server, different ports → worst case Symmetric (APDF)
        let addr = start_mock_stun(10000, 20000, false);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1))).ok();
        let probe = NatProbe::new(vec![addr], 3);
        let result = probe.probe_with_socket(&socket).unwrap();
        assert_eq!(result.nat_type, NatType::APDFSymmetric,
            "single server with different ports → APDFSymmetric");
    }

    #[test]
    fn test_nat_adf_symmetric_two_servers() {
        // Two servers, all ports differ → ADFSymmetric
        let addr1 = start_mock_stun(10000, 20000, false);
        let addr2 = start_mock_stun(30000, 40000, false);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1))).ok();
        let probe = NatProbe::new(vec![addr1, addr2], 3);
        let result = probe.probe_with_socket(&socket).unwrap();
        assert_eq!(result.nat_type, NatType::ADFSymmetric,
            "two servers with differing ports → ADFSymmetric");
    }

    #[test]
    fn test_nat_change_request_rejected() {
        let addr = start_mock_stun(10000, 20000, true); // reject_change=true
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1))).ok();
        let probe = NatProbe::new(vec![addr], 3);
        let result = probe.probe_with_socket(&socket).unwrap();
        assert_eq!(result.nat_type, NatType::APDFSymmetric,
            "CHANGE-REQUEST rejected → APDFSymmetric");
        assert!(result.mapped_addr.is_some(), "basic probe should still succeed");
    }

    #[test]
    fn test_nat_cone_false_alarm_two_servers() {
        // Server1: basic=10000, change=20000 (looks symmetric)
        // Server2: basic=20000 (same as change port → cone after all)
        let addr1 = start_mock_stun(10000, 20000, false);
        let addr2 = start_mock_stun(20000, 30000, false);
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(1))).ok();
        let probe = NatProbe::new(vec![addr1, addr2], 3);
        let result = probe.probe_with_socket(&socket).unwrap();
        assert_eq!(result.nat_type, NatType::Cone,
            "second server basic == first change port → Cone after all");
    }

    #[test]
    fn test_build_binding_request() {
        let req = NatProbe::build_binding_request(false);
        assert_eq!(req.len(), 20);
        assert_eq!(req[0], 0x00);
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
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        let ip = [192, 168, 1, 1];
        let port: u16 = 1234;
        let port_xor = port ^ u16::from_be_bytes([cookie[0], cookie[1]]);
        let mut data = vec![0u8; 8];
        data[0] = 0;
        data[1] = 0x01;
        data[2..4].copy_from_slice(&port_xor.to_be_bytes());
        for i in 0..4 { data[4 + i] = ip[i] ^ cookie[i]; }
        let result = parse_xor_mapped(&data, &cookie).unwrap();
        assert_eq!(result.port(), port);
    }

    #[test]
    fn test_parse_mapped_address_ipv4() {
        let mut data = vec![0u8; 8];
        data[1] = 0x01;
        data[2..4].copy_from_slice(&8080u16.to_be_bytes());
        data[4..8].copy_from_slice(&[10, 0, 0, 1u8]);
        let result = parse_mapped_address(&data, 8).unwrap();
        assert_eq!(result.port(), 8080);
    }

    #[test]
    fn test_parse_mapped_address_ipv6() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        let mut data = vec![0u8; 20];
        data[1] = 0x02;
        data[2..4].copy_from_slice(&443u16.to_be_bytes());
        data[4..20].copy_from_slice(&ip);
        let result = parse_mapped_address(&data, 20).unwrap();
        assert_eq!(result.port(), 443);
        assert!(result.is_ipv6());
    }

    #[test]
    fn test_parse_mapped_address_rejects_too_short() {
        assert!(parse_mapped_address(&[0u8; 3], 3).is_none());
        let mut data = vec![0u8; 6];
        data[1] = 0x01;
        assert!(parse_mapped_address(&data, 6).is_none());
    }

    #[test]
    fn test_parse_mapped_address_unknown_family() {
        let mut data = vec![0u8; 8];
        data[1] = 0x03;
        assert!(parse_mapped_address(&data, 8).is_none());
    }

    #[test]
    fn test_build_binding_request_with_change() {
        let req = NatProbe::build_binding_request(true);
        assert_eq!(req.len(), 28);
        assert_eq!(&req[20..22], &[0x00, 0x03]);
        assert_eq!(&req[22..24], &[0x00, 0x04]);
        assert_eq!(&req[24..28], &[0x00, 0x00, 0x00, 0x04]);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 8,
            "CHANGE-REQUEST message length must be 8");
    }

    #[test]
    fn test_parse_binding_response_with_mapped_address() {
        let mut msg = vec![0u8; 32];
        msg[0] = 0x01; msg[1] = 0x01;
        msg[2] = 0x00; msg[3] = 12;
        msg[20] = 0x00; msg[21] = 0x01;
        msg[22] = 0x00; msg[23] = 0x08;
        msg[24] = 0; msg[25] = 1;
        msg[26] = 0x1F; msg[27] = 0x90;
        msg[28..32].copy_from_slice(&[192, 168, 1, 100]);
        let result = NatProbe::parse_binding_response(&msg, "1.2.3.4:3478".parse().unwrap());
        let addr = result.unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_parse_binding_response_with_xor_mapped() {
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        let real_ip = [10, 20, 30, 40u8];
        let real_port: u16 = 9999;
        let port_xor = real_port ^ u16::from_be_bytes([cookie[0], cookie[1]]);
        let mut msg = vec![0u8; 32];
        msg[0] = 0x01; msg[1] = 0x01;
        msg[2] = 0x00; msg[3] = 12;
        msg[20] = 0x00; msg[21] = 0x20;
        msg[22] = 0x00; msg[23] = 0x08;
        msg[24] = 0; msg[25] = 1;
        msg[26..28].copy_from_slice(&port_xor.to_be_bytes());
        for i in 0..4 { msg[28 + i] = real_ip[i] ^ cookie[i]; }
        let result = NatProbe::parse_binding_response(&msg, "1.2.3.4:3478".parse().unwrap());
        let addr = result.unwrap();
        assert_eq!(addr.port(), real_port);
    }

    #[test]
    fn test_parse_binding_response_rejects_too_short() {
        assert!(NatProbe::parse_binding_response(&[0u8; 10], "1.2.3.4:3478".parse().unwrap()).is_none());
    }

    #[test]
    fn test_parse_binding_response_fallback_to_stun_addr() {
        let mut msg = vec![0u8; 24];
        msg[0] = 0x01; msg[1] = 0x01;
        msg[2] = 0x00; msg[3] = 4;
        let stun = "8.8.8.8:3478".parse().unwrap();
        let result = NatProbe::parse_binding_response(&msg, stun).unwrap();
        assert_eq!(result, stun);
    }

    #[test]
    fn test_parse_xor_mapped_rejects_ipv6_family() {
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        let mut data = vec![0u8; 20];
        data[1] = 0x02;
        assert!(parse_xor_mapped(&data, &cookie).is_none());
    }

    #[test]
    fn test_parse_xor_mapped_rejects_too_short() {
        assert!(parse_xor_mapped(&[0u8; 3], &[0u8; 4]).is_none());
        let mut data = vec![0u8; 6];
        data[1] = 0x01;
        assert!(parse_xor_mapped(&data, &[0u8; 4]).is_none());
    }
}
