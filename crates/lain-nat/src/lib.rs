#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::error::CoreError;
use lain_core::nat::{NatProbeResult, NatProber, NatType};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub struct NatProbe {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl NatProbe {
    pub fn new(servers: Vec<SocketAddr>, timeout_secs: u64) -> Self {
        Self { servers, timeout: Duration::from_secs(timeout_secs) }
    }
}

/// STUN probe 的一次尝试结果
struct ProbeAttempt {
    mapped: SocketAddr,
    rtt: Duration,
}

impl NatProbe {
    fn bind_socket(&self) -> Result<UdpSocket, CoreError> {
        let s = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
        s.set_read_timeout(Some(self.timeout))
            .map_err(|e| CoreError::InvalidEndpoint(e.to_string()))?;
        Ok(s)
    }

    /// 向单个 STUN server 发 Binding Request，返回 mapped address，重试 1 次
    fn stun_once(&self, socket: &UdpSocket, server: SocketAddr) -> Option<ProbeAttempt> {
        for _ in 0..2 {
            let start = Instant::now();
            let req = build_binding_request();
            if socket.send_to(&req, server).is_err() { continue; }

            let mut buf = [0u8; 1024];
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    if let Some(addr) = parse_mapped(&buf[..len]) {
                        return Some(ProbeAttempt { mapped: addr, rtt: start.elapsed() });
                    }
                }
                Err(_) => continue,
            }
        }
        None
    }

    fn ipv6_status() -> (bool, Option<std::net::Ipv6Addr>) {
        let v6_avail = UdpSocket::bind("[::1]:0").is_ok();
        let global = if v6_avail {
            if_addrs::get_if_addrs().ok().and_then(|ifs| {
                    ifs.into_iter().find_map(|i| match i.addr {
                        if_addrs::IfAddr::V6(v6)
                            if !v6.ip.is_loopback()
                               && (v6.ip.segments()[0] & 0xE000) == 0x2000 =>
                            Some(v6.ip),
                        _ => None,
                    })
                })
        } else { None };
        (v6_avail, global)
    }
}

#[async_trait::async_trait]
impl NatProber for NatProbe {
    async fn probe(&self) -> Result<NatProbeResult, CoreError> {
        let socket = self.bind_socket()?;

        // 向每个 server 发 Binding Request，收集 mapped address
        let mut results: Vec<ProbeAttempt> = Vec::new();
        let mut rtt_total: u64 = 0;

        for &server in &self.servers {
            if let Some(a) = self.stun_once(&socket, server) {
                rtt_total += a.rtt.as_millis() as u64;
                results.push(a);
            }
            if results.len() >= 2 { break; } // 2 个 server 足够判断
        }

        if results.is_empty() {
            let status = Self::ipv6_status();
            return Ok(NatProbeResult {
                nat_type: NatType::Unknown,
                ipv6_inbound: status.0,
                ipv6_addr: status.1,
                mapped_addr: None,
                port_delta: None,
                stun_rtt_ms: None,
            });
        }

        let rtt = rtt_total / results.len() as u64;
        let base = results[0].mapped;

        // 判断 endpoint-independent vs endpoint-dependent mapping
        //
        // 原理：向不同服务器发送 Binding Request。
        //   - 所有服务器返回的 mapped address 相同 → EIM (Cone)
        //   - 返回的 IP 相同但 port 不同 → EDM (Symmetric)
        let all_same = results.iter().all(|r| r.mapped == base);
        let ip_same = results.iter().all(|r| r.mapped.ip() == base.ip());

        // 端口 delta
        let deltas: Vec<u16> = if results.len() >= 2 {
            results.windows(2).filter_map(|w| {
                let d = w[0].mapped.port().abs_diff(w[1].mapped.port());
                if d > 0 { Some(d) } else { None }
            }).collect()
        } else { vec![] };

        let port_delta = if deltas.iter().all(|&d| d == 1) { Some(1) }
            else if deltas.windows(2).all(|w| w[0] == w[1]) { deltas.first().copied() }
            else { None };

        // Filtering behavior: from single server data we can't determine ADF vs APDF.
        // The simpler classification (Cone vs Symmetric) is sufficient for routing.
        // ADF vs APDF only affects whether same-IP-different-port can reach us,
        // which doesn't change our layer 1/2/3 strategy.
        // Default to ADFSymmetric (less conservative than APDF) when EDM detected.
        let nat_type = if all_same { NatType::Cone }
                       else if ip_same { NatType::ADFSymmetric }
                       else { NatType::APDFSymmetric };

        let status = Self::ipv6_status();
        Ok(NatProbeResult {
            nat_type,
            ipv6_inbound: status.0,
            ipv6_addr: status.1,
            mapped_addr: Some(base),
            port_delta,
            stun_rtt_ms: Some(rtt),
        })
    }
}

// ── STUN wire format ──

fn build_binding_request() -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x00; p[1] = 0x01; // Binding Request
    p[2] = 0x00; p[3] = 0x00; // message length
    p[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    for i in 8..20 { p[i] = rand::random::<u8>(); } // transaction ID
    p
}

fn parse_mapped(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 20 { return None; }
    if data[0] != 0x01 || data[1] != 0x01 { return None; } // not a response

    let cookie = [0x21, 0x12, 0xA4, 0x42];
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let end = (20 + msg_len).min(data.len());
    let mut off = 20usize;

    while off + 4 <= end {
        let ty = u16::from_be_bytes([data[off], data[off + 1]]);
        let len = u16::from_be_bytes([data[off + 2], data[off + 3]]) as usize;
        off += 4;
        let val_end = (off + len).min(data.len());

        if ty == 0x0001 || ty == 0x0020 {
            // MAPPED-ADDRESS (0x0001) or XOR-MAPPED-ADDRESS (0x0020)
            if val_end < off + 4 { return None; }
            let family = data[off + 1];
            let port_raw = u16::from_be_bytes([data[off + 2], data[off + 3]]);
            let port = if ty == 0x0020 { port_raw ^ u16::from_be_bytes([cookie[0], cookie[1]]) } else { port_raw };

            if family == 0x01 {
                // IPv4
                if val_end < off + 8 { return None; }
                let ip = if ty == 0x0020 {
                    std::net::Ipv4Addr::new(
                        data[off + 4] ^ cookie[0], data[off + 5] ^ cookie[1],
                        data[off + 6] ^ cookie[2], data[off + 7] ^ cookie[3],
                    )
                } else {
                    std::net::Ipv4Addr::new(data[off + 4], data[off + 5], data[off + 6], data[off + 7])
                };
                return Some(SocketAddr::new(std::net::IpAddr::V4(ip), port));
            }
            // IPv6 not handled for simplicity — STUN servers typically communicate over v4
        }

        off = val_end;
        while off % 4 != 0 { off += 1; }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn mock_stun(port: u16, ip: [u8; 4]) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let cookie = [0x21, 0x12, 0xA4, 0x42];
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            tx.send(()).ok();
            let mut buf = [0u8; 1024];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        if len < 20 { continue; }
                        let port_xor = port ^ u16::from_be_bytes([cookie[0], cookie[1]]);
                        let mut resp = vec![0u8; 32];
                        resp[0] = 0x01; resp[1] = 0x01;
                        resp[2] = 0x00; resp[3] = 12;
                        resp[4..8].copy_from_slice(&cookie);
                        resp[20] = 0x00; resp[21] = 0x20;
                        resp[22] = 0x00; resp[23] = 0x08;
                        resp[24] = 0x00; resp[25] = 0x01;
                        resp[26..28].copy_from_slice(&port_xor.to_be_bytes());
                        for i in 0..4 { resp[28 + i] = ip[i] ^ cookie[i]; }
                        socket.send_to(&resp, src).ok();
                    }
                    Err(_) => break,
                }
            }
        });
        rx.recv_timeout(Duration::from_secs(1)).ok();
        addr
    }

    fn async_probe(p: &NatProbe) -> NatProbeResult {
        tokio::runtime::Runtime::new().unwrap().block_on(p.probe()).unwrap()
    }

    #[test]
    fn test_cone() {
        let s = mock_stun(10000, [10, 0, 0, 1]);
        let r = async_probe(&NatProbe::new(vec![s, s], 3));
        assert_eq!(r.nat_type, NatType::Cone);
        assert!(r.mapped_addr.is_some());
    }

    #[test]
    fn test_symmetric() {
        let s1 = mock_stun(10000, [10, 0, 0, 1]);
        let s2 = mock_stun(20000, [10, 0, 0, 1]);
        let r = async_probe(&NatProbe::new(vec![s1, s2], 3));
        assert_eq!(r.nat_type, NatType::ADFSymmetric);
    }

    #[test]
    fn test_no_servers() {
        let r = async_probe(&NatProbe::new(vec![], 1));
        assert_eq!(r.nat_type, NatType::Unknown);
    }

    #[test]
    fn test_parse_mapped() {
        let mut msg = vec![0u8; 32];
        msg[0] = 0x01; msg[1] = 0x01;
        msg[2] = 0x00; msg[3] = 12;
        msg[20] = 0x00; msg[21] = 0x01;
        msg[22] = 0x00; msg[23] = 0x08;
        msg[24] = 0; msg[25] = 1;
        msg[26..28].copy_from_slice(&8080u16.to_be_bytes());
        msg[28..32].copy_from_slice(&[192, 168, 1, 100]);
        let r = parse_mapped(&msg).unwrap();
        assert_eq!(r.port(), 8080);
    }
}
