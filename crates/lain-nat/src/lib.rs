#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::error::CoreError;
use lain_core::nat::{NatProbeResult, NatProber, NatType};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub struct NatProbe {
    servers: Vec<SocketAddr>,
    timeout: Duration,
}

impl NatProbe {
    pub fn new(servers: Vec<SocketAddr>, timeout_secs: u64) -> Self {
        let secs = timeout_secs.max(1);
        Self { servers, timeout: Duration::from_secs(secs) }
    }
}

/// STUN probe 的一次尝试结果
struct ProbeAttempt {
    mapped: SocketAddr,
}

impl NatProbe {
    pub async fn ipv6_status() -> (bool, Option<std::net::Ipv6Addr>) {
        let v6_avail = tokio::net::UdpSocket::bind("[::1]:0").await.is_ok();
        let global = if v6_avail {
            tokio::task::spawn_blocking(|| {
                if_addrs::get_if_addrs().ok().and_then(|ifs| {
                    ifs.into_iter().find_map(|i| match i.addr {
                        if_addrs::IfAddr::V6(v6)
                            if !v6.ip.is_loopback()
                               && (v6.ip.segments()[0] & 0xE000) == 0x2000 =>
                            Some(v6.ip),
                        _ => None,
                    })
                })
            }).await.unwrap_or(None)
        } else { None };
        (v6_avail, global)
    }
}

/// 单个 STUN server 独立探测任务
async fn probe_server(timeout: Duration, server: SocketAddr) -> Option<(SocketAddr, Duration)> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    for attempt in 0..2 {
        let start = Instant::now();
        let (req, tid) = build_binding_request();
        if socket.send_to(&req, server).await.is_err() {
            tracing::debug!("STUN send_to {server} failed");
            continue;
        }

        let mut buf = [0u8; 1024];
        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, _))) => {
                if let Some(addr) = parse_mapped(&buf[..len], &tid) {
                    tracing::info!("STUN {server} → {addr} ({:?})", start.elapsed());
                    return Some((addr, start.elapsed()));
                }
                tracing::debug!("STUN {server} response parse failed");
            }
            Ok(Err(e)) => tracing::debug!("STUN {server} recv error: {e}"),
            Err(_) => tracing::debug!("STUN {server} timeout (attempt {})", attempt + 1),
        }
    }
    None
}

#[async_trait::async_trait]
impl NatProber for NatProbe {
    async fn probe(&self) -> Result<NatProbeResult, CoreError> {
        // 并发探测所有服务器，每个服务器独立 socket
        let mut results: Vec<ProbeAttempt> = Vec::new();
        let mut rtt_total: u64 = 0;

        if !self.servers.is_empty() {
            let global_timeout = self.timeout * 2;
            let collect_fut = async {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<(SocketAddr, Duration)>(self.servers.len());
                for &server in &self.servers {
                    let tx = tx.clone();
                    let t = self.timeout;
                    tokio::spawn(async move {
                        if let Some(r) = probe_server(t, server).await {
                            tx.send(r).await.ok();
                        }
                    });
                }
                drop(tx);
                while let Some((addr, rtt)) = rx.recv().await {
                    rtt_total += rtt.as_millis() as u64;
                    results.push(ProbeAttempt { mapped: addr });
                    if results.len() >= 2 { break; }
                }
            };
            let _ = tokio::time::timeout(global_timeout, collect_fut).await;
            // results and rtt_total may be partial if timeout fired — that's ok
        }

        if results.is_empty() {
            tracing::warn!("STUN: all servers failed, no mapped address");
            let status = Self::ipv6_status().await;
            return Ok(NatProbeResult {
                nat_type: NatType::Unknown,
                ipv6_inbound: status.0,
                ipv6_addr: status.1,
                mapped_addr: None,
                port_delta: None,
                stun_rtt_ms: None,
            });
        }

        let avg_rtt = rtt_total / results.len() as u64;
        let base = results[0].mapped;
        let all_same = results.iter().all(|r| r.mapped == base);
        let ip_same = results.iter().all(|r| r.mapped.ip() == base.ip());
        tracing::info!("STUN: {} results, mapped={base}, type={}, delta={:?}, rtt={avg_rtt}ms",
            results.len(),
            if all_same { "Cone" } else if ip_same { "Symmetric(ADF)" } else { "Symmetric(APDF)" },
            results.get(1).and_then(|r| {
                let d = base.port().abs_diff(r.mapped.port());
                if d > 0 { Some(d) } else { None }
            }),
        );

        let deltas: Vec<u16> = if results.len() >= 2 {
            results.windows(2).filter_map(|w| {
                let d = w[0].mapped.port().abs_diff(w[1].mapped.port());
                if d > 0 { Some(d) } else { None }
            }).collect()
        } else { vec![] };

        let port_delta = if deltas.is_empty() { None }
            else if deltas.iter().all(|&d| d == 1) { Some(1) }
            else if deltas.windows(2).all(|w| w[0] == w[1]) { deltas.first().copied() }
            else { None };

        let nat_type = if all_same { NatType::Cone }
                       else if ip_same { NatType::ADFSymmetric }
                       else { NatType::APDFSymmetric };

        let status = Self::ipv6_status().await;
        Ok(NatProbeResult {
            nat_type,
            ipv6_inbound: status.0,
            ipv6_addr: status.1,
            mapped_addr: Some(base),
            port_delta,
            stun_rtt_ms: Some(avg_rtt),
        })
    }
}

// ── STUN wire format ──

fn build_binding_request() -> (Vec<u8>, [u8; 12]) {
    let mut p = vec![0u8; 20];
    p[0] = 0x00; p[1] = 0x01; // Binding Request
    p[2] = 0x00; p[3] = 0x00; // message length
    p[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    let mut tid = [0u8; 12];
    for b in &mut tid { *b = rand::random::<u8>(); }
    p[8..20].copy_from_slice(&tid); // transaction ID
    (p, tid)
}

fn parse_mapped(data: &[u8], expected_tid: &[u8; 12]) -> Option<SocketAddr> {
    if data.len() < 20 { return None; }
    if data[0] != 0x01 || data[1] != 0x01 { return None; }
    if &data[4..8] != &[0x21, 0x12, 0xA4, 0x42] { return None; }
    if &data[8..20] != expected_tid { return None; }

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
            if val_end < off + 4 { return None; }
            let family = data[off + 1];
            let port_raw = u16::from_be_bytes([data[off + 2], data[off + 3]]);
            let port = if ty == 0x0020 { port_raw ^ u16::from_be_bytes([cookie[0], cookie[1]]) } else { port_raw };

            if family == 0x01 {
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
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
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
                        resp[8..20].copy_from_slice(&buf[8..20]); // echo transaction ID
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
        msg[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
        let tid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        msg[8..20].copy_from_slice(&tid);
        msg[20] = 0x00; msg[21] = 0x01;
        msg[22] = 0x00; msg[23] = 0x08;
        msg[24] = 0; msg[25] = 1;
        msg[26..28].copy_from_slice(&8080u16.to_be_bytes());
        msg[28..32].copy_from_slice(&[192, 168, 1, 100]);
        let r = parse_mapped(&msg, &tid).unwrap();
        assert_eq!(r.port(), 8080);
    }
}
