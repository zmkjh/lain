#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::peer::PeerId;
use lain_core::transport::TransportLayer;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing;

/// 活跃连接的流状态
#[derive(Clone, Debug, Default)]
struct PeerStreamState {
    active_streams: Vec<u64>,
    last_seq: HashMap<u64, u64>,
}

/// 连接管理器：跟踪活跃 peer，断线时触发重连
pub struct ConnectionManager {
    peers: Arc<RwLock<HashMap<PeerId, PeerStreamState>>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// 记录新连接
    pub async fn add_peer(&self, peer_id: PeerId) {
        self.peers.write().await.insert(peer_id, PeerStreamState::default());
        tracing::info!("ConnectionManager: added {peer_id}");
    }

    /// 移除连接
    pub async fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.write().await.remove(peer_id);
        tracing::info!("ConnectionManager: removed {peer_id}");
    }

    /// 连接断开时触发重连
    /// 返回是否需要重连（peer 已被标记为 STALE 且未 EXPIRED）
    pub async fn on_disconnect(
        &self,
        peer_id: &PeerId,
        dht: &Arc<lain_dht::DhtHandle>,
        transport: &Arc<lain_transport::Transport>,
    ) {
        tracing::warn!("ConnectionManager: {peer_id} disconnected, reconnecting...");

        let peer_state = {
            let peers = self.peers.read().await;
            peers.get(peer_id).cloned()
        };

        let peer_state = match peer_state {
            Some(s) => s,
            None => return,
        };

        // Exponential backoff reconnect loop
        let mut backoff = 1u64;
        let max_backoff = 300; // 5 minutes max
        let max_attempts = 8;

        for attempt in 0..max_attempts {
            tracing::info!("{peer_id} reconnect attempt {}/{max_attempts}", attempt + 1);

            // Look up peer's latest endpoints from DHT
            let record = match dht.find_peer(peer_id).await {
                Ok(Some(r)) => r,
                _ => {
                    tracing::debug!("{peer_id} not found in DHT");
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 3).min(max_backoff);
                    continue;
                }
            };

            // Try reconnect
            match transport.connect(peer_id, &record.pubkey, &record.endpoints).await {
                Ok(_conn) => {
                    tracing::info!("{peer_id} reconnected!");

                    // Send STREAM_RESUME frame
                    let streams: Vec<u64> = peer_state.active_streams.clone();
                    if !streams.is_empty() {
                        let mut payload = Vec::new();
                        encode_varint(streams.len() as u64, &mut payload);
                        for sid in &streams {
                            encode_varint(*sid, &mut payload);
                            let lseq = peer_state.last_seq.get(sid).copied().unwrap_or(0);
                            encode_varint(lseq, &mut payload);
                        }
                        let resume = lain_core::frame::encode_frame(
                            0,
                            lain_core::frame::FrameType::StreamResume,
                            &payload,
                        );
                        // In production: send this frame on stream 0 of the new connection
                        let _ = resume;
                    }

                    // Re-add peer
                    self.peers.write().await.insert(*peer_id, peer_state);
                    return;
                }
                Err(e) => {
                    tracing::debug!("{peer_id} reconnect failed: {e}");
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 3).min(max_backoff);
        }

        tracing::warn!("{peer_id} reconnect failed after {max_attempts} attempts, marking expired");
        self.peers.write().await.remove(peer_id);
    }

    /// 处理收到的 STREAM_RESUME 帧
    pub async fn handle_resume(
        &self,
        peer_id: &PeerId,
        payload: &[u8],
    ) -> Option<Vec<(u64, u64)>> {
        let mut offset = 0usize;
        let (count, cnt_len) = decode_varint(&payload[offset..])?;
        offset += cnt_len;
        let mut streams = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let (sid, sid_len) = decode_varint(&payload[offset..])?;
            offset += sid_len;
            let (seq, seq_len) = decode_varint(&payload[offset..])?;
            offset += seq_len;
            streams.push((sid, seq));
        }

        tracing::info!("{peer_id} STREAM_RESUME: {} streams", streams.len());
        Some(streams)
    }

    /// 列出所有活跃 peer
    pub async fn active_peers(&self) -> Vec<PeerId> {
        self.peers.read().await.keys().copied().collect()
    }
}

fn encode_varint(value: u64, buf: &mut Vec<u8>) {
    if value <= 63 {
        buf.push(value as u8);
    } else if value <= 16383 {
        buf.push(0x40 | ((value >> 8) as u8 & 0x3F));
        buf.push(value as u8);
    } else if value <= 1073741823 {
        buf.push(0x80 | ((value >> 24) as u8 & 0x3F));
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    } else {
        buf.push(0xC0 | ((value >> 56) as u8 & 0x3F));
        buf.push((value >> 48) as u8);
        buf.push((value >> 40) as u8);
        buf.push((value >> 32) as u8);
        buf.push((value >> 24) as u8);
        buf.push((value >> 16) as u8);
        buf.push((value >> 8) as u8);
        buf.push(value as u8);
    }
}

fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() { return None; }
    let first = data[0];
    if first & 0xC0 == 0 {
        Some((first as u64, 1))
    } else if first & 0xC0 == 0x40 {
        if data.len() < 2 { return None; }
        Some((((first & 0x3F) as u64) << 8 | data[1] as u64, 2))
    } else if first & 0xC0 == 0x80 {
        if data.len() < 4 { return None; }
        Some((((first & 0x3F) as u64) << 24
            | (data[1] as u64) << 16
            | (data[2] as u64) << 8
            | data[3] as u64, 4))
    } else {
        if data.len() < 8 { return None; }
        Some((((first & 0x3F) as u64) << 56
            | (data[1] as u64) << 48
            | (data[2] as u64) << 40
            | (data[3] as u64) << 32
            | (data[4] as u64) << 24
            | (data[5] as u64) << 16
            | (data[6] as u64) << 8
            | data[7] as u64, 8))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = ConnectionManager::new();
            let pid = PeerId([1u8; 32]);
            mgr.add_peer(pid).await;
            assert_eq!(mgr.active_peers().await.len(), 1);
            mgr.remove_peer(&pid).await;
            assert_eq!(mgr.active_peers().await.len(), 0);
        });
    }

    #[test]
    fn test_stream_resume_parse() {
        let mut payload = Vec::new();
        encode_varint(2, &mut payload); // 2 streams
        encode_varint(3, &mut payload); // sid=3
        encode_varint(100, &mut payload); // seq=100
        encode_varint(5, &mut payload); // sid=5
        encode_varint(200, &mut payload); // seq=200

        let mgr = ConnectionManager::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let result = mgr.handle_resume(&PeerId([1u8; 32]), &payload).await;
            assert!(result.is_some());
            let streams = result.unwrap();
            assert_eq!(streams.len(), 2);
            assert_eq!(streams[0], (3, 100));
            assert_eq!(streams[1], (5, 200));
        });
    }
}
