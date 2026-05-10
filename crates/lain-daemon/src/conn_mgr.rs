#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

use lain_core::frame::{encode_varint, decode_varint};
use lain_core::peer::PeerId;
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
    /// 成功时返回新的 QUIC 连接，失败返回 None
    pub async fn on_disconnect(
        &self,
        peer_id: &PeerId,
        dht: &Arc<lain_dht::DhtHandle>,
        transport: &Arc<lain_transport::Transport>,
    ) -> Option<quinn::Connection> {
        tracing::warn!("ConnectionManager: {peer_id} disconnected, reconnecting...");

        let peer_state = {
            let peers = self.peers.read().await;
            peers.get(peer_id).cloned()
        }?;

        let mut backoff = 1u64;
        let max_backoff = 300;

        for attempt in 0u32..8 {
            tracing::info!("{peer_id} reconnect attempt {}/8", attempt + 1);

            let record = match dht.find_peer(peer_id).await {
                Ok(Some(r)) => r,
                _ => {
                    tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                    backoff = (backoff * 3).min(max_backoff);
                    continue;
                }
            };

            match transport.connect_raw(&record.pubkey, &record.endpoints).await {
                Ok(conn) => {
                    tracing::info!("{peer_id} reconnected!");

                    // Send STREAM_RESUME frame on stream 0
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
                        // Send on a new stream of the reconnected connection
                        if let Ok((mut send, _recv)) = conn.open_bi().await {
                            let _ = send.write_all(&resume).await;
                            let _ = send.finish();
                            tracing::info!("sent STREAM_RESUME for {} streams", streams.len());
                        }
                    }

                    self.peers.write().await.insert(*peer_id, peer_state);
                    return Some(conn);
                }
                Err(e) => {
                    tracing::debug!("{peer_id} reconnect failed: {e}");
                }
            }

            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 3).min(max_backoff);
        }

        tracing::warn!("{peer_id} reconnect failed, marking expired");
        self.peers.write().await.remove(peer_id);
        None
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
