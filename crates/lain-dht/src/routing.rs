use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use lain_core::peer::PeerId;

#[derive(Clone, Debug)]
pub struct BucketEntry {
    pub node_id: PeerId,
    pub address: SocketAddr,
    pub last_seen: Instant,
}

pub struct KBucket {
    entries: VecDeque<BucketEntry>,
    k: usize,
}

#[allow(dead_code)]
impl KBucket {
    pub fn new(k: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(k),
            k,
        }
    }

    pub fn contains(&self, node_id: &PeerId) -> bool {
        self.entries.iter().any(|e| e.node_id == *node_id)
    }

    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.k
    }

    pub fn head(&self) -> Option<&BucketEntry> {
        self.entries.front()
    }

    pub fn insert_or_update(&mut self, entry: BucketEntry) -> bool {
        // If already present, move to tail (most recent)
        if let Some(pos) = self.entries.iter().position(|e| e.node_id == entry.node_id) {
            if let Some(existing) = self.entries.get_mut(pos) {
                existing.address = entry.address;
                existing.last_seen = entry.last_seen;
            }
            // Move to end
            if let Some(removed) = self.entries.remove(pos) {
                self.entries.push_back(removed);
            }
            return true;
        }

        // If not full, add to tail
        if !self.is_full() {
            self.entries.push_back(entry);
            return true;
        }

        // Bucket full, reject (caller should try to ping head)
        false
    }

    pub fn remove(&mut self, node_id: &PeerId) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.node_id == *node_id) {
            self.entries.remove(pos);
            return true;
        }
        false
    }

    pub fn replace_head(&mut self, entry: BucketEntry) {
        self.entries.pop_front();
        self.entries.push_back(entry);
    }

    pub fn entries(&self) -> &VecDeque<BucketEntry> {
        &self.entries
    }

    pub fn iter(&self) -> impl Iterator<Item = &BucketEntry> {
        self.entries.iter()
    }
}

pub struct RoutingTable {
    local_id: PeerId,
    buckets: Vec<KBucket>,
    #[allow(dead_code)]
    k: usize,
}

#[allow(dead_code)]
impl RoutingTable {
    pub fn new(local_id: PeerId, k: usize) -> Self {
        let mut buckets = Vec::with_capacity(lain_core::DHT_BUCKET_COUNT);
        for _ in 0..lain_core::DHT_BUCKET_COUNT {
            buckets.push(KBucket::new(k));
        }
        Self { local_id, buckets, k }
    }

    pub fn bucket_index(&self, node_id: &PeerId) -> usize {
        self.local_id.bucket_index(node_id)
    }

    pub fn insert_or_update(&mut self, entry: BucketEntry) -> bool {
        let bucket_idx = self.bucket_index(&entry.node_id);
        if bucket_idx >= self.buckets.len() {
            return false;
        }

        let bucket = &mut self.buckets[bucket_idx];

        if bucket.contains(&entry.node_id) || !bucket.is_full() {
            bucket.insert_or_update(entry);
            return true;
        }

        // Bucket full: try to ping head (oldest entry).
        // For now, just reject - caller handles.
        false
    }

    pub fn remove_node(&mut self, node_id: &PeerId) {
        let bucket_idx = self.bucket_index(node_id);
        if bucket_idx < self.buckets.len() {
            self.buckets[bucket_idx].remove(node_id);
        }
    }

    pub fn closest_nodes(&self, target: &PeerId, count: usize) -> Vec<BucketEntry> {
        let mut all: Vec<&BucketEntry> = self.buckets.iter().flat_map(|b| b.iter()).collect();
        all.sort_by(|a, b| {
            a.node_id
                .distance(target)
                .cmp(&b.node_id.distance(target))
        });
        all.iter()
            .take(count)
            .map(|e| (**e).clone())
            .collect()
    }

    pub fn all_nodes(&self) -> Vec<BucketEntry> {
        self.buckets.iter().flat_map(|b| b.iter().cloned()).collect()
    }

    pub fn size(&self) -> usize {
        self.buckets.iter().map(|b| b.entries().len()).sum()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn entry(id: u8) -> BucketEntry {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        BucketEntry {
            node_id: PeerId(bytes),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), id as u16)),
            last_seen: Instant::now(),
        }
    }

    fn entry_full(id: usize) -> BucketEntry {
        let mut bytes = [0u8; 32];
        for (i, b) in id.to_be_bytes().iter().enumerate() {
            bytes[32 - 8 + i] = *b;
        }
        BucketEntry {
            node_id: PeerId(bytes),
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 1)),
            last_seen: Instant::now(),
        }
    }

    #[test]
    fn test_distance_symmetric() {
        let a = PeerId([1u8; 32]);
        let b = PeerId([2u8; 32]);
        assert_eq!(a.distance(&b), b.distance(&a));
    }

    #[test]
    fn test_distance_self_zero() {
        let a = PeerId([42u8; 32]);
        assert_eq!(a.distance(&a), [0u8; 32]);
    }

    #[test]
    fn test_bucket_index() {
        let local = PeerId([0u8; 32]);
        // MSB of first byte = position 0
        let mut far = [0u8; 32];
        far[0] = 0x80;
        assert_eq!(local.bucket_index(&PeerId(far)), 0);
        // Bit 6 of first byte = position 1
        far[0] = 0x40;
        assert_eq!(local.bucket_index(&PeerId(far)), 1);
        // LSB of first byte = position 7
        far[0] = 1;
        assert_eq!(local.bucket_index(&PeerId(far)), 7);
        // LSB of last byte = position 255
        far = [0u8; 32];
        far[31] = 1;
        assert_eq!(local.bucket_index(&PeerId(far)), 255);
    }

    #[test]
    fn test_kbucket_insert_and_contains() {
        let mut kb = KBucket::new(20);
        let e = entry(1);
        assert!(kb.insert_or_update(e.clone()));
        assert!(kb.contains(&e.node_id));
        assert_eq!(kb.entries().len(), 1);
    }

    #[test]
    fn test_kbucket_move_to_tail_on_update() {
        let mut kb = KBucket::new(20);
        kb.insert_or_update(entry(1));
        kb.insert_or_update(entry(2));
        kb.insert_or_update(entry(1)); // update moves to tail
        // Last entry should be node 1
        assert_eq!(kb.entries().back().unwrap().node_id.0[0], 1);
    }

    #[test]
    fn test_kbucket_full_rejects() {
        let mut kb = KBucket::new(3);
        assert!(kb.insert_or_update(entry(1)));
        assert!(kb.insert_or_update(entry(2)));
        assert!(kb.insert_or_update(entry(3)));
        // Bucket is full, insertion rejected
        assert!(!kb.insert_or_update(entry(4)));
    }

    #[test]
    fn test_routing_table_insert_and_find() {
        let local = PeerId([0u8; 32]);
        let mut rt = RoutingTable::new(local, 20);
        rt.insert_or_update(entry(1));
        rt.insert_or_update(entry(2));
        rt.insert_or_update(entry(3));
        assert_eq!(rt.size(), 3);
    }

    #[test]
    fn test_closest_nodes_ordering() {
        let local = PeerId([0u8; 32]);
        let mut rt = RoutingTable::new(local, 20);
        // Insert nodes at different XOR distances
        rt.insert_or_update(entry_full(0x01));
        rt.insert_or_update(entry_full(0xFF));
        rt.insert_or_update(entry_full(0x42));
        // Closest to local should be 0x01 (smallest XOR)
        let target = PeerId([0u8; 32]);
        let closest = rt.closest_nodes(&target, 3);
        assert_eq!(closest.len(), 3);
        // Closest should have smallest distance to target
        for i in 1..closest.len() {
            let d1 = closest[i - 1].node_id.distance(&target);
            let d2 = closest[i].node_id.distance(&target);
            // d1 should be lexicographically smaller or equal
            assert!(d1 <= d2, "closest nodes not ordered by distance");
        }
    }

    #[test]
    fn test_remove_node() {
        let local = PeerId([0u8; 32]);
        let mut rt = RoutingTable::new(local, 20);
        let e = entry(5);
        rt.insert_or_update(e.clone());
        assert_eq!(rt.size(), 1);
        rt.remove_node(&e.node_id);
        assert_eq!(rt.size(), 0);
    }

    #[test]
    fn test_stress_many_nodes() {
        let local = PeerId([0u8; 32]);
        let mut rt = RoutingTable::new(local, 20);
        for i in 0u32..500 {
            let e = entry_full(i as usize * 7919 % 1000007);
            let _ = rt.insert_or_update(e);
        }
        // Should have at least some nodes (buckets fill up)
        assert!(rt.size() > 20);
        // All nodes should be findable
        let all = rt.all_nodes();
        assert_eq!(all.len(), rt.size());
    }
}
