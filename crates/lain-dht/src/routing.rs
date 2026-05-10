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
