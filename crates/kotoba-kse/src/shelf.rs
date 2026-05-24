use kotoba_core::cid::KotobaCid;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const BUCKET_BLOCKS:   &str = "KOTOBA_BLOCKS";
pub const BUCKET_GRAPHS:   &str = "KOTOBA_GRAPHS";
pub const BUCKET_HEADS:    &str = "KOTOBA_HEADS";
pub const BUCKET_UCANS:    &str = "KOTOBA_UCANS";
pub const BUCKET_WARRANTS: &str = "KOTOBA_WARRANTS";
pub const BUCKET_WEIGHTS:  &str = "KOTOBA_WEIGHTS";  // FP8 weight blob CIDs

/// Shelf — CID-keyed KV, built on Journal (clean room, inspired by NATS KV)
pub struct Shelf {
    buckets: Arc<RwLock<HashMap<String, ShelfBucket>>>,
}

pub struct ShelfBucket {
    pub name: String,
    entries:  HashMap<String, (Bytes, u64)>, // key → (value, revision)
}

impl ShelfBucket {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), entries: HashMap::new() }
    }

    pub fn get(&self, key: &str) -> Option<&Bytes> {
        self.entries.get(key).map(|(v, _)| v)
    }

    pub fn put(&mut self, key: String, value: Bytes) -> u64 {
        let rev = self.entries.get(&key).map(|(_, r)| r + 1).unwrap_or(1);
        self.entries.insert(key, (value, rev));
        rev
    }

    pub fn delete(&mut self, key: &str) { self.entries.remove(key); }
}

impl Shelf {
    pub fn new() -> Self {
        let mut buckets = HashMap::new();
        for name in &[
            BUCKET_BLOCKS, BUCKET_GRAPHS, BUCKET_HEADS,
            BUCKET_UCANS, BUCKET_WARRANTS, BUCKET_WEIGHTS,
        ] {
            buckets.insert(name.to_string(), ShelfBucket::new(*name));
        }
        Self { buckets: Arc::new(RwLock::new(buckets)) }
    }

    pub async fn get(&self, bucket: &str, key: &str) -> Option<Bytes> {
        self.buckets.read().await
            .get(bucket)?.get(key).cloned()
    }

    pub async fn put(&self, bucket: &str, key: String, value: Bytes) -> u64 {
        self.buckets.write().await
            .entry(bucket.to_string())
            .or_insert_with(|| ShelfBucket::new(bucket))
            .put(key, value)
    }

    pub async fn get_head(&self, graph_cid: &KotobaCid) -> Option<KotobaCid> {
        let bytes = self.get(BUCKET_HEADS, &graph_cid.to_multibase()).await?;
        if bytes.len() == 36 {
            let mut arr = [0u8; 36];
            arr.copy_from_slice(&bytes);
            Some(KotobaCid(arr))
        } else { None }
    }

    pub async fn set_head(&self, graph_cid: &KotobaCid, commit_cid: &KotobaCid) {
        self.put(
            BUCKET_HEADS,
            graph_cid.to_multibase(),
            Bytes::copy_from_slice(&commit_cid.0),
        ).await;
    }
}
