use kotoba_core::cid::KotobaCid;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const BUCKET_BLOCKS:    &str = "KOTOBA_BLOCKS";
pub const BUCKET_GRAPHS:    &str = "KOTOBA_GRAPHS";
pub const BUCKET_HEADS:     &str = "KOTOBA_HEADS";
pub const BUCKET_UCANS:     &str = "KOTOBA_UCANS";
pub const BUCKET_WARRANTS:  &str = "KOTOBA_WARRANTS";
pub const BUCKET_WEIGHTS:   &str = "KOTOBA_WEIGHTS";   // FP8 weight blob CIDs
pub const BUCKET_PRE_KEYS:  &str = "KOTOBA_PRE_KEYS";  // PRE grant index

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

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    #[tokio::test]
    async fn get_on_unknown_key_returns_none() {
        let shelf = Shelf::new();
        let result = shelf.get(BUCKET_BLOCKS, "no-such-key").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn put_then_get_returns_value() {
        let shelf = Shelf::new();
        let value = Bytes::from_static(b"hello shelf");
        shelf.put(BUCKET_BLOCKS, "key1".to_string(), value.clone()).await;
        let got = shelf.get(BUCKET_BLOCKS, "key1").await;
        assert_eq!(got, Some(value));
    }

    #[tokio::test]
    async fn put_increments_revision_on_re_put() {
        let shelf = Shelf::new();
        let rev1 = shelf
            .put(BUCKET_GRAPHS, "k".to_string(), Bytes::from_static(b"v1"))
            .await;
        let rev2 = shelf
            .put(BUCKET_GRAPHS, "k".to_string(), Bytes::from_static(b"v2"))
            .await;
        assert_eq!(rev1, 1);
        assert_eq!(rev2, 2);
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let mut bucket = ShelfBucket::new("test-bucket");
        bucket.put("del-key".to_string(), Bytes::from_static(b"to-delete"));
        assert!(bucket.get("del-key").is_some());
        bucket.delete("del-key");
        assert!(bucket.get("del-key").is_none());
    }

    #[tokio::test]
    async fn get_head_set_head_roundtrip() {
        let shelf = Shelf::new();
        let graph_cid = KotobaCid::from_bytes(b"graph-cid-data");
        let commit_cid = KotobaCid::from_bytes(b"commit-cid-data");
        // Before set_head, get_head returns None
        assert!(shelf.get_head(&graph_cid).await.is_none());
        shelf.set_head(&graph_cid, &commit_cid).await;
        let retrieved = shelf.get_head(&graph_cid).await.expect("head should be set");
        assert_eq!(retrieved, commit_cid);
    }

    #[tokio::test]
    async fn put_to_unknown_bucket_creates_bucket_on_demand() {
        let shelf = Shelf::new();
        let custom_bucket = "KOTOBA_CUSTOM";
        let rev = shelf
            .put(custom_bucket, "some-key".to_string(), Bytes::from_static(b"val"))
            .await;
        assert_eq!(rev, 1);
        let got = shelf.get(custom_bucket, "some-key").await;
        assert_eq!(got, Some(Bytes::from_static(b"val")));
    }
}
