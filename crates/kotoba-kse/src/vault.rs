use crate::chunker::{split, strategy_for};
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_store::car_bundle::CarBundleWriter;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// BlobRef — reference to a content-addressed blob (or blob manifest).
///
/// When the blob is split into multiple chunks, `cid` is the CID of a
/// CBOR-encoded `BlobManifest` block, not the raw data directly.
#[derive(Debug, Clone)]
pub struct BlobRef {
    pub cid:       KotobaCid,
    pub size:      usize,
    pub mime_type: Option<String>,
    /// `true` when `cid` points to a `BlobManifest` (chunked blob).
    pub chunked:   bool,
}

/// CBOR-encoded manifest stored as a block when a blob is split into chunks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobManifest {
    pub mime_type:  String,
    pub total_size: u64,
    /// Ordered chunk CIDs (each chunk is a raw block in the store).
    pub chunks:     Vec<KotobaCid>,
}

/// Vault — chunked, content-addressed binary blob store.
///
/// Blobs are split using a file-type–aware strategy before storage:
/// - **Fixed-length** (512 KB) for video/audio/opaque binary.
/// - **Gear-hash CDC** (~256 KB avg) for text/JSON/code.
/// - **CBOR item boundaries** for dag-cbor/cbor.
/// - **Single block** for blobs smaller than 128 KB.
///
/// When a blob is chunked, a `BlobManifest` block is stored and its CID is
/// returned as `BlobRef.cid`.  Single-chunk blobs skip the manifest.
pub struct Vault {
    /// In-memory cache: manifest/raw CID multibase → raw bytes (or manifest CBOR).
    blobs: Arc<RwLock<HashMap<String, Bytes>>>,
    store: Option<Arc<dyn BlockStore + Send + Sync>>,
}

impl Vault {
    /// In-memory only — no persistence.
    pub fn new() -> Self {
        Self { blobs: Arc::new(RwLock::new(HashMap::new())), store: None }
    }

    /// Persistent — blobs are written to / read from the given block store.
    pub fn with_block_store(store: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self { blobs: Arc::new(RwLock::new(HashMap::new())), store: Some(store) }
    }

    /// Store a blob, choosing the chunking strategy from its MIME type.
    ///
    /// Returns a `BlobRef` whose `cid` is:
    /// - the raw data CID when the blob fits in a single chunk, or
    /// - the CID of a `BlobManifest` block when the blob is split.
    pub async fn put_typed(&self, data: Bytes, mime_type: impl Into<String>) -> BlobRef {
        let mime = mime_type.into();
        let strategy = strategy_for(&mime, data.len());
        let chunks = split(&data, &strategy);

        if chunks.len() == 1 {
            // Single chunk — store raw, no manifest overhead.
            let cid  = KotobaCid::from_bytes(&data);
            let key  = cid.to_multibase();
            let size = data.len();
            self.blobs.write().await.insert(key, data.clone());
            if let Some(s) = &self.store { s.put(&cid, &data).ok(); }
            BlobRef { cid, size, mime_type: Some(mime), chunked: false }
        } else {
            self.put_chunks(data.len(), mime, chunks).await
        }
    }

    /// Store a blob without MIME type (defaults to `ContentDefined` for large
    /// blobs, `Single` for small ones).
    pub async fn put(&self, data: Bytes) -> BlobRef {
        self.put_typed(data, "application/octet-stream").await
    }

    /// Retrieve the raw bytes for a blob previously stored via `put` / `put_typed`.
    ///
    /// Handles both single-block blobs and chunked manifests transparently.
    pub async fn get(&self, cid: &KotobaCid) -> Option<Bytes> {
        let key = cid.to_multibase();

        // Fast path: raw blob in cache
        if let Some(blob) = self.blobs.read().await.get(&key).cloned() {
            // If this is a manifest, reassemble from chunks.
            if let Ok(manifest) = ciborium::from_reader::<BlobManifest, _>(&blob[..]) {
                return self.reassemble(&manifest).await;
            }
            return Some(blob);
        }

        // Fallback: block store
        if let Some(store) = &self.store {
            if let Ok(Some(bytes)) = store.get(cid) {
                // Might be a manifest or raw data.
                if let Ok(manifest) = ciborium::from_reader::<BlobManifest, _>(&bytes[..]) {
                    self.blobs.write().await.insert(key, bytes);
                    return self.reassemble(&manifest).await;
                }
                self.blobs.write().await.insert(key, bytes.clone());
                return Some(bytes);
            }
        }

        None
    }

    pub async fn contains(&self, cid: &KotobaCid) -> bool {
        let key = cid.to_multibase();
        if self.blobs.read().await.contains_key(&key) { return true; }
        if let Some(s) = &self.store { return s.has(cid); }
        false
    }

    /// Bundle all blocks currently pinned in `cids` into a single CAR file.
    ///
    /// Useful for batch-flushing a session's blobs to a single S3 PUT.
    /// The returned `Bytes` is a valid CAR v1 file.
    pub async fn flush_as_car(&self, root_cid: &KotobaCid, cids: &[KotobaCid]) -> Option<Bytes> {
        let store = self.store.as_ref()?;
        let mut writer = CarBundleWriter::new(root_cid.clone());
        for cid in cids {
            if let Ok(Some(data)) = store.get(cid) {
                writer.append(cid, &data);
            }
        }
        let (car_bytes, _index) = writer.finish();
        Some(Bytes::from(car_bytes))
    }

    // ── internals ────────────────────────────────────────────────────────────

    async fn put_chunks(&self, total_size: usize, mime: String, chunks: Vec<Bytes>) -> BlobRef {
        let mut chunk_cids = Vec::with_capacity(chunks.len());
        for chunk in &chunks {
            let cid = KotobaCid::from_bytes(chunk);
            self.blobs.write().await.insert(cid.to_multibase(), chunk.clone());
            if let Some(s) = &self.store { s.put(&cid, chunk).ok(); }
            chunk_cids.push(cid);
        }

        let manifest = BlobManifest {
            mime_type:  mime.clone(),
            total_size: total_size as u64,
            chunks:     chunk_cids,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&manifest, &mut cbor)
            .expect("BlobManifest CBOR serialization");
        let manifest_cid = KotobaCid::from_bytes(&cbor);
        let cbor_bytes   = Bytes::from(cbor);
        self.blobs.write().await.insert(manifest_cid.to_multibase(), cbor_bytes.clone());
        if let Some(s) = &self.store { s.put(&manifest_cid, &cbor_bytes).ok(); }

        BlobRef { cid: manifest_cid, size: total_size, mime_type: Some(mime), chunked: true }
    }

    async fn reassemble(&self, manifest: &BlobManifest) -> Option<Bytes> {
        let mut buf = Vec::with_capacity(manifest.total_size as usize);
        for chunk_cid in &manifest.chunks {
            let chunk = self.get_raw(chunk_cid).await?;
            buf.extend_from_slice(&chunk);
        }
        Some(Bytes::from(buf))
    }

    async fn get_raw(&self, cid: &KotobaCid) -> Option<Bytes> {
        let key = cid.to_multibase();
        if let Some(b) = self.blobs.read().await.get(&key).cloned() { return Some(b); }
        if let Some(s) = &self.store {
            if let Ok(Some(b)) = s.get(cid) {
                self.blobs.write().await.insert(key, b.clone());
                return Some(b);
            }
        }
        None
    }
}

impl Default for Vault {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::store::BlockStore;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock as StdRwLock};

    #[derive(Default)]
    struct MemStore(StdRwLock<HashMap<[u8; 36], Bytes>>);
    impl BlockStore for MemStore {
        fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
            self.0.write().unwrap().insert(cid.0, Bytes::copy_from_slice(data));
            Ok(())
        }
        fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
            Ok(self.0.read().unwrap().get(&cid.0).cloned())
        }
        fn has(&self, cid: &KotobaCid) -> bool {
            self.0.read().unwrap().contains_key(&cid.0)
        }
        fn delete(&self, cid: &KotobaCid) -> anyhow::Result<()> {
            self.0.write().unwrap().remove(&cid.0);
            Ok(())
        }
        fn pin(&self, _: &KotobaCid) {}
        fn unpin(&self, _: &KotobaCid) {}
        fn is_pinned(&self, _: &KotobaCid) -> bool { false }
    }

    #[tokio::test]
    async fn put_returns_blob_ref_with_correct_size() {
        let vault = Vault::new();
        let data = Bytes::from_static(b"size test payload");
        let blob_ref = vault.put(data.clone()).await;
        assert_eq!(blob_ref.size, data.len());
    }

    #[tokio::test]
    async fn put_then_get_returns_same_bytes() {
        let vault = Vault::new();
        let data = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let blob_ref = vault.put(data.clone()).await;
        let retrieved = vault.get(&blob_ref.cid).await;
        assert_eq!(retrieved, Some(data));
    }

    #[tokio::test]
    async fn get_on_unknown_cid_returns_none() {
        let vault = Vault::new();
        let unknown_cid = KotobaCid::from_bytes(b"this was never stored");
        assert!(vault.get(&unknown_cid).await.is_none());
    }

    #[tokio::test]
    async fn contains_returns_true_after_put_false_before() {
        let vault = Vault::new();
        let data = Bytes::from_static(b"contains check");
        let cid = KotobaCid::from_bytes(&data);
        assert!(!vault.contains(&cid).await);
        vault.put(data).await;
        assert!(vault.contains(&cid).await);
    }

    #[tokio::test]
    async fn different_content_produces_different_cids() {
        let vault = Vault::new();
        let ref_a = vault.put(Bytes::from_static(b"content alpha")).await;
        let ref_b = vault.put(Bytes::from_static(b"content beta")).await;
        assert_ne!(ref_a.cid, ref_b.cid);
    }

    #[tokio::test]
    async fn block_store_vault_survives_cache_eviction() {
        let store = Arc::new(MemStore::default()) as Arc<dyn BlockStore + Send + Sync>;
        let vault = Vault::with_block_store(store.clone());

        let data = Bytes::from_static(b"persistent blob");
        let blob_ref = vault.put(data.clone()).await;

        // Fresh vault with same block store (empty in-memory cache)
        let vault2 = Vault::with_block_store(store);
        let retrieved = vault2.get(&blob_ref.cid).await;
        assert_eq!(retrieved, Some(data));
    }

    #[tokio::test]
    async fn put_typed_small_is_single_block() {
        let vault = Vault::new();
        let data = Bytes::from_static(b"small text blob");
        let blob_ref = vault.put_typed(data.clone(), "text/plain").await;
        assert!(!blob_ref.chunked);
        assert_eq!(blob_ref.mime_type.as_deref(), Some("text/plain"));
        assert_eq!(vault.get(&blob_ref.cid).await, Some(data));
    }

    #[tokio::test]
    async fn put_typed_large_binary_is_chunked_and_reassembled() {
        let store = Arc::new(MemStore::default()) as Arc<dyn BlockStore + Send + Sync>;
        let vault = Vault::with_block_store(store);

        // ~1.5 MB of pseudo-random bytes (> SINGLE_THRESHOLD, triggers FixedLen for video/mp4)
        let mut data = Vec::with_capacity(1_500_000);
        let mut v: u8 = 7;
        for _ in 0..data.capacity() { v = v.wrapping_mul(13).wrapping_add(37); data.push(v); }
        let data = Bytes::from(data);

        let blob_ref = vault.put_typed(data.clone(), "video/mp4").await;
        assert!(blob_ref.chunked, "large video should be chunked");
        assert_eq!(blob_ref.size, 1_500_000);

        let retrieved = vault.get(&blob_ref.cid).await.expect("get must succeed");
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn flush_as_car_produces_non_empty_bytes() {
        let store = Arc::new(MemStore::default()) as Arc<dyn BlockStore + Send + Sync>;
        let vault = Vault::with_block_store(store);

        let ref1 = vault.put(Bytes::from_static(b"block one")).await;
        let ref2 = vault.put(Bytes::from_static(b"block two")).await;

        let car = vault.flush_as_car(&ref1.cid, &[ref1.cid.clone(), ref2.cid.clone()]).await;
        assert!(car.is_some());
        assert!(car.unwrap().len() > 16); // CAR header + at least one block
    }
}
