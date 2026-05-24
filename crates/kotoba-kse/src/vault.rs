use kotoba_core::cid::KotobaCid;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// BlobRef — reference to a content-addressed blob
#[derive(Debug, Clone)]
pub struct BlobRef {
    pub cid:  KotobaCid,
    pub size: usize,
}

/// Vault — chunked binary blob store (clean room, inspired by NATS Object Store)
/// Large tensors (FP8 weights, embeddings) stored here
pub struct Vault {
    blobs: Arc<RwLock<HashMap<String, Bytes>>>,
    // TODO: object_store backend for B2
}

impl Vault {
    pub fn new() -> Self {
        Self { blobs: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub async fn put(&self, data: Bytes) -> BlobRef {
        let cid = KotobaCid::from_bytes(&data);
        let key = cid.to_multibase();
        let size = data.len();
        self.blobs.write().await.insert(key, data);
        BlobRef { cid, size }
    }

    pub async fn get(&self, cid: &KotobaCid) -> Option<Bytes> {
        self.blobs.read().await.get(&cid.to_multibase()).cloned()
    }

    pub async fn contains(&self, cid: &KotobaCid) -> bool {
        self.blobs.read().await.contains_key(&cid.to_multibase())
    }
}
