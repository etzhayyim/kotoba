/// S3-compatible (Backblaze B2 / AWS S3) content-addressed block store.
///
/// Object key = `{prefix}/{cid_multibase}` (e.g. `kotoba/blocks/baaaa...`)
/// Implements the sync `BlockStore` trait via `block_in_place` — safe to call
/// from a tokio multi-threaded runtime.
use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use object_store::{ObjectStore, path::Path, PutPayload};
use std::sync::Arc;

pub struct S3BlockStore {
    store:  Arc<dyn ObjectStore>,
    prefix: String,
}

impl S3BlockStore {
    pub fn new(store: Arc<dyn ObjectStore>, prefix: impl Into<String>) -> Self {
        Self { store, prefix: prefix.into() }
    }

    fn path(&self, cid: &KotobaCid) -> Path {
        let key = cid.to_multibase();
        if self.prefix.is_empty() {
            Path::from(key.as_str())
        } else {
            Path::from(format!("{}/{}", self.prefix, key).as_str())
        }
    }

    pub async fn put_async(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        let path    = self.path(cid);
        let payload = PutPayload::from_bytes(Bytes::copy_from_slice(data));
        self.store.put(&path, payload).await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("s3 put: {e}"))
    }

    pub async fn get_async(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        match self.store.get(&self.path(cid)).await {
            Ok(r) => {
                let b = r.bytes().await.map_err(|e| anyhow::anyhow!("s3 get bytes: {e}"))?;
                Ok(Some(b))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("s3 get: {e}")),
        }
    }

    pub async fn has_async(&self, cid: &KotobaCid) -> bool {
        self.store.head(&self.path(cid)).await.is_ok()
    }
}

impl BlockStore for S3BlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.put_async(cid, data))
        })
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.get_async(cid))
        })
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.has_async(cid))
        })
    }
}
