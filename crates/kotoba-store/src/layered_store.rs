/// Sled (primary, sync) + S3/B2 (secondary, async fire-and-forget).
///
/// Writes: synchronous sled put, then tokio::spawn B2 backup (non-blocking).
/// Reads:  sled first; on miss, B2 fallback + write-back to sled cache.
use bytes::Bytes;
use kotoba_core::{cid::KotobaCid, store::BlockStore};
use std::sync::Arc;

use crate::{S3BlockStore, SledBlockStore};

pub struct LayeredBlockStore {
    primary:   Arc<SledBlockStore>,
    secondary: Arc<S3BlockStore>,
}

impl LayeredBlockStore {
    pub fn new(primary: Arc<SledBlockStore>, secondary: Arc<S3BlockStore>) -> Self {
        Self { primary, secondary }
    }
}

impl BlockStore for LayeredBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        self.primary.put(cid, data)?;
        let s3   = Arc::clone(&self.secondary);
        let cid2 = cid.clone();
        let buf  = data.to_vec();
        tokio::spawn(async move {
            if let Err(e) = s3.put_async(&cid2, &buf).await {
                tracing::warn!("layered B2 backup put failed: {e}");
            }
        });
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        if let Some(b) = self.primary.get(cid)? {
            return Ok(Some(b));
        }
        let bytes = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.secondary.get_async(cid))
        })?;
        if let Some(ref b) = bytes {
            if let Err(e) = self.primary.put(cid, b) {
                tracing::warn!("layered sled write-back failed: {e}");
            }
        }
        Ok(bytes)
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        if self.primary.has(cid) {
            return true;
        }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.secondary.has_async(cid))
        })
    }
}
