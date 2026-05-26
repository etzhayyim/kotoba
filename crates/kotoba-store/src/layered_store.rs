/// Hot (sync `Arc<dyn BlockStore>`) + S3/B2 cold (async fire-and-forget).
///
/// Writes: synchronous hot put, then `tokio::spawn` B2 backup (non-blocking).
/// Reads:  hot first; on miss, B2 fallback + write-back to hot cache.
use bytes::Bytes;
use kotoba_core::{cid::KotobaCid, store::BlockStore};
use std::sync::Arc;

use crate::S3BlockStore;

pub struct LayeredBlockStore {
    hot:  Arc<dyn BlockStore + Send + Sync>,
    cold: Arc<S3BlockStore>,
}

impl LayeredBlockStore {
    pub fn new(
        hot:  Arc<dyn BlockStore + Send + Sync>,
        cold: Arc<S3BlockStore>,
    ) -> Self {
        Self { hot, cold }
    }
}

impl BlockStore for LayeredBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        self.hot.put(cid, data)?;
        let cold = Arc::clone(&self.cold);
        let cid2 = cid.clone();
        let buf  = data.to_vec();
        tokio::spawn(async move {
            if let Err(e) = cold.put_async(&cid2, &buf).await {
                tracing::warn!("layered B2 backup put failed: {e}");
            }
        });
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        if let Some(b) = self.hot.get(cid)? {
            return Ok(Some(b));
        }
        let bytes = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.cold.get_async(cid))
        })?;
        if let Some(ref b) = bytes {
            if let Err(e) = self.hot.put(cid, b) {
                tracing::warn!("layered hot write-back failed: {e}");
            }
        }
        Ok(bytes)
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        if self.hot.has(cid) { return true; }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.cold.has_async(cid))
        })
    }
}
