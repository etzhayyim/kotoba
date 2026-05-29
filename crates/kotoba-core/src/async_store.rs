use crate::cid::KotobaCid;
use async_trait::async_trait;
use bytes::Bytes;

/// Async variant of BlockStore — required for environments where I/O cannot
/// block the thread (wasm32 single-threaded, IndexedDB, etc.).
///
/// On native builds the trait requires Send; on wasm32 it uses `?Send` since
/// browser JS objects are `!Send`.
///
/// Native implementations delegate to the underlying sync BlockStore.
/// Browser implementations (`kotoba-store-web`) use IndexedDB.
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait AsyncBlockStore {
    async fn put_async(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()>;
    async fn get_async(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>>;
    async fn has_async(&self, cid: &KotobaCid) -> bool;

    async fn delete_async(&self, cid: &KotobaCid) -> anyhow::Result<()> {
        let _ = cid;
        Ok(())
    }
    async fn pin_async(&self, cid: &KotobaCid) {
        let _ = cid;
    }
    async fn unpin_async(&self, cid: &KotobaCid) {
        let _ = cid;
    }
    async fn is_pinned_async(&self, cid: &KotobaCid) -> bool {
        let _ = cid;
        false
    }

    /// Evict unpinned blocks until stored bytes ≤ `max_bytes`.
    /// Returns number of bytes freed. Default: no eviction.
    async fn evict_cold_async(&self, max_bytes: usize) -> usize {
        let _ = max_bytes;
        0
    }
}
