use crate::cid::KotobaCid;
use bytes::Bytes;

/// Content-addressed block store — minimal trait defined in kotoba-core
/// so that kotoba-core::prolly can depend on it without a circular dep.
///
/// kotoba-store re-exports this trait and provides concrete implementations
/// (SledBlockStore, MemoryBlockStore, BudgetedBlockStore).
pub trait BlockStore: Send + Sync {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()>;
    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>>;
    fn has(&self, cid: &KotobaCid) -> bool;

    /// Remove a block. Default no-op for read-only or append-only stores.
    fn delete(&self, cid: &KotobaCid) -> anyhow::Result<()> {
        let _ = cid;
        Ok(())
    }

    /// Protect this CID from eviction by BudgetedBlockStore. Default no-op.
    fn pin(&self, cid: &KotobaCid) {
        let _ = cid;
    }

    /// Allow this CID to be evicted again. Default no-op.
    fn unpin(&self, cid: &KotobaCid) {
        let _ = cid;
    }

    /// Returns true if this CID is currently pinned.
    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        let _ = cid;
        false
    }

    /// Enumerate all CIDs stored in this store.  Default returns empty vec for
    /// stores that don't support listing (S3, kubo).  Used by `QuadStore::gc_dead_blocks`.
    fn all_cids(&self) -> Vec<KotobaCid> {
        vec![]
    }
}
