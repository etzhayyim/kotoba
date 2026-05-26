use std::sync::{Arc, Mutex};
use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;

/// Wraps any BlockStore, passing through all operations while recording every
/// `put` call.  Used by `QuadStore::commit()` to collect ProllyTree blocks for
/// CAR bundle assembly without duplicating the write path.
pub struct CapturingBlockStore {
    inner:    Arc<dyn BlockStore + Send + Sync>,
    captured: Mutex<Vec<(KotobaCid, Vec<u8>)>>,
}

impl CapturingBlockStore {
    pub fn new(inner: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self { inner, captured: Mutex::new(Vec::new()) }
    }

    /// Drain and return all captured (cid, data) pairs, leaving the buffer empty.
    pub fn drain(&self) -> Vec<(KotobaCid, Vec<u8>)> {
        std::mem::take(&mut *self.captured.lock().unwrap())
    }

    pub fn len(&self) -> usize {
        self.captured.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BlockStore for CapturingBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        self.inner.put(cid, data)?;
        self.captured.lock().unwrap().push((cid.clone(), data.to_vec()));
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        self.inner.get(cid)
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        self.inner.has(cid)
    }

    fn delete(&self, cid: &KotobaCid) -> anyhow::Result<()> {
        self.inner.delete(cid)
    }

    fn pin(&self, cid: &KotobaCid)   { self.inner.pin(cid) }
    fn unpin(&self, cid: &KotobaCid) { self.inner.unpin(cid) }
    fn is_pinned(&self, cid: &KotobaCid) -> bool { self.inner.is_pinned(cid) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBlockStore;

    fn make_cid(tag: &[u8]) -> KotobaCid { KotobaCid::from_bytes(tag) }

    #[test]
    fn put_is_captured_and_forwarded() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs    = CapturingBlockStore::new(Arc::clone(&inner) as _);

        let cid  = make_cid(b"block-a");
        let data = b"hello";
        cs.put(&cid, data).unwrap();

        // Inner store received the block.
        assert_eq!(inner.get(&cid).unwrap().as_deref(), Some(data.as_slice()));
        // Captured buffer has exactly one entry.
        assert_eq!(cs.len(), 1);
        assert!(!cs.is_empty());
    }

    #[test]
    fn drain_returns_and_clears_captured() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs    = CapturingBlockStore::new(Arc::clone(&inner) as _);

        let c1 = make_cid(b"block-1");
        let c2 = make_cid(b"block-2");
        cs.put(&c1, b"data1").unwrap();
        cs.put(&c2, b"data2").unwrap();

        let drained = cs.drain();
        assert_eq!(drained.len(), 2);
        assert!(cs.is_empty(), "drain must empty the buffer");
        // Inner store still has both blocks.
        assert!(inner.has(&c1));
        assert!(inner.has(&c2));
    }

    #[test]
    fn get_and_has_delegate_to_inner() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cid   = make_cid(b"get-test");
        inner.put(&cid, b"value").unwrap();

        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);
        assert!(cs.has(&cid));
        assert_eq!(cs.get(&cid).unwrap().as_deref(), Some(b"value".as_slice()));
        // A put-via-inner is NOT captured (only CapturingBlockStore::put is tracked).
        assert_eq!(cs.len(), 0);
    }

    #[test]
    fn delete_delegates_to_inner() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cid   = make_cid(b"del-test");
        let cs    = CapturingBlockStore::new(Arc::clone(&inner) as _);

        cs.put(&cid, b"will-be-deleted").unwrap();
        cs.delete(&cid).unwrap();
        assert!(!inner.has(&cid));
    }
}
