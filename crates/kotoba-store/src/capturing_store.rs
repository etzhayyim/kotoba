use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use std::sync::{Arc, Mutex};

/// Wraps any BlockStore, passing through all operations while recording every
/// `put` call.  Used by `QuadStore::commit()` to collect ProllyTree blocks for
/// CAR bundle assembly without duplicating the write path.
pub struct CapturingBlockStore {
    inner: Arc<dyn BlockStore + Send + Sync>,
    captured: Mutex<Vec<(KotobaCid, Vec<u8>)>>,
}

impl CapturingBlockStore {
    pub fn new(inner: Arc<dyn BlockStore + Send + Sync>) -> Self {
        Self {
            inner,
            captured: Mutex::new(Vec::new()),
        }
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
        self.captured
            .lock()
            .unwrap()
            .push((cid.clone(), data.to_vec()));
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

    fn pin(&self, cid: &KotobaCid) {
        self.inner.pin(cid)
    }
    fn unpin(&self, cid: &KotobaCid) {
        self.inner.unpin(cid)
    }
    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        self.inner.is_pinned(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBlockStore;

    fn make_cid(tag: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(tag)
    }

    #[test]
    fn put_is_captured_and_forwarded() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        let cid = make_cid(b"block-a");
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
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

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
        let cid = make_cid(b"get-test");
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
        let cid = make_cid(b"del-test");
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        cs.put(&cid, b"will-be-deleted").unwrap();
        cs.delete(&cid).unwrap();
        assert!(!inner.has(&cid));
    }

    #[test]
    fn captured_data_matches_written_data() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        let cid = make_cid(b"data-check");
        let data = b"exact payload bytes";
        cs.put(&cid, data).unwrap();

        let drained = cs.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].1, data.as_slice());
    }

    #[test]
    fn captured_cid_matches_written_cid() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        let cid = make_cid(b"cid-match");
        cs.put(&cid, b"content").unwrap();

        let drained = cs.drain();
        assert_eq!(drained[0].0, cid);
    }

    #[test]
    fn double_drain_second_drain_is_empty() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        cs.put(&make_cid(b"a"), b"a").unwrap();
        cs.put(&make_cid(b"b"), b"b").unwrap();

        let first = cs.drain();
        let second = cs.drain();
        assert_eq!(first.len(), 2);
        assert!(second.is_empty(), "second drain must be empty");
        assert!(cs.is_empty());
    }

    #[test]
    fn new_store_is_empty() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);
        assert!(cs.is_empty());
        assert_eq!(cs.len(), 0);
    }

    #[test]
    fn pin_delegates_to_inner() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cid = make_cid(b"pin-test");
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        cs.put(&cid, b"pinned").unwrap();
        cs.pin(&cid);
        assert!(cs.is_pinned(&cid));
        cs.unpin(&cid);
        assert!(!cs.is_pinned(&cid));
    }

    #[test]
    fn multiple_puts_accumulate_in_order() {
        let inner = Arc::new(MemoryBlockStore::default());
        let cs = CapturingBlockStore::new(Arc::clone(&inner) as _);

        for i in 0u8..5 {
            let cid = make_cid(&[i; 4]);
            cs.put(&cid, &[i; 8]).unwrap();
        }
        assert_eq!(cs.len(), 5);
        let drained = cs.drain();
        assert_eq!(drained.len(), 5);
        // Verify each entry data
        for (i, (_cid, data)) in drained.iter().enumerate() {
            assert_eq!(data, &vec![i as u8; 8]);
        }
    }
}
