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
