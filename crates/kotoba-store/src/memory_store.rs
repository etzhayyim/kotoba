use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Default, Clone)]
pub struct MemoryBlockStore {
    blocks: Arc<RwLock<HashMap<[u8; 36], Bytes>>>,
    pinned: Arc<RwLock<HashSet<[u8; 36]>>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self { Self::default() }

    pub fn block_count(&self) -> usize {
        self.blocks.read().unwrap().len()
    }
}

impl BlockStore for MemoryBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        self.blocks.write().unwrap().insert(cid.0, Bytes::copy_from_slice(data));
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        Ok(self.blocks.read().unwrap().get(&cid.0).cloned())
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        self.blocks.read().unwrap().contains_key(&cid.0)
    }

    fn delete(&self, cid: &KotobaCid) -> anyhow::Result<()> {
        self.blocks.write().unwrap().remove(&cid.0);
        Ok(())
    }

    fn pin(&self, cid: &KotobaCid) {
        self.pinned.write().unwrap().insert(cid.0);
    }

    fn unpin(&self, cid: &KotobaCid) {
        self.pinned.write().unwrap().remove(&cid.0);
    }

    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        self.pinned.read().unwrap().contains(&cid.0)
    }

    fn all_cids(&self) -> Vec<KotobaCid> {
        self.blocks.read().unwrap().keys().map(|k| KotobaCid(*k)).collect()
    }
}
