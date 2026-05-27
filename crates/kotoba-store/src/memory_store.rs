use bytes::Bytes;
use dashmap::DashMap;
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use std::sync::Arc;

#[derive(Default, Clone)]
pub struct MemoryBlockStore {
    blocks: Arc<DashMap<[u8; 36], Bytes>>,
    pinned: Arc<DashMap<[u8; 36], ()>>,
}

impl MemoryBlockStore {
    pub fn new() -> Self { Self::default() }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

impl BlockStore for MemoryBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        self.blocks.insert(cid.0, Bytes::copy_from_slice(data));
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<Bytes>> {
        Ok(self.blocks.get(&cid.0).map(|r| r.clone()))
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        self.blocks.contains_key(&cid.0)
    }

    fn delete(&self, cid: &KotobaCid) -> anyhow::Result<()> {
        self.blocks.remove(&cid.0);
        Ok(())
    }

    fn pin(&self, cid: &KotobaCid) {
        self.pinned.insert(cid.0, ());
    }

    fn unpin(&self, cid: &KotobaCid) {
        self.pinned.remove(&cid.0);
    }

    fn is_pinned(&self, cid: &KotobaCid) -> bool {
        self.pinned.contains_key(&cid.0)
    }

    fn all_cids(&self) -> Vec<KotobaCid> {
        self.blocks.iter().map(|r| KotobaCid(*r.key())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(tag: &[u8]) -> KotobaCid { KotobaCid::from_bytes(tag) }

    #[test]
    fn put_and_get_roundtrip() {
        let store = MemoryBlockStore::new();
        let c = cid(b"block-a");
        store.put(&c, b"data").unwrap();
        assert_eq!(store.get(&c).unwrap().as_deref(), Some(b"data".as_slice()));
    }

    #[test]
    fn get_missing_returns_none() {
        let store = MemoryBlockStore::new();
        assert!(store.get(&cid(b"absent")).unwrap().is_none());
    }

    #[test]
    fn has_reflects_put_and_delete() {
        let store = MemoryBlockStore::new();
        let c = cid(b"has-test");
        assert!(!store.has(&c));
        store.put(&c, b"x").unwrap();
        assert!(store.has(&c));
        store.delete(&c).unwrap();
        assert!(!store.has(&c));
    }

    #[test]
    fn delete_missing_is_idempotent() {
        let store = MemoryBlockStore::new();
        store.delete(&cid(b"never-existed")).unwrap();
    }

    #[test]
    fn block_count_tracks_puts_and_deletes() {
        let store = MemoryBlockStore::new();
        assert_eq!(store.block_count(), 0);
        let c1 = cid(b"c1");
        let c2 = cid(b"c2");
        store.put(&c1, b"a").unwrap();
        store.put(&c2, b"b").unwrap();
        assert_eq!(store.block_count(), 2);
        store.delete(&c1).unwrap();
        assert_eq!(store.block_count(), 1);
    }

    #[test]
    fn pin_prevents_nothing_but_is_tracked() {
        let store = MemoryBlockStore::new();
        let c = cid(b"pinned");
        store.put(&c, b"v").unwrap();
        assert!(!store.is_pinned(&c));
        store.pin(&c);
        assert!(store.is_pinned(&c));
        store.unpin(&c);
        assert!(!store.is_pinned(&c));
    }

    #[test]
    fn all_cids_returns_all_stored_keys() {
        let store = MemoryBlockStore::new();
        let c1 = cid(b"all-cids-1");
        let c2 = cid(b"all-cids-2");
        store.put(&c1, b"").unwrap();
        store.put(&c2, b"").unwrap();
        let cids = store.all_cids();
        assert!(cids.contains(&c1));
        assert!(cids.contains(&c2));
        assert_eq!(cids.len(), 2);
    }

    #[test]
    fn put_overwrites_existing() {
        let store = MemoryBlockStore::new();
        let c = cid(b"overwrite");
        store.put(&c, b"old").unwrap();
        store.put(&c, b"new").unwrap();
        assert_eq!(store.get(&c).unwrap().as_deref(), Some(b"new".as_slice()));
        assert_eq!(store.block_count(), 1);
    }

    #[test]
    fn clone_shares_underlying_data() {
        let store1 = MemoryBlockStore::new();
        let store2 = store1.clone();
        let c = cid(b"shared");
        store1.put(&c, b"value").unwrap();
        assert!(store2.has(&c), "clone shares inner Arc");
        assert_eq!(store2.get(&c).unwrap().as_deref(), Some(b"value".as_slice()));
    }

    #[test]
    fn empty_data_put_and_get() {
        let store = MemoryBlockStore::new();
        let c = cid(b"empty-val");
        store.put(&c, b"").unwrap();
        let got = store.get(&c).unwrap().expect("block should exist");
        assert_eq!(got.len(), 0);
        assert!(store.has(&c));
    }

    #[test]
    fn unpin_nonexistent_cid_is_noop() {
        let store = MemoryBlockStore::new();
        let c = cid(b"never-pinned");
        store.unpin(&c);
        assert!(!store.is_pinned(&c));
    }

    #[test]
    fn pin_then_delete_does_not_keep_pin() {
        let store = MemoryBlockStore::new();
        let c = cid(b"pin-del");
        store.put(&c, b"data").unwrap();
        store.pin(&c);
        assert!(store.is_pinned(&c));
        store.delete(&c).unwrap();
        assert!(!store.has(&c));
        assert!(store.is_pinned(&c));
    }

    #[test]
    fn all_cids_empty_on_new_store() {
        let store = MemoryBlockStore::new();
        assert!(store.all_cids().is_empty());
    }

    #[test]
    fn block_count_starts_at_zero() {
        let store = MemoryBlockStore::new();
        assert_eq!(store.block_count(), 0);
    }

    #[test]
    fn large_block_data_roundtrip() {
        let store = MemoryBlockStore::new();
        let large_data: Vec<u8> = (0u8..=255u8).cycle().take(4096).collect();
        let c = cid(&large_data[..16]);
        store.put(&c, &large_data).unwrap();
        let got = store.get(&c).unwrap().expect("should exist");
        assert_eq!(got.as_ref(), large_data.as_slice());
    }
}
