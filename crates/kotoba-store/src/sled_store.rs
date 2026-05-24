use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use crate::block_store::{BlockStore, StoreError};

/// Sled-backed block store.  The 36-byte CID is used directly as the key.
pub struct SledBlockStore {
    db: sled::Db,
}

impl SledBlockStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// In-memory temporary database (useful for tests / ephemeral nodes).
    pub fn temporary() -> Result<Self, StoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self { db })
    }
}

impl BlockStore for SledBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<(), StoreError> {
        self.db.insert(&cid.0, data)?;
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>, StoreError> {
        Ok(self.db.get(&cid.0)?.map(|v| Bytes::copy_from_slice(&v)))
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        self.db.contains_key(&cid.0).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_store::BlockStore;

    #[test]
    fn put_and_get_roundtrip() {
        let store = SledBlockStore::temporary().unwrap();
        let data = b"hello kotoba block";
        let cid = kotoba_core::cid::KotobaCid::from_bytes(data);
        store.put(&cid, data).unwrap();
        let retrieved = store.get(&cid).unwrap().unwrap();
        assert_eq!(retrieved.as_ref(), data);
    }

    #[test]
    fn put_verified_rejects_mismatch() {
        let store = SledBlockStore::temporary().unwrap();
        let cid = kotoba_core::cid::KotobaCid::from_bytes(b"real data");
        let result = store.put_verified(&cid, b"wrong data");
        assert!(result.is_err());
    }

    #[test]
    fn has_returns_false_for_missing() {
        let store = SledBlockStore::temporary().unwrap();
        let cid = kotoba_core::cid::KotobaCid::from_bytes(b"not stored");
        assert!(!store.has(&cid));
    }
}
