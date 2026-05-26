use kotoba_core::cid::KotobaCid;
use thiserror::Error;

/// The canonical BlockStore trait lives in kotoba-core to avoid circular deps.
/// Re-export it here so callers can use `kotoba_store::BlockStore`.
pub use kotoba_core::store::BlockStore;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Verify that `blake3(data) == cid`, then put.  Returns `Err` on CID mismatch.
pub fn put_verified(store: &dyn BlockStore, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
    let computed = KotobaCid::from_bytes(data);
    anyhow::ensure!(
        &computed == cid,
        "cid mismatch: expected {}, got {}",
        cid.to_multibase(),
        computed.to_multibase(),
    );
    store.put(cid, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBlockStore;
    use std::sync::Arc;

    #[test]
    fn put_verified_succeeds_with_correct_cid() {
        let store = Arc::new(MemoryBlockStore::new());
        let data  = b"hello kotoba";
        let cid   = KotobaCid::from_bytes(data);
        put_verified(&*store, &cid, data).unwrap();
        assert!(store.has(&cid));
    }

    #[test]
    fn put_verified_fails_with_wrong_cid() {
        let store    = Arc::new(MemoryBlockStore::new());
        let data     = b"real data";
        let bad_cid  = KotobaCid::from_bytes(b"different data");
        let result   = put_verified(&*store, &bad_cid, data);
        assert!(result.is_err(), "must reject CID mismatch");
        // Block must NOT have been written
        assert!(!store.has(&bad_cid));
    }

    #[test]
    fn store_error_is_displayable() {
        let err = StoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));
        let msg = err.to_string();
        assert!(msg.contains("io error") || msg.contains("disk full"), "got: {msg}");
    }

    #[test]
    fn put_verified_empty_data() {
        let store = Arc::new(MemoryBlockStore::new());
        let data  = b"";
        let cid   = KotobaCid::from_bytes(data);
        put_verified(&*store, &cid, data).unwrap();
        assert!(store.has(&cid), "empty data must be stored");
    }

    #[test]
    fn put_verified_binary_data() {
        let store = Arc::new(MemoryBlockStore::new());
        let data: Vec<u8> = (0u8..=255).collect();
        let cid = KotobaCid::from_bytes(&data);
        put_verified(&*store, &cid, &data).unwrap();
        assert!(store.has(&cid));
    }

    #[test]
    fn put_verified_two_different_blocks() {
        let store = Arc::new(MemoryBlockStore::new());
        let d1 = b"block one";
        let d2 = b"block two";
        let c1 = KotobaCid::from_bytes(d1);
        let c2 = KotobaCid::from_bytes(d2);
        put_verified(&*store, &c1, d1).unwrap();
        put_verified(&*store, &c2, d2).unwrap();
        assert!(store.has(&c1));
        assert!(store.has(&c2));
        assert_ne!(c1, c2, "different data must yield different CIDs");
    }

    #[test]
    fn store_error_debug_is_non_empty() {
        let err = StoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, "err"));
        let s = format!("{:?}", err);
        assert!(!s.is_empty());
    }
}
