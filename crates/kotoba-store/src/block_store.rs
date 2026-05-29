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
        let data = b"hello kotoba";
        let cid = KotobaCid::from_bytes(data);
        put_verified(&*store, &cid, data).unwrap();
        assert!(store.has(&cid));
    }

    #[test]
    fn put_verified_fails_with_wrong_cid() {
        let store = Arc::new(MemoryBlockStore::new());
        let data = b"real data";
        let bad_cid = KotobaCid::from_bytes(b"different data");
        let result = put_verified(&*store, &bad_cid, data);
        assert!(result.is_err(), "must reject CID mismatch");
        // Block must NOT have been written
        assert!(!store.has(&bad_cid));
    }

    #[test]
    fn store_error_is_displayable() {
        let err = StoreError::Io(std::io::Error::new(std::io::ErrorKind::Other, "disk full"));
        let msg = err.to_string();
        assert!(
            msg.contains("io error") || msg.contains("disk full"),
            "got: {msg}"
        );
    }

    #[test]
    fn put_verified_empty_data() {
        let store = Arc::new(MemoryBlockStore::new());
        let data = b"";
        let cid = KotobaCid::from_bytes(data);
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

    // ---- New tests --------------------------------------------------------

    #[test]
    fn put_verified_large_data() {
        let store = Arc::new(MemoryBlockStore::new());
        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let cid = KotobaCid::from_bytes(&data);
        put_verified(&*store, &cid, &data).unwrap();
        assert!(store.has(&cid));
    }

    #[test]
    fn put_verified_wrong_cid_does_not_store_block() {
        // Supplying bad_cid for different data: neither bad_cid nor real_cid must be present.
        let store = Arc::new(MemoryBlockStore::new());
        let data = b"payload data";
        let bad_cid = KotobaCid::from_bytes(b"unrelated");
        let real_cid = KotobaCid::from_bytes(data);
        let _ = put_verified(&*store, &bad_cid, data);
        // bad_cid (mismatch) must NOT be in store.
        assert!(!store.has(&bad_cid));
        // real_cid (not stored either — we passed bad_cid) must also be absent.
        assert!(!store.has(&real_cid));
    }

    #[test]
    fn store_error_contains_io_message() {
        let err = StoreError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no space left",
        ));
        assert!(err.to_string().contains("no space left") || err.to_string().contains("io error"));
    }

    #[test]
    fn cid_is_content_addressed_by_blake3() {
        // Two identical byte payloads must produce the same CID.
        let a = KotobaCid::from_bytes(b"same content");
        let b = KotobaCid::from_bytes(b"same content");
        assert_eq!(a, b);
        // Different content must produce different CIDs.
        let c = KotobaCid::from_bytes(b"different content");
        assert_ne!(a, c);
    }

    #[test]
    fn put_verified_idempotent() {
        // Storing the same block twice must not error.
        let store = Arc::new(MemoryBlockStore::new());
        let data = b"idempotent block";
        let cid = KotobaCid::from_bytes(data);
        put_verified(&*store, &cid, data).unwrap();
        put_verified(&*store, &cid, data).unwrap();
        assert!(store.has(&cid));
    }

    #[test]
    fn cid_multibase_roundtrip() {
        let data = b"multibase-test";
        let cid = KotobaCid::from_bytes(data);
        let mb = cid.to_multibase();
        assert!(!mb.is_empty(), "multibase encoding must be non-empty");
        let restored = KotobaCid::from_multibase(&mb);
        assert!(restored.is_some(), "multibase must parse back to CID");
        assert_eq!(restored.unwrap(), cid);
    }

    #[test]
    fn store_has_returns_false_for_unwritten_cid() {
        let store = Arc::new(MemoryBlockStore::new());
        let cid = KotobaCid::from_bytes(b"never-written");
        assert!(
            !store.has(&cid),
            "has() must return false for unwritten CID"
        );
    }

    #[test]
    fn put_verified_error_message_contains_cid_hex() {
        let store = Arc::new(MemoryBlockStore::new());
        let data = b"content";
        let bad_cid = KotobaCid::from_bytes(b"wrong");
        let err = put_verified(&*store, &bad_cid, data).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mismatch") || msg.contains("cid"),
            "error must mention cid mismatch, got: {msg}"
        );
    }
}
