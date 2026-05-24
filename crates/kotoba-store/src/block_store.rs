use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sled error: {0}")]
    Sled(#[from] sled::Error),
    #[error("cid mismatch: expected {expected}, got {actual}")]
    CidMismatch { expected: String, actual: String },
}

/// Content-addressed block store.
/// `put` verifies the CID matches blake3(bytes) before writing.
/// `get` returns None if the block is not present (no CID verification on get — caller must verify if needed).
pub trait BlockStore: Send + Sync {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> Result<(), StoreError>;
    fn get(&self, cid: &KotobaCid) -> Result<Option<Bytes>, StoreError>;
    fn has(&self, cid: &KotobaCid) -> bool;
    /// Verify and put: compute CID from bytes, assert it matches `cid`.
    fn put_verified(&self, cid: &KotobaCid, data: &[u8]) -> Result<(), StoreError> {
        let computed = KotobaCid::from_bytes(data);
        if &computed != cid {
            return Err(StoreError::CidMismatch {
                expected: cid.to_multibase(),
                actual: computed.to_multibase(),
            });
        }
        self.put(cid, data)
    }
}
