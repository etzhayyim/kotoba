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
