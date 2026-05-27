use cid::Cid;
use multihash::Multihash;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// SHA2-256 multihash code.
const SHA2_256: u64 = 0x12;
/// CIDv1 raw codec.
const RAW: u64 = 0x55;

/// Compute a CIDv1 SHA2-256 raw content identifier.
pub fn cid_for(data: &[u8]) -> Cid {
    let digest = Sha256::digest(data);
    let mh = Multihash::<64>::wrap(SHA2_256, &digest).expect("multihash wrap");
    Cid::new_v1(RAW, mh)
}

/// In-memory block store keyed by CIDv1 SHA2-256.
#[derive(Clone, Default)]
pub struct MemBlockStore {
    inner: Arc<RwLock<HashMap<Cid, Vec<u8>>>>,
}

impl MemBlockStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute CID and store block; returns the CID.
    pub fn put(&self, data: Vec<u8>) -> Cid {
        let cid = cid_for(&data);
        self.inner.write().unwrap().insert(cid, data);
        cid
    }

    /// Store block under an already-known CID (received from remote).
    pub fn insert(&self, cid: Cid, data: Vec<u8>) {
        self.inner.write().unwrap().insert(cid, data);
    }

    pub fn get_local(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.inner.read().unwrap().get(cid).cloned()
    }

    pub fn contains_local(&self, cid: &Cid) -> bool {
        self.inner.read().unwrap().contains_key(cid)
    }
}
