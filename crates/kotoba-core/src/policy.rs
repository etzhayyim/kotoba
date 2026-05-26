use crate::cid::KotobaCid;
use serde::{Deserialize, Serialize};

/// Access policy attached to any datum in kotoba.
///
/// The CID always refers to the ciphertext block and is iroh-public regardless
/// of policy — the network carries ciphertext freely; only key holders can decrypt.
///
/// `Open`      — plaintext; no key required.
/// `Encrypted` — AES-GCM ciphertext.  Symmetric data-key is delivered via PRE
///               after CACAO authorisation (see `PreKeyRegistry` + `PreProxy`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DataPolicy {
    #[default]
    Open,
    Encrypted {
        /// CID of the AES-GCM ciphertext block stored in BlockStore / iroh.
        ct_cid: KotobaCid,
        /// CID of the PRE key-registry entry: maps (owner_did, accessor_did) → re-key.
        policy_cid: KotobaCid,
    },
}

impl DataPolicy {
    #[inline] pub fn is_open(&self) -> bool { matches!(self, DataPolicy::Open) }
    #[inline] pub fn is_encrypted(&self) -> bool { !self.is_open() }
}
