use kotoba_core::cid::KotobaCid;
use serde::{Deserialize, Serialize};

/// Warrant — signed proof of invalid ChainEntry (Byzantine eviction signal)
/// Propagates through neighborhood gossip; K/2 warrants → peer eviction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warrant {
    pub accused:   Vec<u8>,    // accused NodeId bytes
    pub evidence:  KotobaCid,  // CID of the invalid ChainEntry
    pub rule_id:   u8,         // which validation rule failed
    pub validator: Vec<u8>,    // NodeId of detecting node
    pub ts:        u64,
    pub sig:       Vec<u8>,    // validator Ed25519 signature
}

#[repr(u8)]
pub enum ValidationRule {
    InvalidSignature   = 1,
    SeqBreak           = 2,
    PrevMismatch       = 3,
    CacaoInvalid       = 4,
    ProllyInconsistent = 5,
    MaxStepsExceeded   = 6,
}
