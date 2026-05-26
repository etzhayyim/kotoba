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
    /// PRE re-key grant revoked by owner — peers must drop cached grant.
    RekeyRevoked       = 7,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    #[test]
    fn warrant_cbor_roundtrip() {
        let w = Warrant {
            accused:   vec![0xAAu8; 32],
            evidence:  KotobaCid::from_bytes(b"bad-entry"),
            rule_id:   ValidationRule::InvalidSignature as u8,
            validator: vec![0xBBu8; 32],
            ts:        1_700_000_000_000,
            sig:       vec![0xCCu8; 64],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&w, &mut buf).unwrap();
        let decoded: Warrant = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded.rule_id, ValidationRule::InvalidSignature as u8);
        assert_eq!(decoded.accused, w.accused);
        assert_eq!(decoded.evidence, w.evidence);
        assert_eq!(decoded.ts, w.ts);
    }

    #[test]
    fn validation_rule_discriminants_are_stable() {
        assert_eq!(ValidationRule::InvalidSignature   as u8, 1);
        assert_eq!(ValidationRule::SeqBreak           as u8, 2);
        assert_eq!(ValidationRule::PrevMismatch       as u8, 3);
        assert_eq!(ValidationRule::CacaoInvalid       as u8, 4);
        assert_eq!(ValidationRule::ProllyInconsistent as u8, 5);
        assert_eq!(ValidationRule::MaxStepsExceeded   as u8, 6);
        assert_eq!(ValidationRule::RekeyRevoked       as u8, 7);
    }
}
