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

    #[test]
    fn warrant_fields_preserved_after_roundtrip() {
        let ts: u64 = 1_234_567_890_000;
        let w = Warrant {
            accused:   vec![0x01u8; 32],
            evidence:  KotobaCid::from_bytes(b"evidence-block"),
            rule_id:   ValidationRule::SeqBreak as u8,
            validator: vec![0x02u8; 32],
            ts,
            sig:       vec![0xFFu8; 64],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&w, &mut buf).unwrap();
        let decoded: Warrant = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(decoded.ts, ts);
        assert_eq!(decoded.rule_id, ValidationRule::SeqBreak as u8);
        assert_eq!(decoded.sig.len(), 64);
        assert_eq!(decoded.sig[0], 0xFF);
    }

    #[test]
    fn warrant_json_roundtrip() {
        let w = Warrant {
            accused:   vec![0xAAu8; 16],
            evidence:  KotobaCid::from_bytes(b"test"),
            rule_id:   ValidationRule::RekeyRevoked as u8,
            validator: vec![0xBBu8; 16],
            ts:        9_999_999_999,
            sig:       vec![0x00u8; 64],
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: Warrant = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rule_id, ValidationRule::RekeyRevoked as u8);
        assert_eq!(back.ts, 9_999_999_999);
        assert_eq!(back.accused, w.accused);
    }

    #[test]
    fn all_validation_rules_unique_discriminants() {
        let rules = [
            ValidationRule::InvalidSignature   as u8,
            ValidationRule::SeqBreak           as u8,
            ValidationRule::PrevMismatch       as u8,
            ValidationRule::CacaoInvalid       as u8,
            ValidationRule::ProllyInconsistent as u8,
            ValidationRule::MaxStepsExceeded   as u8,
            ValidationRule::RekeyRevoked       as u8,
        ];
        let mut seen = std::collections::HashSet::new();
        for r in &rules {
            assert!(seen.insert(*r), "duplicate discriminant: {}", r);
        }
        assert_eq!(rules.len(), 7);
    }

    #[test]
    fn validation_rule_range_is_one_through_seven() {
        let values: Vec<u8> = (1u8..=7).collect();
        let rules = [
            ValidationRule::InvalidSignature   as u8,
            ValidationRule::SeqBreak           as u8,
            ValidationRule::PrevMismatch       as u8,
            ValidationRule::CacaoInvalid       as u8,
            ValidationRule::ProllyInconsistent as u8,
            ValidationRule::MaxStepsExceeded   as u8,
            ValidationRule::RekeyRevoked       as u8,
        ];
        let mut sorted = rules.to_vec();
        sorted.sort();
        assert_eq!(sorted, values);
    }

    #[test]
    fn warrant_accused_and_validator_separate() {
        let accused_bytes   = vec![0x11u8; 32];
        let validator_bytes = vec![0x22u8; 32];
        let w = Warrant {
            accused:   accused_bytes.clone(),
            evidence:  KotobaCid::from_bytes(b"ev"),
            rule_id:   ValidationRule::CacaoInvalid as u8,
            validator: validator_bytes.clone(),
            ts:        42,
            sig:       vec![0u8; 64],
        };
        assert_ne!(w.accused, w.validator, "accused and validator must differ");
        assert_eq!(w.accused,   accused_bytes);
        assert_eq!(w.validator, validator_bytes);
    }

    #[test]
    fn warrant_cbor_roundtrip_all_rule_variants() {
        for rule in [
            ValidationRule::InvalidSignature,
            ValidationRule::SeqBreak,
            ValidationRule::PrevMismatch,
            ValidationRule::CacaoInvalid,
            ValidationRule::ProllyInconsistent,
            ValidationRule::MaxStepsExceeded,
            ValidationRule::RekeyRevoked,
        ] {
            let expected_id = rule as u8;
            let w = Warrant {
                accused:   vec![0xAAu8; 16],
                evidence:  KotobaCid::from_bytes(b"ev"),
                rule_id:   expected_id,
                validator: vec![0xBBu8; 16],
                ts:        1_000_000,
                sig:       vec![0x42u8; 64],
            };
            let mut buf = Vec::new();
            ciborium::into_writer(&w, &mut buf).unwrap();
            let decoded: Warrant = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(decoded.rule_id, expected_id, "rule_id mismatch for variant {}", expected_id);
        }
    }

    #[test]
    fn warrant_ts_zero_is_valid() {
        let w = Warrant {
            accused:   vec![0u8; 32],
            evidence:  KotobaCid::from_bytes(b"genesis"),
            rule_id:   ValidationRule::SeqBreak as u8,
            validator: vec![1u8; 32],
            ts:        0,
            sig:       vec![0u8; 64],
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: Warrant = serde_json::from_str(&json).unwrap();
        assert_eq!(back.ts, 0);
    }

    #[test]
    fn warrant_sig_length_preserved_in_roundtrip() {
        for sig_len in [32usize, 64, 96] {
            let w = Warrant {
                accused:   vec![0xABu8; 32],
                evidence:  KotobaCid::from_bytes(b"e"),
                rule_id:   ValidationRule::MaxStepsExceeded as u8,
                validator: vec![0xCDu8; 32],
                ts:        999,
                sig:       vec![0xEFu8; sig_len],
            };
            let mut buf = Vec::new();
            ciborium::into_writer(&w, &mut buf).unwrap();
            let decoded: Warrant = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(decoded.sig.len(), sig_len, "sig length changed for len={}", sig_len);
        }
    }
}
