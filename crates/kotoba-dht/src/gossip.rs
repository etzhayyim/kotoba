use super::source_chain::ChainEntry;
use super::warrant::Warrant;

/// Gossip protocol — neighborhood-scoped (not full mesh)
/// Each node forwards validated entries to K nearest peers
pub struct GossipMessage {
    pub kind: GossipKind,
}

pub enum GossipKind {
    Entry(Box<ChainEntry>),
    Warrant(Warrant),
}

/// Gossip router (placeholder — full libp2p GossipSub integration in kotoba-net)
pub struct GossipRouter;

impl GossipRouter {
    pub fn validate_and_forward(_entry: &ChainEntry) -> Result<(), GossipError> {
        // Phase 1: signature check + seq continuity
        // Phase 2: CACAO capability chain
        // Phase 3: Prolly consistency (for Commit entries)
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GossipError {
    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;
    use super::super::source_chain::{ChainContent, ChainEntry};

    fn make_entry() -> ChainEntry {
        ChainEntry::new(
            None,
            "did:example:alice".to_string(),
            0,
            ChainContent::Commit {
                graph_cid:   KotobaCid::from_bytes(b"graph"),
                prolly_root: KotobaCid::from_bytes(b"root"),
            },
            vec![0u8; 64],
        )
    }

    #[test]
    fn validate_and_forward_returns_ok() {
        let entry = make_entry();
        assert!(GossipRouter::validate_and_forward(&entry).is_ok());
    }

    #[test]
    fn gossip_error_validation_failed_display() {
        let e = GossipError::ValidationFailed("bad sig".to_string());
        assert_eq!(e.to_string(), "validation failed: bad sig");
    }

    #[test]
    fn gossip_message_entry_kind() {
        let entry = make_entry();
        let msg = GossipMessage { kind: GossipKind::Entry(Box::new(entry.clone())) };
        if let GossipKind::Entry(e) = msg.kind {
            assert_eq!(e.agent, entry.agent);
        } else {
            panic!("expected Entry kind");
        }
    }

    #[test]
    fn gossip_message_warrant_kind() {
        use super::super::warrant::Warrant;
        let w = Warrant {
            accused:   vec![0xAAu8; 32],
            evidence:  KotobaCid::from_bytes(b"bad-entry"),
            rule_id:   1,
            validator: vec![0xBBu8; 32],
            ts:        1_700_000_000_000,
            sig:       vec![0xCCu8; 64],
        };
        let msg = GossipMessage { kind: GossipKind::Warrant(w) };
        assert!(matches!(msg.kind, GossipKind::Warrant(_)));
    }

    #[test]
    fn gossip_error_is_debug() {
        let e = GossipError::ValidationFailed("test".to_string());
        let debug_str = format!("{e:?}");
        assert!(debug_str.contains("ValidationFailed"));
    }

    #[test]
    fn gossip_error_empty_message_display() {
        let e = GossipError::ValidationFailed(String::new());
        assert_eq!(e.to_string(), "validation failed: ");
    }

    #[test]
    fn validate_and_forward_multiple_calls_all_ok() {
        let entry = make_entry();
        for _ in 0..5 {
            assert!(GossipRouter::validate_and_forward(&entry).is_ok());
        }
    }

    #[test]
    fn gossip_error_display_long_message() {
        let long_msg = "x".repeat(200);
        let e = GossipError::ValidationFailed(long_msg.clone());
        assert_eq!(e.to_string(), format!("validation failed: {long_msg}"));
    }

    #[test]
    fn gossip_message_entry_preserves_seq() {
        let entry = make_entry();
        let expected_seq = entry.seq;
        let msg = GossipMessage { kind: GossipKind::Entry(Box::new(entry)) };
        if let GossipKind::Entry(e) = msg.kind {
            assert_eq!(e.seq, expected_seq);
        } else {
            panic!("expected Entry kind");
        }
    }
}
