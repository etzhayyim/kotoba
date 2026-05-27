//! Wire format for Pregel messages exchanged between KOTOBA nodes via GossipSub.
//! Serialized as JSON for human-readability during dev; switch to CBOR in prod.

/// Wire format for Pregel inter-node messages.
/// Serialized as JSON for human-readability during dev; switch to CBOR in prod.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PregelNetMessage {
    /// Source vertex ID (multibase-encoded CID)
    pub src: String,
    /// Destination vertex ID (multibase-encoded CID)
    pub dst: String,
    /// Opaque payload (base64-encoded)
    pub payload_b64: String,
}

/// GossipSub topic key for Pregel inter-node messages.
/// Passed to `KotobaSwarm::subscribe` / `publish` — the swarm prepends `kotoba/`.
pub const PREGEL_GOSSIP_TOPIC: &str = "pregel/messages";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pregel_gossip_topic_has_no_kotoba_prefix() {
        // The swarm prepends "kotoba/"; the constant must NOT include it.
        assert!(!PREGEL_GOSSIP_TOPIC.starts_with("kotoba/"));
        assert_eq!(PREGEL_GOSSIP_TOPIC, "pregel/messages");
    }

    #[test]
    fn pregel_net_message_json_roundtrip() {
        let msg = PregelNetMessage {
            src:         "bsrc000cid".to_string(),
            dst:         "bdst000cid".to_string(),
            payload_b64: "aGVsbG8=".to_string(),
        };
        let json  = serde_json::to_string(&msg).unwrap();
        let back: PregelNetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.src,         msg.src);
        assert_eq!(back.dst,         msg.dst);
        assert_eq!(back.payload_b64, msg.payload_b64);
    }

    #[test]
    fn pregel_net_message_json_field_names() {
        let msg = PregelNetMessage {
            src:         "s".to_string(),
            dst:         "d".to_string(),
            payload_b64: "p".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"src\""));
        assert!(json.contains("\"dst\""));
        assert!(json.contains("\"payload_b64\""));
    }

    #[test]
    fn empty_src_and_dst_roundtrip() {
        let msg = PregelNetMessage {
            src:         "".to_string(),
            dst:         "".to_string(),
            payload_b64: "".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: PregelNetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.src, "");
        assert_eq!(back.dst, "");
        assert_eq!(back.payload_b64, "");
    }

    #[test]
    fn large_payload_b64_roundtrip() {
        // 1 KB of 'A' characters as payload_b64
        let big = "A".repeat(1024);
        let msg = PregelNetMessage {
            src:         "bsrcbig".to_string(),
            dst:         "bdstbig".to_string(),
            payload_b64: big.clone(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: PregelNetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload_b64, big);
    }

    #[test]
    fn deserialize_from_handcrafted_json() {
        let json = r#"{"src":"bsrc1","dst":"bdst1","payload_b64":"dGVzdA=="}"#;
        let msg: PregelNetMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.src, "bsrc1");
        assert_eq!(msg.dst, "bdst1");
        assert_eq!(msg.payload_b64, "dGVzdA==");
    }

    #[test]
    fn clone_produces_equal_message() {
        let msg = PregelNetMessage {
            src:         "bclone".to_string(),
            dst:         "bdst".to_string(),
            payload_b64: "cGF5bG9hZA==".to_string(),
        };
        let cloned = msg.clone();
        assert_eq!(cloned.src, msg.src);
        assert_eq!(cloned.dst, msg.dst);
        assert_eq!(cloned.payload_b64, msg.payload_b64);
    }

    // ── New tests ─────────────────────────────────────────────────────────────

    #[test]
    fn pregel_gossip_topic_is_non_empty() {
        assert!(!PREGEL_GOSSIP_TOPIC.is_empty());
    }

    #[test]
    fn pregel_gossip_topic_contains_slash() {
        // "pregel/messages" — must contain a slash as sub-topic separator.
        assert!(PREGEL_GOSSIP_TOPIC.contains('/'));
    }

    #[test]
    fn pregel_net_message_debug_contains_field_values() {
        let msg = PregelNetMessage {
            src:         "bsrcdbg".to_string(),
            dst:         "bdstdbg".to_string(),
            payload_b64: "payload".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("bsrcdbg"));
        assert!(dbg.contains("bdstdbg"));
        assert!(dbg.contains("payload"));
    }

    #[test]
    fn pregel_net_message_src_dst_can_be_multibase_cids() {
        // Verify realistic CID-like strings round-trip correctly.
        let msg = PregelNetMessage {
            src:         "bafy2bzacexxxxxxxxxx".to_string(),
            dst:         "bafy2bzaceyyyyyyyyyy".to_string(),
            payload_b64: "dGVzdA==".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: PregelNetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.src, "bafy2bzacexxxxxxxxxx");
        assert_eq!(back.dst, "bafy2bzaceyyyyyyyyyy");
    }

    #[test]
    fn pregel_net_message_missing_field_deserialize_fails() {
        // Missing "payload_b64" field should fail deserialization.
        let json = r#"{"src":"bsrc1","dst":"bdst1"}"#;
        let result: Result<PregelNetMessage, _> = serde_json::from_str(json);
        assert!(result.is_err(), "missing payload_b64 should fail");
    }

    #[test]
    fn pregel_net_message_with_unicode_src_dst() {
        // Unicode characters in src/dst survive round-trip (JSON escaping).
        let msg = PregelNetMessage {
            src:         "src_日本語".to_string(),
            dst:         "dst_漢字".to_string(),
            payload_b64: "dGVzdA==".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: PregelNetMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.src, "src_日本語");
        assert_eq!(back.dst, "dst_漢字");
    }
}
