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
}
