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
