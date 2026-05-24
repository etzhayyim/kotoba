use super::source_chain::ChainEntry;
use super::warrant::Warrant;

/// Gossip protocol — neighborhood-scoped (not full mesh)
/// Each node forwards validated entries to K nearest peers
pub struct GossipMessage {
    pub kind: GossipKind,
}

pub enum GossipKind {
    Entry(ChainEntry),
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
