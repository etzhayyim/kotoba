use super::cacao::Cacao;
use thiserror::Error;

/// DelegationChain — CACAO-based UCAN-like capability delegation
/// Root: wallet signs CACAO (SIWE) → session DID
/// Delegation: session DID signs CACAO → agent DID
/// Invocation: agent DID signs CACAO → Kotoba node
#[derive(Debug)]
pub struct DelegationChain {
    pub chain: Vec<Cacao>,
}

impl DelegationChain {
    pub fn new(invocation: Cacao) -> Self {
        Self { chain: vec![invocation] }
    }

    pub fn verify(&self, _graph_cid: &str, _required_cap: &str) -> Result<(), DelegationError> {
        if self.chain.is_empty() {
            return Err(DelegationError::EmptyChain);
        }
        // Phase 3 full implementation:
        // 1. Verify each CACAO signature
        // 2. Walk prf chain (resolve from Shelf["KOTOBA_UCANS"])
        // 3. Check capability attenuation (child ≤ parent)
        // 4. Verify root issuer = graph owner DID
        // 5. Check expiry
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DelegationError {
    #[error("empty delegation chain")]
    EmptyChain,
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("capability not granted: {0}")]
    CapabilityDenied(String),
    #[error("expired")]
    Expired,
    #[error("root issuer mismatch")]
    RootMismatch,
}
