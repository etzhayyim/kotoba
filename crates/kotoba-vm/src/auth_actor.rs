/// Actor-first, crypto-aware Pregel types.
///
/// The PRE proxy in kotoba-server decrypts all inbound messages and encrypts
/// all outbound messages at the node boundary.  Compute functions always see
/// plaintext — they are completely crypto-unaware.
///
/// Encryption policy lives on `AuthOutMessage` and `AuthQuad`, not inside the
/// compute function itself.  The node applies the policy after `compute()` returns.
use std::sync::Arc;
use kotoba_core::{cid::KotobaCid, policy::DataPolicy};
use kotoba_auth::{cacao::Cacao, delegation::DelegationChain};
use kotoba_kqe::quad::Quad;

// ---------------------------------------------------------------------------
// Actor — identity-bearing Pregel vertex
// ---------------------------------------------------------------------------

/// A Pregel vertex with a DID identity, X25519 public key, and held capabilities.
pub struct Actor {
    /// Content-addressed vertex ID (= subject CID in the Quad store).
    pub vertex_cid: KotobaCid,
    /// DID of this actor (e.g. `did:erc725:gftd:260425:0x...`).
    pub did: String,
    /// X25519 public key — used by the PRE proxy to HPKE-seal replies to this actor.
    pub public_key: [u8; 32],
    /// Opaque vertex state (CBOR-encoded; managed by the compute function).
    pub state: Vec<u8>,
    /// Capabilities this actor currently holds (verified `DelegationChain`s).
    pub caps: Vec<DelegationChain>,
}

// ---------------------------------------------------------------------------
// Inbound — what the compute function receives
// ---------------------------------------------------------------------------

/// Inbound message delivered to an actor's compute function.
///
/// Always plaintext — the node's PRE proxy decrypted it before delivery.
pub struct AuthMessage {
    /// DID of the sending actor.
    pub src_did: String,
    /// Plaintext payload (typically CBOR-encoded `Delta` or arbitrary bytes).
    pub payload: Vec<u8>,
    /// Optional capability delegated by the sender to this actor.
    pub cap: Option<DelegationChain>,
}

// ---------------------------------------------------------------------------
// Outbound — what the compute function produces
// ---------------------------------------------------------------------------

/// Outbound message to another actor, with an attached data policy.
///
/// The node's PRE proxy reads `policy` after `compute()` returns:
/// - `Open`      → gossip payload as-is.
/// - `Encrypted` → HPKE-seal payload to `dst_did`'s public key, gossip ciphertext.
pub struct AuthOutMessage {
    /// Destination actor DID.
    pub dst_did: String,
    /// Plaintext payload — the node encrypts this according to `policy`.
    pub payload: Vec<u8>,
    /// Data policy for this message.
    pub policy: DataPolicy,
    /// Optional capability to grant to the recipient alongside this message.
    pub cap: Option<Cacao>,
}

/// Quad assertion emitted by a compute function, with policy and provenance.
pub struct AuthQuad {
    pub quad: Quad,
    /// Data policy for the quad's object value.
    pub policy: DataPolicy,
    /// Delegation chain proving the actor's right to assert this quad.
    pub chain: DelegationChain,
}

// ---------------------------------------------------------------------------
// ActorOutput — full result of one compute() invocation
// ---------------------------------------------------------------------------

pub struct ActorOutput {
    /// Updated actor state (replaces `actor.state` after this superstep).
    pub new_state: Vec<u8>,
    /// Outbound messages (routed by the distributed Pregel runner).
    pub messages: Vec<AuthOutMessage>,
    /// Quad assertions with policy and provenance (applied to QuadStore).
    pub assertions: Vec<AuthQuad>,
    /// `true` → this actor votes to halt (becomes inactive if no future messages arrive).
    pub vote_halt: bool,
}

// ---------------------------------------------------------------------------
// ActorComputeFn — the actor's business-logic function
// ---------------------------------------------------------------------------

/// Actor-aware, crypto-unaware compute function.
///
/// The host (kotoba-server PRE proxy) guarantees that all `AuthMessage::payload`
/// values are plaintext on entry and handles encryption of `AuthOutMessage`
/// and `AuthQuad` values after return.
pub type ActorComputeFn =
    Arc<dyn Fn(&Actor, &[AuthMessage]) -> ActorOutput + Send + Sync>;
