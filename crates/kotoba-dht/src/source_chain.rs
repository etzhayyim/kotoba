use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::Quad;
use serde::{Deserialize, Serialize};

/// How to dispatch an Invoke ChainEntry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProgramType {
    /// Evaluate via KotobaVm Datalog engine
    Datalog,
    /// Execute via WasmExecutor (kotoba-node world: exports `run`)
    WasmNode,
    /// Execute via UdfExecutor (kotoba-udf world: exports `eval`, stateless)
    WasmUdf,
}

/// ChainContent — what a ChainEntry carries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainContent {
    Quad(Quad),
    Commit { graph_cid: KotobaCid, prolly_root: KotobaCid },
    Invoke {
        program_cid:  KotobaCid,
        program_type: ProgramType,
        input_topics: Vec<String>,
        max_steps:    u32,
        call_id:      u64,
    },
    Result {
        call_id:    u64,
        status:     u8,   // 0=ok 1=halt 2=exceeded 3=error
        steps_used: u32,
    },
    Warrant {
        accused:   Vec<u8>,  // accused NodeId
        evidence:  KotobaCid,
        rule_id:   u8,
    },
    /// LLM inference request (special Invoke subtype)
    Infer {
        model_cid:    KotobaCid,
        adapter_cid:  Option<KotobaCid>,  // LoRA
        session_cid:  Option<KotobaCid>,  // KV-cache
        max_tokens:   u32,
        call_id:      u64,
    },
}

/// ChainEntry — signed, ordered, append-only fact (per-DID Source Chain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub cid:     KotobaCid,
    pub prev:    Option<KotobaCid>,
    pub agent:   String,         // DID
    pub seq:     u64,
    pub content: ChainContent,
    pub ts:      u64,
    pub sig:     Vec<u8>,        // Ed25519 signature over signing_bytes()
    /// Access policy for this entry.  `Open` entries gossip as plaintext;
    /// `Encrypted` entries gossip only the `ct_cid` — PRE re-encryption on demand.
    #[serde(default, skip_serializing_if = "kotoba_core::DataPolicy::is_open")]
    pub policy:  kotoba_core::DataPolicy,
}

/// Subset of ChainEntry fields that are covered by the Ed25519 signature.
/// `cid` is excluded (it is derived); `sig` is excluded (it is the signature itself).
/// `policy` is included so that downgrading `Encrypted → Open` without re-signing is
/// cryptographically detectable.
#[derive(Serialize)]
struct SigningPayload<'a> {
    prev:    &'a Option<KotobaCid>,
    agent:   &'a str,
    seq:     u64,
    content: &'a ChainContent,
    ts:      u64,
    policy:  &'a kotoba_core::DataPolicy,
}

impl ChainEntry {
    pub fn new(
        prev: Option<KotobaCid>,
        agent: String,
        seq: u64,
        content: ChainContent,
        sig: Vec<u8>,
    ) -> Self {
        Self::new_with_policy(prev, agent, seq, content, sig, kotoba_core::DataPolicy::Open)
    }

    pub fn new_with_policy(
        prev: Option<KotobaCid>,
        agent: String,
        seq: u64,
        content: ChainContent,
        sig: Vec<u8>,
        policy: kotoba_core::DataPolicy,
    ) -> Self {
        let ts = now_ms();
        let payload = format!("{:?}{:?}{}{}", prev, content, seq, ts);
        let cid = KotobaCid::from_bytes(payload.as_bytes());
        Self { cid, prev, agent, seq, content, ts, sig, policy }
    }

    /// Canonical CBOR bytes that the agent signs.
    ///
    /// Uses ciborium (dag-cbor compatible) rather than JSON to guarantee a
    /// stable, canonical encoding regardless of workspace feature flags.
    /// Field order is fixed by struct declaration order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let payload = SigningPayload {
            prev:    &self.prev,
            agent:   &self.agent,
            seq:     self.seq,
            content: &self.content,
            ts:      self.ts,
            policy:  &self.policy,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut buf)
            .expect("CBOR serialization of SigningPayload is infallible");
        buf
    }

    /// Verify the Ed25519 signature against `pubkey_bytes` (32-byte compressed key).
    ///
    /// Returns `Err(ChainError::InvalidSignature)` if the key or signature bytes
    /// are malformed, or if the signature does not match `signing_bytes()`.
    pub fn verify_sig(&self, pubkey_bytes: &[u8]) -> Result<(), ChainError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let key_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| ChainError::InvalidSignature)?;
        let verifying_key = VerifyingKey::from_bytes(&key_arr)
            .map_err(|_| ChainError::InvalidSignature)?;

        let sig_arr: [u8; 64] = self.sig
            .as_slice()
            .try_into()
            .map_err(|_| ChainError::InvalidSignature)?;
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(&self.signing_bytes(), &signature)
            .map_err(|_| ChainError::InvalidSignature)
    }
}

/// Source Chain — per-DID append-only log (≅ AT Protocol Repo with Prolly Tree)
#[derive(Debug, Default)]
pub struct SourceChain {
    pub agent: String,
    entries:   Vec<ChainEntry>,
}

impl SourceChain {
    pub fn new(agent: impl Into<String>) -> Self {
        Self { agent: agent.into(), entries: Vec::new() }
    }

    /// Append without signature verification.
    ///
    /// Intended for: internal construction, test fixtures, and trusted paths where
    /// the caller has already verified the signature upstream.  Prefer
    /// `append_verified` for all untrusted / peer-supplied entries.
    pub(crate) fn append(&mut self, entry: ChainEntry) -> Result<(), ChainError> {
        let expected_seq = self.entries.len() as u64;
        if entry.seq != expected_seq {
            return Err(ChainError::SeqMismatch { expected: expected_seq, got: entry.seq });
        }
        let expected_prev = self.entries.last().map(|e| &e.cid);
        if entry.prev.as_ref() != expected_prev {
            return Err(ChainError::PrevMismatch);
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Append after verifying the Ed25519 signature.
    ///
    /// `pubkey_bytes` must be the 32-byte compressed Ed25519 public key that
    /// corresponds to the `agent` DID of this chain.  Rejects entries whose
    /// signature does not cover the canonical `signing_bytes()`.
    pub fn append_verified(
        &mut self,
        entry: ChainEntry,
        pubkey_bytes: &[u8],
    ) -> Result<(), ChainError> {
        entry.verify_sig(pubkey_bytes)?;
        self.append(entry)
    }

    pub fn head(&self) -> Option<&ChainEntry> { self.entries.last() }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("seq mismatch: expected {expected}, got {got}")]
    SeqMismatch { expected: u64, got: u64 },
    #[error("prev CID mismatch")]
    PrevMismatch,
    #[error("invalid signature")]
    InvalidSignature,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};

    fn make_signed_entry(
        signing_key: &SigningKey,
        prev: Option<KotobaCid>,
        agent: &str,
        seq: u64,
        content: ChainContent,
    ) -> ChainEntry {
        // Build entry with a placeholder sig so we can compute signing_bytes
        let mut entry = ChainEntry::new(prev, agent.to_string(), seq, content, vec![0u8; 64]);
        let sig = signing_key.sign(&entry.signing_bytes());
        entry.sig = sig.to_bytes().to_vec();
        entry
    }

    fn test_keypair() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn dummy_content() -> ChainContent {
        ChainContent::Result { call_id: 1, status: 0, steps_used: 10 }
    }

    #[test]
    fn verify_sig_valid_key_passes() {
        let sk = test_keypair();
        let entry = make_signed_entry(&sk, None, "did:plc:alice", 0, dummy_content());
        assert!(entry.verify_sig(sk.verifying_key().as_bytes()).is_ok());
    }

    #[test]
    fn verify_sig_wrong_key_fails() {
        let sk = test_keypair();
        let wrong_sk = SigningKey::from_bytes(&[99u8; 32]);
        let entry = make_signed_entry(&sk, None, "did:plc:alice", 0, dummy_content());
        assert!(entry.verify_sig(wrong_sk.verifying_key().as_bytes()).is_err());
    }

    #[test]
    fn verify_sig_tampered_content_fails() {
        let sk = test_keypair();
        let mut entry = make_signed_entry(&sk, None, "did:plc:alice", 0, dummy_content());
        // Tamper the agent field after signing
        entry.agent = "did:plc:eve".to_string();
        assert!(entry.verify_sig(sk.verifying_key().as_bytes()).is_err());
    }

    #[test]
    fn verify_sig_tampered_policy_fails() {
        let sk = test_keypair();
        let mut entry = make_signed_entry(&sk, None, "did:plc:alice", 0, dummy_content());
        // Sign with Open policy, then flip to Encrypted — signature must not verify.
        entry.policy = kotoba_core::DataPolicy::Encrypted {
            ct_cid:     kotoba_core::cid::KotobaCid::from_bytes(b"fake-ct"),
            policy_cid: kotoba_core::cid::KotobaCid::from_bytes(b"fake-pol"),
        };
        assert!(entry.verify_sig(sk.verifying_key().as_bytes()).is_err());
    }

    #[test]
    fn verify_sig_truncated_sig_fails() {
        let sk = test_keypair();
        let mut entry = make_signed_entry(&sk, None, "did:plc:alice", 0, dummy_content());
        entry.sig = vec![0u8; 32]; // wrong length
        assert!(entry.verify_sig(sk.verifying_key().as_bytes()).is_err());
    }

    #[test]
    fn append_verified_accepts_valid_entry() {
        let sk = test_keypair();
        let mut chain = SourceChain::new("did:plc:alice");
        let entry = make_signed_entry(&sk, None, "did:plc:alice", 0, dummy_content());
        assert!(chain.append_verified(entry, sk.verifying_key().as_bytes()).is_ok());
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn append_verified_rejects_bad_sig() {
        let sk = test_keypair();
        let wrong_sk = SigningKey::from_bytes(&[99u8; 32]);
        let mut chain = SourceChain::new("did:plc:alice");
        let entry = make_signed_entry(&wrong_sk, None, "did:plc:alice", 0, dummy_content());
        let result = chain.append_verified(entry, sk.verifying_key().as_bytes());
        assert!(matches!(result, Err(ChainError::InvalidSignature)));
        assert_eq!(chain.len(), 0); // chain must not have grown
    }
}
