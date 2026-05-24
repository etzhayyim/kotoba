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
    pub sig:     Vec<u8>,        // Ed25519 signature
}

impl ChainEntry {
    pub fn new(
        prev: Option<KotobaCid>,
        agent: String,
        seq: u64,
        content: ChainContent,
        sig: Vec<u8>,
    ) -> Self {
        let ts = now_ms();
        // CID computed from content (excluding cid field itself)
        let payload = format!("{:?}{:?}{}{}", prev, content, seq, ts);
        let cid = KotobaCid::from_bytes(payload.as_bytes());
        Self { cid, prev, agent, seq, content, ts, sig }
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

    pub fn append(&mut self, entry: ChainEntry) -> Result<(), ChainError> {
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
