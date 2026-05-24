use crate::quad::Quad;

/// Multiplicity: +1 = assert, -1 = retract (Datom retraction as Delta)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplicity { Assert = 1, Retract = -1 }

/// Delta — atomic Pregel message: (Quad, ±1)
#[derive(Debug, Clone)]
pub struct Delta {
    pub quad:     Quad,
    pub mult:     Multiplicity,
    pub ts:       u64,
}

impl Delta {
    pub fn assert(quad: Quad) -> Self {
        Self { quad, mult: Multiplicity::Assert, ts: now_ms() }
    }
    pub fn retract(quad: Quad) -> Self {
        Self { quad, mult: Multiplicity::Retract, ts: now_ms() }
    }
    pub fn is_assert(&self) -> bool { self.mult == Multiplicity::Assert }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
