use kotoba_core::cid::KotobaCid;
use kotoba_kse::vault::Vault;
use kotoba_kqe::quad::{Quad, QuadObject, TensorDtype};
use bytes::Bytes;

/// Unified weight predicate scheme (ADR-2605250005).
///
/// Maps to Datom predicates: `weight/{kind.path()}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WeightKind {
    /// Embedding table: `weight/embed` — shape [vocab × H]
    Embed,
    /// LM head projection: `weight/lm_head` — shape [H × vocab]
    LmHead,
    /// Final RMSNorm: `weight/norm/final` — shape [H]
    FinalNorm,
    /// Q projection for block N: `weight/block/{N}/attn/q`
    BlockAttnQ(u32),
    /// K projection (GQA) for block N: `weight/block/{N}/attn/k`
    BlockAttnK(u32),
    /// V projection (GQA) for block N: `weight/block/{N}/attn/v`
    BlockAttnV(u32),
    /// Output projection for block N: `weight/block/{N}/attn/o`
    BlockAttnO(u32),
    /// SwiGLU gate for block N: `weight/block/{N}/ffn/gate`
    BlockFfnGate(u32),
    /// SwiGLU up for block N: `weight/block/{N}/ffn/up`
    BlockFfnUp(u32),
    /// SwiGLU down for block N: `weight/block/{N}/ffn/down`
    BlockFfnDown(u32),
    /// Pre-attention RMSNorm for block N: `weight/block/{N}/norm/attn`
    BlockNormAttn(u32),
    /// Pre-FFN RMSNorm for block N: `weight/block/{N}/norm/ffn`
    BlockNormFfn(u32),
}

impl WeightKind {
    /// Path component after `weight/`, e.g. `"embed"` or `"block/3/attn/q"`.
    pub fn path(&self) -> String {
        match self {
            Self::Embed            => "embed".to_string(),
            Self::LmHead           => "lm_head".to_string(),
            Self::FinalNorm        => "norm/final".to_string(),
            Self::BlockAttnQ(n)    => format!("block/{n}/attn/q"),
            Self::BlockAttnK(n)    => format!("block/{n}/attn/k"),
            Self::BlockAttnV(n)    => format!("block/{n}/attn/v"),
            Self::BlockAttnO(n)    => format!("block/{n}/attn/o"),
            Self::BlockFfnGate(n)  => format!("block/{n}/ffn/gate"),
            Self::BlockFfnUp(n)    => format!("block/{n}/ffn/up"),
            Self::BlockFfnDown(n)  => format!("block/{n}/ffn/down"),
            Self::BlockNormAttn(n) => format!("block/{n}/norm/attn"),
            Self::BlockNormFfn(n)  => format!("block/{n}/norm/ffn"),
        }
    }

    /// Full Datom predicate string: `weight/{path}`.
    pub fn predicate(&self) -> String {
        format!("weight/{}", self.path())
    }
}

/// WeightRef — CID-addressed model weight tensor stored as a Datom.
///
/// Datom predicate: `weight/{kind.path()}` (ADR-2605250005).
#[derive(Debug, Clone)]
pub struct WeightRef {
    pub model_cid: KotobaCid,
    pub kind:      WeightKind,
    pub blob_cid:  KotobaCid,
    pub shape:     Vec<u32>,
    pub dtype:     TensorDtype,
}

impl WeightRef {
    /// Convert to Datom (Quad) for storage in Arrangement.
    pub fn to_quad(&self, graph_cid: KotobaCid) -> Quad {
        Quad {
            graph:     graph_cid,
            subject:   self.model_cid.clone(),
            predicate: self.kind.predicate(),
            object:    QuadObject::TensorCid {
                cid:   self.blob_cid.clone(),
                shape: self.shape.clone(),
                dtype: self.dtype.clone(),
            },
        }
    }
}

/// WeightBlob — raw FP8 tensor bytes in Vault.
pub struct WeightBlob {
    pub blob_cid: KotobaCid,
    pub bytes:    Bytes,
    pub shape:    Vec<u32>,
    pub dtype:    TensorDtype,
}

impl WeightBlob {
    pub async fn store(vault: &Vault, bytes: Bytes, shape: Vec<u32>, dtype: TensorDtype) -> Self {
        let blob_ref = vault.put(bytes.clone()).await;
        Self { blob_cid: blob_ref.cid, bytes, shape, dtype }
    }
}
