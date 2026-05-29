use bytes::Bytes;
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::datom::{Datom, Value};
use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject, TensorDtype};
use kotoba_kse::vault::Vault;

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
            Self::Embed => "embed".to_string(),
            Self::LmHead => "lm_head".to_string(),
            Self::FinalNorm => "norm/final".to_string(),
            Self::BlockAttnQ(n) => format!("block/{n}/attn/q"),
            Self::BlockAttnK(n) => format!("block/{n}/attn/k"),
            Self::BlockAttnV(n) => format!("block/{n}/attn/v"),
            Self::BlockAttnO(n) => format!("block/{n}/attn/o"),
            Self::BlockFfnGate(n) => format!("block/{n}/ffn/gate"),
            Self::BlockFfnUp(n) => format!("block/{n}/ffn/up"),
            Self::BlockFfnDown(n) => format!("block/{n}/ffn/down"),
            Self::BlockNormAttn(n) => format!("block/{n}/norm/attn"),
            Self::BlockNormFfn(n) => format!("block/{n}/norm/ffn"),
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
    pub kind: WeightKind,
    pub blob_cid: KotobaCid,
    pub shape: Vec<u32>,
    pub dtype: TensorDtype,
}

impl WeightRef {
    /// Convert to Datom for storage in Arrangement.
    pub fn to_datom(&self, tx_cid: KotobaCid) -> Datom {
        Datom::assert(
            self.model_cid.clone(),
            self.kind.predicate(),
            Value::TensorCid {
                cid: self.blob_cid.clone(),
                shape: self.shape.clone(),
                dtype: self.dtype.clone().into(),
            },
            tx_cid,
        )
    }

    /// Convert to legacy Quad at RDF/compatibility boundaries.
    pub fn to_quad(&self, graph_cid: KotobaCid) -> Quad {
        Quad {
            graph: graph_cid,
            subject: self.model_cid.clone(),
            predicate: self.kind.predicate(),
            object: QuadObject::TensorCid {
                cid: self.blob_cid.clone(),
                shape: self.shape.clone(),
                dtype: self.dtype.clone(),
            },
        }
    }
}

/// WeightBlob — raw FP8 tensor bytes in Vault.
pub struct WeightBlob {
    pub blob_cid: KotobaCid,
    pub bytes: Bytes,
    pub shape: Vec<u32>,
    pub dtype: TensorDtype,
}

impl WeightBlob {
    pub async fn store(vault: &Vault, bytes: Bytes, shape: Vec<u32>, dtype: TensorDtype) -> Self {
        let blob_ref = vault.put(bytes.clone()).await;
        Self {
            blob_cid: blob_ref.cid,
            bytes,
            shape,
            dtype,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── WeightKind::path ──────────────────────────────────────────────────────

    #[test]
    fn path_embed() {
        assert_eq!(WeightKind::Embed.path(), "embed");
    }
    #[test]
    fn path_lm_head() {
        assert_eq!(WeightKind::LmHead.path(), "lm_head");
    }
    #[test]
    fn path_final_norm() {
        assert_eq!(WeightKind::FinalNorm.path(), "norm/final");
    }

    #[test]
    fn path_block_attn_q() {
        assert_eq!(WeightKind::BlockAttnQ(3).path(), "block/3/attn/q");
        assert_eq!(WeightKind::BlockAttnK(7).path(), "block/7/attn/k");
        assert_eq!(WeightKind::BlockAttnV(0).path(), "block/0/attn/v");
        assert_eq!(WeightKind::BlockAttnO(25).path(), "block/25/attn/o");
    }

    #[test]
    fn path_block_ffn() {
        assert_eq!(WeightKind::BlockFfnGate(1).path(), "block/1/ffn/gate");
        assert_eq!(WeightKind::BlockFfnUp(2).path(), "block/2/ffn/up");
        assert_eq!(WeightKind::BlockFfnDown(3).path(), "block/3/ffn/down");
    }

    #[test]
    fn path_block_norm() {
        assert_eq!(WeightKind::BlockNormAttn(4).path(), "block/4/norm/attn");
        assert_eq!(WeightKind::BlockNormFfn(5).path(), "block/5/norm/ffn");
    }

    // ── WeightKind::predicate ─────────────────────────────────────────────────

    #[test]
    fn predicate_has_weight_prefix() {
        for kind in [
            WeightKind::Embed,
            WeightKind::LmHead,
            WeightKind::FinalNorm,
            WeightKind::BlockAttnQ(0),
            WeightKind::BlockFfnDown(0),
        ] {
            let pred = kind.predicate();
            assert!(
                pred.starts_with("weight/"),
                "predicate missing 'weight/': {pred}"
            );
        }
    }

    #[test]
    fn predicate_equals_weight_slash_path() {
        let kind = WeightKind::BlockAttnQ(7);
        assert_eq!(kind.predicate(), format!("weight/{}", kind.path()));
    }

    // ── WeightRef::to_datom ──────────────────────────────────────────────────

    #[test]
    fn to_datom_attribute_matches_kind() {
        let model_cid = KotobaCid::from_bytes(b"model");
        let blob_cid = KotobaCid::from_bytes(b"blob");
        let kind = WeightKind::BlockAttnQ(3);
        let wr = WeightRef {
            model_cid: model_cid.clone(),
            kind: kind.clone(),
            blob_cid: blob_cid.clone(),
            shape: vec![2048, 256],
            dtype: TensorDtype::F32,
        };
        let tx_cid = KotobaCid::from_bytes(b"tx");
        let datom = wr.to_datom(tx_cid.clone());
        assert_eq!(datom.a, kind.predicate());
        assert_eq!(datom.e, model_cid);
        assert_eq!(datom.tx, tx_cid);
        assert!(datom.op);
    }

    #[test]
    fn to_datom_value_is_tensor_cid() {
        let model_cid = KotobaCid::from_bytes(b"m");
        let blob_cid = KotobaCid::from_bytes(b"b");
        let wr = WeightRef {
            model_cid,
            kind: WeightKind::Embed,
            blob_cid: blob_cid.clone(),
            shape: vec![32000, 2048],
            dtype: TensorDtype::F8E4M3,
        };
        let datom = wr.to_datom(KotobaCid::from_bytes(b"tx"));
        if let Value::TensorCid { cid, shape, dtype } = datom.v {
            assert_eq!(cid, blob_cid);
            assert_eq!(shape, vec![32000, 2048]);
            assert_eq!(dtype, kotoba_kqe::datom::TensorDtype::F8E4M3);
        } else {
            panic!("expected TensorCid value");
        }
    }
}
