/// Training pipeline types: TrainBatch, GradientRef, AdamMoments, OptimizerStep.
///
/// Datom encoding (ADR-2605250004, amended by ADR-2605250005):
///   grad  -> Datom(model_cid, "grad/{kind.path()}/step/{M}", TensorCid{f32}, tx, true)
///   adam  -> Datom(model_cid, "train/adam/m1/{kind.path()}",  TensorCid{f32}, tx, true)
///   adam  -> Datom(model_cid, "train/adam/m2/{kind.path()}",  TensorCid{f32}, tx, true)
///   weight update: retract(old) + assert(new) via kind.predicate() — atomic pair
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::datom::{Datom, TensorDtype, Value};
use kotoba_kqe::delta::Delta;

use crate::weight::WeightKind;

/// A training mini-batch: token sequences with a quality score.
///
/// `quality` ∈ [0.0, 1.0] scales the CE loss gradient so low-quality
/// data has proportionally less influence on weight updates.
#[derive(Debug, Clone)]
pub struct TrainBatch {
    /// Input token IDs — shape `[seq_len]`
    pub input_tokens: Vec<u32>,
    /// Target token IDs — shape `[seq_len]`
    pub target_tokens: Vec<u32>,
    /// Curation quality score: 1.0 = gold data, 0.0 = skip
    pub quality: f32,
}

/// CID-addressed gradient tensor stored as a Datom (ephemeral).
///
/// Gradient tensors are f32 (WebGPU native) and are retracted from
/// the Arrangement immediately after the optimizer step completes.
#[derive(Debug, Clone)]
pub struct GradientRef {
    pub model_cid: KotobaCid,
    pub kind: WeightKind,
    /// Optimizer step counter
    pub step: u64,
    pub blob_cid: KotobaCid,
    pub shape: Vec<u32>,
}

impl GradientRef {
    /// Assert gradient into Arrangement.
    pub fn to_assert_delta(&self, graph_cid: KotobaCid) -> Delta {
        Delta::assert_datom(self.datom(graph_cid))
    }

    /// Retract gradient from Arrangement (call after optimizer step).
    pub fn to_retract_delta(&self, graph_cid: KotobaCid) -> Delta {
        Delta::retract_datom(self.datom(graph_cid))
    }

    fn datom(&self, graph_cid: KotobaCid) -> Datom {
        Datom::assert(
            self.model_cid.clone(),
            format!("grad/{}/step/{}", self.kind.path(), self.step),
            Value::TensorCid {
                cid: self.blob_cid.clone(),
                shape: self.shape.clone(),
                dtype: TensorDtype::F32,
            },
            graph_cid,
        )
    }
}

/// AdamW first and second moment tensors for one weight (persistent).
#[derive(Debug, Clone)]
pub struct AdamMoments {
    pub model_cid: KotobaCid,
    pub kind: WeightKind,
    /// First moment (mean of gradients) — f32
    pub m1_cid: KotobaCid,
    /// Second moment (uncentered variance) — f32
    pub m2_cid: KotobaCid,
    pub shape: Vec<u32>,
}

impl AdamMoments {
    /// Assert both moment tensors.
    pub fn to_assert_deltas(&self, graph_cid: KotobaCid) -> [Delta; 2] {
        [
            Delta::assert_datom(self.m1_datom(graph_cid.clone())),
            Delta::assert_datom(self.m2_datom(graph_cid)),
        ]
    }

    /// Retract both moment tensors (before replacing with updated moments).
    pub fn to_retract_deltas(&self, graph_cid: KotobaCid) -> [Delta; 2] {
        [
            Delta::retract_datom(self.m1_datom(graph_cid.clone())),
            Delta::retract_datom(self.m2_datom(graph_cid)),
        ]
    }

    fn m1_datom(&self, graph_cid: KotobaCid) -> Datom {
        Datom::assert(
            self.model_cid.clone(),
            format!("train/adam/m1/{}", self.kind.path()),
            Value::TensorCid {
                cid: self.m1_cid.clone(),
                shape: self.shape.clone(),
                dtype: TensorDtype::F32,
            },
            graph_cid,
        )
    }

    fn m2_datom(&self, graph_cid: KotobaCid) -> Datom {
        Datom::assert(
            self.model_cid.clone(),
            format!("train/adam/m2/{}", self.kind.path()),
            Value::TensorCid {
                cid: self.m2_cid.clone(),
                shape: self.shape.clone(),
                dtype: TensorDtype::F32,
            },
            graph_cid,
        )
    }
}

/// One complete optimizer step: old weight out, new weight in.
///
/// Produces an atomic Delta pair: retract(old) + assert(new).
#[derive(Debug, Clone)]
pub struct OptimizerStep {
    pub model_cid: KotobaCid,
    pub kind: WeightKind,
    /// Previous weight (to be retracted)
    pub old_weight_cid: KotobaCid,
    /// Updated weight (to be asserted, stored in Vault as FP8)
    pub new_weight_cid: KotobaCid,
    pub shape: Vec<u32>,
    /// AdamW step count (bias-correction denominator)
    pub step: u64,
}

impl OptimizerStep {
    /// Atomic weight-swap Delta pair: [retract_old, assert_new].
    pub fn weight_deltas(&self, graph_cid: KotobaCid) -> [Delta; 2] {
        let predicate = self.kind.predicate();
        let old_datom = Datom::retract(
            self.model_cid.clone(),
            predicate.clone(),
            Value::TensorCid {
                cid: self.old_weight_cid.clone(),
                shape: self.shape.clone(),
                dtype: TensorDtype::F8E4M3,
            },
            graph_cid.clone(),
        );
        let new_datom = Datom::assert(
            self.model_cid.clone(),
            predicate,
            Value::TensorCid {
                cid: self.new_weight_cid.clone(),
                shape: self.shape.clone(),
                dtype: TensorDtype::F8E4M3,
            },
            graph_cid,
        );
        [
            Delta::retract_datom(old_datom),
            Delta::assert_datom(new_datom),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    fn cid(s: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(s)
    }
    fn g() -> KotobaCid {
        cid(b"graph")
    }

    #[test]
    fn gradient_ref_embed_predicate() {
        let gr = GradientRef {
            model_cid: cid(b"model"),
            kind: WeightKind::Embed,
            step: 1,
            blob_cid: cid(b"grad_blob"),
            shape: vec![32000, 2048],
        };
        let assert_d = gr.to_assert_delta(g());
        let retract_d = gr.to_retract_delta(g());

        assert!(assert_d.is_assert());
        assert!(!retract_d.is_assert());
        assert_eq!(assert_d.datom.a, "grad/embed/step/1");
        assert_eq!(retract_d.datom.a, "grad/embed/step/1");
        assert!(matches!(
            assert_d.datom.v,
            Value::TensorCid {
                dtype: TensorDtype::F32,
                ..
            }
        ));
    }

    #[test]
    fn gradient_ref_block_predicate() {
        let gr = GradientRef {
            model_cid: cid(b"model"),
            kind: WeightKind::BlockAttnQ(3),
            step: 5,
            blob_cid: cid(b"g"),
            shape: vec![256, 2048],
        };
        assert_eq!(
            gr.to_assert_delta(g()).datom.a,
            "grad/block/3/attn/q/step/5"
        );
    }

    #[test]
    fn adam_moments_embed_lmhead() {
        let m_embed = AdamMoments {
            model_cid: cid(b"model"),
            kind: WeightKind::Embed,
            m1_cid: cid(b"m1"),
            m2_cid: cid(b"m2"),
            shape: vec![32000, 2048],
        };
        let m_lm = AdamMoments {
            model_cid: cid(b"model"),
            kind: WeightKind::LmHead,
            m1_cid: cid(b"m1"),
            m2_cid: cid(b"m2"),
            shape: vec![2048, 32000],
        };
        let [a1, a2] = m_embed.to_assert_deltas(g());
        let [r1, r2] = m_embed.to_retract_deltas(g());
        assert_eq!(a1.datom.a, "train/adam/m1/embed");
        assert_eq!(a2.datom.a, "train/adam/m2/embed");
        assert!(!r1.is_assert());
        assert!(!r2.is_assert());

        let [al1, _] = m_lm.to_assert_deltas(g());
        assert_eq!(al1.datom.a, "train/adam/m1/lm_head");
    }

    #[test]
    fn optimizer_step_weight_deltas_embed() {
        let step = OptimizerStep {
            model_cid: cid(b"model"),
            kind: WeightKind::Embed,
            old_weight_cid: cid(b"w_old"),
            new_weight_cid: cid(b"w_new"),
            shape: vec![32000, 2048],
            step: 5,
        };
        let [retract, assert_d] = step.weight_deltas(g());
        assert!(!retract.is_assert());
        assert!(assert_d.is_assert());
        assert_eq!(retract.datom.a, "weight/embed");
        assert_eq!(assert_d.datom.a, "weight/embed");
        if let Value::TensorCid { cid: blob_cid, .. } = &retract.datom.v {
            assert_eq!(*blob_cid, cid(b"w_old"));
        }
    }

    #[test]
    fn optimizer_step_weight_deltas_block() {
        let step = OptimizerStep {
            model_cid: cid(b"model"),
            kind: WeightKind::BlockAttnQ(2),
            old_weight_cid: cid(b"w_old"),
            new_weight_cid: cid(b"w_new"),
            shape: vec![256, 2048],
            step: 1,
        };
        let [r, a] = step.weight_deltas(g());
        assert_eq!(r.datom.a, "weight/block/2/attn/q");
        assert_eq!(a.datom.a, "weight/block/2/attn/q");
    }

    #[test]
    fn gradient_ref_step_zero() {
        let gr = GradientRef {
            model_cid: cid(b"model"),
            kind: WeightKind::LmHead,
            step: 0,
            blob_cid: cid(b"grad"),
            shape: vec![2048, 32000],
        };
        assert_eq!(gr.to_assert_delta(g()).datom.a, "grad/lm_head/step/0");
    }

    #[test]
    fn gradient_ref_large_step() {
        let gr = GradientRef {
            model_cid: cid(b"model"),
            kind: WeightKind::Embed,
            step: 1_000_000,
            blob_cid: cid(b"grad"),
            shape: vec![32000, 2048],
        };
        assert_eq!(gr.to_assert_delta(g()).datom.a, "grad/embed/step/1000000");
    }

    #[test]
    fn adam_moments_block_ffn_predicates() {
        let m = AdamMoments {
            model_cid: cid(b"model"),
            kind: WeightKind::BlockFfnGate(7),
            m1_cid: cid(b"m1"),
            m2_cid: cid(b"m2"),
            shape: vec![2048, 8192],
        };
        let [a1, a2] = m.to_assert_deltas(g());
        assert_eq!(a1.datom.a, "train/adam/m1/block/7/ffn/gate");
        assert_eq!(a2.datom.a, "train/adam/m2/block/7/ffn/gate");
    }

    #[test]
    fn optimizer_step_retract_uses_old_cid_assert_uses_new() {
        let old = cid(b"old_weight");
        let new = cid(b"new_weight");
        let step = OptimizerStep {
            model_cid: cid(b"model"),
            kind: WeightKind::LmHead,
            old_weight_cid: old.clone(),
            new_weight_cid: new.clone(),
            shape: vec![2048, 32000],
            step: 10,
        };
        let [retract, assert_d] = step.weight_deltas(g());
        if let Value::TensorCid { cid: rc, .. } = &retract.datom.v {
            assert_eq!(*rc, old, "retract must use old CID");
        } else {
            panic!("expected TensorCid");
        }
        if let Value::TensorCid { cid: ac, .. } = &assert_d.datom.v {
            assert_eq!(*ac, new, "assert must use new CID");
        } else {
            panic!("expected TensorCid");
        }
    }

    #[test]
    fn train_batch_quality_field() {
        let b = TrainBatch {
            input_tokens: vec![1, 2, 3],
            target_tokens: vec![2, 3, 4],
            quality: 0.75,
        };
        assert!((b.quality - 0.75).abs() < f32::EPSILON);
        assert_eq!(b.input_tokens.len(), b.target_tokens.len());
    }

    #[test]
    fn adam_moments_retract_all_have_retract_multiplicity() {
        let m = AdamMoments {
            model_cid: cid(b"model"),
            kind: WeightKind::FinalNorm,
            m1_cid: cid(b"m1"),
            m2_cid: cid(b"m2"),
            shape: vec![2048],
        };
        let [r1, r2] = m.to_retract_deltas(g());
        assert!(!r1.is_assert());
        assert!(!r2.is_assert());
        assert_eq!(r1.datom.a, "train/adam/m1/norm/final");
        assert_eq!(r2.datom.a, "train/adam/m2/norm/final");
    }
}
