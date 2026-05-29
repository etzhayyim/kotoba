pub mod embed;
pub mod gemma;
pub mod gpu_common;
pub mod http_infer;
pub mod infer;
pub mod kvcache;
pub mod lora;
pub mod train;
pub mod weight;

#[cfg(feature = "webgpu-train")]
pub mod train_gpu;

#[cfg(feature = "webgpu-infer")]
pub mod infer_gpu;

#[allow(deprecated)]
pub use embed::{embed_to_delta, embed_to_quad, Embedding};
pub use gpu_common::{dequantize_fp8_e4m3, quantize_f32_to_fp8_e4m3};
pub use infer::{InferError, InferenceRequest, InferenceSession};
pub use kvcache::KvCache;
pub use lora::{lora_to_delta, LoraAdapter};
pub use train::{AdamMoments, GradientRef, OptimizerStep, TrainBatch};
pub use weight::{WeightBlob, WeightKind, WeightRef};

#[cfg(feature = "local-inference")]
pub use gemma::GemmaRunner;

#[cfg(feature = "http-inference")]
pub use http_infer::HttpInferEngine;

#[cfg(feature = "webgpu-train")]
pub use train_gpu::{
    wgsl_shaders as train_wgsl_shaders, AdamConfig, TrainStepResult, WebGpuTrainer,
};

#[cfg(feature = "webgpu-infer")]
pub use infer_gpu::{
    wgsl_shaders as infer_wgsl_shaders, LayerBlobRefs, LayerWeights, TransformerBlobRefs,
    TransformerWeights, WebGpuInferConfig, WebGpuInferSession,
};

#[cfg(test)]
mod tests {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::datom::{TensorDtype, Value};

    fn cid(seed: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(seed)
    }

    // ── WeightRef ──────────────────────────────────────────────────────────

    #[test]
    fn weight_ref_embed_predicate() {
        use super::weight::{WeightKind, WeightRef};
        use kotoba_kqe::quad::TensorDtype as LegacyTensorDtype;

        let model = cid(b"model");
        let blob = cid(b"blob");
        let tx = cid(b"tx");

        let w = WeightRef {
            model_cid: model.clone(),
            kind: WeightKind::Embed,
            blob_cid: blob.clone(),
            shape: vec![32000, 2048],
            dtype: LegacyTensorDtype::F8E4M3,
        };
        let datom = w.to_datom(tx);
        assert_eq!(datom.a, "weight/embed");
        assert_eq!(datom.e, model);
    }

    #[test]
    fn weight_kind_block_predicate() {
        use super::weight::WeightKind;
        assert_eq!(
            WeightKind::BlockAttnQ(3).predicate(),
            "weight/block/3/attn/q"
        );
        assert_eq!(
            WeightKind::BlockFfnDown(0).predicate(),
            "weight/block/0/ffn/down"
        );
        assert_eq!(WeightKind::LmHead.predicate(), "weight/lm_head");
        assert_eq!(WeightKind::FinalNorm.predicate(), "weight/norm/final");
    }

    // ── LoRA ──────────────────────────────────────────────────────────────

    #[test]
    fn lora_to_delta_is_assert() {
        use super::lora::{lora_to_delta, LoraAdapter};

        let adapter = LoraAdapter {
            base_cid: cid(b"base"),
            adapter_cid: cid(b"adapter"),
            scale: 0.5,
            rank: 16,
        };
        let delta = lora_to_delta(&adapter, cid(b"tx"));
        assert!(delta.is_assert());
        assert_eq!(delta.datom.a, "lora/adapter");
    }

    #[test]
    fn lora_retract_delta_is_retract() {
        use super::lora::{lora_retract_delta, LoraAdapter};

        let adapter = LoraAdapter {
            base_cid: cid(b"base"),
            adapter_cid: cid(b"adapter"),
            scale: 1.0,
            rank: 8,
        };
        let delta = lora_retract_delta(&adapter, cid(b"tx"));
        assert!(!delta.is_assert());
        assert!(!delta.is_assert());
    }

    // ── KvCache ───────────────────────────────────────────────────────────

    #[test]
    fn kv_cache_store_returns_assert_delta() {
        use super::kvcache::KvCache;

        let session = cid(b"session");
        let mut cache = KvCache::new(session);
        let delta = cache.store_kv(cid(b"tx"), 0, 5, cid(b"kv_blob"));
        assert!(delta.is_assert());
        assert_eq!(delta.datom.a, "kv/layer/0/seq/5");
    }

    #[test]
    fn kv_cache_clear_resets_arrangement() {
        use super::kvcache::KvCache;

        let mut cache = KvCache::new(cid(b"sess"));
        cache.store_kv(cid(b"tx"), 0, 0, cid(b"kv0"));
        cache.store_kv(cid(b"tx"), 0, 1, cid(b"kv1"));
        assert_eq!(cache.arrangement.len(), 2);
        cache.clear();
        assert!(cache.arrangement.is_empty());
    }

    // ── Embedding ─────────────────────────────────────────────────────────

    #[test]
    fn embed_inline_for_small_vector() {
        use super::embed::{embed_to_delta, Embedding};

        let emb = Embedding {
            doc_cid: cid(b"doc"),
            model_cid: cid(b"m"),
            vector: vec![0.1_f32; 512],
        };
        let delta = embed_to_delta(&emb, cid(b"tx"));
        assert!(delta.is_assert());
        assert!(matches!(delta.datom.v, Value::VectorF32(_)));
    }

    #[test]
    fn embed_tensor_cid_for_large_vector() {
        use super::embed::{embed_to_delta, Embedding};

        let emb = Embedding {
            doc_cid: cid(b"doc"),
            model_cid: cid(b"m"),
            vector: vec![0.1_f32; 2048],
        };
        let delta = embed_to_delta(&emb, cid(b"tx"));
        assert!(matches!(
            delta.datom.v,
            Value::TensorCid {
                dtype: TensorDtype::F32,
                ..
            }
        ));
    }

    // ── InferenceSession ──────────────────────────────────────────────────

    #[test]
    fn inference_session_new_empty_output() {
        use super::infer::{InferenceRequest, InferenceSession};

        let req = InferenceRequest {
            model_cid: cid(b"model"),
            adapter_cid: None,
            input_tokens: vec![1, 2, 3],
            max_tokens: 256,
            call_id: 42,
            ucan_cid: cid(b"ucan"),
        };
        let sess = InferenceSession::new(req, cid(b"session"));
        assert!(sess.output.is_empty());
        assert_eq!(sess.request.max_tokens, 256);
        assert_eq!(sess.request.call_id, 42);
    }

    // ── FP8 codec (gpu_common) ────────────────────────────────────────────

    #[test]
    fn fp8_roundtrip_from_lib() {
        use super::{dequantize_fp8_e4m3, quantize_f32_to_fp8_e4m3};
        let vals = vec![1.0f32, -2.0, 0.5, 64.0];
        let enc = quantize_f32_to_fp8_e4m3(&vals);
        let dec = dequantize_fp8_e4m3(&enc);
        for (o, d) in vals.iter().zip(dec.iter()) {
            assert!((o - d).abs() / o.abs().max(1e-6) < 0.15);
        }
    }
}
