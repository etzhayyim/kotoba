pub mod weight;
pub mod lora;
pub mod kvcache;
pub mod embed;
pub mod infer;
pub mod gemma;

pub use weight::{WeightRef, WeightBlob};
pub use lora::{LoraAdapter, lora_to_delta};
pub use kvcache::KvCache;
pub use embed::{Embedding, embed_to_quad};
pub use infer::{InferenceRequest, InferenceSession, InferError};

#[cfg(feature = "local-inference")]
pub use gemma::GemmaRunner;

#[cfg(test)]
mod tests {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::delta::Multiplicity;
    use kotoba_kqe::quad::QuadObject;

    fn cid(seed: &[u8]) -> KotobaCid { KotobaCid::from_bytes(seed) }

    // ── WeightRef ──────────────────────────────────────────────────────────

    #[test]
    fn weight_ref_to_quad_predicate() {
        use super::weight::WeightRef;
        use kotoba_kqe::quad::TensorDtype;

        let model = cid(b"model");
        let blob  = cid(b"blob");
        let graph = cid(b"graph");

        let w = WeightRef {
            model_cid: model.clone(),
            layer: 3,
            blob_cid: blob.clone(),
            shape: vec![4096, 4096],
            dtype: TensorDtype::F8E4M3,
        };
        let quad = w.to_quad(graph);
        assert_eq!(quad.predicate, "weight/layer/3");
        assert!(matches!(quad.object, QuadObject::TensorCid { .. }));
        assert_eq!(quad.subject, model);
    }

    // ── LoRA ──────────────────────────────────────────────────────────────

    #[test]
    fn lora_to_delta_is_assert() {
        use super::lora::{LoraAdapter, lora_to_delta};

        let adapter = LoraAdapter {
            base_cid:    cid(b"base"),
            adapter_cid: cid(b"adapter"),
            scale: 0.5,
            rank:  16,
        };
        let delta = lora_to_delta(&adapter, cid(b"graph"));
        assert_eq!(delta.mult, Multiplicity::Assert);
        assert_eq!(delta.quad.predicate, "lora/adapter");
    }

    #[test]
    fn lora_retract_delta_is_retract() {
        use super::lora::{LoraAdapter, lora_retract_delta};

        let adapter = LoraAdapter {
            base_cid:    cid(b"base"),
            adapter_cid: cid(b"adapter"),
            scale: 1.0,
            rank:  8,
        };
        let delta = lora_retract_delta(&adapter, cid(b"graph"));
        assert!(!delta.is_assert());
        assert_eq!(delta.mult, Multiplicity::Retract);
    }

    // ── KvCache ───────────────────────────────────────────────────────────

    #[test]
    fn kv_cache_store_returns_assert_delta() {
        use super::kvcache::KvCache;

        let session = cid(b"session");
        let mut cache = KvCache::new(session);
        let delta = cache.store_kv(cid(b"graph"), 0, 5, cid(b"kv_blob"));
        assert!(delta.is_assert());
        assert_eq!(delta.quad.predicate, "kv/layer/0/seq/5");
    }

    #[test]
    fn kv_cache_clear_resets_arrangement() {
        use super::kvcache::KvCache;

        let mut cache = KvCache::new(cid(b"sess"));
        cache.store_kv(cid(b"g"), 0, 0, cid(b"kv0"));
        cache.store_kv(cid(b"g"), 0, 1, cid(b"kv1"));
        assert_eq!(cache.arrangement.len(), 2);
        cache.clear();
        assert!(cache.arrangement.is_empty());
    }

    // ── Embedding ─────────────────────────────────────────────────────────

    #[test]
    fn embed_inline_for_small_vector() {
        use super::embed::{Embedding, embed_to_quad};

        let emb = Embedding {
            doc_cid:   cid(b"doc"),
            model_cid: cid(b"m"),
            vector:    vec![0.1_f32; 512],
        };
        let delta = embed_to_quad(&emb, cid(b"g"));
        assert!(delta.is_assert());
        assert!(matches!(delta.quad.object, QuadObject::VectorF32(_)));
    }

    #[test]
    fn embed_tensor_cid_for_large_vector() {
        use super::embed::{Embedding, embed_to_quad};

        let emb = Embedding {
            doc_cid:   cid(b"doc"),
            model_cid: cid(b"m"),
            vector:    vec![0.1_f32; 2048],
        };
        let delta = embed_to_quad(&emb, cid(b"g"));
        assert!(matches!(delta.quad.object, QuadObject::TensorCid { .. }));
    }

    // ── InferenceSession ──────────────────────────────────────────────────

    #[test]
    fn inference_session_new_empty_output() {
        use super::infer::{InferenceRequest, InferenceSession};

        let req = InferenceRequest {
            model_cid:    cid(b"model"),
            adapter_cid:  None,
            input_tokens: vec![1, 2, 3],
            max_tokens:   256,
            call_id:      42,
            ucan_cid:     cid(b"ucan"),
        };
        let sess = InferenceSession::new(req, cid(b"session"));
        assert!(sess.output.is_empty());
        assert_eq!(sess.request.max_tokens, 256);
        assert_eq!(sess.request.call_id, 42);
    }
}
