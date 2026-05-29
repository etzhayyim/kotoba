use kotoba_core::cid::KotobaCid;
use kotoba_kqe::datom::{Datom, TensorDtype, Value};
use kotoba_kqe::delta::Delta;

/// Embedding — vector<f32> stored as typed Datom value.
/// dim <= 1024: inline in Datom.v as VectorF32
/// dim > 1024: Vault blob CID as TensorCid
pub struct Embedding {
    pub doc_cid: KotobaCid,
    pub model_cid: KotobaCid,
    pub vector: Vec<f32>,
}

/// Convert embedding to Datom Delta for Arrangement insertion
pub fn embed_to_quad(emb: &Embedding, graph_cid: KotobaCid) -> Delta {
    let value = if emb.vector.len() <= 1024 {
        Value::VectorF32(emb.vector.clone())
    } else {
        // Large vectors → serialize to blob CID (stored in Vault separately)
        let bytes: Vec<u8> = emb.vector.iter().flat_map(|f| f.to_le_bytes()).collect();
        let cid = KotobaCid::from_bytes(&bytes);
        Value::TensorCid {
            cid,
            shape: vec![emb.vector.len() as u32],
            dtype: TensorDtype::F32,
        }
    };

    Delta::assert_datom(Datom::assert(
        emb.doc_cid.clone(),
        format!("embedding/{}", emb.model_cid.to_multibase()),
        value,
        graph_cid,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(seed: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(seed)
    }

    fn embedding(size: usize) -> Embedding {
        Embedding {
            doc_cid: cid(b"doc"),
            model_cid: cid(b"model"),
            vector: vec![1.0f32; size],
        }
    }

    #[test]
    fn embed_to_quad_is_assert_delta() {
        let d = embed_to_quad(&embedding(4), cid(b"g"));
        assert!(d.is_assert());
    }

    #[test]
    fn embed_to_quad_predicate_contains_model_cid() {
        let emb = embedding(4);
        let d = embed_to_quad(&emb, cid(b"g"));
        assert!(
            d.datom.a.starts_with("embedding/"),
            "predicate should start with 'embedding/': {}",
            d.datom.a
        );
    }

    #[test]
    fn embed_to_quad_small_vector_is_inline() {
        let d = embed_to_quad(&embedding(10), cid(b"g"));
        assert!(
            matches!(d.datom.v, Value::VectorF32(_)),
            "small vector (≤1024) should be inline VectorF32"
        );
    }

    #[test]
    fn embed_to_quad_exactly_1024_is_inline() {
        let d = embed_to_quad(&embedding(1024), cid(b"g"));
        assert!(
            matches!(d.datom.v, Value::VectorF32(_)),
            "exactly 1024 dims should be inline"
        );
    }

    #[test]
    fn embed_to_quad_large_vector_is_tensor_cid() {
        let d = embed_to_quad(&embedding(1025), cid(b"g"));
        assert!(
            matches!(d.datom.v, Value::TensorCid { .. }),
            "vector > 1024 dims should be TensorCid"
        );
    }

    #[test]
    fn embed_to_quad_subject_is_doc_cid() {
        let emb = embedding(5);
        let d = embed_to_quad(&emb, cid(b"g"));
        assert_eq!(d.datom.e, emb.doc_cid);
    }

    #[test]
    fn embed_to_quad_large_shape_is_vector_len() {
        let emb = embedding(2048);
        let d = embed_to_quad(&emb, cid(b"g"));
        if let Value::TensorCid { shape, .. } = d.datom.v {
            assert_eq!(shape, vec![2048u32]);
        } else {
            panic!("expected TensorCid");
        }
    }

    #[test]
    fn embed_to_quad_empty_vector_is_inline() {
        let emb = Embedding {
            doc_cid: cid(b"doc"),
            model_cid: cid(b"model"),
            vector: vec![],
        };
        let d = embed_to_quad(&emb, cid(b"g"));
        assert!(
            matches!(d.datom.v, Value::VectorF32(_)),
            "empty vector (size 0 <= 1024) should be VectorF32"
        );
    }

    #[test]
    fn embed_to_quad_size_1023_is_inline() {
        let d = embed_to_quad(&embedding(1023), cid(b"g"));
        assert!(
            matches!(d.datom.v, Value::VectorF32(_)),
            "1023 dims should be inline VectorF32"
        );
    }

    #[test]
    fn embed_to_quad_graph_cid_stored_in_quad() {
        let graph = cid(b"my-graph");
        let d = embed_to_quad(&embedding(4), graph.clone());
        assert_eq!(d.datom.tx, graph, "graph_cid should be stored in datom.tx");
    }

    #[test]
    fn embed_to_quad_different_model_cids_different_predicates() {
        let emb1 = Embedding {
            doc_cid: cid(b"doc"),
            model_cid: cid(b"modelA"),
            vector: vec![1.0; 4],
        };
        let emb2 = Embedding {
            doc_cid: cid(b"doc"),
            model_cid: cid(b"modelB"),
            vector: vec![1.0; 4],
        };
        let d1 = embed_to_quad(&emb1, cid(b"g"));
        let d2 = embed_to_quad(&emb2, cid(b"g"));
        assert_ne!(
            d1.datom.a, d2.datom.a,
            "different model_cids must produce different predicates"
        );
    }

    #[test]
    fn embed_to_quad_large_tensor_dtype_is_f32() {
        let d = embed_to_quad(&embedding(1025), cid(b"g"));
        if let Value::TensorCid { dtype, .. } = d.datom.v {
            assert_eq!(dtype, TensorDtype::F32);
        } else {
            panic!("expected TensorCid");
        }
    }
}
