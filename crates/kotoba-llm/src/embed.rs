use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kqe::delta::Delta;

/// Embedding — vector<f32> stored as typed QuadObject
/// dim ≤ 1024: inline in Quad.object as VectorF32
/// dim > 1024: Vault blob CID as TensorCid
pub struct Embedding {
    pub doc_cid:   KotobaCid,
    pub model_cid: KotobaCid,
    pub vector:    Vec<f32>,
}

/// Convert embedding to Datom Delta for Arrangement insertion
pub fn embed_to_quad(emb: &Embedding, graph_cid: KotobaCid) -> Delta {
    let object = if emb.vector.len() <= 1024 {
        QuadObject::VectorF32(emb.vector.clone())
    } else {
        // Large vectors → serialize to blob CID (stored in Vault separately)
        let bytes: Vec<u8> = emb.vector.iter()
            .flat_map(|f| f.to_le_bytes())
            .collect();
        let cid = KotobaCid::from_bytes(&bytes);
        QuadObject::TensorCid {
            cid,
            shape: vec![emb.vector.len() as u32],
            dtype: kotoba_kqe::quad::TensorDtype::F32,
        }
    };

    let quad = Quad {
        graph:     graph_cid,
        subject:   emb.doc_cid.clone(),
        predicate: format!("embedding/{}", emb.model_cid.to_multibase()),
        object,
    };
    Delta::assert(quad)
}
