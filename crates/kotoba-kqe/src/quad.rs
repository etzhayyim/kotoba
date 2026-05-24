use kotoba_core::cid::KotobaCid;
use serde::{Deserialize, Serialize};

/// Quad — (S, P, O, G) = KOTOBA's atomic fact unit (≅ Datom E,A,V,T)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Quad {
    pub graph:     KotobaCid,   // G = named graph (≅ Datom T, content-addressed)
    pub subject:   KotobaCid,   // S = entity  (≅ Datom E)
    pub predicate: String,      // P = attribute (≅ Datom A) — NSID
    pub object:    QuadObject,  // O = value (≅ Datom V)
}

/// Typed object — CID reference, scalar literal, or vector (for embeddings/weights)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuadObject {
    Cid(KotobaCid),
    Integer(i64),
    Float(f64),
    Text(String),
    Bool(bool),
    Bytes(Vec<u8>),
    /// Embedding vector (dim ≤ 1024 inline; larger → Vault CID)
    VectorF32(Vec<f32>),
    /// FP8 tensor reference (dim > 1024 → Vault blob CID)
    TensorCid { cid: KotobaCid, shape: Vec<u32>, dtype: TensorDtype },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TensorDtype { F32, F16, BF16, F8E4M3, F8E5M2 }

impl Quad {
    /// SPO sort key for EAVT index
    pub fn spo_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(&self.subject.0);
        key.extend_from_slice(self.predicate.as_bytes());
        // object hash for dedup
        if let QuadObject::Cid(ref c) = self.object {
            key.extend_from_slice(&c.0);
        }
        key
    }
}
