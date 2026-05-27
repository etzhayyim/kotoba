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

/// Typed object — CID reference, scalar literal, vector, or encrypted value.
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
    /// Encrypted value — the actual content is AES-GCM ciphertext at `ct_cid`.
    /// The symmetric key is delivered via PRE after CACAO authorisation.
    /// VAET (reverse-ref index) does NOT index this variant — encrypted refs stay private.
    Encrypted {
        /// CID of the AES-GCM ciphertext block (ipfs-public, safe to distribute).
        ct_cid: KotobaCid,
        /// CID of the PRE key-registry entry for this value.
        policy_cid: KotobaCid,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TensorDtype { F32, F16, BF16, F8E4M3, F8E5M2 }

impl Quad {
    /// SPO sort key for EAVT index
    pub fn spo_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(&self.subject.0);
        key.extend_from_slice(self.predicate.as_bytes());
        match &self.object {
            QuadObject::Cid(c) => key.extend_from_slice(&c.0),
            // Encrypted: use ct_cid for dedup so each ciphertext is a distinct fact.
            QuadObject::Encrypted { ct_cid, .. } => key.extend_from_slice(&ct_cid.0),
            _ => {}
        }
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(tag: &[u8]) -> KotobaCid { KotobaCid::from_bytes(tag) }

    fn quad(pred: &str, obj: QuadObject) -> Quad {
        Quad { graph: cid(b"g"), subject: cid(b"s"), predicate: pred.to_string(), object: obj }
    }

    #[test]
    fn spo_key_starts_with_subject_bytes() {
        let q = quad("pred/foo", QuadObject::Text("v".to_string()));
        let key = q.spo_key();
        assert_eq!(&key[..36], &cid(b"s").0);
    }

    #[test]
    fn spo_key_differs_by_predicate() {
        let a = quad("pred/a", QuadObject::Text("same".to_string())).spo_key();
        let b = quad("pred/b", QuadObject::Text("same".to_string())).spo_key();
        assert_ne!(a, b);
    }

    #[test]
    fn spo_key_cid_object_appended() {
        let obj_cid = cid(b"obj");
        let q = quad("rel", QuadObject::Cid(obj_cid.clone()));
        let key = q.spo_key();
        // Key = subject(36) + predicate bytes + cid bytes(36)
        assert_eq!(key.len(), 36 + "rel".len() + 36);
        assert_eq!(&key[36 + "rel".len()..], &obj_cid.0);
    }

    #[test]
    fn spo_key_scalar_object_not_appended() {
        let q_int  = quad("p", QuadObject::Integer(42)).spo_key();
        let q_text = quad("p", QuadObject::Text("x".to_string())).spo_key();
        // Both should be same length: subject + predicate only
        let expected_len = 36 + "p".len();
        assert_eq!(q_int.len(),  expected_len);
        assert_eq!(q_text.len(), expected_len);
    }

    #[test]
    fn spo_key_encrypted_uses_ct_cid() {
        let ct = cid(b"ct");
        let pol = cid(b"policy");
        let q = quad("enc/field", QuadObject::Encrypted { ct_cid: ct.clone(), policy_cid: pol });
        let key = q.spo_key();
        assert_eq!(&key[36 + "enc/field".len()..], &ct.0);
    }

    // ── spo_key for remaining scalar variants ────────────────────────────────

    #[test]
    fn spo_key_bool_not_appended() {
        let k = quad("p", QuadObject::Bool(true)).spo_key();
        assert_eq!(k.len(), 36 + "p".len());
    }

    #[test]
    fn spo_key_float_not_appended() {
        let k = quad("p", QuadObject::Float(3.14)).spo_key();
        assert_eq!(k.len(), 36 + "p".len());
    }

    #[test]
    fn spo_key_bytes_not_appended() {
        let k = quad("p", QuadObject::Bytes(vec![1, 2, 3])).spo_key();
        assert_eq!(k.len(), 36 + "p".len());
    }

    #[test]
    fn spo_key_vector_f32_not_appended() {
        let k = quad("p", QuadObject::VectorF32(vec![0.1, 0.2])).spo_key();
        assert_eq!(k.len(), 36 + "p".len());
    }

    #[test]
    fn spo_key_tensor_cid_not_appended() {
        let k = quad("p", QuadObject::TensorCid {
            cid: cid(b"t"),
            shape: vec![4, 4],
            dtype: TensorDtype::F32,
        }).spo_key();
        assert_eq!(k.len(), 36 + "p".len());
    }

    // ── TensorDtype: all 5 variants ───────────────────────────────────────────

    #[test]
    fn tensor_dtype_equality_all_variants() {
        assert_eq!(TensorDtype::F32,   TensorDtype::F32);
        assert_eq!(TensorDtype::F16,   TensorDtype::F16);
        assert_eq!(TensorDtype::BF16,  TensorDtype::BF16);
        assert_eq!(TensorDtype::F8E4M3, TensorDtype::F8E4M3);
        assert_eq!(TensorDtype::F8E5M2, TensorDtype::F8E5M2);
        assert_ne!(TensorDtype::F32,   TensorDtype::F16);
        assert_ne!(TensorDtype::F8E4M3, TensorDtype::F8E5M2);
    }

    #[test]
    fn tensor_dtype_clone() {
        let d = TensorDtype::BF16;
        assert_eq!(d.clone(), TensorDtype::BF16);
    }

    // ── QuadObject PartialEq ─────────────────────────────────────────────────

    #[test]
    fn quad_object_partial_eq_same_variant() {
        assert_eq!(QuadObject::Integer(7), QuadObject::Integer(7));
        assert_ne!(QuadObject::Integer(7), QuadObject::Integer(8));
        assert_eq!(QuadObject::Bool(false), QuadObject::Bool(false));
        assert_ne!(QuadObject::Bool(true), QuadObject::Bool(false));
        assert_eq!(QuadObject::Text("hi".to_string()), QuadObject::Text("hi".to_string()));
    }

    #[test]
    fn quad_object_partial_eq_cid_variant() {
        let a = QuadObject::Cid(cid(b"a"));
        let b = QuadObject::Cid(cid(b"b"));
        assert_eq!(a.clone(), a.clone());
        assert_ne!(a, b);
    }

    #[test]
    fn quad_object_partial_eq_encrypted_variant() {
        let enc1 = QuadObject::Encrypted { ct_cid: cid(b"ct1"), policy_cid: cid(b"pol") };
        let enc2 = QuadObject::Encrypted { ct_cid: cid(b"ct2"), policy_cid: cid(b"pol") };
        assert_eq!(enc1.clone(), enc1.clone());
        assert_ne!(enc1, enc2);
    }

    // ── Quad PartialEq ───────────────────────────────────────────────────────

    #[test]
    fn quad_partial_eq_same_fields() {
        let q1 = quad("ns/pred", QuadObject::Integer(1));
        let q2 = quad("ns/pred", QuadObject::Integer(1));
        assert_eq!(q1, q2);
    }

    #[test]
    fn quad_partial_eq_differs_by_object() {
        let q1 = quad("ns/pred", QuadObject::Integer(1));
        let q2 = quad("ns/pred", QuadObject::Integer(2));
        assert_ne!(q1, q2);
    }

    // ── Serde JSON roundtrip per QuadObject variant ──────────────────────────

    fn roundtrip(obj: QuadObject) -> QuadObject {
        let json = serde_json::to_string(&obj).expect("serialize");
        serde_json::from_str(&json).expect("deserialize")
    }

    #[test]
    fn serde_quad_object_cid() {
        let obj = QuadObject::Cid(cid(b"serde-test"));
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_integer() {
        let obj = QuadObject::Integer(-42);
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_float() {
        let obj = QuadObject::Float(2.718281828);
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_text() {
        let obj = QuadObject::Text("hello kotoba".to_string());
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_bool() {
        assert_eq!(roundtrip(QuadObject::Bool(true)),  QuadObject::Bool(true));
        assert_eq!(roundtrip(QuadObject::Bool(false)), QuadObject::Bool(false));
    }

    #[test]
    fn serde_quad_object_bytes() {
        let obj = QuadObject::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_vector_f32() {
        let obj = QuadObject::VectorF32(vec![1.0, 2.0, 3.0]);
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_tensor_cid() {
        let obj = QuadObject::TensorCid {
            cid: cid(b"tensor"),
            shape: vec![768, 1],
            dtype: TensorDtype::F8E4M3,
        };
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_object_encrypted() {
        let obj = QuadObject::Encrypted {
            ct_cid:     cid(b"ct"),
            policy_cid: cid(b"policy"),
        };
        assert_eq!(roundtrip(obj.clone()), obj);
    }

    #[test]
    fn serde_quad_full_roundtrip() {
        let q = Quad {
            graph:     cid(b"graph"),
            subject:   cid(b"subj"),
            predicate: "ai.gftd.test/attr".to_string(),
            object:    QuadObject::Text("value".to_string()),
        };
        let json = serde_json::to_string(&q).expect("serialize");
        let q2: Quad = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(q, q2);
    }
}
