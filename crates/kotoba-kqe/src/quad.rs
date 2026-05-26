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
        /// CID of the AES-GCM ciphertext block (iroh-public, safe to distribute).
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
}
