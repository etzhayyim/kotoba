use kotoba_core::cid::KotobaCid;
use kotoba_kse::vault::Vault;
use kotoba_kqe::quad::{Quad, QuadObject, TensorDtype};
use bytes::Bytes;

/// WeightRef — CID-addressed model weight tensor
/// Stored as Datom: Quad(model_cid, "weight/layer/N", blob_cid)
#[derive(Debug, Clone)]
pub struct WeightRef {
    pub model_cid: KotobaCid,
    pub layer:     u32,
    pub blob_cid:  KotobaCid,
    pub shape:     Vec<u32>,
    pub dtype:     TensorDtype,
}

impl WeightRef {
    /// Convert to Datom (Quad) for storage in Arrangement
    pub fn to_quad(&self, graph_cid: KotobaCid) -> Quad {
        Quad {
            graph:     graph_cid,
            subject:   self.model_cid.clone(),
            predicate: format!("weight/layer/{}", self.layer),
            object:    QuadObject::TensorCid {
                cid:   self.blob_cid.clone(),
                shape: self.shape.clone(),
                dtype: self.dtype.clone(),
            },
        }
    }
}

/// WeightBlob — raw FP8 tensor bytes in Vault
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
