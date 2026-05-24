use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kqe::delta::Delta;

/// LoraAdapter — weight delta as Datom Delta
/// LoRA is natively expressed as Delta(Quad, +1) in KOTOBA
/// effective_weight = base + lora_A × lora_B × scale
#[derive(Debug, Clone)]
pub struct LoraAdapter {
    pub base_cid:    KotobaCid,  // base model CID
    pub adapter_cid: KotobaCid,  // adapter blob CID
    pub scale:       f32,
    pub rank:        u32,
}

/// Convert LoRA adapter to Kotoba Delta (Datom assertion)
/// Bonsai ADR-2605092100: LoRA-per-Cell as MoE Expert = LoRA as Delta per DHT Node
pub fn lora_to_delta(adapter: &LoraAdapter, graph_cid: KotobaCid) -> Delta {
    let quad = Quad {
        graph:     graph_cid,
        subject:   adapter.base_cid.clone(),
        predicate: "lora/adapter".to_string(),
        object:    QuadObject::TensorCid {
            cid:   adapter.adapter_cid.clone(),
            shape: vec![adapter.rank],
            dtype: kotoba_kqe::quad::TensorDtype::F8E4M3,
        },
    };
    Delta::assert(quad)
}

/// Remove LoRA adapter (retraction)
pub fn lora_retract_delta(adapter: &LoraAdapter, graph_cid: KotobaCid) -> Delta {
    let quad = Quad {
        graph:     graph_cid,
        subject:   adapter.base_cid.clone(),
        predicate: "lora/adapter".to_string(),
        object:    QuadObject::TensorCid {
            cid:   adapter.adapter_cid.clone(),
            shape: vec![adapter.rank],
            dtype: kotoba_kqe::quad::TensorDtype::F8E4M3,
        },
    };
    Delta::retract(quad)
}
