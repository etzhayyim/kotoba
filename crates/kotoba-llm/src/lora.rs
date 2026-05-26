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

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_kqe::delta::Multiplicity;

    fn adapter() -> LoraAdapter {
        LoraAdapter {
            base_cid:    KotobaCid::from_bytes(b"base"),
            adapter_cid: KotobaCid::from_bytes(b"adapter"),
            scale:       0.5,
            rank:        16,
        }
    }

    #[test]
    fn lora_to_delta_is_assert() {
        let d = lora_to_delta(&adapter(), KotobaCid::from_bytes(b"g"));
        assert_eq!(d.mult, Multiplicity::Assert);
    }

    #[test]
    fn lora_to_delta_predicate() {
        let d = lora_to_delta(&adapter(), KotobaCid::from_bytes(b"g"));
        assert_eq!(d.quad.predicate, "lora/adapter");
    }

    #[test]
    fn lora_to_delta_subject_is_base_cid() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"g"));
        assert_eq!(d.quad.subject, a.base_cid);
    }

    #[test]
    fn lora_to_delta_shape_is_rank() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"g"));
        if let QuadObject::TensorCid { shape, .. } = d.quad.object {
            assert_eq!(shape, vec![a.rank]);
        } else {
            panic!("expected TensorCid");
        }
    }

    #[test]
    fn lora_retract_delta_is_retract() {
        let d = lora_retract_delta(&adapter(), KotobaCid::from_bytes(b"g"));
        assert_eq!(d.mult, Multiplicity::Retract);
    }

    #[test]
    fn assert_and_retract_have_matching_quads() {
        let a = adapter();
        let g = KotobaCid::from_bytes(b"g");
        let da = lora_to_delta(&a, g.clone());
        let dr = lora_retract_delta(&a, g);
        assert_eq!(da.quad.subject,   dr.quad.subject);
        assert_eq!(da.quad.predicate, dr.quad.predicate);
    }

    // ── additional LoraAdapter tests ──────────────────────────────────────────

    #[test]
    fn lora_adapter_scale_field_accessible() {
        let a = adapter();
        assert!((a.scale - 0.5_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn lora_adapter_rank_field_is_16() {
        let a = adapter();
        assert_eq!(a.rank, 16);
    }

    #[test]
    fn lora_to_delta_graph_cid_is_stored_correctly() {
        let a = adapter();
        let g = KotobaCid::from_bytes(b"my-graph");
        let d = lora_to_delta(&a, g.clone());
        assert_eq!(d.quad.graph, g);
    }

    #[test]
    fn lora_retract_graph_cid_is_stored_correctly() {
        let a = adapter();
        let g = KotobaCid::from_bytes(b"my-graph");
        let d = lora_retract_delta(&a, g.clone());
        assert_eq!(d.quad.graph, g);
    }

    #[test]
    fn lora_to_delta_tensor_dtype_is_f8e4m3() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"g"));
        if let QuadObject::TensorCid { dtype, .. } = d.quad.object {
            assert!(matches!(dtype, kotoba_kqe::quad::TensorDtype::F8E4M3));
        } else {
            panic!("expected TensorCid object");
        }
    }

    #[test]
    fn lora_adapter_clone_has_same_fields() {
        let a = adapter();
        let b = a.clone();
        assert_eq!(a.base_cid, b.base_cid);
        assert_eq!(a.adapter_cid, b.adapter_cid);
        assert_eq!(a.rank, b.rank);
    }

    #[test]
    fn lora_to_delta_adapter_cid_in_object() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"g"));
        if let QuadObject::TensorCid { cid, .. } = d.quad.object {
            assert_eq!(cid, a.adapter_cid);
        } else {
            panic!("expected TensorCid object");
        }
    }
}
