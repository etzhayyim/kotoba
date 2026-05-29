use kotoba_core::cid::KotobaCid;
use kotoba_kqe::datom::{Datom, TensorDtype, Value};
use kotoba_kqe::delta::Delta;

/// LoraAdapter — weight delta as Datom Delta
/// LoRA is natively expressed as Delta(Datom) in KOTOBA
/// effective_weight = base + lora_A × lora_B × scale
#[derive(Debug, Clone)]
pub struct LoraAdapter {
    pub base_cid: KotobaCid,    // base model CID
    pub adapter_cid: KotobaCid, // adapter blob CID
    pub scale: f32,
    pub rank: u32,
}

/// Convert LoRA adapter to Kotoba Delta (Datom assertion)
/// Bonsai ADR-2605092100: LoRA-per-Cell as MoE Expert = LoRA as Delta per DHT Node
pub fn lora_to_delta(adapter: &LoraAdapter, tx_cid: KotobaCid) -> Delta {
    Delta::assert_datom(Datom::assert(
        adapter.base_cid.clone(),
        "lora/adapter".to_string(),
        Value::TensorCid {
            cid: adapter.adapter_cid.clone(),
            shape: vec![adapter.rank],
            dtype: TensorDtype::F8E4M3,
        },
        tx_cid,
    ))
}

/// Remove LoRA adapter (retraction)
pub fn lora_retract_delta(adapter: &LoraAdapter, tx_cid: KotobaCid) -> Delta {
    Delta::retract_datom(Datom::retract(
        adapter.base_cid.clone(),
        "lora/adapter".to_string(),
        Value::TensorCid {
            cid: adapter.adapter_cid.clone(),
            shape: vec![adapter.rank],
            dtype: TensorDtype::F8E4M3,
        },
        tx_cid,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> LoraAdapter {
        LoraAdapter {
            base_cid: KotobaCid::from_bytes(b"base"),
            adapter_cid: KotobaCid::from_bytes(b"adapter"),
            scale: 0.5,
            rank: 16,
        }
    }

    #[test]
    fn lora_to_delta_is_assert() {
        let d = lora_to_delta(&adapter(), KotobaCid::from_bytes(b"g"));
        assert!(d.is_assert());
    }

    #[test]
    fn lora_to_delta_predicate() {
        let d = lora_to_delta(&adapter(), KotobaCid::from_bytes(b"g"));
        assert_eq!(d.datom.a, "lora/adapter");
    }

    #[test]
    fn lora_to_delta_subject_is_base_cid() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"g"));
        assert_eq!(d.datom.e, a.base_cid);
    }

    #[test]
    fn lora_to_delta_shape_is_rank() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"g"));
        if let Value::TensorCid { shape, .. } = d.datom.v {
            assert_eq!(shape, vec![a.rank]);
        } else {
            panic!("expected TensorCid");
        }
    }

    #[test]
    fn lora_retract_delta_is_retract() {
        let d = lora_retract_delta(&adapter(), KotobaCid::from_bytes(b"g"));
        assert!(!d.is_assert());
    }

    #[test]
    fn assert_and_retract_have_matching_quads() {
        let a = adapter();
        let tx = KotobaCid::from_bytes(b"tx");
        let da = lora_to_delta(&a, tx.clone());
        let dr = lora_retract_delta(&a, tx);
        assert_eq!(da.datom.e, dr.datom.e);
        assert_eq!(da.datom.a, dr.datom.a);
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
    fn lora_to_delta_tx_cid_is_stored_correctly() {
        let a = adapter();
        let tx = KotobaCid::from_bytes(b"my-tx");
        let d = lora_to_delta(&a, tx.clone());
        assert_eq!(d.datom.tx, tx);
    }

    #[test]
    fn lora_retract_tx_cid_is_stored_correctly() {
        let a = adapter();
        let tx = KotobaCid::from_bytes(b"my-tx");
        let d = lora_retract_delta(&a, tx.clone());
        assert_eq!(d.datom.tx, tx);
    }

    #[test]
    fn lora_to_delta_tensor_dtype_is_f8e4m3() {
        let a = adapter();
        let d = lora_to_delta(&a, KotobaCid::from_bytes(b"tx"));
        if let Value::TensorCid { dtype, .. } = d.datom.v {
            assert!(matches!(dtype, TensorDtype::F8E4M3));
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
        if let Value::TensorCid { cid, .. } = d.datom.v {
            assert_eq!(cid, a.adapter_cid);
        } else {
            panic!("expected TensorCid object");
        }
    }
}
