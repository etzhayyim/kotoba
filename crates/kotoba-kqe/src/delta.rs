use crate::quad::Quad;

/// Multiplicity: +1 = assert, -1 = retract (Datom retraction as Delta)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplicity { Assert = 1, Retract = -1 }

/// Delta — atomic Pregel message: (Quad, ±1)
#[derive(Debug, Clone)]
pub struct Delta {
    pub quad:     Quad,
    pub mult:     Multiplicity,
    pub ts:       u64,
}

impl Delta {
    pub fn assert(quad: Quad) -> Self {
        Self { quad, mult: Multiplicity::Assert, ts: now_ms() }
    }
    pub fn retract(quad: Quad) -> Self {
        Self { quad, mult: Multiplicity::Retract, ts: now_ms() }
    }
    pub fn is_assert(&self) -> bool { self.mult == Multiplicity::Assert }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    fn make_quad() -> Quad {
        let cid = KotobaCid::from_bytes(b"test");
        Quad {
            graph:     cid.clone(),
            subject:   cid.clone(),
            predicate: "test/pred".to_string(),
            object:    crate::quad::QuadObject::Text("value".to_string()),
        }
    }

    #[test]
    fn assert_delta_has_assert_multiplicity() {
        let d = Delta::assert(make_quad());
        assert_eq!(d.mult, Multiplicity::Assert);
        assert!(d.is_assert());
    }

    #[test]
    fn retract_delta_has_retract_multiplicity() {
        let d = Delta::retract(make_quad());
        assert_eq!(d.mult, Multiplicity::Retract);
        assert!(!d.is_assert());
    }

    #[test]
    fn delta_ts_is_nonzero() {
        let d = Delta::assert(make_quad());
        assert!(d.ts > 0);
    }

    #[test]
    fn multiplicity_discriminant_values() {
        assert_eq!(Multiplicity::Assert  as i32,  1);
        assert_eq!(Multiplicity::Retract as i32, -1);
    }

    #[test]
    fn multiplicity_copy_and_clone() {
        let m = Multiplicity::Assert;
        let m2 = m;          // Copy
        let m3 = m.clone();  // Clone
        assert_eq!(m2, Multiplicity::Assert);
        assert_eq!(m3, Multiplicity::Assert);
    }

    #[test]
    fn delta_clone_preserves_fields() {
        let d = Delta::assert(make_quad());
        let d2 = d.clone();
        assert_eq!(d2.mult, Multiplicity::Assert);
        assert_eq!(d2.quad, d.quad);
        assert_eq!(d2.ts,   d.ts);
    }

    #[test]
    fn retract_is_not_assert() {
        let d = Delta::retract(make_quad());
        assert!(!d.is_assert());
        assert_eq!(d.mult, Multiplicity::Retract);
    }

    #[test]
    fn delta_preserves_quad_predicate() {
        let d = Delta::assert(make_quad());
        assert_eq!(d.quad.predicate, "test/pred");
    }

    #[test]
    fn delta_preserves_quad_object_text() {
        let d = Delta::assert(make_quad());
        if let crate::quad::QuadObject::Text(ref s) = d.quad.object {
            assert_eq!(s, "value");
        } else {
            panic!("expected Text object");
        }
    }

    #[test]
    fn assert_and_retract_ts_monotonic() {
        let d1 = Delta::assert(make_quad());
        let d2 = Delta::retract(make_quad());
        // Timestamps should be >= 0 and d2.ts >= d1.ts
        assert!(d1.ts > 0);
        assert!(d2.ts >= d1.ts, "retract timestamp should be >= assert timestamp");
    }

    #[test]
    fn multiplicity_debug_format() {
        let s = format!("{:?}", Multiplicity::Assert);
        assert!(s.contains("Assert"), "Debug for Assert should contain 'Assert'");
        let s2 = format!("{:?}", Multiplicity::Retract);
        assert!(s2.contains("Retract"), "Debug for Retract should contain 'Retract'");
    }
}
