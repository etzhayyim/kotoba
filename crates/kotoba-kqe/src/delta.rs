use crate::datom::{Datom, Value};
use crate::quad::LegacyQuad as Quad;
use kotoba_core::cid::KotobaCid;
use serde::{Deserialize, Serialize};

/// Delta — atomic Pregel message. The op is stored only in `datom.op`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delta {
    pub datom: Datom,
    pub ts: u64,
}

impl Delta {
    #[deprecated(note = "use assert_datom() or assert_legacy_quad() at explicit legacy boundaries")]
    pub fn assert(quad: Quad) -> Self {
        Self::assert_legacy_quad(quad)
    }

    #[deprecated(
        note = "use retract_datom() or retract_legacy_quad() at explicit legacy boundaries"
    )]
    pub fn retract(quad: Quad) -> Self {
        Self::retract_legacy_quad(quad)
    }

    pub fn assert_legacy_quad(quad: Quad) -> Self {
        Self::assert_datom(Datom::from_legacy_quad(quad, true))
    }

    pub fn retract_legacy_quad(quad: Quad) -> Self {
        Self::retract_datom(Datom::from_legacy_quad(quad, false))
    }

    pub fn assert_datom(mut datom: Datom) -> Self {
        datom.op = true;
        Self::from_datom(datom)
    }

    pub fn retract_datom(mut datom: Datom) -> Self {
        datom.op = false;
        Self::from_datom(datom)
    }

    pub fn from_datom(datom: Datom) -> Self {
        Self {
            datom,
            ts: now_ms(),
        }
    }

    pub fn is_assert(&self) -> bool {
        self.datom.op
    }

    pub fn entity(&self) -> &KotobaCid {
        &self.datom.e
    }

    pub fn attribute(&self) -> &str {
        &self.datom.a
    }

    pub fn value(&self) -> &Value {
        &self.datom.v
    }

    pub fn to_legacy_quad(&self) -> Quad {
        self.datom.to_legacy_quad()
    }

    #[deprecated(note = "use to_legacy_quad() only at explicit legacy Quad boundaries")]
    pub fn quad(&self) -> Quad {
        self.to_legacy_quad()
    }
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

    fn make_datom() -> Datom {
        let cid = KotobaCid::from_bytes(b"test");
        Datom::assert(
            cid.clone(),
            "test/pred".to_string(),
            Value::Text("value".to_string()),
            cid,
        )
    }

    #[test]
    fn assert_delta_sets_datom_op_true() {
        let d = Delta::assert_datom(make_datom());
        assert!(d.datom.op);
        assert!(d.is_assert());
    }

    #[test]
    fn retract_delta_sets_datom_op_false() {
        let d = Delta::retract_datom(make_datom());
        assert!(!d.datom.op);
        assert!(!d.is_assert());
    }

    #[test]
    fn delta_ts_is_nonzero() {
        let d = Delta::assert_datom(make_datom());
        assert!(d.ts > 0);
    }

    #[test]
    fn delta_clone_preserves_fields() {
        let d = Delta::assert_datom(make_datom());
        let d2 = d.clone();
        assert_eq!(d2.datom, d.datom);
        assert_eq!(d2.ts, d.ts);
    }

    #[test]
    fn delta_preserves_datom_fields() {
        let d = Delta::assert_datom(make_datom());
        assert_eq!(d.attribute(), "test/pred");
        assert_eq!(d.value(), &Value::Text("value".to_string()));
    }
}
