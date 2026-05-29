use kotoba_core::cid::KotobaCid;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};

/// Datom — exact Datomic atomic fact `(E, A, V, T, Added)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Datom {
    pub e: KotobaCid,
    pub a: String,
    pub v: Value,
    pub tx: KotobaCid,
    pub op: bool,
}

/// Datomic value stored in a datom's V slot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Cid(KotobaCid),
    Integer(i64),
    Float(f64),
    Text(String),
    Bool(bool),
    Bytes(Vec<u8>),
    /// Embedding vector (dim <= 1024 inline; larger -> Vault CID).
    VectorF32(Vec<f32>),
    /// FP8 tensor reference (dim > 1024 -> Vault blob CID).
    TensorCid {
        cid: KotobaCid,
        shape: Vec<u32>,
        dtype: TensorDtype,
    },
    /// Encrypted value. VAET does not index this variant.
    Encrypted {
        ct_cid: KotobaCid,
        policy_cid: KotobaCid,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TensorDtype {
    F32,
    F16,
    BF16,
    F8E4M3,
    F8E5M2,
}

/// DatomArrangement — five covering indexes: EAVT / AEVT / AVET / VAET / TEA.
#[derive(Debug, Default, Clone)]
pub struct DatomArrangement {
    eavt: BTreeMap<Vec<u8>, Datom>,
    aevt: BTreeMap<Vec<u8>, Datom>,
    avet: BTreeMap<Vec<u8>, Datom>,
    vaet: BTreeMap<Vec<u8>, Datom>,
    tea: BTreeMap<Vec<u8>, Datom>,
    log: Vec<Datom>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatomIndex {
    Eavt,
    Aevt,
    Avet,
    Vaet,
    Tea,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DatomIndexComponent {
    Entity(KotobaCid),
    Attribute(String),
    Value(Value),
    Tx(KotobaCid),
}

impl Datom {
    pub fn assert(e: KotobaCid, a: String, v: Value, tx: KotobaCid) -> Self {
        Self {
            e,
            a,
            v,
            tx,
            op: true,
        }
    }

    pub fn retract(e: KotobaCid, a: String, v: Value, tx: KotobaCid) -> Self {
        Self {
            e,
            a,
            v,
            tx,
            op: false,
        }
    }

    pub fn as_tuple(&self) -> (&KotobaCid, &str, &Value, &KotobaCid, bool) {
        (&self.e, &self.a, &self.v, &self.tx, self.op)
    }

    /// EAVT key: E + A + V + descending T + op.
    pub fn eavt_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(&self.e.0);
        push_str(&mut key, &self.a);
        push_value(&mut key, &self.v);
        push_tx_desc_and_op(&mut key, &self.tx, self.op);
        key
    }

    /// AEVT key: A + E + V + descending T + op.
    pub fn aevt_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        push_str(&mut key, &self.a);
        key.extend_from_slice(&self.e.0);
        push_value(&mut key, &self.v);
        push_tx_desc_and_op(&mut key, &self.tx, self.op);
        key
    }

    /// AVET key: A + V + E + descending T + op.
    pub fn avet_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        push_str(&mut key, &self.a);
        push_value(&mut key, &self.v);
        key.extend_from_slice(&self.e.0);
        push_tx_desc_and_op(&mut key, &self.tx, self.op);
        key
    }

    /// VAET key: V + A + E + descending T + op. Only ref values have a key.
    pub fn vaet_key(&self) -> Option<Vec<u8>> {
        if !matches!(self.v, Value::Cid(_)) {
            return None;
        }
        let mut key = Vec::new();
        push_value(&mut key, &self.v);
        push_str(&mut key, &self.a);
        key.extend_from_slice(&self.e.0);
        push_tx_desc_and_op(&mut key, &self.tx, self.op);
        Some(key)
    }

    /// TEA key: T + E + A + V + op.
    ///
    /// Datomic's logical lookup prefix is T/E/A, but the stored key must include
    /// V and op so a single transaction can persist multiple facts for the same
    /// entity and attribute without overwriting a previous TEA leaf.
    pub fn tea_key(&self) -> Vec<u8> {
        let mut key = Vec::new();
        key.extend_from_slice(&self.tx.0);
        key.extend_from_slice(&self.e.0);
        push_str(&mut key, &self.a);
        push_value(&mut key, &self.v);
        // Ascending TEA scans must replay assert before retract when both are
        // emitted in the same tx for the same E/A/V.
        key.push(if self.op { 0 } else { 1 });
        key
    }

    pub fn from_legacy_quad(quad: Quad, op: bool) -> Self {
        Self {
            e: quad.subject,
            a: quad.predicate,
            v: Value::from(quad.object),
            tx: quad.graph,
            op,
        }
    }

    pub fn into_legacy_quad(self) -> Quad {
        Quad {
            graph: self.tx,
            subject: self.e,
            predicate: self.a,
            object: self.v.into(),
        }
    }

    pub fn to_legacy_quad(&self) -> Quad {
        self.clone().into_legacy_quad()
    }
}

impl From<QuadObject> for Value {
    fn from(value: QuadObject) -> Self {
        match value {
            QuadObject::Cid(cid) => Self::Cid(cid),
            QuadObject::Integer(n) => Self::Integer(n),
            QuadObject::Float(f) => Self::Float(f),
            QuadObject::Text(s) => Self::Text(s),
            QuadObject::Bool(b) => Self::Bool(b),
            QuadObject::Bytes(bytes) => Self::Bytes(bytes),
            QuadObject::VectorF32(v) => Self::VectorF32(v),
            QuadObject::TensorCid { cid, shape, dtype } => Self::TensorCid {
                cid,
                shape,
                dtype: dtype.into(),
            },
            QuadObject::Encrypted { ct_cid, policy_cid } => Self::Encrypted { ct_cid, policy_cid },
        }
    }
}

impl From<Value> for QuadObject {
    fn from(value: Value) -> Self {
        match value {
            Value::Cid(cid) => Self::Cid(cid),
            Value::Integer(n) => Self::Integer(n),
            Value::Float(f) => Self::Float(f),
            Value::Text(s) => Self::Text(s),
            Value::Bool(b) => Self::Bool(b),
            Value::Bytes(bytes) => Self::Bytes(bytes),
            Value::VectorF32(v) => Self::VectorF32(v),
            Value::TensorCid { cid, shape, dtype } => Self::TensorCid {
                cid,
                shape,
                dtype: dtype.into(),
            },
            Value::Encrypted { ct_cid, policy_cid } => Self::Encrypted { ct_cid, policy_cid },
        }
    }
}

impl From<crate::quad::TensorDtype> for TensorDtype {
    fn from(value: crate::quad::TensorDtype) -> Self {
        match value {
            crate::quad::TensorDtype::F32 => Self::F32,
            crate::quad::TensorDtype::F16 => Self::F16,
            crate::quad::TensorDtype::BF16 => Self::BF16,
            crate::quad::TensorDtype::F8E4M3 => Self::F8E4M3,
            crate::quad::TensorDtype::F8E5M2 => Self::F8E5M2,
        }
    }
}

impl From<TensorDtype> for crate::quad::TensorDtype {
    fn from(value: TensorDtype) -> Self {
        match value {
            TensorDtype::F32 => Self::F32,
            TensorDtype::F16 => Self::F16,
            TensorDtype::BF16 => Self::BF16,
            TensorDtype::F8E4M3 => Self::F8E4M3,
            TensorDtype::F8E5M2 => Self::F8E5M2,
        }
    }
}

impl DatomArrangement {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, datom: Datom) {
        self.eavt.insert(datom.eavt_key(), datom.clone());
        self.aevt.insert(datom.aevt_key(), datom.clone());
        self.avet.insert(datom.avet_key(), datom.clone());
        if let Some(key) = datom.vaet_key() {
            self.vaet.insert(key, datom.clone());
        }
        self.tea.insert(datom.tea_key(), datom.clone());
        self.log.push(datom);
    }

    pub fn apply<I: IntoIterator<Item = Datom>>(&mut self, datoms: I) {
        for datom in datoms {
            self.insert(datom);
        }
    }

    pub fn len(&self) -> usize {
        self.tea.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tea.is_empty()
    }

    pub fn clear(&mut self) {
        self.eavt.clear();
        self.aevt.clear();
        self.avet.clear();
        self.vaet.clear();
        self.tea.clear();
        self.log.clear();
    }

    pub fn history(&self) -> Vec<Datom> {
        self.log.clone()
    }

    pub fn current(&self) -> Vec<Datom> {
        current_from_history(self.history())
    }

    pub fn as_of(&self, tx: &KotobaCid) -> Vec<Datom> {
        let mut out = Vec::new();
        for datom in &self.log {
            out.push(datom.clone());
            if &datom.tx == tx {
                let wanted = self.log.iter().filter(|d| &d.tx == tx).count();
                if out.iter().filter(|d| &d.tx == tx).count() == wanted {
                    break;
                }
            }
        }
        current_from_history(out)
    }

    pub fn since(&self, tx: &KotobaCid) -> Vec<Datom> {
        let mut seen = false;
        self.log
            .iter()
            .filter_map(|datom| {
                if &datom.tx == tx {
                    seen = true;
                    None
                } else if seen && datom.op {
                    Some(datom.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn scan_prefix(
        &self,
        index: DatomIndex,
        components: &[DatomIndexComponent],
    ) -> Result<Vec<Datom>, String> {
        let prefix = datom_index_prefix(index, components)?;
        Ok(self
            .index_map(index)
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(_, datom)| datom.clone())
            .collect())
    }

    pub fn eavt_len(&self) -> usize {
        self.eavt.len()
    }

    pub fn aevt_len(&self) -> usize {
        self.aevt.len()
    }

    pub fn avet_len(&self) -> usize {
        self.avet.len()
    }

    pub fn vaet_len(&self) -> usize {
        self.vaet.len()
    }

    pub fn tea_len(&self) -> usize {
        self.tea.len()
    }

    fn index_map(&self, index: DatomIndex) -> &BTreeMap<Vec<u8>, Datom> {
        match index {
            DatomIndex::Eavt => &self.eavt,
            DatomIndex::Aevt => &self.aevt,
            DatomIndex::Avet => &self.avet,
            DatomIndex::Vaet => &self.vaet,
            DatomIndex::Tea => &self.tea,
        }
    }
}

fn datom_index_prefix(
    index: DatomIndex,
    components: &[DatomIndexComponent],
) -> Result<Vec<u8>, String> {
    if components.len() > 4 {
        return Err(format!("{index:?} index supports at most 4 components"));
    }
    let mut key = Vec::new();
    for (position, component) in components.iter().enumerate() {
        match (index, position, component) {
            (DatomIndex::Eavt, 0, DatomIndexComponent::Entity(entity))
            | (DatomIndex::Aevt, 1, DatomIndexComponent::Entity(entity))
            | (DatomIndex::Avet, 2, DatomIndexComponent::Entity(entity))
            | (DatomIndex::Vaet, 2, DatomIndexComponent::Entity(entity))
            | (DatomIndex::Tea, 1, DatomIndexComponent::Entity(entity)) => {
                key.extend_from_slice(&entity.0);
            }
            (DatomIndex::Eavt, 1, DatomIndexComponent::Attribute(attr))
            | (DatomIndex::Aevt, 0, DatomIndexComponent::Attribute(attr))
            | (DatomIndex::Avet, 0, DatomIndexComponent::Attribute(attr))
            | (DatomIndex::Vaet, 1, DatomIndexComponent::Attribute(attr))
            | (DatomIndex::Tea, 2, DatomIndexComponent::Attribute(attr)) => {
                push_str(&mut key, attr)
            }
            (DatomIndex::Eavt, 2, DatomIndexComponent::Value(value))
            | (DatomIndex::Aevt, 2, DatomIndexComponent::Value(value))
            | (DatomIndex::Avet, 1, DatomIndexComponent::Value(value))
            | (DatomIndex::Vaet, 0, DatomIndexComponent::Value(value))
            | (DatomIndex::Tea, 3, DatomIndexComponent::Value(value)) => {
                push_value(&mut key, value);
            }
            (DatomIndex::Eavt, 3, DatomIndexComponent::Tx(tx))
            | (DatomIndex::Aevt, 3, DatomIndexComponent::Tx(tx))
            | (DatomIndex::Avet, 3, DatomIndexComponent::Tx(tx))
            | (DatomIndex::Vaet, 3, DatomIndexComponent::Tx(tx)) => push_tx_desc(&mut key, tx),
            (DatomIndex::Tea, 0, DatomIndexComponent::Tx(tx)) => key.extend_from_slice(&tx.0),
            _ => {
                return Err(format!(
                    "{index:?} component {position} has invalid kind: {component:?}"
                ));
            }
        }
    }
    Ok(key)
}

fn current_from_history(history: Vec<Datom>) -> Vec<Datom> {
    let mut seen = BTreeSet::<Vec<u8>>::new();
    let mut out = Vec::new();
    for datom in history.into_iter().rev() {
        let key = eav_key(&datom);
        if !seen.insert(key) {
            continue;
        }
        if datom.op {
            out.push(datom);
        }
    }
    out.reverse();
    out
}

fn eav_key(datom: &Datom) -> Vec<u8> {
    let mut key = Vec::new();
    key.extend_from_slice(&datom.e.0);
    push_str(&mut key, &datom.a);
    push_value(&mut key, &datom.v);
    key
}

fn push_tx_desc_and_op(key: &mut Vec<u8>, tx: &KotobaCid, op: bool) {
    push_tx_desc(key, tx);
    key.push(u8::from(op));
}

fn push_tx_desc(key: &mut Vec<u8>, tx: &KotobaCid) {
    key.extend(tx.0.iter().map(|b| !b));
}

fn push_str(key: &mut Vec<u8>, value: &str) {
    key.extend_from_slice(value.as_bytes());
    key.push(0);
}

fn push_value(key: &mut Vec<u8>, value: &Value) {
    match value {
        Value::Cid(cid) => {
            key.push(0x01);
            key.extend_from_slice(&cid.0);
        }
        Value::Integer(n) => {
            key.push(0x02);
            key.extend_from_slice(&n.to_be_bytes());
        }
        Value::Float(f) => {
            key.push(0x03);
            key.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        Value::Text(s) => {
            key.push(0x04);
            push_str(key, s);
        }
        Value::Bool(b) => {
            key.push(0x05);
            key.push(u8::from(*b));
        }
        Value::Bytes(bytes) => {
            key.push(0x06);
            key.extend_from_slice(bytes);
            key.push(0);
        }
        Value::VectorF32(vec) => {
            key.push(0x07);
            for f in vec {
                key.extend_from_slice(&f.to_bits().to_be_bytes());
            }
            key.push(0);
        }
        Value::TensorCid { cid, .. } => {
            key.push(0x08);
            key.extend_from_slice(&cid.0);
        }
        Value::Encrypted { ct_cid, .. } => {
            key.push(0x09);
            key.extend_from_slice(&ct_cid.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(seed: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(seed)
    }

    #[test]
    fn datom_is_exact_five_tuple() {
        let e = cid(b"e");
        let tx = cid(b"tx");
        let v = Value::Text("Alice".into());
        let d = Datom::assert(e.clone(), ":person/name".into(), v.clone(), tx.clone());
        assert_eq!(d.as_tuple(), (&e, ":person/name", &v, &tx, true));
    }

    #[test]
    fn all_five_indexes_include_tx_and_op() {
        let d = Datom::assert(
            cid(b"alice"),
            ":person/knows".into(),
            Value::Cid(cid(b"bob")),
            cid(b"tx1"),
        );
        assert!(d.eavt_key().ends_with(&[1]));
        assert!(d.aevt_key().ends_with(&[1]));
        assert!(d.avet_key().ends_with(&[1]));
        assert!(d.vaet_key().unwrap().ends_with(&[1]));
        assert_eq!(&d.tea_key()[..36], &cid(b"tx1").0);
    }

    #[test]
    fn vaet_is_ref_only() {
        let d = Datom::assert(
            cid(b"alice"),
            ":person/name".into(),
            Value::Text("Alice".into()),
            cid(b"tx1"),
        );
        assert!(d.vaet_key().is_none());
    }

    #[test]
    fn tx_desc_orders_newer_bytes_first_for_same_eav() {
        let e = cid(b"alice");
        let v = Value::Text("Alice".into());
        let old = Datom::assert(e.clone(), ":person/name".into(), v.clone(), cid(b"old"));
        let new = Datom::assert(e, ":person/name".into(), v, cid(b"new"));
        let old_key = old.eavt_key();
        let new_key = new.eavt_key();
        assert_ne!(old_key, new_key);
        assert_eq!(old_key.last(), Some(&1));
        assert_eq!(new_key.last(), Some(&1));
    }

    #[test]
    fn arrangement_builds_five_indexes_and_tea_history() {
        let e = cid(b"alice");
        let tx1 = cid(b"tx1");
        let tx2 = cid(b"tx2");
        let mut arr = DatomArrangement::new();
        arr.insert(Datom::assert(
            e.clone(),
            ":person/name".into(),
            Value::Text("Alice".into()),
            tx1.clone(),
        ));
        arr.insert(Datom::retract(
            e.clone(),
            ":person/name".into(),
            Value::Text("Alice".into()),
            tx2.clone(),
        ));

        assert_eq!(arr.eavt_len(), 2);
        assert_eq!(arr.aevt_len(), 2);
        assert_eq!(arr.avet_len(), 2);
        assert_eq!(arr.vaet_len(), 0);
        assert_eq!(arr.tea_len(), 2);
        assert!(arr.current().is_empty());
        assert_eq!(arr.as_of(&tx1).len(), 1);
        assert!(arr.since(&tx1).is_empty());
        assert_eq!(arr.history().iter().filter(|d| !d.op).count(), 1);
    }

    #[test]
    fn tea_preserves_multiple_values_for_same_tx_entity_attr() {
        let e = cid(b"alice");
        let tx = cid(b"tx");
        let mut arr = DatomArrangement::new();
        arr.insert(Datom::assert(
            e.clone(),
            ":person/tag".into(),
            Value::Text("a".into()),
            tx.clone(),
        ));
        arr.insert(Datom::assert(
            e,
            ":person/tag".into(),
            Value::Text("b".into()),
            tx,
        ));

        assert_eq!(arr.tea_len(), 2);
        assert_eq!(arr.history().len(), 2);
    }

    #[test]
    fn scan_prefix_reads_all_five_datomic_indexes() {
        let alice = cid(b"alice");
        let bob = cid(b"bob");
        let tx1 = cid(b"tx1");
        let tx2 = cid(b"tx2");
        let mut arr = DatomArrangement::new();
        arr.apply(vec![
            Datom::assert(
                alice.clone(),
                ":person/name".into(),
                Value::Text("Alice".into()),
                tx1.clone(),
            ),
            Datom::assert(
                alice.clone(),
                ":person/friend".into(),
                Value::Cid(bob.clone()),
                tx1.clone(),
            ),
            Datom::retract(
                alice.clone(),
                ":person/name".into(),
                Value::Text("Alice".into()),
                tx2.clone(),
            ),
        ]);

        assert_eq!(
            arr.scan_prefix(
                DatomIndex::Eavt,
                &[DatomIndexComponent::Entity(alice.clone())]
            )
            .unwrap()
            .len(),
            3
        );
        assert_eq!(
            arr.scan_prefix(
                DatomIndex::Aevt,
                &[DatomIndexComponent::Attribute(":person/name".into())]
            )
            .unwrap()
            .len(),
            2
        );
        assert_eq!(
            arr.scan_prefix(
                DatomIndex::Avet,
                &[
                    DatomIndexComponent::Attribute(":person/name".into()),
                    DatomIndexComponent::Value(Value::Text("Alice".into())),
                    DatomIndexComponent::Entity(alice.clone()),
                ]
            )
            .unwrap()
            .len(),
            2
        );
        let vaet = arr
            .scan_prefix(
                DatomIndex::Vaet,
                &[
                    DatomIndexComponent::Value(Value::Cid(bob.clone())),
                    DatomIndexComponent::Attribute(":person/friend".into()),
                ],
            )
            .unwrap();
        assert_eq!(vaet.len(), 1);
        assert_eq!(vaet[0].e, alice);

        let tx1_history = arr
            .scan_prefix(DatomIndex::Tea, &[DatomIndexComponent::Tx(tx1)])
            .unwrap();
        assert_eq!(tx1_history.len(), 2);
        assert!(tx1_history.iter().all(|datom| datom.op));

        let err = arr
            .scan_prefix(
                DatomIndex::Eavt,
                &[DatomIndexComponent::Attribute(":person/name".into())],
            )
            .expect_err("EAVT first component must be entity");
        assert!(err.contains("invalid kind"));
    }
}
