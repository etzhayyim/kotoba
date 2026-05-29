use crate::datom::{Datom, DatomArrangement, DatomIndex, DatomIndexComponent, Value};
use crate::delta::Delta;
use crate::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};
use kotoba_core::cid::KotobaCid;
use std::collections::{BTreeMap, HashMap};

/// Arrangement — hot current-state Datom indexes for KOTOBA.
///
/// | Datomic | Key order            | Primary use                         |
/// |---------|----------------------|-------------------------------------|
/// | EAVT    | E → A → [V]          | Entity lookup (all attrs of E)      |
/// | AEVT    | A → E → [V]          | Attribute scan (all E with attr A)  |
/// | AVET    | A → value_key → [E]  | Value lookup (find E by A + V)      |
/// | VAET    | V_cid → A → [E]      | Reverse ref (who points to V_cid?)  |
///
/// VAET only indexes `Value::Cid` values — mirroring Datomic's ref-only VAET.
#[derive(Debug, Default, Clone)]
pub struct Arrangement {
    datom_index: DatomArrangement,
    /// EAVT ≅ SPO: subject → predicate → [object]
    spo: HashMap<KotobaCid, BTreeMap<String, Vec<QuadObject>>>,
    /// AEVT ≅ PSO: predicate → subject → [object]  (BTreeMap for attribute range scan)
    pso: BTreeMap<String, HashMap<KotobaCid, Vec<QuadObject>>>,
    /// AVET ≅ POS: predicate → object_key → [subject]
    pos: BTreeMap<String, BTreeMap<String, Vec<KotobaCid>>>,
    /// VAET ≅ OCP: object_cid → predicate → [subject]  (ref-type only)
    ocp: HashMap<KotobaCid, BTreeMap<String, Vec<KotobaCid>>>,
    count: usize,
}

impl Arrangement {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply Delta batch (Pregel Phase 2 Reducer).
    pub fn apply(&mut self, deltas: &[Delta]) {
        for delta in deltas {
            match delta.datom.op {
                true => self.insert_datom(&delta.datom),
                false => self.remove_datom(&delta.datom),
            }
        }
    }

    pub fn insert(&mut self, quad: &Quad) {
        self.insert_datom(&Datom::from_legacy_quad(quad.clone(), true));
    }

    pub fn insert_datom(&mut self, datom: &Datom) {
        if !datom.op {
            self.remove_datom(datom);
            return;
        }
        self.datom_index.insert(datom.clone());
        self.insert_value(&datom.e, &datom.a, &datom.v);
    }

    fn insert_value(&mut self, entity: &KotobaCid, attr: &str, value: &Value) {
        let legacy_object: QuadObject = value.clone().into();

        self.spo
            .entry(entity.clone())
            .or_default()
            .entry(attr.to_string())
            .or_default()
            .push(legacy_object.clone());

        self.pso
            .entry(attr.to_string())
            .or_default()
            .entry(entity.clone())
            .or_default()
            .push(legacy_object.clone());

        self.pos
            .entry(attr.to_string())
            .or_default()
            .entry(value_key(value))
            .or_default()
            .push(entity.clone());

        if let Value::Cid(cid) = value {
            self.ocp
                .entry(cid.clone())
                .or_default()
                .entry(attr.to_string())
                .or_default()
                .push(entity.clone());
        }

        self.count += 1;
    }

    pub fn remove(&mut self, quad: &Quad) {
        self.remove_datom(&Datom::from_legacy_quad(quad.clone(), false));
    }

    pub fn remove_datom(&mut self, datom: &Datom) {
        let mut retraction = datom.clone();
        retraction.op = false;
        self.datom_index.insert(retraction);
        self.remove_value(&datom.e, &datom.a, &datom.v);
    }

    fn remove_value(&mut self, entity: &KotobaCid, attr: &str, value: &Value) {
        let legacy_object: QuadObject = value.clone().into();
        let okey = value_key(value);

        if let Some(pmap) = self.spo.get_mut(entity) {
            if let Some(objs) = pmap.get_mut(attr) {
                let before = objs.len();
                objs.retain(|o| o != &legacy_object);
                self.count = self.count.saturating_sub(before - objs.len());
            }
        }

        if let Some(smap) = self.pso.get_mut(attr) {
            if let Some(objs) = smap.get_mut(entity) {
                objs.retain(|o| o != &legacy_object);
            }
        }

        if let Some(omap) = self.pos.get_mut(attr) {
            if let Some(subs) = omap.get_mut(&okey) {
                subs.retain(|s| s != entity);
            }
        }

        if let Value::Cid(cid) = value {
            if let Some(pmap) = self.ocp.get_mut(cid) {
                if let Some(subs) = pmap.get_mut(attr) {
                    subs.retain(|s| s != entity);
                }
            }
        }
    }

    // ── EAVT queries ─────────────────────────────────────────────────────────

    /// All Datomic values for (entity, attribute) — EAVT index.
    pub fn get_values(&self, entity: &KotobaCid, attr: &str) -> Vec<Value> {
        self.spo
            .get(entity)
            .and_then(|p| p.get(attr))
            .map(|values| values.iter().cloned().map(Value::from).collect())
            .unwrap_or_default()
    }

    pub fn get_subject_datoms(&self, tx: &KotobaCid, subject: &KotobaCid) -> Vec<Datom> {
        let mut out = vec![];
        if let Some(pmap) = self.spo.get(subject) {
            for (attr, objects) in pmap {
                for object in objects {
                    out.push(Datom::assert(
                        subject.clone(),
                        attr.clone(),
                        Value::from(object.clone()),
                        tx.clone(),
                    ));
                }
            }
        }
        out
    }

    // ── AEVT queries ─────────────────────────────────────────────────────────

    /// All entities that have `attr` — AEVT index (attribute scan).
    pub fn get_entities_by_attribute(&self, attr: &str) -> Vec<KotobaCid> {
        self.pso
            .get(attr)
            .map(|smap| smap.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// All (entity, [value]) pairs for `attr` — AEVT index.
    pub fn get_by_attribute(&self, attr: &str) -> Vec<(KotobaCid, Vec<Value>)> {
        self.pso
            .get(attr)
            .map(|emap| {
                emap.iter()
                    .map(|(entity, values)| {
                        (
                            entity.clone(),
                            values.iter().cloned().map(Value::from).collect(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // ── AVET queries ─────────────────────────────────────────────────────────

    /// Entities that have (attr, value_key) — AVET index.
    /// `object_key` matches Text values directly and CID multibase strings.
    pub fn get_entities_by_attribute_value(&self, attr: &str, object_key: &str) -> Vec<KotobaCid> {
        self.pos
            .get(attr)
            .and_then(|omap| omap.get(object_key))
            .cloned()
            .unwrap_or_default()
    }

    /// Datoms whose attribute starts with `prefix` — AVET index.
    pub fn datoms_with_attribute_prefix(&self, tx: &KotobaCid, prefix: &str) -> Vec<Datom> {
        let mut out = vec![];
        for (attr, omap) in self.pos.range(prefix.to_string()..) {
            if !attr.starts_with(prefix) {
                break;
            }
            for subjects in omap.values() {
                for entity in subjects {
                    if let Some(pmap) = self.spo.get(entity) {
                        if let Some(values) = pmap.get(attr) {
                            for value in values {
                                out.push(Datom::assert(
                                    entity.clone(),
                                    attr.clone(),
                                    Value::from(value.clone()),
                                    tx.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Count datoms whose attribute starts with `prefix` — AVET index.
    pub fn count_by_attribute_prefix(&self, prefix: &str) -> usize {
        let mut n = 0usize;
        for (predicate, omap) in self.pos.range(prefix.to_string()..) {
            if !predicate.starts_with(prefix) {
                break;
            }
            n += omap.values().map(|v| v.len()).sum::<usize>();
        }
        n
    }

    // ── VAET (OCP) queries ────────────────────────────────────────────────────

    /// All subjects that reference `object_cid` via any predicate — VAET index.
    pub fn get_referencing_subjects(&self, object_cid: &KotobaCid) -> Vec<KotobaCid> {
        self.ocp
            .get(object_cid)
            .map(|pmap| pmap.values().flatten().cloned().collect())
            .unwrap_or_default()
    }

    /// All subjects that reference `object_cid` via `predicate` — VAET index.
    pub fn get_referencing_subjects_by_predicate(
        &self,
        object_cid: &KotobaCid,
        predicate: &str,
    ) -> Vec<KotobaCid> {
        self.ocp
            .get(object_cid)
            .and_then(|pmap| pmap.get(predicate))
            .cloned()
            .unwrap_or_default()
    }

    // ── Bulk / snapshot ───────────────────────────────────────────────────────

    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Drop all index data and reset to empty. Used after a batch commit to reclaim RAM.
    pub fn clear(&mut self) {
        self.datom_index.clear();
        self.spo.clear();
        self.pso.clear();
        self.pos.clear();
        self.ocp.clear();
        self.count = 0;
    }

    /// Snapshot all quads as Assert Deltas (seed for Datalog evaluation).
    pub fn to_deltas(&self, graph: &KotobaCid) -> Vec<Delta> {
        self.datoms(graph)
            .into_iter()
            .map(Delta::assert_datom)
            .collect()
    }

    pub fn to_datom_deltas(&self, tx: &KotobaCid) -> Vec<Delta> {
        self.datoms(tx).into_iter().map(Delta::from_datom).collect()
    }

    pub fn datom_history(&self) -> Vec<Datom> {
        self.datom_index.history()
    }

    pub fn current_datoms(&self) -> Vec<Datom> {
        self.datom_index.current()
    }

    pub fn scan_datom_prefix(
        &self,
        index: DatomIndex,
        components: &[DatomIndexComponent],
    ) -> Result<Vec<Datom>, String> {
        self.datom_index.scan_prefix(index, components)
    }

    /// Reconstruct all Quads from the SPO index, attaching the given graph CID.
    pub fn quads(&self, graph: &KotobaCid) -> Vec<Quad> {
        let mut out = Vec::with_capacity(self.count);
        for (subject, pmap) in &self.spo {
            for (predicate, objects) in pmap {
                for object in objects {
                    out.push(Quad {
                        graph: graph.clone(),
                        subject: subject.clone(),
                        predicate: predicate.clone(),
                        object: object.clone(),
                    });
                }
            }
        }
        out
    }

    pub fn datoms(&self, tx: &KotobaCid) -> Vec<Datom> {
        let mut out = Vec::with_capacity(self.count);
        for (entity, pmap) in &self.spo {
            for (attr, objects) in pmap {
                for object in objects {
                    out.push(Datom::assert(
                        entity.clone(),
                        attr.clone(),
                        Value::from(object.clone()),
                        tx.clone(),
                    ));
                }
            }
        }
        out
    }

    /// All (predicate, subject) pairs sorted by predicate — AEVT scan.
    /// Returns an iterator-friendly vec for building AEVT ProllyTree entries.
    pub fn aevt_value_entries(&self) -> Vec<(String, KotobaCid, Vec<QuadObject>)> {
        let mut out = vec![];
        for (pred, smap) in &self.pso {
            for (subj, objs) in smap {
                out.push((pred.clone(), subj.clone(), objs.clone()));
            }
        }
        out
    }

    /// All (predicate, object_key, subjects) sorted by predicate — AVET scan.
    pub fn avet_entity_entries(&self) -> Vec<(String, String, Vec<KotobaCid>)> {
        let mut out = vec![];
        for (pred, omap) in &self.pos {
            for (okey, subs) in omap {
                out.push((pred.clone(), okey.clone(), subs.clone()));
            }
        }
        out
    }

    /// All (object_cid, predicate, subjects) — VAET scan.
    pub fn vaet_entity_entries(&self) -> Vec<(KotobaCid, String, Vec<KotobaCid>)> {
        let mut out = vec![];
        for (ocid, pmap) in &self.ocp {
            for (pred, subs) in pmap {
                out.push((ocid.clone(), pred.clone(), subs.clone()));
            }
        }
        out
    }
}

fn value_key(value: &Value) -> String {
    match value {
        Value::Cid(c) => c.to_multibase(),
        Value::Text(s) => s.clone(),
        Value::Integer(n) => n.to_string(),
        Value::Encrypted { ct_cid, .. } => format!("enc:{}", ct_cid.to_multibase()),
        _ => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    fn cid(s: &str) -> KotobaCid {
        KotobaCid::from_bytes(s.as_bytes())
    }

    fn quad(s: &str, p: &str, o: &str) -> Quad {
        Quad {
            graph: cid("g"),
            subject: cid(s),
            predicate: p.to_string(),
            object: QuadObject::Text(o.to_string()),
        }
    }

    fn ref_quad(s: &str, p: &str, o: &str) -> Quad {
        Quad {
            graph: cid("g"),
            subject: cid(s),
            predicate: p.to_string(),
            object: QuadObject::Cid(cid(o)),
        }
    }

    #[test]
    fn all_four_indexes_insert() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&ref_quad("alice", "knows", "bob"));

        // EAVT (SPO)
        assert_eq!(arr.get_values(&cid("alice"), "name").len(), 1);

        // AEVT (PSO): who has "name"?
        let subs = arr.get_entities_by_attribute("name");
        assert!(subs.contains(&cid("alice")));

        // AVET (POS): who has name="Alice"?
        let subs = arr.get_entities_by_attribute_value("name", "Alice");
        assert!(subs.contains(&cid("alice")));

        // VAET (OCP): who references bob?
        let refs = arr.get_referencing_subjects(&cid("bob"));
        assert!(refs.contains(&cid("alice")));
    }

    #[test]
    fn vaet_only_indexes_cid_objects() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice")); // Text — should NOT enter OCP
        assert!(arr.ocp.is_empty(), "Text objects must not enter VAET");

        arr.insert(&ref_quad("alice", "knows", "bob")); // Cid — should enter OCP
        assert!(!arr.ocp.is_empty());
    }

    #[test]
    fn remove_cleans_all_four_indexes() {
        let mut arr = Arrangement::new();
        let q = ref_quad("alice", "knows", "bob");
        arr.insert(&q);
        assert_eq!(arr.len(), 1);

        arr.remove(&q);
        assert_eq!(arr.len(), 0);
        assert!(arr.get_referencing_subjects(&cid("bob")).is_empty());
        assert!(arr
            .get_entities_by_attribute("knows")
            .iter()
            .all(|s| arr.get_values(s, "knows").is_empty()));
    }

    #[test]
    fn predicate_prefix_scan_uses_avet() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "weight/embed", "e1"));
        arr.insert(&quad("alice", "weight/lm_head", "e2"));
        arr.insert(&quad("alice", "other/attr", "e3"));

        let g = cid("g");
        let quads = arr.datoms_with_attribute_prefix(&g, "weight/");
        assert_eq!(quads.len(), 2);
    }

    #[test]
    fn get_referencing_subjects_by_predicate() {
        let mut arr = Arrangement::new();
        arr.insert(&ref_quad("alice", "knows", "bob"));
        arr.insert(&ref_quad("carol", "knows", "bob"));
        arr.insert(&ref_quad("dave", "follows", "bob"));

        let knows_bob = arr.get_referencing_subjects_by_predicate(&cid("bob"), "knows");
        assert_eq!(knows_bob.len(), 2);
        assert!(knows_bob.contains(&cid("alice")));
        assert!(knows_bob.contains(&cid("carol")));

        let follows_bob = arr.get_referencing_subjects_by_predicate(&cid("bob"), "follows");
        assert_eq!(follows_bob.len(), 1);
    }

    #[test]
    fn apply_mixed_assert_retract_batch() {
        let mut arr = Arrangement::new();
        let q1 = quad("alice", "name", "Alice");
        let q2 = quad("bob", "name", "Bob");
        let deltas = vec![
            Delta::assert_datom(Datom::from_legacy_quad(q1.clone(), true)),
            Delta::assert_datom(Datom::from_legacy_quad(q2.clone(), true)),
            Delta::retract_datom(Datom::from_legacy_quad(q1.clone(), false)),
        ];
        arr.apply(&deltas);
        assert_eq!(arr.len(), 1);
        assert!(arr.get_values(&cid("alice"), "name").is_empty());
        assert_eq!(arr.get_values(&cid("bob"), "name").len(), 1);
    }

    #[test]
    fn datom_insert_remove_and_snapshot_match_current_indexes() {
        let mut arr = Arrangement::new();
        let tx = cid("tx");
        let datom = Datom::assert(
            cid("alice"),
            "knows".to_string(),
            Value::Cid(cid("bob")),
            tx.clone(),
        );

        arr.insert_datom(&datom);
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr.get_subject_datoms(&tx, &cid("alice")),
            vec![datom.clone()]
        );
        assert_eq!(arr.datoms(&tx), vec![datom.clone()]);
        assert_eq!(
            arr.datoms_with_attribute_prefix(&tx, "kno"),
            vec![datom.clone()]
        );
        assert_eq!(
            arr.get_values(&cid("alice"), "knows"),
            vec![Value::Cid(cid("bob"))]
        );
        assert_eq!(arr.to_datom_deltas(&tx)[0].datom, datom);
        assert_eq!(
            arr.get_referencing_subjects_by_predicate(&cid("bob"), "knows"),
            vec![cid("alice")]
        );

        arr.remove_datom(&Datom::retract(
            cid("alice"),
            "knows".to_string(),
            Value::Cid(cid("bob")),
            tx,
        ));
        assert!(arr.is_empty());
        assert!(arr.get_referencing_subjects(&cid("bob")).is_empty());
    }

    #[test]
    fn arrangement_keeps_datom_five_index_history_for_legacy_quad_boundaries() {
        let mut arr = Arrangement::new();
        let alice_name = quad("alice", "name", "Alice");
        let alice_friend = ref_quad("alice", "knows", "bob");

        arr.insert(&alice_name);
        arr.insert(&alice_friend);
        arr.remove(&alice_name);

        assert_eq!(arr.len(), 1);
        assert_eq!(arr.datom_history().len(), 3);
        assert_eq!(arr.current_datoms().len(), 1);

        let eavt = arr
            .scan_datom_prefix(
                DatomIndex::Eavt,
                &[DatomIndexComponent::Entity(cid("alice"))],
            )
            .unwrap();
        assert_eq!(eavt.len(), 3);

        let vaet = arr
            .scan_datom_prefix(
                DatomIndex::Vaet,
                &[
                    DatomIndexComponent::Value(Value::Cid(cid("bob"))),
                    DatomIndexComponent::Attribute("knows".to_string()),
                ],
            )
            .unwrap();
        assert_eq!(vaet.len(), 1);
        assert_eq!(vaet[0].e, cid("alice"));
    }

    #[test]
    fn clear_resets_count_and_all_indexes() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&ref_quad("alice", "knows", "bob"));
        assert_eq!(arr.len(), 2);
        assert!(!arr.is_empty());

        arr.clear();
        assert_eq!(arr.len(), 0);
        assert!(arr.is_empty());
        assert!(arr.get_values(&cid("alice"), "name").is_empty());
        assert!(arr.get_entities_by_attribute("name").is_empty());
        assert!(arr.get_referencing_subjects(&cid("bob")).is_empty());
    }

    #[test]
    fn to_deltas_and_quads_roundtrip() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&quad("bob", "name", "Bob"));

        let g = cid("g");
        let all_quads = arr.quads(&g);
        assert_eq!(all_quads.len(), 2);

        let deltas = arr.to_deltas(&g);
        assert_eq!(deltas.len(), 2);
        assert!(deltas.iter().all(|d| d.datom.op == true));
    }

    #[test]
    fn aevt_entries_returns_all_predicate_subject_pairs() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&quad("bob", "name", "Bob"));
        arr.insert(&quad("alice", "age", "30"));

        let entries = arr.aevt_value_entries();
        // 3 (pred, subj) pairs: (name, alice), (name, bob), (age, alice)
        assert_eq!(entries.len(), 3);

        let mut name_values = arr.get_by_attribute("name");
        name_values.sort_by_key(|(entity, _)| entity.to_multibase());
        assert_eq!(name_values.len(), 2);
        assert!(name_values
            .iter()
            .all(|(_, values)| matches!(values.first(), Some(Value::Text(_)))));
    }

    #[test]
    fn avet_entries_returns_all_predicate_objectkey_subject_triples() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&quad("bob", "name", "Bob"));

        let entries = arr.avet_entity_entries();
        assert_eq!(entries.len(), 2); // (name, Alice, [alice]), (name, Bob, [bob])
    }

    #[test]
    fn vaet_entries_only_for_cid_objects() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice")); // Text — no VAET
        arr.insert(&ref_quad("alice", "knows", "bob")); // Cid — VAET
        arr.insert(&ref_quad("carol", "knows", "bob")); // second ref to same cid

        let entries = arr.vaet_entity_entries();
        // (bob_cid, "knows", [alice, carol])
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, cid("bob"));
        assert_eq!(entries[0].1, "knows");
        assert_eq!(entries[0].2.len(), 2);
    }

    #[test]
    fn count_by_predicate_prefix_sums_correct_count() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "rel/friend", "Bob"));
        arr.insert(&quad("alice", "rel/colleague", "Carol"));
        arr.insert(&quad("alice", "meta/created", "2024"));

        assert_eq!(arr.count_by_attribute_prefix("rel/"), 2);
        assert_eq!(arr.count_by_attribute_prefix("meta/"), 1);
        assert_eq!(arr.count_by_attribute_prefix("nonexistent/"), 0);
    }

    #[test]
    fn remove_nonexistent_quad_does_not_panic_or_alter_count() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        assert_eq!(arr.len(), 1);

        // Remove a quad that was never inserted
        arr.remove(&quad("bob", "name", "Bob"));
        assert_eq!(arr.len(), 1); // count unchanged
    }

    #[test]
    fn get_subject_datoms_returns_all_attributes_for_entity() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&quad("alice", "age", "30"));
        arr.insert(&quad("bob", "name", "Bob"));

        let tx = cid("tx");
        let alice_datoms = arr.get_subject_datoms(&tx, &cid("alice"));
        assert_eq!(alice_datoms.len(), 2);
        assert!(alice_datoms.iter().all(|d| d.e == cid("alice")));

        let bob_datoms = arr.get_subject_datoms(&tx, &cid("bob"));
        assert_eq!(bob_datoms.len(), 1);
    }

    #[test]
    fn get_by_predicate_returns_all_subject_object_pairs() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "knows", "Bob"));
        arr.insert(&quad("carol", "knows", "Dave"));
        arr.insert(&quad("alice", "likes", "music"));

        let pairs = arr.get_by_attribute("knows");
        assert_eq!(pairs.len(), 2);

        let empty = arr.get_by_attribute("nonexistent");
        assert!(empty.is_empty());
    }

    #[test]
    fn new_arrangement_is_empty() {
        let arr = Arrangement::new();
        assert_eq!(arr.len(), 0);
        assert!(arr.is_empty());
        assert!(arr.quads(&cid("g")).is_empty());
        assert!(arr.aevt_value_entries().is_empty());
        assert!(arr.avet_entity_entries().is_empty());
        assert!(arr.vaet_entity_entries().is_empty());
    }
}
