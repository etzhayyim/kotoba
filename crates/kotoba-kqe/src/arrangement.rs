use crate::quad::{Quad, QuadObject};
use crate::delta::{Delta, Multiplicity};
use kotoba_core::cid::KotobaCid;
use std::collections::{HashMap, BTreeMap};

/// Arrangement — 4 covering Datomic-equivalent indexes for KOTOBA (G, S, P, O).
///
/// | Datomic | Name | Key order               | Primary use                       |
/// |---------|------|-------------------------|-----------------------------------|
/// | EAVT    | SPO  | S → P → [O]             | Entity lookup (all attrs of S)    |
/// | AEVT    | PSO  | P → S → [O]             | Attribute scan (all S with attr P)|
/// | AVET    | POS  | P → object_key → [S]    | Value lookup (find S by P + O)    |
/// | VAET    | OCP  | O_cid → P → [S]         | Reverse ref (who points to O_cid?)|
///
/// VAET (OCP) only indexes `QuadObject::Cid` values — mirroring Datomic's ref-only VAET.
#[derive(Debug, Default, Clone)]
pub struct Arrangement {
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
    pub fn new() -> Self { Self::default() }

    /// Apply Delta batch (Pregel Phase 2 Reducer).
    pub fn apply(&mut self, deltas: &[Delta]) {
        for delta in deltas {
            match delta.mult {
                Multiplicity::Assert  => self.insert(&delta.quad),
                Multiplicity::Retract => self.remove(&delta.quad),
            }
        }
    }

    pub fn insert(&mut self, quad: &Quad) {
        // EAVT (SPO): S → P → [O]
        self.spo
            .entry(quad.subject.clone())
            .or_default()
            .entry(quad.predicate.clone())
            .or_default()
            .push(quad.object.clone());

        // AEVT (PSO): P → S → [O]
        self.pso
            .entry(quad.predicate.clone())
            .or_default()
            .entry(quad.subject.clone())
            .or_default()
            .push(quad.object.clone());

        // AVET (POS): P → object_key → [S]
        let okey = object_key(&quad.object);
        self.pos
            .entry(quad.predicate.clone())
            .or_default()
            .entry(okey)
            .or_default()
            .push(quad.subject.clone());

        // VAET (OCP): O_cid → P → [S]  — ref-type only
        if let QuadObject::Cid(ref cid) = quad.object {
            self.ocp
                .entry(cid.clone())
                .or_default()
                .entry(quad.predicate.clone())
                .or_default()
                .push(quad.subject.clone());
        }

        self.count += 1;
    }

    pub fn remove(&mut self, quad: &Quad) {
        let okey = object_key(&quad.object);

        // EAVT (SPO)
        if let Some(pmap) = self.spo.get_mut(&quad.subject) {
            if let Some(objs) = pmap.get_mut(&quad.predicate) {
                let before = objs.len();
                objs.retain(|o| o != &quad.object);
                self.count = self.count.saturating_sub(before - objs.len());
            }
        }

        // AEVT (PSO)
        if let Some(smap) = self.pso.get_mut(&quad.predicate) {
            if let Some(objs) = smap.get_mut(&quad.subject) {
                objs.retain(|o| o != &quad.object);
            }
        }

        // AVET (POS)
        if let Some(omap) = self.pos.get_mut(&quad.predicate) {
            if let Some(subs) = omap.get_mut(&okey) {
                subs.retain(|s| s != &quad.subject);
            }
        }

        // VAET (OCP) — ref-type only
        if let QuadObject::Cid(ref cid) = quad.object {
            if let Some(pmap) = self.ocp.get_mut(cid) {
                if let Some(subs) = pmap.get_mut(&quad.predicate) {
                    subs.retain(|s| s != &quad.subject);
                }
            }
        }
    }

    // ── EAVT (SPO) queries ────────────────────────────────────────────────────

    /// All objects for (subject, predicate) — EAVT index.
    pub fn get_objects(&self, subject: &KotobaCid, predicate: &str) -> Vec<&QuadObject> {
        self.spo
            .get(subject)
            .and_then(|p| p.get(predicate))
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// All quads for a specific subject (SPO row scan) — EAVT index.
    pub fn get_subject_quads(&self, graph: &KotobaCid, subject: &KotobaCid) -> Vec<Quad> {
        let mut out = vec![];
        if let Some(pmap) = self.spo.get(subject) {
            for (predicate, objects) in pmap {
                for object in objects {
                    out.push(Quad {
                        graph:     graph.clone(),
                        subject:   subject.clone(),
                        predicate: predicate.clone(),
                        object:    object.clone(),
                    });
                }
            }
        }
        out
    }

    // ── AEVT (PSO) queries ────────────────────────────────────────────────────

    /// All subjects that have `predicate` — AEVT index (attribute scan).
    pub fn get_subjects_by_predicate(&self, predicate: &str) -> Vec<KotobaCid> {
        self.pso
            .get(predicate)
            .map(|smap| smap.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// All (subject, [object]) pairs for `predicate` — AEVT index.
    pub fn get_by_predicate(&self, predicate: &str) -> Vec<(KotobaCid, Vec<QuadObject>)> {
        self.pso
            .get(predicate)
            .map(|smap| smap.iter().map(|(s, o)| (s.clone(), o.clone())).collect())
            .unwrap_or_default()
    }

    // ── AVET (POS) queries ────────────────────────────────────────────────────

    /// Subjects that have (predicate, object_key) — AVET index.
    /// `object_key` matches Text values directly and CID multibase strings.
    pub fn get_subjects_by_predicate_object(
        &self,
        predicate: &str,
        object_key: &str,
    ) -> Vec<KotobaCid> {
        self.pos
            .get(predicate)
            .and_then(|omap| omap.get(object_key))
            .cloned()
            .unwrap_or_default()
    }

    /// Quads whose predicate starts with `prefix` — AVET index (BTree range scan on POS).
    pub fn quads_with_predicate_prefix(&self, graph: &KotobaCid, prefix: &str) -> Vec<Quad> {
        let mut out = vec![];
        for (predicate, omap) in self.pos.range(prefix.to_string()..) {
            if !predicate.starts_with(prefix) { break; }
            for subjects in omap.values() {
                for subject in subjects {
                    if let Some(pmap) = self.spo.get(subject) {
                        if let Some(objects) = pmap.get(predicate) {
                            for object in objects {
                                out.push(Quad {
                                    graph:     graph.clone(),
                                    subject:   subject.clone(),
                                    predicate: predicate.clone(),
                                    object:    object.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Count quads whose predicate starts with `prefix` — AVET index.
    pub fn count_by_predicate_prefix(&self, prefix: &str) -> usize {
        let mut n = 0usize;
        for (predicate, omap) in self.pos.range(prefix.to_string()..) {
            if !predicate.starts_with(prefix) { break; }
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

    pub fn len(&self) -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }

    /// Drop all index data and reset to empty. Used after a batch commit to reclaim RAM.
    pub fn clear(&mut self) {
        self.spo.clear();
        self.pso.clear();
        self.pos.clear();
        self.ocp.clear();
        self.count = 0;
    }

    /// Snapshot all quads as Assert Deltas (seed for Datalog evaluation).
    pub fn to_deltas(&self, graph: &KotobaCid) -> Vec<Delta> {
        self.quads(graph).into_iter().map(Delta::assert).collect()
    }

    /// Reconstruct all Quads from the SPO index, attaching the given graph CID.
    pub fn quads(&self, graph: &KotobaCid) -> Vec<Quad> {
        let mut out = Vec::with_capacity(self.count);
        for (subject, pmap) in &self.spo {
            for (predicate, objects) in pmap {
                for object in objects {
                    out.push(Quad {
                        graph:     graph.clone(),
                        subject:   subject.clone(),
                        predicate: predicate.clone(),
                        object:    object.clone(),
                    });
                }
            }
        }
        out
    }

    /// All (predicate, subject) pairs sorted by predicate — AEVT scan.
    /// Returns an iterator-friendly vec for building AEVT ProllyTree entries.
    pub fn aevt_entries(&self) -> Vec<(String, KotobaCid, Vec<QuadObject>)> {
        let mut out = vec![];
        for (pred, smap) in &self.pso {
            for (subj, objs) in smap {
                out.push((pred.clone(), subj.clone(), objs.clone()));
            }
        }
        out
    }

    /// All (predicate, object_key, subjects) sorted by predicate — AVET scan.
    pub fn avet_entries(&self) -> Vec<(String, String, Vec<KotobaCid>)> {
        let mut out = vec![];
        for (pred, omap) in &self.pos {
            for (okey, subs) in omap {
                out.push((pred.clone(), okey.clone(), subs.clone()));
            }
        }
        out
    }

    /// All (object_cid, predicate, subjects) — VAET scan.
    pub fn vaet_entries(&self) -> Vec<(KotobaCid, String, Vec<KotobaCid>)> {
        let mut out = vec![];
        for (ocid, pmap) in &self.ocp {
            for (pred, subs) in pmap {
                out.push((ocid.clone(), pred.clone(), subs.clone()));
            }
        }
        out
    }
}

fn object_key(obj: &QuadObject) -> String {
    match obj {
        QuadObject::Cid(c)              => c.to_multibase(),
        QuadObject::Text(s)             => s.clone(),
        QuadObject::Integer(n)          => n.to_string(),
        // Encrypted objects are not indexed by value in AVET; ct_cid used for identity only.
        QuadObject::Encrypted { ct_cid, .. } => format!("enc:{}", ct_cid.to_multibase()),
        _                               => "?".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

    fn quad(s: &str, p: &str, o: &str) -> Quad {
        Quad {
            graph:     cid("g"),
            subject:   cid(s),
            predicate: p.to_string(),
            object:    QuadObject::Text(o.to_string()),
        }
    }

    fn ref_quad(s: &str, p: &str, o: &str) -> Quad {
        Quad {
            graph:     cid("g"),
            subject:   cid(s),
            predicate: p.to_string(),
            object:    QuadObject::Cid(cid(o)),
        }
    }

    #[test]
    fn all_four_indexes_insert() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "name", "Alice"));
        arr.insert(&ref_quad("alice", "knows", "bob"));

        // EAVT (SPO)
        assert_eq!(arr.get_objects(&cid("alice"), "name").len(), 1);

        // AEVT (PSO): who has "name"?
        let subs = arr.get_subjects_by_predicate("name");
        assert!(subs.contains(&cid("alice")));

        // AVET (POS): who has name="Alice"?
        let subs = arr.get_subjects_by_predicate_object("name", "Alice");
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
        assert!(arr.get_subjects_by_predicate("knows").iter()
            .all(|s| arr.get_objects(s, "knows").is_empty()));
    }

    #[test]
    fn predicate_prefix_scan_uses_avet() {
        let mut arr = Arrangement::new();
        arr.insert(&quad("alice", "weight/embed", "e1"));
        arr.insert(&quad("alice", "weight/lm_head", "e2"));
        arr.insert(&quad("alice", "other/attr", "e3"));

        let g = cid("g");
        let quads = arr.quads_with_predicate_prefix(&g, "weight/");
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
}
