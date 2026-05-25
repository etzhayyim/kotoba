use crate::quad::{Quad, QuadObject};
use crate::delta::{Delta, Multiplicity};
use kotoba_core::cid::KotobaCid;
use std::collections::{HashMap, BTreeMap};

/// Arrangement — indexed Quad collection = Pregel vertex state (≅ Datom DB at T)
/// Primary index: SPO (subject → predicate → object)
#[derive(Debug, Default, Clone)]
pub struct Arrangement {
    /// SPO index: subject_cid → predicate → [object]
    spo: HashMap<KotobaCid, BTreeMap<String, Vec<QuadObject>>>,
    /// POS index: predicate → object_key → [subject_cid]
    pos: BTreeMap<String, BTreeMap<String, Vec<KotobaCid>>>,
    count: usize,
}

impl Arrangement {
    pub fn new() -> Self { Self::default() }

    /// Apply Delta batch (Pregel Phase 2 Reducer)
    pub fn apply(&mut self, deltas: &[Delta]) {
        for delta in deltas {
            match delta.mult {
                Multiplicity::Assert  => self.insert(&delta.quad),
                Multiplicity::Retract => self.remove(&delta.quad),
            }
        }
    }

    pub fn insert(&mut self, quad: &Quad) {
        self.spo
            .entry(quad.subject.clone())
            .or_default()
            .entry(quad.predicate.clone())
            .or_default()
            .push(quad.object.clone());

        let obj_key = object_key(&quad.object);
        self.pos
            .entry(quad.predicate.clone())
            .or_default()
            .entry(obj_key)
            .or_default()
            .push(quad.subject.clone());

        self.count += 1;
    }

    pub fn remove(&mut self, quad: &Quad) {
        // SPO cleanup
        if let Some(pmap) = self.spo.get_mut(&quad.subject) {
            if let Some(objs) = pmap.get_mut(&quad.predicate) {
                let before = objs.len();
                objs.retain(|o| o != &quad.object);
                self.count = self.count.saturating_sub(before - objs.len());
            }
        }
        // POS cleanup (was previously left stale)
        let obj_key = object_key(&quad.object);
        if let Some(omap) = self.pos.get_mut(&quad.predicate) {
            if let Some(subs) = omap.get_mut(&obj_key) {
                subs.retain(|s| s != &quad.subject);
            }
        }
    }

    /// SPO lookup: all objects for (subject, predicate)
    pub fn get_objects(&self, subject: &KotobaCid, predicate: &str) -> Vec<&QuadObject> {
        self.spo
            .get(subject)
            .and_then(|p| p.get(predicate))
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize { self.count }
    pub fn is_empty(&self) -> bool { self.count == 0 }

    /// All quads for a specific subject (SPO row scan).
    pub fn get_subject_quads(&self, graph: &KotobaCid, subject: &KotobaCid) -> Vec<crate::quad::Quad> {
        let mut out = vec![];
        if let Some(pmap) = self.spo.get(subject) {
            for (predicate, objects) in pmap {
                for object in objects {
                    out.push(crate::quad::Quad {
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

    /// POS lookup: subjects that have (predicate, object_key).
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

    /// Quads whose predicate starts with `prefix` (BTreeMap range scan on POS).
    /// Uses SPO index to recover the full object value for each matching subject.
    pub fn quads_with_predicate_prefix(&self, graph: &KotobaCid, prefix: &str) -> Vec<crate::quad::Quad> {
        let mut out = vec![];
        for (predicate, omap) in self.pos.range(prefix.to_string()..) {
            if !predicate.starts_with(prefix) { break; }
            for subjects in omap.values() {
                for subject in subjects {
                    if let Some(pmap) = self.spo.get(subject) {
                        if let Some(objects) = pmap.get(predicate) {
                            for object in objects {
                                out.push(crate::quad::Quad {
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

    /// Count quads whose predicate starts with `prefix`.
    pub fn count_by_predicate_prefix(&self, prefix: &str) -> usize {
        let mut n = 0usize;
        for (predicate, omap) in self.pos.range(prefix.to_string()..) {
            if !predicate.starts_with(prefix) { break; }
            n += omap.values().map(|v| v.len()).sum::<usize>();
        }
        n
    }

    /// Snapshot all quads as Assert Deltas (seed for Datalog evaluation).
    pub fn to_deltas(&self, graph: &KotobaCid) -> Vec<Delta> {
        self.quads(graph).into_iter().map(Delta::assert).collect()
    }

    /// Reconstruct all Quads from the SPO index, attaching the given graph CID.
    pub fn quads(&self, graph: &KotobaCid) -> Vec<crate::quad::Quad> {
        let mut out = Vec::with_capacity(self.count);
        for (subject, pmap) in &self.spo {
            for (predicate, objects) in pmap {
                for object in objects {
                    out.push(crate::quad::Quad {
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
}

fn object_key(obj: &QuadObject) -> String {
    match obj {
        QuadObject::Cid(c) => c.to_multibase(),
        QuadObject::Text(s) => s.clone(),
        QuadObject::Integer(n) => n.to_string(),
        _ => "?".to_string(),
    }
}
