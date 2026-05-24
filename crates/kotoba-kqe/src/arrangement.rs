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
        if let Some(pmap) = self.spo.get_mut(&quad.subject) {
            if let Some(objs) = pmap.get_mut(&quad.predicate) {
                objs.retain(|o| o != &quad.object);
                self.count = self.count.saturating_sub(1);
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
}

fn object_key(obj: &QuadObject) -> String {
    match obj {
        QuadObject::Cid(c) => c.to_multibase(),
        QuadObject::Text(s) => s.clone(),
        QuadObject::Integer(n) => n.to_string(),
        _ => "?".to_string(),
    }
}
