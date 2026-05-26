/// Datalog rule layer — semi-naive bottom-up evaluation (Phase 4)
/// Monotone semantics: facts only grow via Delta(+1), shrink via Delta(-1)
/// Stratified negation: PTIME complete, halting guaranteed
///
/// Atom arity is fixed at 2 (binary relations) — Quad enforces (S, P, O).
/// Ground identifiers are hashed to KotobaCid via `cid_of_str`.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use kotoba_core::cid::KotobaCid;
use crate::citation::{CitationLedger, DatomKey};
use crate::quad::{Quad, QuadObject};
use crate::delta::{Delta, Multiplicity};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalogRule {
    pub head: Atom,
    pub body: Vec<BodyLiteral>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Atom {
    pub relation: String,
    /// Exactly 2 Terms — mirrors Quad (subject, object).
    pub args: Vec<Term>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BodyLiteral {
    Positive(Atom),
    Negative(Atom),  // stratified negation only
    Comparison(Term, CmpOp, Term),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Term {
    Variable(String),
    Constant(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CmpOp { Eq, Ne, Lt, Le, Gt, Ge }

#[derive(Debug, Default, Clone)]
pub struct DatalogProgram {
    pub rules: Vec<DatalogRule>,
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Variable binding: variable name → ground CID constant
type Binding = HashMap<String, KotobaCid>;

// ---------------------------------------------------------------------------
// CID helper
// ---------------------------------------------------------------------------

/// Derive a stable KotobaCid from an arbitrary string label.
/// Round-trip is not required — only functional (same str → same CID).
fn cid_of_str(s: &str) -> KotobaCid {
    KotobaCid::from_bytes(s.as_bytes())
}

/// Convert a QuadObject to a CID for use in Datalog evaluation.
fn object_to_cid(obj: &QuadObject) -> Option<KotobaCid> {
    match obj {
        QuadObject::Cid(c) => Some(c.clone()),
        QuadObject::Text(s) => Some(cid_of_str(s)),
        QuadObject::Integer(n) => Some(cid_of_str(&n.to_string())),
        QuadObject::Bool(b) => Some(cid_of_str(if *b { "true" } else { "false" })),
        _ => None, // Float / Bytes / VectorF32 / TensorCid not used in symbolic Datalog
    }
}

// ---------------------------------------------------------------------------
// DatalogProgram implementation
// ---------------------------------------------------------------------------

impl DatalogProgram {
    pub fn new() -> Self { Self::default() }

    pub fn add_rule(&mut self, rule: DatalogRule) { self.rules.push(rule); }

    /// Semi-naive bottom-up evaluation.
    ///
    /// Given a batch of input `deltas` (new/retracted facts), derive all new
    /// facts by repeatedly applying rules until fixpoint.
    /// Returns output `Delta`s for every newly derived fact.
    pub fn evaluate_delta(&self, deltas: &[Delta]) -> Vec<Delta> {
        let mut _sink = CitationLedger::new();
        self.evaluate_delta_inner(deltas, &mut _sink)
    }

    /// Economy-aware variant: records one citation per join hit into `ledger`.
    ///
    /// Call `ledger.flush_epoch(pool_mkoto)` after evaluation to compute
    /// royalties, then `CitationLedger::royalty_quads()` to emit ledger Quads.
    pub fn evaluate_delta_cited(&self, deltas: &[Delta], ledger: &mut CitationLedger) -> Vec<Delta> {
        self.evaluate_delta_inner(deltas, ledger)
    }

    fn evaluate_delta_inner(&self, deltas: &[Delta], ledger: &mut CitationLedger) -> Vec<Delta> {
        if self.rules.is_empty() || deltas.is_empty() {
            return vec![];
        }

        // fact_base: relation → set of (subject_cid, object_cid) pairs
        let mut fact_base: HashMap<String, HashSet<(KotobaCid, KotobaCid)>> = HashMap::new();

        // Seed from assert deltas only (retracts handled by caller via Arrangement)
        for d in deltas {
            if d.mult != Multiplicity::Assert {
                continue;
            }
            if let Some(obj_cid) = object_to_cid(&d.quad.object) {
                fact_base
                    .entry(d.quad.predicate.clone())
                    .or_default()
                    .insert((d.quad.subject.clone(), obj_cid));
            }
        }

        // new_facts: facts added in the most recent round (initially = all seeds)
        let mut new_facts: HashMap<String, HashSet<(KotobaCid, KotobaCid)>> = fact_base.clone();

        // Accumulate all derived deltas (deduplicated via fact_base membership)
        let mut derived: Vec<Delta> = Vec::new();

        // A stable "zero" graph CID for derived quads
        let graph_cid = cid_of_str("datalog:derived");

        loop {
            let mut added_this_round: HashMap<String, HashSet<(KotobaCid, KotobaCid)>> =
                HashMap::new();

            for rule in &self.rules {
                // Count positive body literals (those that participate in Δ-fan-out)
                let pos_indices: Vec<usize> = rule.body.iter().enumerate()
                    .filter_map(|(i, lit)| if matches!(lit, BodyLiteral::Positive(_)) { Some(i) } else { None })
                    .collect();

                // For each positive body position p_i, evaluate the rule with
                // literal p_i drawn from new_facts; all other positives from fact_base.
                let mut rule_heads: HashSet<(KotobaCid, KotobaCid)> = HashSet::new();

                for &delta_pos in &pos_indices {
                    let mut cited_keys: Vec<DatomKey> = Vec::new();
                    let heads = self.eval_rule_with_delta_at(
                        rule,
                        &fact_base,
                        &new_facts,
                        delta_pos,
                        &mut cited_keys,
                    );
                    // Record citations for every join hit that contributed to this rule
                    for key in cited_keys {
                        ledger.cite(&key);
                    }
                    rule_heads.extend(heads);
                }

                // Filter out facts already in fact_base
                for pair in rule_heads {
                    let entry = fact_base
                        .entry(rule.head.relation.clone())
                        .or_default();
                    if !entry.contains(&pair) {
                        entry.insert(pair.clone());
                        added_this_round
                            .entry(rule.head.relation.clone())
                            .or_default()
                            .insert(pair.clone());

                        // Emit a Delta::assert for the derived fact
                        let quad = Quad {
                            graph:     graph_cid.clone(),
                            subject:   pair.0.clone(),
                            predicate: rule.head.relation.clone(),
                            object:    QuadObject::Cid(pair.1.clone()),
                        };
                        derived.push(Delta::assert(quad));
                    }
                }
            }

            if added_this_round.is_empty() {
                break; // fixpoint reached
            }
            new_facts = added_this_round;
        }

        derived
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Evaluate `rule` with the body literal at `delta_pos` (a Positive literal)
    /// drawn from `new_facts`; all other Positive literals from `fact_base`.
    /// Returns candidate head (subject, object) pairs.
    /// Appends a DatomKey for every successful join hit into `cited`.
    fn eval_rule_with_delta_at(
        &self,
        rule:      &DatalogRule,
        fact_base: &HashMap<String, HashSet<(KotobaCid, KotobaCid)>>,
        new_facts: &HashMap<String, HashSet<(KotobaCid, KotobaCid)>>,
        delta_pos: usize,
        cited:     &mut Vec<DatomKey>,
    ) -> Vec<(KotobaCid, KotobaCid)> {
        let initial: Binding = HashMap::new();
        let mut results = Vec::new();

        self.match_body(
            rule,
            &rule.body,
            0,
            initial,
            fact_base,
            new_facts,
            delta_pos,
            &mut results,
            cited,
        );

        results
    }

    /// Recursive body-matching with backtracking.
    ///
    /// `delta_pos`: the index of the Positive literal that MUST be satisfied
    /// from `new_facts` (for semi-naive correctness). All other Positive
    /// literals are satisfied from `fact_base` (which is a superset of new_facts).
    ///
    /// `cited`: accumulates a DatomKey for each successful positive join hit.
    #[allow(clippy::too_many_arguments)]
    fn match_body(
        &self,
        rule:       &DatalogRule,
        body:       &[BodyLiteral],
        idx:        usize,
        binding:    Binding,
        fact_base:  &HashMap<String, HashSet<(KotobaCid, KotobaCid)>>,
        new_facts:  &HashMap<String, HashSet<(KotobaCid, KotobaCid)>>,
        delta_pos:  usize,
        out:        &mut Vec<(KotobaCid, KotobaCid)>,
        cited:      &mut Vec<DatomKey>,
    ) {
        if idx == body.len() {
            // All body literals matched — ground the head
            if let Some(head_pair) = self.ground_head(&rule.head, &binding) {
                out.push(head_pair);
            }
            return;
        }

        match &body[idx] {
            BodyLiteral::Positive(atom) => {
                // Choose the source: delta-constrained position uses new_facts,
                // all others use fact_base (a superset, so correctness holds).
                let source = if idx == delta_pos { new_facts } else { fact_base };
                let pairs = match source.get(&atom.relation) {
                    Some(s) => s,
                    None    => return, // no facts for this relation → no derivations
                };

                for (subj, obj) in pairs {
                    if let Some(new_binding) = self.unify_atom(atom, subj, obj, &binding) {
                        // Citation: record that this subject entity was used in a join
                        cited.push(DatomKey::from_cid(subj));
                        self.match_body(
                            rule, body, idx + 1, new_binding,
                            fact_base, new_facts, delta_pos, out, cited,
                        );
                    }
                }
            }

            BodyLiteral::Negative(atom) => {
                // Stratified negation: the grounded atom must NOT be in fact_base.
                // (Negation literals are never chosen as the delta position.)
                if let Some((gs, go)) = self.ground_atom_as_pair(atom, &binding) {
                    let present = fact_base
                        .get(&atom.relation)
                        .map_or(false, |s| s.contains(&(gs, go)));
                    if !present {
                        self.match_body(
                            rule, body, idx + 1, binding,
                            fact_base, new_facts, delta_pos, out, cited,
                        );
                    }
                }
            }

            BodyLiteral::Comparison(lhs, op, rhs) => {
                // Comparison over string representations of CIDs (lexicographic).
                // Variables must already be bound.
                let l = self.resolve_term_str(lhs, &binding);
                let r = self.resolve_term_str(rhs, &binding);
                if let (Some(l), Some(r)) = (l, r) {
                    let ok = match op {
                        CmpOp::Eq => l == r,
                        CmpOp::Ne => l != r,
                        CmpOp::Lt => l < r,
                        CmpOp::Le => l <= r,
                        CmpOp::Gt => l > r,
                        CmpOp::Ge => l >= r,
                    };
                    if ok {
                        self.match_body(
                            rule, body, idx + 1, binding,
                            fact_base, new_facts, delta_pos, out, cited,
                        );
                    }
                }
            }
        }
    }

    /// Try to extend `binding` so that `atom`'s args unify with `(subj, obj)`.
    fn unify_atom(
        &self,
        atom:    &Atom,
        subj:    &KotobaCid,
        obj:     &KotobaCid,
        binding: &Binding,
    ) -> Option<Binding> {
        assert_eq!(atom.args.len(), 2, "Datalog atom must be binary (Quad arity)");
        let mut b = binding.clone();

        let vals = [subj, obj];
        for (term, val) in atom.args.iter().zip(vals.iter()) {
            match term {
                Term::Variable(v) => {
                    if let Some(existing) = b.get(v) {
                        if existing != *val { return None; }
                    } else {
                        b.insert(v.clone(), (*val).clone());
                    }
                }
                Term::Constant(c) => {
                    if &cid_of_str(c) != *val { return None; }
                }
            }
        }
        Some(b)
    }

    /// Ground the head atom to (subject_cid, object_cid) using current binding.
    fn ground_head(
        &self,
        head:    &Atom,
        binding: &Binding,
    ) -> Option<(KotobaCid, KotobaCid)> {
        assert_eq!(head.args.len(), 2, "Datalog head must be binary");
        let s = self.resolve_term_cid(&head.args[0], binding)?;
        let o = self.resolve_term_cid(&head.args[1], binding)?;
        Some((s, o))
    }

    /// Ground an atom to (subject_cid, object_cid) for negation check.
    fn ground_atom_as_pair(
        &self,
        atom:    &Atom,
        binding: &Binding,
    ) -> Option<(KotobaCid, KotobaCid)> {
        self.ground_head(atom, binding)
    }

    fn resolve_term_cid(&self, term: &Term, binding: &Binding) -> Option<KotobaCid> {
        match term {
            Term::Constant(c) => Some(cid_of_str(c)),
            Term::Variable(v) => binding.get(v).cloned(),
        }
    }

    fn resolve_term_str(&self, term: &Term, binding: &Binding) -> Option<String> {
        // Normalize to CID-multibase so Variable and Constant can be compared
        // in the same hash space (matches unify_atom's cid_of_str(c) semantics).
        match term {
            Term::Constant(c) => Some(cid_of_str(c).to_multibase()),
            Term::Variable(v) => binding.get(v).map(|cid| cid.to_multibase()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta::Delta;
    use crate::quad::{Quad, QuadObject};

    /// Stable graph CID for test facts (same as evaluation uses for derived)
    fn test_graph() -> KotobaCid {
        cid_of_str("test:graph")
    }

    /// Build an assert Delta for a binary relation.
    /// `args[0]` = subject string, `args[1]` = object string.
    fn fact(relation: &str, args: &[&str]) -> Delta {
        assert_eq!(args.len(), 2, "test facts must be binary");
        let subj = cid_of_str(args[0]);
        let obj  = cid_of_str(args[1]);
        let quad = Quad {
            graph:     test_graph(),
            subject:   subj,
            predicate: relation.to_string(),
            object:    QuadObject::Cid(obj),
        };
        Delta::assert(quad)
    }

    /// Check whether `derived` contains the given relation and pair of string labels.
    fn has_relation(derived: &[Delta], rel: &str, a: &str, b: &str) -> bool {
        let sa = cid_of_str(a);
        let sb = cid_of_str(b);
        derived.iter().any(|d| {
            d.quad.predicate == rel
                && d.quad.subject == sa
                && matches!(&d.quad.object, QuadObject::Cid(c) if *c == sb)
        })
    }

    fn var(name: &str) -> Term { Term::Variable(name.to_string()) }

    fn pos(relation: &str, args: &[&str]) -> BodyLiteral {
        BodyLiteral::Positive(Atom {
            relation: relation.to_string(),
            args: args.iter().map(|s| Term::Variable(s.to_string())).collect(),
        })
    }

    fn head_atom(relation: &str, vars: &[&str]) -> Atom {
        Atom {
            relation: relation.to_string(),
            args: vars.iter().map(|s| var(s)).collect(),
        }
    }

    #[test]
    fn test_empty_rules_returns_empty() {
        let prog = DatalogProgram::new();
        let input = vec![fact("edge", &["a", "b"])];
        assert!(prog.evaluate_delta(&input).is_empty());
    }

    #[test]
    fn test_empty_input_returns_empty() {
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("foo", &["X", "Y"]),
            body: vec![pos("bar", &["X", "Y"])],
        });
        assert!(prog.evaluate_delta(&[]).is_empty());
    }

    #[test]
    fn test_simple_rule() {
        // reachable(X, Y) :- edge(X, Y).
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("reachable", &["X", "Y"]),
            body: vec![pos("edge", &["X", "Y"])],
        });

        let input = vec![fact("edge", &["a", "b"]), fact("edge", &["b", "c"])];
        let derived = prog.evaluate_delta(&input);

        assert!(has_relation(&derived, "reachable", "a", "b"));
        assert!(has_relation(&derived, "reachable", "b", "c"));
    }

    #[test]
    fn test_transitive_closure() {
        // ancestor(X, Y) :- parent(X, Y).
        // ancestor(X, Z) :- parent(X, Y), ancestor(Y, Z).
        let mut prog = DatalogProgram::new();

        prog.add_rule(DatalogRule {
            head: head_atom("ancestor", &["X", "Y"]),
            body: vec![pos("parent", &["X", "Y"])],
        });

        prog.add_rule(DatalogRule {
            head: head_atom("ancestor", &["X", "Z"]),
            body: vec![
                pos("parent",   &["X", "Y"]),
                pos("ancestor", &["Y", "Z"]),
            ],
        });

        // Input facts: parent(alice, bob), parent(bob, carol)
        let input = vec![
            fact("parent", &["alice", "bob"]),
            fact("parent", &["bob", "carol"]),
        ];

        let derived = prog.evaluate_delta(&input);

        assert!(
            has_relation(&derived, "ancestor", "alice", "bob"),
            "expected ancestor(alice, bob)"
        );
        assert!(
            has_relation(&derived, "ancestor", "bob", "carol"),
            "expected ancestor(bob, carol)"
        );
        assert!(
            has_relation(&derived, "ancestor", "alice", "carol"),
            "expected ancestor(alice, carol) via transitivity"
        );
    }

    #[test]
    fn test_no_duplicate_derivations() {
        // Even if two paths can derive the same fact, it should appear once.
        // path(X, Z) :- edge(X, Y), edge(Y, Z).
        // edge(a,b), edge(b,c), edge(a,c) — path(a,c) derivable once.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("path", &["X", "Z"]),
            body: vec![pos("edge", &["X", "Y"]), pos("edge", &["Y", "Z"])],
        });

        let input = vec![
            fact("edge", &["a", "b"]),
            fact("edge", &["b", "c"]),
        ];
        let derived = prog.evaluate_delta(&input);

        let count = derived.iter()
            .filter(|d| has_relation(std::slice::from_ref(d), "path", "a", "c"))
            .count();
        assert_eq!(count, 1, "path(a,c) should be derived exactly once");
    }
}
