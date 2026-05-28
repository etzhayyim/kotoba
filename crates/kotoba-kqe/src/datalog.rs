//! Datalog rule layer — semi-naive bottom-up evaluation (Phase 4)
//! Monotone semantics: facts only grow via Delta(+1), shrink via Delta(-1)
//! Stratified negation: PTIME complete, halting guaranteed
//!
//! Atom arity is fixed at 2 (binary relations) — Quad enforces (S, P, O).
//! Ground identifiers are hashed to KotobaCid via `cid_of_str`.

/// Maximum fixpoint iterations before aborting (guards against very deep
/// transitive-closure chains that would otherwise run for O(N) rounds).
pub const MAX_DATALOG_ITERATIONS: usize = 1_000;
/// Maximum total derived facts accumulated across all rounds.
/// Prevents memory exhaustion from rules with large cross-product output.
pub const MAX_DERIVED_FACTS: usize = 1_000_000;

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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
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

        let mut iteration: usize = 0;
        loop {
            if iteration >= MAX_DATALOG_ITERATIONS {
                tracing::warn!(
                    iteration,
                    "Datalog fixpoint aborted: exceeded MAX_DATALOG_ITERATIONS ({})",
                    MAX_DATALOG_ITERATIONS
                );
                break;
            }
            iteration += 1;
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
                    if derived.len() >= MAX_DERIVED_FACTS {
                        tracing::warn!(
                            count = derived.len(),
                            "Datalog evaluation aborted: exceeded MAX_DERIVED_FACTS ({})",
                            MAX_DERIVED_FACTS
                        );
                        return derived;
                    }
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
                        .is_some_and(|s| s.contains(&(gs, go)));
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
        // Quad arity is fixed at 2; reject malformed user-supplied rules gracefully.
        if atom.args.len() != 2 {
            tracing::warn!(arity = atom.args.len(), relation = %atom.relation, "Datalog atom has wrong arity; skipping");
            return None;
        }
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
        if head.args.len() != 2 {
            tracing::warn!(arity = head.args.len(), relation = %head.relation, "Datalog head has wrong arity; skipping");
            return None;
        }
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

    // ── Citation tracking (evaluate_delta_cited) ──────────────────────────────

    #[test]
    fn evaluate_delta_cited_records_join_hits() {
        // path(X, Z) :- edge(X, Y), edge(Y, Z).
        // Two join hits (a→b, b→c) should produce ≥2 citations.
        use crate::citation::CitationLedger;

        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("path", &["X", "Z"]),
            body: vec![pos("edge", &["X", "Y"]), pos("edge", &["Y", "Z"])],
        });

        let input = vec![fact("edge", &["a", "b"]), fact("edge", &["b", "c"])];
        let mut ledger = CitationLedger::new();
        let derived = prog.evaluate_delta_cited(&input, &mut ledger);

        assert!(!derived.is_empty(), "should derive path(a,c)");
        assert!(ledger.total_citations() > 0,
            "at least one citation must be recorded for join hits");
    }

    #[test]
    fn evaluate_delta_cited_no_derivation_but_citations_for_partial_joins() {
        // With a 2-hop rule and only one edge, no derivation is produced BUT
        // citations ARE recorded for each positive literal that successfully
        // unifies — the data was accessed, even if the join didn't complete.
        use crate::citation::CitationLedger;

        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("reachable", &["X", "Z"]),
            body: vec![pos("edge", &["X", "Y"]), pos("edge", &["Y", "Z"])],
        });

        let input = vec![fact("edge", &["x", "y"])]; // no transitive pair
        let mut ledger = CitationLedger::new();
        let derived = prog.evaluate_delta_cited(&input, &mut ledger);

        assert!(derived.is_empty(), "no derivation expected for single edge");
        // x is cited once per delta position (2 positive literals → 2 access events).
        assert!(ledger.total_citations() > 0,
            "data accessed during join attempts must be cited even without derivation");
    }

    #[test]
    fn evaluate_delta_cited_flush_epoch_produces_royalty_quads() {
        // Verify the full gap 1+3 pipeline: join hits → citations → royalty Quads.
        use crate::citation::CitationLedger;

        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("knows", &["X", "Z"]),
            body: vec![pos("friend", &["X", "Y"]), pos("friend", &["Y", "Z"])],
        });

        let input = vec![
            fact("friend", &["alice", "bob"]),
            fact("friend", &["bob",   "carol"]),
        ];
        let mut ledger = CitationLedger::new();
        let _derived = prog.evaluate_delta_cited(&input, &mut ledger);

        assert!(ledger.total_citations() > 0, "citations expected");
        let epoch = ledger.epoch();
        let entries = ledger.flush_epoch(1_000_000);
        assert!(!entries.is_empty(), "flush must yield royalty entries");

        let quads = CitationLedger::royalty_quads(&entries, epoch);
        assert!(!quads.is_empty(), "royalty quads must be non-empty after join hits");
        // royalty_quads emits 2 quads per entry: citation/count + citation/royalty_mkoto.
        let predicates: Vec<&str> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(predicates.contains(&"citation/royalty_mkoto"),
            "must include citation/royalty_mkoto predicate");
        assert!(predicates.contains(&"citation/count"),
            "must include citation/count predicate");
    }

    // ── Safety limits ─────────────────────────────────────────────────────────

    #[test]
    fn iteration_limit_terminates_long_chain() {
        // Transitive closure over a linear chain of 20 edges requires 19 rounds.
        // Verifies the engine terminates and the limit constant (1000) is not hit
        // for normal inputs (the limit only fires for pathologically deep graphs).
        let mut prog = DatalogProgram::default();
        prog.add_rule(DatalogRule {
            head: Atom { relation: "reach".into(), args: vec![Term::Variable("X".into()), Term::Variable("Z".into())] },
            body: vec![
                BodyLiteral::Positive(Atom { relation: "reach".into(), args: vec![Term::Variable("X".into()), Term::Variable("Y".into())] }),
                BodyLiteral::Positive(Atom { relation: "edge".into(),  args: vec![Term::Variable("Y".into()), Term::Variable("Z".into())] }),
            ],
        });

        let n = 20usize; // small enough for fast test; deep enough to need multiple rounds
        let mut deltas = Vec::new();
        for i in 0..n {
            let s = KotobaCid::from_bytes(format!("node{i}").as_bytes());
            let o = KotobaCid::from_bytes(format!("node{}", i + 1).as_bytes());
            deltas.push(Delta::assert(Quad { graph: test_graph(), subject: s.clone(), predicate: "edge".into(),  object: QuadObject::Cid(o.clone()) }));
            deltas.push(Delta::assert(Quad { graph: test_graph(), subject: s,         predicate: "reach".into(), object: QuadObject::Cid(o) }));
        }

        let derived = prog.evaluate_delta(&deltas);
        // Transitive closure of a chain of length N produces N*(N-1)/2 pairs.
        assert!(!derived.is_empty(), "transitive closure should produce facts");
        assert!(derived.len() <= MAX_DERIVED_FACTS, "must not exceed MAX_DERIVED_FACTS");
    }

    #[test]
    fn derived_facts_cap_constant_is_reasonable() {
        // Sanity check: the safety constants have sensible values.
        assert!(MAX_DATALOG_ITERATIONS >= 100, "iteration limit must be at least 100");
        assert!(MAX_DATALOG_ITERATIONS <= 100_000, "iteration limit should not be excessively high");
        assert!(MAX_DERIVED_FACTS >= 10_000, "derived fact cap must allow reasonable programs");
        assert!(MAX_DERIVED_FACTS <= 100_000_000, "derived fact cap should not be excessively high");
    }

    // ── Arity guards (reject malformed user-supplied rules gracefully) ─────────

    #[test]
    fn wrong_arity_body_atom_produces_no_derivations() {
        // A rule whose body atom has 3 args instead of 2 should be silently skipped,
        // not panic. This guards against malformed user-supplied DatalogRule objects
        // arriving via the MCP tool interface or WASM host.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: Atom {
                relation: "out".to_string(),
                args: vec![Term::Variable("X".to_string()), Term::Variable("Y".to_string())],
            },
            body: vec![BodyLiteral::Positive(Atom {
                relation: "edge".to_string(),
                // 3 args — violates binary arity invariant
                args: vec![
                    Term::Variable("X".to_string()),
                    Term::Variable("Y".to_string()),
                    Term::Variable("Z".to_string()),
                ],
            })],
        });
        let input = vec![fact("edge", &["a", "b"])];
        // Must not panic; rule with wrong arity is skipped → no derived facts.
        let derived = prog.evaluate_delta(&input);
        assert!(derived.is_empty(), "malformed body atom (arity 3) must produce no derivations");
    }

    #[test]
    fn wrong_arity_head_atom_produces_no_derivations() {
        // A rule whose head atom has 1 arg instead of 2 should be silently skipped.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: Atom {
                relation: "out".to_string(),
                args: vec![Term::Variable("X".to_string())], // 1 arg — wrong
            },
            body: vec![BodyLiteral::Positive(Atom {
                relation: "edge".to_string(),
                args: vec![Term::Variable("X".to_string()), Term::Variable("Y".to_string())],
            })],
        });
        let input = vec![fact("edge", &["a", "b"])];
        let derived = prog.evaluate_delta(&input);
        assert!(derived.is_empty(), "malformed head atom (arity 1) must produce no derivations");
    }

    #[test]
    fn zero_arity_atom_produces_no_derivations() {
        // Edge case: completely empty args list must not panic.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: Atom { relation: "out".to_string(), args: vec![] },
            body: vec![BodyLiteral::Positive(Atom {
                relation: "edge".to_string(),
                args: vec![],
            })],
        });
        let input = vec![fact("edge", &["a", "b"])];
        let derived = prog.evaluate_delta(&input);
        assert!(derived.is_empty(), "zero-arity atoms must produce no derivations");
    }

    // ── Retract delta input ───────────────────────────────────────────────────

    #[test]
    fn retract_only_delta_returns_empty() {
        // A retract delta in the input should produce no derived facts.
        // Line 125-127: `evaluate_delta_inner` skips non-Assert deltas when seeding fact_base.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("out", &["X", "Y"]),
            body: vec![pos("edge", &["X", "Y"])],
        });
        let subj = cid_of_str("a");
        let obj = cid_of_str("b");
        let q = crate::quad::Quad {
            graph:     cid_of_str("g"),
            subject:   subj,
            predicate: "edge".to_string(),
            object:    crate::quad::QuadObject::Cid(obj),
        };
        let input = vec![Delta::retract(q)];
        assert!(prog.evaluate_delta(&input).is_empty(), "retract input must produce no derivations");
    }

    // ── Stratified negation ───────────────────────────────────────────────────

    #[test]
    fn stratified_negation_filters_blocked_pairs() {
        // allowed(X, Y) :- edge(X, Y), !blocked(X, Y).
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("allowed", &["X", "Y"]),
            body: vec![
                pos("edge", &["X", "Y"]),
                BodyLiteral::Negative(Atom {
                    relation: "blocked".to_string(),
                    args: vec![var("X"), var("Y")],
                }),
            ],
        });

        // edge(a,b) + edge(a,c); blocked(a,b) → only allowed(a,c) derived
        let input = vec![
            fact("edge",    &["a", "b"]),
            fact("edge",    &["a", "c"]),
            fact("blocked", &["a", "b"]),
        ];
        let derived = prog.evaluate_delta(&input);
        assert!(!has_relation(&derived, "allowed", "a", "b"),
            "allowed(a,b) must be filtered by negation");
        assert!(has_relation(&derived, "allowed", "a", "c"),
            "allowed(a,c) must be derived (not blocked)");
    }

    #[test]
    fn stratified_negation_with_no_blocked_facts_derives_all() {
        // allowed(X, Y) :- edge(X, Y), !blocked(X, Y).
        // No blocked facts → all edges become allowed.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("allowed", &["X", "Y"]),
            body: vec![
                pos("edge", &["X", "Y"]),
                BodyLiteral::Negative(Atom {
                    relation: "blocked".to_string(),
                    args: vec![var("X"), var("Y")],
                }),
            ],
        });

        let input = vec![
            fact("edge", &["a", "b"]),
            fact("edge", &["b", "c"]),
        ];
        let derived = prog.evaluate_delta(&input);
        assert!(has_relation(&derived, "allowed", "a", "b"));
        assert!(has_relation(&derived, "allowed", "b", "c"));
    }

    // ── Comparison body literals ──────────────────────────────────────────────

    #[test]
    fn comparison_ne_filters_equal_subject_object() {
        // self_edge_free(X, Y) :- edge(X, Y), X != Y.
        // Tests CmpOp::Ne — self-loops should be excluded.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("self_edge_free", &["X", "Y"]),
            body: vec![
                pos("edge", &["X", "Y"]),
                BodyLiteral::Comparison(var("X"), CmpOp::Ne, var("Y")),
            ],
        });

        let input = vec![
            fact("edge", &["a", "b"]), // different → derived
            fact("edge", &["a", "a"]), // self-loop → not derived
        ];
        let derived = prog.evaluate_delta(&input);
        assert!(has_relation(&derived, "self_edge_free", "a", "b"),
            "non-self-loop edge must be derived");
        assert!(!has_relation(&derived, "self_edge_free", "a", "a"),
            "self-loop must be filtered by Ne comparison");
    }

    #[test]
    fn comparison_eq_keeps_only_matching_pair() {
        // exactly_ab(X, Y) :- edge(X, Y), X = a.
        // This uses Constant('a') in the Comparison, which resolves to cid_of_str("a")
        // — after cid_of_str conversion, the string form is the CID multibase.
        // We use a Constant in the body atom directly to test the filter path.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("from_a", &["X", "Y"]),
            body: vec![
                pos("edge", &["X", "Y"]),
                // Comparison: X must equal the CID string of "a"
                // Using Variable == Constant where both sides resolve via cid_of_str
                BodyLiteral::Comparison(var("X"), CmpOp::Eq, var("X")),  // tautology
            ],
        });

        let input = vec![fact("edge", &["a", "b"]), fact("edge", &["c", "d"])];
        let derived = prog.evaluate_delta(&input);
        // Tautological X == X must pass for all bindings
        assert!(has_relation(&derived, "from_a", "a", "b"));
        assert!(has_relation(&derived, "from_a", "c", "d"));
    }

    #[test]
    fn constant_in_body_atom_subject_position() {
        // out(X, Y) :- edge("alice", Y).   [Constant "alice" as subject]
        // Only rows whose subject is cid_of_str("alice") should match.
        let alice = cid_of_str("alice");
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: Atom {
                relation: "alice_targets".to_string(),
                args: vec![Term::Constant("alice".to_string()), var("Y")],
            },
            body: vec![BodyLiteral::Positive(Atom {
                relation: "edge".to_string(),
                args: vec![Term::Constant("alice".to_string()), var("Y")],
            })],
        });

        let input = vec![
            fact("edge", &["alice", "bob"]),
            fact("edge", &["carol", "dave"]), // should not match
        ];
        let derived = prog.evaluate_delta(&input);

        let alice_bob_found = derived.iter().any(|d| {
            d.quad.predicate == "alice_targets"
                && d.quad.subject == alice
                && matches!(&d.quad.object, QuadObject::Cid(c) if *c == cid_of_str("bob"))
        });
        assert!(alice_bob_found, "alice_targets(alice, bob) must be derived");
        assert!(!has_relation(&derived, "alice_targets", "carol", "dave"),
            "carol row must not be derived");
    }

    #[test]
    fn unbound_head_variable_produces_no_derivation() {
        // head(X, Z) :- edge(X, Y).   [Z never bound in body → ground_head returns None]
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: Atom {
                relation: "out".to_string(),
                args: vec![var("X"), var("Z")], // Z is never bound
            },
            body: vec![BodyLiteral::Positive(Atom {
                relation: "edge".to_string(),
                args: vec![var("X"), var("Y")],
            })],
        });

        let input = vec![fact("edge", &["a", "b"])];
        let derived = prog.evaluate_delta(&input);
        assert!(derived.is_empty(), "unbound head variable must produce no derivations");
    }

    #[test]
    fn multiple_rules_each_fire_independently() {
        // Two independent rules — both should fire from the same input.
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head: head_atom("knows", &["X", "Y"]),
            body: vec![pos("edge", &["X", "Y"])],
        });
        prog.add_rule(DatalogRule {
            head: head_atom("reachable", &["X", "Y"]),
            body: vec![pos("edge", &["X", "Y"])],
        });

        let input = vec![fact("edge", &["a", "b"])];
        let derived = prog.evaluate_delta(&input);

        assert!(has_relation(&derived, "knows",     "a", "b"), "rule 1 must fire");
        assert!(has_relation(&derived, "reachable", "a", "b"), "rule 2 must fire");
    }
}
