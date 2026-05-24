use crate::arrangement::Arrangement;
use crate::delta::Delta;
use crate::datalog::DatalogProgram;

/// MaterializedView — incrementally maintained Datalog query result
/// = Pregel Aggregator (cross-vertex Arrangement)
pub struct MaterializedView {
    pub name:    String,
    pub program: DatalogProgram,
    pub state:   Arrangement,
}

impl MaterializedView {
    pub fn new(name: impl Into<String>, program: DatalogProgram) -> Self {
        Self { name: name.into(), program, state: Arrangement::new() }
    }

    /// Pregel Phase 2: apply incoming Deltas, produce out_deltas
    pub fn apply(&mut self, deltas: &[Delta]) -> Vec<Delta> {
        self.state.apply(deltas);
        self.program.evaluate_delta(deltas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datalog::{Atom, BodyLiteral, DatalogRule, Term};
    use crate::delta::Delta;
    use crate::quad::{Quad, QuadObject};
    use kotoba_core::cid::KotobaCid;

    fn cid(seed: &str) -> KotobaCid {
        KotobaCid::from_bytes(seed.as_bytes())
    }

    fn edge_quad(from: &str, to: &str) -> Quad {
        Quad {
            graph:     cid("g"),
            subject:   cid(from),
            predicate: "edge".to_string(),
            object:    QuadObject::Cid(cid(to)),
        }
    }

    fn make_rule(head_rel: &str, body_rel: &str) -> DatalogRule {
        DatalogRule {
            head: Atom {
                relation: head_rel.to_string(),
                args: vec![Term::Variable("X".into()), Term::Variable("Y".into())],
            },
            body: vec![BodyLiteral::Positive(Atom {
                relation: body_rel.to_string(),
                args: vec![Term::Variable("X".into()), Term::Variable("Y".into())],
            })],
        }
    }

    // ── Basic construction ─────────────────────────────────────────────────

    #[test]
    fn new_mv_has_empty_state() {
        let mut prog = DatalogProgram::new();
        prog.add_rule(make_rule("reachable", "edge"));
        let mv = MaterializedView::new("reachable", prog);
        assert!(mv.state.is_empty());
        assert_eq!(mv.name, "reachable");
    }

    // ── Apply: simple projection rule ─────────────────────────────────────

    #[test]
    fn apply_projects_edge_to_reachable() {
        let mut prog = DatalogProgram::new();
        prog.add_rule(make_rule("reachable", "edge"));
        let mut mv = MaterializedView::new("reachable", prog);

        let deltas = vec![
            Delta::assert(edge_quad("a", "b")),
            Delta::assert(edge_quad("b", "c")),
        ];
        let out = mv.apply(&deltas);

        // Output should contain derived reachable(a,b) and reachable(b,c)
        assert!(!out.is_empty(), "apply should produce derived deltas");
        let derived_rels: Vec<&str> = out.iter().map(|d| d.quad.predicate.as_str()).collect();
        assert!(derived_rels.iter().all(|&r| r == "reachable"),
            "all derived quads should have relation 'reachable'");

        let subjects: Vec<KotobaCid> = out.iter().map(|d| d.quad.subject.clone()).collect();
        assert!(subjects.contains(&cid("a")));
        assert!(subjects.contains(&cid("b")));
    }

    // ── Apply: state accumulation across calls ────────────────────────────

    #[test]
    fn apply_accumulates_state_across_calls() {
        let mut prog = DatalogProgram::new();
        prog.add_rule(make_rule("reachable", "edge"));
        let mut mv = MaterializedView::new("reachable", prog);

        mv.apply(&[Delta::assert(edge_quad("a", "b"))]);
        assert_eq!(mv.state.len(), 1, "state should have 1 quad after first apply");

        mv.apply(&[Delta::assert(edge_quad("b", "c"))]);
        assert_eq!(mv.state.len(), 2, "state should have 2 quads after second apply");
    }

    // ── Apply: retraction removes from state ─────────────────────────────

    #[test]
    fn retract_removes_from_state() {
        let mut prog = DatalogProgram::new();
        prog.add_rule(make_rule("reachable", "edge"));
        let mut mv = MaterializedView::new("reachable", prog);

        let quad = edge_quad("a", "b");
        mv.apply(&[Delta::assert(quad.clone())]);
        assert_eq!(mv.state.len(), 1);

        mv.apply(&[Delta::retract(quad)]);
        assert_eq!(mv.state.len(), 0);
    }

    // ── End-to-end: SQL→Datalog→MV ───────────────────────────────────────

    #[test]
    fn sql_compiled_mv_derives_correct_quads() {
        use crate::sql::SqlMvCompiler;

        // SQL: SELECT a.s, a.o FROM edge AS a WHERE a.s = 'alice'
        // → reachable(X, Y) :- edge(X, Y), X = cid("alice")
        let compiled = SqlMvCompiler::compile(
            "SELECT a.s, a.o FROM edge AS a WHERE a.s = 'alice'",
            "reachable_from_alice",
        ).expect("SQL compile should succeed");

        let mut mv = MaterializedView::new("reachable_from_alice", compiled.program);

        // alice→bob and carol→dave — only alice→bob should be derived
        let alice_bob = Quad {
            graph:     cid("g"),
            subject:   cid("alice"),
            predicate: "edge".to_string(),
            object:    QuadObject::Cid(cid("bob")),
        };
        let carol_dave = Quad {
            graph:     cid("g"),
            subject:   cid("carol"),
            predicate: "edge".to_string(),
            object:    QuadObject::Cid(cid("dave")),
        };

        let out = mv.apply(&[
            Delta::assert(alice_bob),
            Delta::assert(carol_dave),
        ]);

        // Only alice→bob matches the WHERE clause
        let derived_subjects: Vec<KotobaCid> = out.iter()
            .filter(|d| d.quad.predicate == "reachable_from_alice")
            .map(|d| d.quad.subject.clone())
            .collect();

        assert!(derived_subjects.contains(&cid("alice")),
            "alice should be derived");
        assert!(!derived_subjects.contains(&cid("carol")),
            "carol should be filtered out");
    }
}
