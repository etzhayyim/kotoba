//! SPARQL SELECT → Datalog rule compiler (kotoba-graph)
//!
//! Supported subset:
//!   PREFIX p: <iri/>
//!   SELECT ?var1 ?var2
//!   WHERE {
//!     ?s <predicate_iri> ?o .
//!     FILTER(?var = "literal")   -- substitutes constant
//!     FILTER(?var != "literal")  -- emits Comparison(Ne)
//!   }
//!
//! The IRI string of each predicate is used verbatim as the Datalog relation
//! name — it must match `Quad.predicate` strings already in the store.
//! SELECT must project exactly 2 variables (binary-relation arity invariant).
//! Variable predicates, OPTIONAL, UNION, aggregates, and subqueries are
//! not supported.

use std::collections::HashMap;

use anyhow::anyhow;
use spargebra::algebra::{Expression, GraphPattern};
use spargebra::term::{NamedNodePattern, TermPattern, TriplePattern, Variable};

use kotoba_kqe::datalog::{Atom, BodyLiteral, CmpOp, DatalogProgram, DatalogRule, Term};

// ── Public types ──────────────────────────────────────────────────────────────

pub struct CompiledSparqlMv {
    pub program:         DatalogProgram,
    pub output_relation: String,
}

pub struct SparqlCompiler;

impl SparqlCompiler {
    /// Compile a SPARQL SELECT into a `DatalogProgram`.
    ///
    /// `output_relation` becomes the head predicate. SELECT must project
    /// exactly 2 variables (the kotoba binary-relation arity invariant).
    pub fn compile(sparql: &str, output_relation: &str) -> anyhow::Result<CompiledSparqlMv> {
        let query = spargebra::SparqlParser::new()
            .parse_query(sparql)
            .map_err(|e| anyhow!("SPARQL parse error: {e}"))?;

        let pattern = match query {
            spargebra::Query::Select { pattern, .. } => pattern,
            _ => anyhow::bail!("only SELECT queries are supported"),
        };

        // Unwrap mandatory top-level Project (and optional Distinct/Reduced)
        let (select_vars, inner) = unwrap_project(pattern)?;

        // Collect BGP triple patterns and FILTER expressions
        let (triples, filters): (Vec<TriplePattern>, Vec<Expression>) = collect_bgp(&inner)?;

        anyhow::ensure!(!triples.is_empty(), "SPARQL WHERE clause has no triple patterns");

        // Build VarMap: SPARQL ?var → Datalog Term
        let mut var_map = SparqlVarMap::new();
        for tp in &triples {
            register_term_vars(&tp.subject, &mut var_map);
            register_term_vars(&tp.object, &mut var_map);
            if let NamedNodePattern::Variable(v) = &tp.predicate {
                var_map.ensure(v.as_str());
            }
        }
        for v in &select_vars {
            var_map.ensure(v.as_str());
        }

        // Process FILTER: equality → constant substitution; inequality → Comparison literal
        let mut ne_body: Vec<BodyLiteral> = Vec::new();
        for expr in &filters {
            process_filter(expr, &mut var_map, &mut ne_body)?;
        }

        // Build body atoms from triple patterns
        let mut body: Vec<BodyLiteral> = Vec::new();
        for tp in &triples {
            let relation = match &tp.predicate {
                NamedNodePattern::NamedNode(nn) => nn.as_str().to_string(),
                NamedNodePattern::Variable(_) =>
                    anyhow::bail!("variable predicates are not supported; use a concrete IRI"),
            };
            let s_term = term_from_pattern(&tp.subject, &var_map)?;
            let o_term = term_from_pattern(&tp.object, &var_map)?;
            body.push(BodyLiteral::Positive(Atom { relation, args: vec![s_term, o_term] }));
        }
        body.extend(ne_body);

        // Build head from SELECT projection (exactly 2 variables required)
        let head_args: Vec<Term> = select_vars.iter().map(|v| var_map.get(v.as_str())).collect();
        anyhow::ensure!(
            head_args.len() == 2,
            "SELECT must project exactly 2 variables (kotoba binary arity); got {}",
            head_args.len()
        );

        let head = Atom { relation: output_relation.to_string(), args: head_args };
        let mut program = DatalogProgram::new();
        program.add_rule(DatalogRule { head, body });

        Ok(CompiledSparqlMv { program, output_relation: output_relation.to_string() })
    }
}

// ── Internal VarMap ───────────────────────────────────────────────────────────

struct SparqlVarMap {
    bindings: HashMap<String, Term>,
}

impl SparqlVarMap {
    fn new() -> Self { Self { bindings: HashMap::new() } }

    fn ensure(&mut self, var_name: &str) {
        self.bindings.entry(var_name.to_string())
            .or_insert_with(|| Term::Variable(var_name.to_string()));
    }

    /// Substitute all occurrences of `var_name` with a constant (for FILTER =).
    fn set_const(&mut self, var_name: &str, value: String) {
        let old_var = match self.bindings.get(var_name) {
            Some(Term::Variable(v)) => Some(v.clone()),
            _ => None,
        };
        let const_term = Term::Constant(value);
        if let Some(old) = old_var {
            for slot in self.bindings.values_mut() {
                if let Term::Variable(v) = slot {
                    if *v == old { *slot = const_term.clone(); }
                }
            }
        }
        self.bindings.insert(var_name.to_string(), const_term);
    }

    fn get(&self, var_name: &str) -> Term {
        self.bindings.get(var_name)
            .cloned()
            .unwrap_or_else(|| Term::Variable(var_name.to_string()))
    }
}

// ── Graph pattern traversal ───────────────────────────────────────────────────

fn unwrap_project(pattern: GraphPattern) -> anyhow::Result<(Vec<Variable>, GraphPattern)> {
    match pattern {
        GraphPattern::Project { inner, variables } => Ok((variables, *inner)),
        GraphPattern::Distinct { inner }           => unwrap_project(*inner),
        GraphPattern::Reduced  { inner }           => unwrap_project(*inner),
        _ => anyhow::bail!("expected a SELECT projection at the top of the query pattern"),
    }
}

fn collect_bgp(pattern: &GraphPattern)
    -> anyhow::Result<(Vec<TriplePattern>, Vec<Expression>)>
{
    match pattern {
        GraphPattern::Bgp { patterns } => Ok((patterns.clone(), vec![])),

        GraphPattern::Join { left, right } => {
            let (mut t, mut f): (Vec<TriplePattern>, Vec<Expression>) = collect_bgp(left)?;
            let (t2, f2): (Vec<TriplePattern>, Vec<Expression>)       = collect_bgp(right)?;
            t.extend(t2); f.extend(f2);
            Ok((t, f))
        }

        GraphPattern::Filter { expr, inner } => {
            let (t, mut f): (Vec<TriplePattern>, Vec<Expression>) = collect_bgp(inner)?;
            f.push(expr.clone());
            Ok((t, f))
        }

        GraphPattern::Graph { inner, .. }    => collect_bgp(inner),
        GraphPattern::Distinct { inner }     => collect_bgp(inner),
        GraphPattern::Reduced  { inner }     => collect_bgp(inner),

        other => anyhow::bail!(
            "unsupported graph pattern: {other:?}; only BGP, JOIN, FILTER, and GRAPH are supported"
        ),
    }
}

fn register_term_vars(term: &TermPattern, var_map: &mut SparqlVarMap) {
    if let TermPattern::Variable(v) = term {
        var_map.ensure(v.as_str());
    }
}

fn term_from_pattern(term: &TermPattern, var_map: &SparqlVarMap) -> anyhow::Result<Term> {
    match term {
        TermPattern::Variable(v)  => Ok(var_map.get(v.as_str())),
        TermPattern::NamedNode(nn) => {
            let iri = nn.as_str();
            // <cid:b...> is a CID IRI; store as constant using the multibase suffix
            let constant = iri.strip_prefix("cid:").unwrap_or(iri);
            Ok(Term::Constant(constant.to_string()))
        }
        TermPattern::Literal(lit)  => Ok(Term::Constant(lit.value().to_string())),
        TermPattern::BlankNode(bn) => Ok(Term::Variable(format!("_bn_{}", bn.as_str()))),
    }
}

// ── FILTER processing ─────────────────────────────────────────────────────────

fn process_filter(
    expr:         &Expression,
    var_map:      &mut SparqlVarMap,
    ne_body:      &mut Vec<BodyLiteral>,
) -> anyhow::Result<()> {
    match expr {
        Expression::Equal(l, r)    => apply_filter(l, r, false, var_map, ne_body),
        Expression::Not(inner)     => {
            // SPARQL != is represented as NOT(=)
            if let Expression::Equal(l, r) = inner.as_ref() {
                apply_filter(l, r, true, var_map, ne_body)
            } else {
                anyhow::bail!("FILTER NOT is only supported as `?var != literal`")
            }
        }
        Expression::And(l, r) => {
            process_filter(l, var_map, ne_body)?;
            process_filter(r, var_map, ne_body)
        }
        other => anyhow::bail!(
            "unsupported FILTER expression: {other:?}; only = and != are supported"
        ),
    }
}

fn apply_filter(
    left:    &Expression,
    right:   &Expression,
    is_ne:   bool,
    var_map: &mut SparqlVarMap,
    ne_body: &mut Vec<BodyLiteral>,
) -> anyhow::Result<()> {
    // Normalise to (Variable, Literal) regardless of operand order
    let (var_expr, lit_expr) = match (left, right) {
        (Expression::Variable(_), Expression::Literal(_)) => (left, right),
        (Expression::Literal(_),  Expression::Variable(_)) => (right, left),
        _ => anyhow::bail!("FILTER only supports `?var = literal` or `?var != literal`"),
    };

    let var_name = match var_expr {
        Expression::Variable(v) => v.as_str().to_string(),
        _ => unreachable!(),
    };
    let lit_value = match lit_expr {
        Expression::Literal(l) => l.value().to_string(),
        _ => unreachable!(),
    };

    if is_ne {
        ne_body.push(BodyLiteral::Comparison(
            var_map.get(&var_name),
            CmpOp::Ne,
            Term::Constant(lit_value),
        ));
    } else {
        var_map.set_const(&var_name, lit_value);
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::{
        delta::Delta,
        quad::{Quad, QuadObject},
    };

    // IRIs used in test facts and SPARQL queries — must match exactly.
    const KNOWS:  &str = "urn:k:knows";
    const PARENT: &str = "urn:k:parent";
    const FOLLOWS: &str = "urn:k:follows";

    fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

    fn fact(relation: &str, s: &str, o: &str) -> Delta {
        Delta::assert(Quad {
            graph:     cid("g"),
            subject:   cid(s),
            predicate: relation.to_string(),
            object:    QuadObject::Cid(cid(o)),
        })
    }

    fn has(derived: &[Delta], rel: &str, s: &str, o: &str) -> bool {
        derived.iter().any(|d| {
            d.quad.predicate == rel
                && d.quad.subject == cid(s)
                && matches!(&d.quad.object, QuadObject::Cid(c) if *c == cid(o))
        })
    }

    // ── happy-path tests ──────────────────────────────────────────────────────

    #[test]
    fn simple_bgp_one_triple() {
        let sparql = format!(
            "PREFIX k: <urn:k:> SELECT ?s ?o WHERE {{ ?s k:knows ?o }}"
        );
        let mv = SparqlCompiler::compile(&sparql, "output").unwrap();
        let derived = mv.program.evaluate_delta(&[fact(KNOWS, "alice", "bob")]);
        assert!(has(&derived, "output", "alice", "bob"));
    }

    #[test]
    fn join_two_triples_same_predicate() {
        // ancestor(?s, ?o) :- parent(?s, ?mid), parent(?mid, ?o).
        let sparql = format!(
            "PREFIX k: <urn:k:> SELECT ?s ?o WHERE {{ ?s k:parent ?mid . ?mid k:parent ?o }}"
        );
        let mv = SparqlCompiler::compile(&sparql, "ancestor").unwrap();

        let input = vec![
            fact(PARENT, "alice", "bob"),
            fact(PARENT, "bob",   "carol"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "ancestor", "alice", "carol"), "expected ancestor(alice,carol)");
        assert!(!has(&derived, "ancestor", "bob",   "alice"), "no spurious derivation");
    }

    #[test]
    fn join_two_different_predicates() {
        // co_follower(?s, ?o) :- knows(?s,?mid), follows(?mid,?o)
        let sparql = format!(
            "PREFIX k: <urn:k:> SELECT ?s ?o WHERE {{ ?s k:knows ?mid . ?mid k:follows ?o }}"
        );
        let mv = SparqlCompiler::compile(&sparql, "co_follower").unwrap();

        let input = vec![
            fact(KNOWS,   "alice", "bob"),
            fact(FOLLOWS, "bob",   "carol"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "co_follower", "alice", "carol"));
    }

    #[test]
    fn filter_equality_constant_substitution() {
        // alice_knows(?s, ?o) :- knows(alice, ?o)  [?s bound to "alice"]
        let sparql = format!(
            r#"PREFIX k: <urn:k:> SELECT ?s ?o WHERE {{ ?s k:knows ?o FILTER(?s = "alice") }}"#
        );
        let mv = SparqlCompiler::compile(&sparql, "alice_knows").unwrap();

        let input = vec![
            fact(KNOWS, "alice", "bob"),
            fact(KNOWS, "carol", "dave"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!( has(&derived, "alice_knows", "alice", "bob"),  "alice→bob expected");
        assert!(!has(&derived, "alice_knows", "carol", "dave"), "carol should be filtered");
    }

    #[test]
    fn filter_inequality_comparison() {
        let sparql = format!(
            r#"PREFIX k: <urn:k:> SELECT ?s ?o WHERE {{ ?s k:knows ?o FILTER(?s != "carol") }}"#
        );
        let mv = SparqlCompiler::compile(&sparql, "not_carol_knows").unwrap();

        let input = vec![
            fact(KNOWS, "alice", "bob"),
            fact(KNOWS, "carol", "dave"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!( has(&derived, "not_carol_knows", "alice", "bob"));
        assert!(!has(&derived, "not_carol_knows", "carol", "dave"));
    }

    #[test]
    fn filter_and_two_conditions() {
        let sparql = format!(
            r#"PREFIX k: <urn:k:> SELECT ?s ?o WHERE {{ ?s k:knows ?o FILTER(?s = "alice" && ?o != "dave") }}"#
        );
        let mv = SparqlCompiler::compile(&sparql, "out").unwrap();

        let input = vec![
            fact(KNOWS, "alice", "bob"),
            fact(KNOWS, "alice", "dave"),
            fact(KNOWS, "carol", "bob"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!( has(&derived, "out", "alice", "bob"));
        assert!(!has(&derived, "out", "alice", "dave"), "dave excluded by !=");
        assert!(!has(&derived, "out", "carol", "bob"),  "carol excluded by =");
    }

    #[test]
    fn select_distinct_is_accepted() {
        let sparql = format!(
            "PREFIX k: <urn:k:> SELECT DISTINCT ?s ?o WHERE {{ ?s k:knows ?o }}"
        );
        let mv = SparqlCompiler::compile(&sparql, "output").unwrap();
        let derived = mv.program.evaluate_delta(&[fact(KNOWS, "alice", "bob")]);
        assert!(has(&derived, "output", "alice", "bob"));
    }

    // ── error cases ───────────────────────────────────────────────────────────

    #[test]
    fn wrong_arity_one_var_errors() {
        let sparql = "PREFIX k: <urn:k:> SELECT ?s WHERE { ?s k:knows ?o }";
        assert!(SparqlCompiler::compile(sparql, "out").is_err(), "single-var SELECT must fail");
    }

    #[test]
    fn wrong_arity_three_vars_errors() {
        let sparql = "PREFIX k: <urn:k:> SELECT ?s ?p ?o WHERE { ?s ?p ?o }";
        assert!(SparqlCompiler::compile(sparql, "out").is_err(), "three-var SELECT must fail");
    }

    #[test]
    fn variable_predicate_errors() {
        let sparql = "SELECT ?s ?o WHERE { ?s ?p ?o }";
        assert!(SparqlCompiler::compile(sparql, "out").is_err(), "variable predicate must fail");
    }

    #[test]
    fn empty_bgp_errors() {
        // SPARQL with no triple patterns in WHERE
        let sparql = "SELECT ?s ?o WHERE { FILTER(1=1) }";
        // spargebra may or may not parse this; regardless the compiler should error
        match SparqlCompiler::compile(sparql, "out") {
            Err(_) => {} // expected
            Ok(mv) => {
                // if parse somehow succeeds, evaluate should produce nothing
                let derived = mv.program.evaluate_delta(&[fact(KNOWS, "a", "b")]);
                assert!(derived.is_empty());
            }
        }
    }
}
