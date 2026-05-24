//! Cypher MATCH/RETURN → Datalog rule compiler for kotoba-kqe
//!
//! Supported subset:
//!   MATCH (a)-[:RELATION]->(b)
//!   MATCH (a:Label)-[:RELATION]->(b:Label)
//!   MATCH (a)-[:R1]->(b)-[:R2]->(c)
//!   WHERE n.prop = "value"  (or WHERE n = "value" for node-level constant)
//!   RETURN x, y            (exactly 2 node variables — binary-relation arity invariant)
//!
//! Node labels are ignored (schema-free). Anonymous `-->` uses relation `"*"`.
//! No aggregation, no OPTIONAL MATCH, no CREATE/DELETE/MERGE.
//!
//! Implementation: hand-written recursive descent parser — no new dependencies.

use anyhow::anyhow;
use std::collections::HashMap;

use crate::datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term};

// ── Public types ─────────────────────────────────────────────────────────────

pub struct CompiledCypherMv {
    pub program: DatalogProgram,
    pub output_relation: String,
}

pub struct CypherCompiler;

impl CypherCompiler {
    /// Compile a Cypher MATCH/RETURN query into a `DatalogProgram`.
    ///
    /// `output_relation` becomes the head predicate. RETURN must project exactly
    /// 2 node variables (the kotoba binary-relation arity invariant).
    pub fn compile(cypher: &str, output_relation: &str) -> anyhow::Result<CompiledCypherMv> {
        let query = parse(cypher)?;

        // Validate RETURN arity (exactly 2 node variables)
        if query.return_vars.len() != 2 {
            anyhow::bail!(
                "RETURN must project exactly 2 node variables for kotoba binary Datalog; got {}",
                query.return_vars.len()
            );
        }

        // Build VarMap: assign fresh Datalog variable names per node alias
        let mut var_map = VarMap::new();
        for node in &query.nodes {
            var_map.register(&node.alias);
        }

        // Apply WHERE constant substitutions
        for (alias, value) in &query.where_consts {
            var_map.set_const(alias, value.clone());
        }

        // Build body atoms — one Datalog atom per edge in the pattern
        let mut body: Vec<BodyLiteral> = Vec::new();
        for edge in &query.edges {
            let s_term = var_map
                .to_term(&edge.from)
                .ok_or_else(|| anyhow!("unknown node alias '{}' in edge", edge.from))?;
            let o_term = var_map
                .to_term(&edge.to)
                .ok_or_else(|| anyhow!("unknown node alias '{}' in edge", edge.to))?;
            body.push(BodyLiteral::Positive(Atom {
                relation: edge.relation.clone(),
                args: vec![s_term, o_term],
            }));
        }

        // Build head from RETURN projection
        let head_args: Vec<Term> = query
            .return_vars
            .iter()
            .map(|alias| {
                var_map
                    .to_term(alias)
                    .ok_or_else(|| anyhow!("RETURN variable '{}' not found in MATCH pattern", alias))
            })
            .collect::<anyhow::Result<_>>()?;

        let head = Atom {
            relation: output_relation.to_string(),
            args: head_args,
        };

        let mut program = DatalogProgram::new();
        program.add_rule(DatalogRule { head, body });

        Ok(CompiledCypherMv {
            program,
            output_relation: output_relation.to_string(),
        })
    }
}

// ── Internal AST ─────────────────────────────────────────────────────────────

#[derive(Debug)]
struct NodeRef {
    alias: String,
    // label is parsed but intentionally ignored (schema-free)
    #[allow(dead_code)]
    label: Option<String>,
}

#[derive(Debug)]
struct EdgeRef {
    from:     String, // node alias on the left
    to:       String, // node alias on the right
    relation: String, // relation type (lowercased), or "*" for anonymous
}

#[derive(Debug)]
struct CypherQuery {
    nodes:       Vec<NodeRef>,         // deduplicated ordered nodes
    edges:       Vec<EdgeRef>,
    where_consts: Vec<(String, String)>, // (alias, constant_value)
    return_vars:  Vec<String>,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Top-level: parse a Cypher query string into a `CypherQuery`.
fn parse(input: &str) -> anyhow::Result<CypherQuery> {
    let upper = input.trim();

    // Require MATCH clause
    let upper_check = upper.to_uppercase();
    if !upper_check.starts_with("MATCH") {
        anyhow::bail!("query must start with MATCH; got: {}", &upper[..upper.len().min(20)]);
    }

    // Reject non-MATCH write operations
    for kw in &["CREATE", "DELETE", "MERGE", "SET "] {
        if upper_check.contains(kw) {
            anyhow::bail!("only MATCH/WHERE/RETURN is supported; found forbidden keyword '{kw}'");
        }
    }

    // Split into MATCH / WHERE / RETURN clauses (case-insensitive keyword split).
    //
    // Strategy: find each keyword, extract the content between keywords.
    //   "MATCH <match_body> [WHERE <where_body>] RETURN <return_body>"
    //
    // `split_clause_after(s, KW)` returns (text_before_KW, text_after_KW).
    // So text_after_MATCH contains "<match_body> [WHERE ...] RETURN ...".
    let (_, after_match) = split_clause_after(upper, "MATCH")?;

    // Look for RETURN in what follows MATCH (always present)
    let (before_return, return_str) = split_clause_after(&after_match, "RETURN")
        .map_err(|_| anyhow!("missing RETURN clause"))?;

    // Look for WHERE between MATCH and RETURN
    let (match_str, where_str) =
        if let Ok((before_where, after_where)) = split_clause_after(&before_return, "WHERE") {
            (before_where, Some(after_where))
        } else {
            (before_return, None)
        };

    let return_body = return_str.trim().to_string();

    // Parse MATCH path pattern
    let (nodes, edges) = parse_match_pattern(match_str.trim())?;

    // Parse WHERE
    let where_consts = if let Some(w) = where_str {
        parse_where(w.trim())?
    } else {
        vec![]
    };

    // Parse RETURN
    let return_vars = parse_return(&return_body)?;

    Ok(CypherQuery { nodes, edges, where_consts, return_vars })
}

/// Given `input` that contains `keyword` (case-insensitive), return
/// `(text_before_keyword, text_from_after_keyword_to_end)`.
/// Searches for the keyword at a word boundary.
fn split_clause_after(input: &str, keyword: &str) -> anyhow::Result<(String, String)> {
    let upper = input.to_uppercase();
    let kw_upper = keyword.to_uppercase();

    // Find keyword at start or after whitespace
    let mut pos = 0;
    loop {
        match upper[pos..].find(&kw_upper) {
            None => anyhow::bail!("keyword '{}' not found in: {}", keyword, &input[..input.len().min(60)]),
            Some(offset) => {
                let abs = pos + offset;
                // Verify word-boundary before and after
                let before_ok = abs == 0 || !upper.as_bytes()[abs - 1].is_ascii_alphanumeric();
                let after_pos = abs + kw_upper.len();
                let after_ok = after_pos >= upper.len() || !upper.as_bytes()[after_pos].is_ascii_alphanumeric();
                if before_ok && after_ok {
                    let before = input[..abs].to_string();
                    let after  = input[after_pos..].to_string();
                    return Ok((before, after));
                }
                pos = abs + 1;
            }
        }
    }
}

/// Parse the MATCH path pattern, e.g.:
///   `(a:Person)-[:KNOWS]->(b:Person)-[:LIKES]->(c)`
///   `(a)-[]->(b)`
///   `(a)-->(b)`
///
/// Returns (nodes_in_order, edges_in_order).  Nodes are deduplicated.
fn parse_match_pattern(s: &str) -> anyhow::Result<(Vec<NodeRef>, Vec<EdgeRef>)> {
    let mut nodes: Vec<NodeRef> = Vec::new();
    let mut seen_aliases: HashMap<String, ()> = HashMap::new();
    let mut edges: Vec<EdgeRef> = Vec::new();

    let mut chars = s.chars().peekable();

    // Expect first node
    let first = parse_node_pattern(&mut chars)?;
    if !seen_aliases.contains_key(&first.alias) {
        seen_aliases.insert(first.alias.clone(), ());
        nodes.push(NodeRef { alias: first.alias.clone(), label: first.label.clone() });
    }
    let mut prev_alias = first.alias;

    // Repeatedly consume an edge + node
    loop {
        skip_whitespace(&mut chars);
        match chars.peek() {
            None | Some('\n') | Some('\r') => break,
            Some('-') => {
                // Could be `-[...]->`, `-[]->`, or `-->` (anonymous)
                let (relation, _dir) = parse_edge_pattern(&mut chars)?;
                skip_whitespace(&mut chars);
                // Must be followed by a node
                if chars.peek() == Some(&'(') {
                    let next = parse_node_pattern(&mut chars)?;
                    if !seen_aliases.contains_key(&next.alias) {
                        seen_aliases.insert(next.alias.clone(), ());
                        nodes.push(NodeRef { alias: next.alias.clone(), label: next.label.clone() });
                    }
                    edges.push(EdgeRef {
                        from: prev_alias.clone(),
                        to: next.alias.clone(),
                        relation,
                    });
                    prev_alias = next.alias;
                } else {
                    break;
                }
            }
            _ => break,
        }
    }

    if nodes.is_empty() {
        anyhow::bail!("MATCH pattern produced no nodes");
    }

    Ok((nodes, edges))
}

/// Parse `(alias)` or `(alias:Label)`, returning `NodeRef`.
fn parse_node_pattern(chars: &mut std::iter::Peekable<std::str::Chars>) -> anyhow::Result<NodeRef> {
    skip_whitespace(chars);
    expect_char(chars, '(')?;

    let alias = read_identifier(chars);
    let alias = if alias.is_empty() { fresh_anon_alias() } else { alias };

    let label = if chars.peek() == Some(&':') {
        chars.next(); // consume ':'
        let lbl = read_identifier(chars);
        Some(lbl)
    } else {
        None
    };

    skip_whitespace(chars);
    expect_char(chars, ')')?;

    Ok(NodeRef { alias, label })
}

/// Parse `-[r:TYPE]->` or `-[:TYPE]->` or `-[]->` or `-->`.
/// Returns `(relation_name, direction)` where direction is always "forward" for our subset.
fn parse_edge_pattern(chars: &mut std::iter::Peekable<std::str::Chars>) -> anyhow::Result<(String, &'static str)> {
    skip_whitespace(chars);
    expect_char(chars, '-')?;

    skip_whitespace(chars);
    let relation = if chars.peek() == Some(&'[') {
        chars.next(); // '['
        // Optional variable name
        skip_whitespace(chars);
        if chars.peek() != Some(&':') && chars.peek() != Some(&']') {
            // variable name — skip it
            read_identifier(chars);
        }
        let rel = if chars.peek() == Some(&':') {
            chars.next(); // ':'
            let t = read_relation_type(chars);
            t.to_lowercase()
        } else {
            "*".to_string()
        };
        skip_whitespace(chars);
        expect_char(chars, ']')?;
        rel
    } else {
        // anonymous `-->`
        "*".to_string()
    };

    // Consume `->`
    skip_whitespace(chars);
    expect_char(chars, '-')?;
    skip_whitespace(chars);
    expect_char(chars, '>')?;

    Ok((relation, "forward"))
}

/// Parse WHERE clause — supports:
///   `alias.prop = "value"` (dot-qualified property)
///   `alias = "value"`      (bare alias constant substitution)
///   AND-chained conjunctions
fn parse_where(s: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut result = Vec::new();

    // Split on AND (case-insensitive)
    let parts = split_and(s);
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Find '='
        let eq_pos = part.find('=').ok_or_else(|| anyhow!("WHERE condition must be an equality: {part}"))?;
        let lhs = part[..eq_pos].trim();
        let rhs = part[eq_pos + 1..].trim();

        // LHS: alias.prop or alias
        let alias = if let Some(dot) = lhs.find('.') {
            lhs[..dot].trim().to_string()
        } else {
            lhs.to_string()
        };

        // RHS: string literal (single or double quoted)
        let value = parse_string_literal(rhs)
            .ok_or_else(|| anyhow!("WHERE value must be a quoted string literal; got: {rhs}"))?;

        result.push((alias, value));
    }

    Ok(result)
}

/// Parse RETURN clause — comma-separated variable names.
fn parse_return(s: &str) -> anyhow::Result<Vec<String>> {
    let vars: Vec<String> = s
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    Ok(vars)
}

// ── VarMap ────────────────────────────────────────────────────────────────────

enum Slot {
    Var(String),
    Const(String),
}

struct VarMap {
    slots:   HashMap<String, Slot>,
    counter: usize,
}

impl VarMap {
    fn new() -> Self {
        Self { slots: HashMap::new(), counter: 0 }
    }

    /// Assign a fresh Datalog variable name for `alias`.
    fn register(&mut self, alias: &str) {
        let v = format!("V{}", self.counter);
        self.counter += 1;
        self.slots.insert(alias.to_string(), Slot::Var(v));
    }

    /// Replace every occurrence of the variable for `alias` with a constant.
    fn set_const(&mut self, alias: &str, value: String) {
        let old_var = match self.slots.get(alias) {
            Some(Slot::Var(v)) => v.clone(),
            _ => return, // already a const or not found — ignore
        };
        for slot in self.slots.values_mut() {
            if let Slot::Var(v) = slot {
                if *v == old_var {
                    *slot = Slot::Const(value.clone());
                }
            }
        }
    }

    fn to_term(&self, alias: &str) -> Option<Term> {
        match self.slots.get(alias)? {
            Slot::Var(v)   => Some(Term::Variable(v.clone())),
            Slot::Const(c) => Some(Term::Constant(c.clone())),
        }
    }
}

// ── Lexer helpers ─────────────────────────────────────────────────────────────

fn skip_whitespace(chars: &mut std::iter::Peekable<std::str::Chars>) {
    while chars.peek().map_or(false, |c| c.is_whitespace()) {
        chars.next();
    }
}

fn expect_char(chars: &mut std::iter::Peekable<std::str::Chars>, expected: char) -> anyhow::Result<()> {
    match chars.next() {
        Some(c) if c == expected => Ok(()),
        Some(c) => anyhow::bail!("expected '{expected}', got '{c}'"),
        None    => anyhow::bail!("expected '{expected}', got end-of-input"),
    }
}

fn read_identifier(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    let mut s = String::new();
    while chars.peek().map_or(false, |c| c.is_alphanumeric() || *c == '_') {
        s.push(chars.next().unwrap());
    }
    s
}

/// Read a relation type — allow alphanumeric, `_`, and `-` (e.g. KNOWS, HAS-TYPE).
fn read_relation_type(chars: &mut std::iter::Peekable<std::str::Chars>) -> String {
    let mut s = String::new();
    while chars.peek().map_or(false, |c| c.is_alphanumeric() || *c == '_' || *c == '-') {
        s.push(chars.next().unwrap());
    }
    s
}

/// Parse a string literal enclosed in `"` or `'`. Returns the content without quotes.
fn parse_string_literal(s: &str) -> Option<String> {
    let s = s.trim();
    let (open, close) = if s.starts_with('"') {
        ('"', '"')
    } else if s.starts_with('\'') {
        ('\'', '\'')
    } else {
        return None;
    };
    if s.len() < 2 { return None; }
    let inner = &s[1..];
    let end = inner.find(close)?;
    Some(inner[..end].to_string())
}

/// Split `s` on case-insensitive `AND` at word boundaries.
fn split_and(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let upper = s.to_uppercase();
    let mut start = 0usize;
    let mut i = 0usize;

    while i < upper.len() {
        if upper[i..].starts_with("AND") {
            let before_ok = i == 0 || !upper.as_bytes()[i - 1].is_ascii_alphanumeric();
            let after_pos = i + 3;
            let after_ok = after_pos >= upper.len() || !upper.as_bytes()[after_pos].is_ascii_alphanumeric();
            if before_ok && after_ok {
                result.push(s[start..i].to_string());
                start = after_pos;
                i = start;
                continue;
            }
        }
        i += 1;
    }
    result.push(s[start..].to_string());
    result
}

/// Counter for generating unique anonymous alias names.
fn fresh_anon_alias() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    format!("__anon{}", COUNTER.fetch_add(1, Ordering::Relaxed))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        delta::Delta,
        quad::{Quad, QuadObject},
    };
    use kotoba_core::cid::KotobaCid;

    fn cid(s: &str) -> KotobaCid {
        KotobaCid::from_bytes(s.as_bytes())
    }

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

    // 1. simple_match_two_hops
    #[test]
    fn simple_match_two_hops() {
        let mv = CypherCompiler::compile(
            "MATCH (a)-[:knows]->(b) RETURN a, b",
            "output",
        )
        .unwrap();
        let input = vec![fact("knows", "alice", "bob")];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "bob"));
    }

    // 2. match_with_node_labels_ignored
    #[test]
    fn match_with_node_labels_ignored() {
        let mv = CypherCompiler::compile(
            "MATCH (a:Person)-[:knows]->(b:Person) RETURN a, b",
            "output",
        )
        .unwrap();
        let input = vec![fact("knows", "alice", "bob")];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "bob"),
            "node labels should be ignored; relation 'knows' must still match");
    }

    // 3. match_chain_three_nodes — projects the first and last variable
    #[test]
    fn match_chain_three_nodes() {
        let mv = CypherCompiler::compile(
            "MATCH (a)-[:knows]->(b)-[:likes]->(c) RETURN a, c",
            "a_likes_c",
        )
        .unwrap();

        let input = vec![
            fact("knows", "alice", "bob"),
            fact("likes", "bob",   "carol"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "a_likes_c", "alice", "carol"),
            "expected transitive a_likes_c(alice, carol)");
        // Intermediate variable b should not leak into output
        assert!(!has(&derived, "a_likes_c", "alice", "bob"));
    }

    // 4. where_constant_filter — WHERE a.name = "alice"
    #[test]
    fn where_constant_filter() {
        let mv = CypherCompiler::compile(
            r#"MATCH (a)-[:knows]->(b) WHERE a.name = "alice" RETURN a, b"#,
            "output",
        )
        .unwrap();

        let input = vec![
            fact("knows", "alice", "bob"),
            fact("knows", "carol", "dave"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "bob"),
            "alice->bob should match");
        assert!(!has(&derived, "output", "carol", "dave"),
            "carol->dave should be filtered out");
    }

    // 5. wrong_arity_one_var_errors — RETURN with only 1 variable
    #[test]
    fn wrong_arity_one_var_errors() {
        let result = CypherCompiler::compile(
            "MATCH (a)-[:knows]->(b) RETURN a",
            "output",
        );
        assert!(result.is_err(), "single-variable RETURN should fail arity check");
    }

    // 6. wrong_arity_three_vars_errors — RETURN with 3 variables
    #[test]
    fn wrong_arity_three_vars_errors() {
        let result = CypherCompiler::compile(
            "MATCH (a)-[:knows]->(b)-[:likes]->(c) RETURN a, b, c",
            "output",
        );
        assert!(result.is_err(), "three-variable RETURN should fail arity check");
    }

    // 7. non_match_query_errors — query without MATCH
    #[test]
    fn non_match_query_errors() {
        let result = CypherCompiler::compile(
            "RETURN a, b",
            "output",
        );
        assert!(result.is_err(), "query without MATCH should fail");
    }

    // 8. relation_name_from_type — relation type becomes Datalog predicate (lowercased)
    #[test]
    fn relation_name_from_type() {
        let mv = CypherCompiler::compile(
            "MATCH (a)-[:FRIENDS_WITH]->(b) RETURN a, b",
            "friends",
        )
        .unwrap();

        // The predicate stored in DatalogRule body should be lowercased relation type
        let rule = &mv.program.rules[0];
        assert_eq!(rule.head.relation, "friends");
        assert_eq!(rule.body.len(), 1);
        if let BodyLiteral::Positive(atom) = &rule.body[0] {
            assert_eq!(atom.relation, "friends_with",
                "relation type 'FRIENDS_WITH' should become 'friends_with' in body atom");
        } else {
            panic!("expected positive body literal");
        }
    }

    // Bonus: upper-case KNOWS is lowercased correctly
    #[test]
    fn upper_case_relation_lowercased() {
        let mv = CypherCompiler::compile(
            "MATCH (a)-[:KNOWS]->(b) RETURN a, b",
            "output",
        )
        .unwrap();
        let input = vec![fact("knows", "alice", "bob")];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "bob"),
            "KNOWS should be lowercased to 'knows' and match fact");
    }

    // Bonus: chain with WHERE filter on middle node
    #[test]
    fn chain_where_middle_node() {
        let mv = CypherCompiler::compile(
            r#"MATCH (a)-[:knows]->(b)-[:likes]->(c) WHERE b.name = "bob" RETURN a, c"#,
            "output",
        )
        .unwrap();
        let input = vec![
            fact("knows", "alice", "bob"),
            fact("knows", "alice", "mallory"),
            fact("likes", "bob",   "carol"),
            fact("likes", "mallory", "eve"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "carol"));
        assert!(!has(&derived, "output", "alice", "eve"),
            "mallory path should be filtered since WHERE b.name='bob' applies to b");
    }
}
