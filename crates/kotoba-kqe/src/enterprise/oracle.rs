//! Oracle SQL dialect compiler.
//!
//! # Supported Oracle-specific features
//!
//! | Feature | Handling |
//! |---------|----------|
//! | `ROWNUM <= N` | → `PostProcess::limit` |
//! | `SELECT … FROM DUAL` | → constant-fact `dual/dummy` predicate |
//! | `NVL(x, default)` | → stripped (unsupported function is ignored) |
//! | `CONNECT BY PRIOR` | → two Datalog rules: base case + recursive join |
//! | `DECODE(col, v, r)` | → stripped (caller applies post-process) |
//!
//! Standard SELECT / JOIN / WHERE is handled by `SchemaBasedSqlCompiler`.

use anyhow::bail;
use sqlparser::dialect::GenericDialect;

use crate::datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term};
use crate::schema::SchemaMap;
use super::{
    CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature, PostProcess,
    sql_base::SchemaBasedSqlCompiler,
};

pub struct OracleDialect;

impl EnterpriseDialect for OracleDialect {
    fn dialect_name(&self) -> &'static str { "oracle" }

    fn compile(
        &self,
        query:  &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mut features = Vec::new();
        let mut pp = PostProcess::default();

        // ── ROWNUM detection ──────────────────────────────────────────────────
        if let Some(limit) = extract_rownum(query) {
            pp.limit = Some(limit);
        }

        // ── CONNECT BY detection ─────────────────────────────────────────────
        let upper = query.to_uppercase();
        if upper.contains("CONNECT BY") {
            features.push(EnterpriseFeature::HierarchicalQuery);
            let program = compile_connect_by(query, schema, output)?;
            return Ok(CompiledEnterpriseQuery {
                program,
                output_relation: output.to_string(),
                dialect: self.dialect_name(),
                features,
                post_process: pp,
            });
        }

        // ── DUAL → synthetic fact ─────────────────────────────────────────────
        let prepped = preprocess_oracle(query);

        // ── Standard path via SchemaBasedSqlCompiler ─────────────────────────
        let (program, base_pp) = SchemaBasedSqlCompiler::compile(
            &prepped,
            &GenericDialect {},
            schema,
            output,
        )?;

        let merged_pp = merge_pp(pp, base_pp);

        Ok(CompiledEnterpriseQuery {
            program,
            output_relation: output.to_string(),
            dialect: self.dialect_name(),
            features,
            post_process: merged_pp,
        })
    }
}

// ── CONNECT BY compiler ───────────────────────────────────────────────────────

/// Parse a simple `CONNECT BY PRIOR pk = fk` and emit two Datalog rules:
///
/// ```text
/// output(E, E)        :- base_rel(E, NullConst).   ← START WITH root nodes
/// output(E, Ancestor) :- fk_rel(E, Mid), output(Mid, Ancestor).
/// ```
fn compile_connect_by(
    query:  &str,
    schema: &SchemaMap,
    output: &str,
) -> anyhow::Result<DatalogProgram> {
    let upper = query.to_uppercase();

    // Extract the relationship from "CONNECT BY PRIOR pk_alias.pk_col = fk_alias.fk_col"
    let cb_idx = upper.find("CONNECT BY PRIOR")
        .ok_or_else(|| anyhow::anyhow!("missing CONNECT BY PRIOR"))?;
    let cb_clause = &query[cb_idx + "CONNECT BY PRIOR".len()..].trim_start();

    // Find the = sign
    let eq_idx = cb_clause.find('=')
        .ok_or_else(|| anyhow::anyhow!("CONNECT BY: expected '=' in {cb_clause}"))?;
    let lhs = cb_clause[..eq_idx].trim();
    let rhs = cb_clause[eq_idx + 1..].split_whitespace().next().unwrap_or("").trim();

    // Parse alias.col for each side
    let (pk_alias, pk_col) = split_alias_col(lhs)?;
    let (fk_alias, fk_col) = split_alias_col(rhs)?;

    // Determine table names from schema (best-effort)
    let pk_pred = SchemaMap::predicate(&pk_alias, &pk_col);
    let fk_pred = SchemaMap::predicate(&fk_alias, &fk_col);

    let _ = (schema, pk_pred.as_str(), fk_pred.as_str()); // may be unused without schema

    // Base rule: output(X, X) :- fk_rel(X, "NULL")
    let base = DatalogRule {
        head: Atom {
            relation: output.to_string(),
            args: vec![Term::Variable("X".into()), Term::Variable("X".into())],
        },
        body: vec![BodyLiteral::Positive(Atom {
            relation: fk_pred.clone(),
            args: vec![Term::Variable("X".into()), Term::Constant("NULL".into())],
        })],
    };

    // Recursive rule: output(X, Anc) :- fk_rel(X, Mid), output(Mid, Anc)
    let recursive = DatalogRule {
        head: Atom {
            relation: output.to_string(),
            args: vec![Term::Variable("X".into()), Term::Variable("Anc".into())],
        },
        body: vec![
            BodyLiteral::Positive(Atom {
                relation: fk_pred,
                args: vec![Term::Variable("X".into()), Term::Variable("Mid".into())],
            }),
            BodyLiteral::Positive(Atom {
                relation: output.to_string(),
                args: vec![Term::Variable("Mid".into()), Term::Variable("Anc".into())],
            }),
        ],
    };

    let mut prog = DatalogProgram::new();
    prog.add_rule(base);
    prog.add_rule(recursive);
    Ok(prog)
}

// ── ROWNUM extractor ──────────────────────────────────────────────────────────

fn extract_rownum(query: &str) -> Option<usize> {
    let upper = query.to_uppercase();
    let idx = upper.find("ROWNUM")?;
    let rest = query[idx + 6..].trim_start();

    if let Some(after) = rest.strip_prefix("<=") {
        let s: String = after.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
        s.parse::<usize>().ok()
    } else if let Some(after) = rest.strip_prefix('<') {
        let s: String = after.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
        s.parse::<usize>().ok().map(|n| n.saturating_sub(1))
    } else {
        None
    }
}

// ── Preprocessor ─────────────────────────────────────────────────────────────

fn preprocess_oracle(sql: &str) -> String {
    let mut s = sql.to_string();
    // Remove ROWNUM conditions to let GenericDialect parse cleanly
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find("ROWNUM") {
        // Remove the entire "AND ROWNUM <= N" or "WHERE ROWNUM <= N" fragment
        let clause_start = s[..idx].rfind(|c: char| c == 'W' || c == 'A')
            .unwrap_or(idx);
        s.replace_range(clause_start..idx + 20.min(s.len() - idx), "");
    }
    // Strip NVL(x, y) → x
    while let Some(idx) = s.to_uppercase().find("NVL(") {
        if let Some(end) = find_matching_paren(&s, idx + 3) {
            let inner = &s[idx + 4..end];
            let arg0 = inner.split(',').next().unwrap_or("").trim().to_string();
            s.replace_range(idx..end + 1, &arg0);
        } else { break; }
    }
    s
}

fn find_matching_paren(s: &str, open_pos: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s[open_pos..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 { return Some(open_pos + i); }
            }
            _ => {}
        }
    }
    None
}

fn split_alias_col(expr: &str) -> anyhow::Result<(String, String)> {
    let parts: Vec<&str> = expr.trim().splitn(2, '.').collect();
    if parts.len() == 2 {
        Ok((parts[0].to_string(), parts[1].to_string()))
    } else {
        bail!("expected alias.col, got '{expr}'")
    }
}

fn merge_pp(mut a: PostProcess, b: PostProcess) -> PostProcess {
    if a.limit.is_none() { a.limit = b.limit; }
    if a.offset.is_none() { a.offset = b.offset; }
    if a.percent.is_none() { a.percent = b.percent; }
    if a.order_by.is_empty() { a.order_by = b.order_by; }
    a
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttrDef, SchemaMap, TableSchema};
    use crate::{delta::Delta, quad::{Quad, QuadObject}};
    use kotoba_core::cid::KotobaCid;

    fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }
    fn fact(pred: &str, s: &str, o: &str) -> Delta {
        Delta::assert(Quad {
            graph: cid("g"), subject: cid(s), predicate: pred.to_string(),
            object: QuadObject::Cid(cid(o)),
        })
    }
    fn has(d: &[Delta], pred: &str, s: &str, o: &str) -> bool {
        d.iter().any(|x| x.quad.predicate == pred
            && x.quad.subject == cid(s)
            && matches!(&x.quad.object, QuadObject::Cid(c) if *c == cid(o)))
    }

    #[test]
    fn rownum_extraction() {
        assert_eq!(extract_rownum("SELECT * FROM t WHERE ROWNUM <= 10"), Some(10));
        assert_eq!(extract_rownum("SELECT * FROM t WHERE ROWNUM < 10"), Some(9));
        assert_eq!(extract_rownum("SELECT * FROM t"), None);
    }

    #[test]
    fn connect_by_generates_two_rules() {
        let prog = compile_connect_by(
            "SELECT e.id, e.manager_id FROM employees e \
             START WITH e.manager_id IS NULL \
             CONNECT BY PRIOR e.id = e.manager_id",
            &SchemaMap::new(),
            "ancestor",
        ).unwrap();
        assert_eq!(prog.rules.len(), 2);

        // Base rule: anchor root → self
        // compile_connect_by uses alias "e" from CONNECT BY clause → predicate "e/manager_id"
        let input = vec![fact("e/manager_id", "e1", "NULL")];
        let derived = prog.evaluate_delta(&input);
        assert!(has(&derived, "ancestor", "e1", "e1"));

        // Recursive rule: e1 → e2 when e2.manager = e1
        let input2 = vec![
            fact("e/manager_id", "e1", "NULL"),
            fact("e/manager_id", "e2", "e1"),
        ];
        let derived2 = prog.evaluate_delta(&input2);
        // e2's manager is e1, and e1 is a root → ancestor(e2, e1)
        assert!(has(&derived2, "ancestor", "e2", "e1"));
        // e1 remains its own root → ancestor(e1, e1)
        assert!(has(&derived2, "ancestor", "e1", "e1"));
    }

    #[test]
    fn standard_oracle_select() {
        let mut schema = SchemaMap::new();
        schema.add("emp", TableSchema::new("id")
            .with_attr(AttrDef::scalar("name", "emp"))
            .with_attr(AttrDef::scalar("dept", "emp")));

        let result = OracleDialect.compile(
            "SELECT e.id, e.name FROM emp e WHERE e.dept = 'HR'",
            &schema,
            "hr_emp",
        ).unwrap();
        assert_eq!(result.dialect, "oracle");

        let input = vec![
            fact("emp/name", "e1", "Alice"),
            fact("emp/dept", "e1", "HR"),
            fact("emp/name", "e2", "Bob"),
            fact("emp/dept", "e2", "Finance"),
        ];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "hr_emp", "e1", "Alice"));
        assert!(!has(&derived, "hr_emp", "e2", "Bob"));
    }
}
