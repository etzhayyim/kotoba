//! SQL SELECT → Datalog rule compiler for kotoba-kqe
//!
//! Supported subset:
//!   SELECT a.s, b.o
//!   FROM rel_a [AS a] [JOIN rel_b [AS b] ON a.col = b.col]
//!   [WHERE alias.col = 'constant']
//!
//! Tables are binary predicates with two columns: `s` (subject CID) and `o` (object CID).
//! The compiler translates each SELECT into a single Datalog rule whose head predicate
//! is `output_relation`.

use anyhow::anyhow;
use sqlparser::ast::{
    BinaryOperator, Expr, Ident, JoinConstraint, JoinOperator, SelectItem, SetExpr,
    Statement, TableFactor, Value,
};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::collections::HashMap;

use crate::datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term};

// ── Public types ─────────────────────────────────────────────────────────────

pub struct CompiledSqlMv {
    pub program: DatalogProgram,
    pub output_relation: String,
}

pub struct SqlMvCompiler;

impl SqlMvCompiler {
    /// Compile a SQL SELECT into a `DatalogProgram` for use as a `MaterializedView`.
    ///
    /// `output_relation` becomes the head predicate.  The SELECT must project
    /// exactly 2 columns (the kotoba binary-relation arity invariant).
    pub fn compile(sql: &str, output_relation: &str) -> anyhow::Result<CompiledSqlMv> {
        let statements = Parser::parse_sql(&GenericDialect {}, sql)
            .map_err(|e| anyhow!("SQL parse error: {e}"))?;

        let query = match statements.into_iter().next() {
            Some(Statement::Query(q)) => q,
            Some(other) => anyhow::bail!("expected SELECT, got {other:?}"),
            None => anyhow::bail!("empty SQL"),
        };

        let select = match *query.body {
            SetExpr::Select(s) => *s,
            _ => anyhow::bail!("only simple SELECT is supported"),
        };

        let mut var_map = VarMap::new();
        let mut tables: Vec<(String, String)> = Vec::new(); // (table_name, alias)

        // ── 1. Register all tables (FROM + JOINs) ────────────────────────────
        for twj in &select.from {
            let (tname, alias) = extract_table_alias(&twj.relation)?;
            let alias = alias.unwrap_or_else(|| tname.clone());
            var_map.register(&alias);
            tables.push((tname, alias.clone()));

            for join in &twj.joins {
                let (jname, jalias) = extract_table_alias(&join.relation)?;
                let jalias = jalias.unwrap_or_else(|| jname.clone());
                var_map.register(&jalias);
                tables.push((jname, jalias));
            }
        }

        // ── 2. Apply JOIN ON conditions (variable merging) ───────────────────
        for twj in &select.from {
            for join in &twj.joins {
                if let JoinOperator::Inner(JoinConstraint::On(expr)) = &join.join_operator {
                    apply_on(expr, &mut var_map)?;
                }
            }
        }

        // ── 3. Apply WHERE (constant substitution) ───────────────────────────
        if let Some(where_expr) = &select.selection {
            apply_where(where_expr, &mut var_map)?;
        }

        // ── 4. Build body atoms ───────────────────────────────────────────────
        let body: Vec<BodyLiteral> = tables
            .iter()
            .map(|(tname, alias)| {
                let s = var_map.to_term(alias, "s").unwrap();
                let o = var_map.to_term(alias, "o").unwrap();
                BodyLiteral::Positive(Atom {
                    relation: tname.clone(),
                    args: vec![s, o],
                })
            })
            .collect();

        // ── 5. Build head from SELECT projection ─────────────────────────────
        let head_args = build_head_args(&select.projection, &var_map, &tables)?;
        anyhow::ensure!(
            head_args.len() == 2,
            "SELECT must project exactly 2 columns (s and o) for kotoba binary Datalog; got {}",
            head_args.len()
        );

        let head = Atom {
            relation: output_relation.to_string(),
            args: head_args,
        };

        let mut program = DatalogProgram::new();
        program.add_rule(DatalogRule { head, body });

        Ok(CompiledSqlMv {
            program,
            output_relation: output_relation.to_string(),
        })
    }
}

// ── Internal VarMap ───────────────────────────────────────────────────────────

enum Slot {
    Var(String),
    Const(String),
}

/// Maps `"alias.col"` → `Slot`.  Shared variables (from JOIN ON) and constant
/// substitutions (from WHERE) are propagated by mutating the map in place.
struct VarMap {
    slots: HashMap<String, Slot>,
    counter: usize,
}

impl VarMap {
    fn new() -> Self {
        Self { slots: HashMap::new(), counter: 0 }
    }

    /// Assign fresh `(S{N}, O{N})` variables for `alias`.
    fn register(&mut self, alias: &str) {
        let s = format!("S{}", self.counter);
        let o = format!("O{}", self.counter);
        self.counter += 1;
        self.slots.insert(format!("{alias}.s"), Slot::Var(s));
        self.slots.insert(format!("{alias}.o"), Slot::Var(o));
    }

    /// Merge: replace every `Slot::Var(var_b)` with `Slot::Var(var_a)`.
    /// Used to unify join columns: `ON a.o = b.s` → b.s shares a.o's variable.
    fn merge(&mut self, alias_a: &str, col_a: &str, alias_b: &str, col_b: &str) {
        let var_a = match self.slots.get(&format!("{alias_a}.{col_a}")) {
            Some(Slot::Var(v)) => v.clone(),
            _ => return,
        };
        let var_b = match self.slots.get(&format!("{alias_b}.{col_b}")) {
            Some(Slot::Var(v)) => v.clone(),
            _ => return,
        };
        for slot in self.slots.values_mut() {
            if let Slot::Var(v) = slot {
                if *v == var_b {
                    *v = var_a.clone();
                }
            }
        }
    }

    /// Replace every `Slot::Var(old_var)` with `Slot::Const(value)`.
    /// Used to push WHERE equality constants into the body atoms.
    fn set_const(&mut self, alias: &str, col: &str, value: String) {
        let old_var = match self.slots.get(&format!("{alias}.{col}")) {
            Some(Slot::Var(v)) => v.clone(),
            _ => return,
        };
        for slot in self.slots.values_mut() {
            if let Slot::Var(v) = slot {
                if *v == old_var {
                    *slot = Slot::Const(value.clone());
                }
            }
        }
    }

    fn to_term(&self, alias: &str, col: &str) -> Option<Term> {
        match self.slots.get(&format!("{alias}.{col}"))? {
            Slot::Var(v) => Some(Term::Variable(v.clone())),
            Slot::Const(c) => Some(Term::Constant(c.clone())),
        }
    }


}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_table_alias(factor: &TableFactor) -> anyhow::Result<(String, Option<String>)> {
    match factor {
        TableFactor::Table { name, alias, .. } => {
            let tname = name.0.iter().map(|i: &Ident| i.value.as_str()).collect::<Vec<_>>().join(".");
            let alias = alias.as_ref().map(|a| a.name.value.clone());
            Ok((tname, alias))
        }
        _ => anyhow::bail!("only simple table references are supported; got {factor:?}"),
    }
}

fn apply_on(expr: &Expr, var_map: &mut VarMap) -> anyhow::Result<()> {
    match expr {
        Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
            let (la, lc) = extract_alias_col(left)?;
            let (ra, rc) = extract_alias_col(right)?;
            var_map.merge(&la, &lc, &ra, &rc);
            Ok(())
        }
        _ => anyhow::bail!("JOIN ON only supports `alias.col = alias.col`; got {expr:?}"),
    }
}

fn apply_where(expr: &Expr, var_map: &mut VarMap) -> anyhow::Result<()> {
    match expr {
        Expr::BinaryOp { left, op: BinaryOperator::Eq, right } => {
            let (alias, col) = extract_alias_col(left)?;
            let value = expr_to_const(right)?;
            if alias == "_" {
                // Bare column name: find the unique table that has it.
                let matching: Vec<String> = var_map
                    .slots
                    .keys()
                    .filter(|k| k.ends_with(&format!(".{col}")))
                    .map(|k| k[..k.len() - col.len() - 1].to_string())
                    .collect();
                match matching.len() {
                    0 => anyhow::bail!("WHERE: column '{col}' not found in any table"),
                    1 => var_map.set_const(&matching[0], &col, value),
                    _ => anyhow::bail!(
                        "WHERE: column '{col}' is ambiguous across multiple tables; use alias.col"
                    ),
                }
            } else {
                var_map.set_const(&alias, &col, value);
            }
            Ok(())
        }
        Expr::BinaryOp { left, op: BinaryOperator::And, right } => {
            apply_where(left, var_map)?;
            apply_where(right, var_map)
        }
        _ => anyhow::bail!("WHERE only supports equality conditions; got {expr:?}"),
    }
}

fn extract_alias_col(expr: &Expr) -> anyhow::Result<(String, String)> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            Ok((parts[0].value.clone(), parts[1].value.clone()))
        }
        Expr::Identifier(ident) => Ok(("_".to_string(), ident.value.clone())),
        _ => anyhow::bail!("expected alias.col or bare column name; got {expr:?}"),
    }
}

fn expr_to_const(expr: &Expr) -> anyhow::Result<String> {
    match expr {
        Expr::Value(Value::SingleQuotedString(s)) => Ok(s.clone()),
        Expr::Value(Value::Number(n, _)) => Ok(n.clone()),
        _ => anyhow::bail!("only string/number literals supported as WHERE constants; got {expr:?}"),
    }
}

fn build_head_args(
    projection: &[SelectItem],
    var_map: &VarMap,
    tables: &[(String, String)],
) -> anyhow::Result<Vec<Term>> {
    let mut args = Vec::new();
    for item in projection {
        match item {
            SelectItem::UnnamedExpr(expr) => {
                args.push(resolve_select_expr(expr, var_map, tables)?);
            }
            SelectItem::ExprWithAlias { expr, .. } => {
                args.push(resolve_select_expr(expr, var_map, tables)?);
            }
            _ => anyhow::bail!("SELECT * is not supported; list columns explicitly"),
        }
    }
    Ok(args)
}

fn resolve_select_expr(
    expr: &Expr,
    var_map: &VarMap,
    tables: &[(String, String)],
) -> anyhow::Result<Term> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            let alias = &parts[0].value;
            let col = &parts[1].value;
            var_map
                .to_term(alias, col)
                .ok_or_else(|| anyhow!("unknown column {alias}.{col}"))
        }
        Expr::Identifier(ident) => {
            let col = &ident.value;
            let matches: Vec<Term> = tables
                .iter()
                .filter_map(|(_, alias)| var_map.to_term(alias, col))
                .collect();
            match matches.len() {
                0 => anyhow::bail!("column '{col}' not found in any table"),
                1 => Ok(matches.into_iter().next().unwrap()),
                _ => anyhow::bail!(
                    "column '{col}' is ambiguous across multiple tables; use alias.col"
                ),
            }
        }
        _ => anyhow::bail!("unsupported SELECT expression: {expr:?}"),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{delta::Delta, quad::{Quad, QuadObject}};
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

    #[test]
    fn simple_select_no_alias() {
        // SELECT s, o FROM knows  →  output(S, O) :- knows(S, O).
        let mv = SqlMvCompiler::compile("SELECT s, o FROM knows", "output").unwrap();
        let input = vec![fact("knows", "alice", "bob")];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "bob"));
    }

    #[test]
    fn simple_select_with_alias() {
        let mv = SqlMvCompiler::compile("SELECT k.s, k.o FROM knows k", "output").unwrap();
        let input = vec![fact("knows", "alice", "bob")];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "output", "alice", "bob"));
    }

    #[test]
    fn join_two_tables() {
        // ancestor(S, O) :- parent(S, Mid), parent(Mid, O).
        let mv = SqlMvCompiler::compile(
            "SELECT a.s, b.o FROM parent a JOIN parent b ON a.o = b.s",
            "ancestor",
        )
        .unwrap();

        let input = vec![
            fact("parent", "alice", "bob"),
            fact("parent", "bob", "carol"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "ancestor", "alice", "carol"), "expected ancestor(alice, carol)");
        // no spurious derivations
        assert!(!has(&derived, "ancestor", "bob", "alice"));
    }

    #[test]
    fn where_constant_with_alias() {
        // alice_knows(S, O) :- knows(Const("alice"), O), S = Const("alice") in head
        let mv = SqlMvCompiler::compile(
            "SELECT a.s, a.o FROM knows a WHERE a.s = 'alice'",
            "alice_knows",
        )
        .unwrap();

        let input = vec![
            fact("knows", "alice", "bob"),
            fact("knows", "carol", "dave"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "alice_knows", "alice", "bob"));
        assert!(!has(&derived, "alice_knows", "carol", "dave"));
    }

    #[test]
    fn where_bare_column() {
        let mv = SqlMvCompiler::compile(
            "SELECT s, o FROM knows WHERE s = 'alice'",
            "alice_knows",
        )
        .unwrap();

        let input = vec![
            fact("knows", "alice", "bob"),
            fact("knows", "carol", "dave"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        assert!(has(&derived, "alice_knows", "alice", "bob"));
        assert!(!has(&derived, "alice_knows", "carol", "dave"));
    }

    #[test]
    fn wrong_arity_error() {
        let result = SqlMvCompiler::compile("SELECT a.s FROM knows a", "output");
        assert!(result.is_err(), "single-column SELECT should fail");
    }

    #[test]
    fn unknown_column_error() {
        let result = SqlMvCompiler::compile("SELECT a.x, a.y FROM knows a", "output");
        assert!(result.is_err());
    }

    #[test]
    fn wildcard_error() {
        let result = SqlMvCompiler::compile("SELECT * FROM knows", "output");
        assert!(result.is_err());
    }

    // ── Additional edge-case tests ─────────────────────────────────────────────

    #[test]
    fn where_and_conjunction() {
        // WHERE with AND: both conditions must apply simultaneously
        let mv = SqlMvCompiler::compile(
            "SELECT a.s, b.o FROM parent a JOIN parent b ON a.o = b.s WHERE a.s = 'alice' AND b.o = 'carol'",
            "filtered",
        )
        .unwrap();
        let input = vec![
            fact("parent", "alice", "bob"),
            fact("parent", "bob",   "carol"),
            fact("parent", "alice", "bob2"),
            fact("parent", "bob2",  "dave"),
        ];
        let derived = mv.program.evaluate_delta(&input);
        // Only alice→carol path satisfies both conditions
        assert!(has(&derived, "filtered", "alice", "carol"));
        assert!(!has(&derived, "filtered", "alice", "dave"),
            "dave path should be filtered by b.o = 'carol'");
    }

    #[test]
    fn where_number_literal() {
        // WHERE with a numeric constant (sqlparser parses it as Value::Number)
        let result = SqlMvCompiler::compile(
            "SELECT a.s, a.o FROM knows a WHERE a.s = 42",
            "output",
        );
        // Should compile without error — number literal becomes a constant Term
        assert!(result.is_ok(), "numeric WHERE literal should compile");
    }

    #[test]
    fn non_select_statement_error() {
        // INSERT is not a SELECT — the compiler must reject it
        let result = SqlMvCompiler::compile(
            "INSERT INTO knows (s, o) VALUES ('alice', 'bob')",
            "output",
        );
        assert!(result.is_err(), "INSERT statement should be rejected");
    }
}
