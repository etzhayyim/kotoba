//! Schema-based SQL → Datalog compiler shared across all SQL enterprise dialects.
//!
//! Unlike the original `SqlMvCompiler` (which assumes two-column binary tables
//! with columns `s` and `o`), this compiler handles arbitrary N-column tables
//! by consulting `SchemaMap`.  Every attribute access becomes a separate binary
//! predicate atom in the Datalog body.
//!
//! # Compilation model
//!
//! For a registered table `orders(id, customer_id, amount, status)`:
//!
//! ```sql
//! SELECT c.name, o.amount
//! FROM customers c
//! JOIN orders o ON c.id = o.customer_id
//! WHERE o.status = 'active'
//! ```
//!
//! becomes:
//!
//! ```text
//! output(V_c_name, V_o_amount) :-
//!   customers/name(E_c, V_c_name),
//!   orders/customer_id(E_o, E_c),   ← FK join
//!   orders/amount(E_o, V_o_amount),
//!   orders/status(E_o, "active").   ← WHERE constant
//! ```
//!
//! Unregistered tables fall back to the two-column `s`/`o` assumption.

use std::collections::HashMap;

use anyhow::{anyhow, bail};
use sqlparser::ast::{
    BinaryOperator, Expr, Fetch, Ident, JoinConstraint, JoinOperator, OrderByExpr, SelectItem,
    SetExpr, Statement, TableFactor, Top, TopQuantity, Value,
};
use sqlparser::dialect::Dialect;
use sqlparser::parser::Parser;

use super::PostProcess;
use crate::datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term};
use crate::schema::{AttrKind, SchemaMap};

// ── Public entry point ────────────────────────────────────────────────────────

pub struct SchemaBasedSqlCompiler;

impl SchemaBasedSqlCompiler {
    /// Compile `sql` using the supplied sqlparser `dialect` and `schema`.
    ///
    /// Returns the `DatalogProgram` (exactly one rule) and a `PostProcess` for
    /// LIMIT / ORDER BY directives that cannot be expressed in Datalog.
    pub fn compile(
        sql: &str,
        dialect: &dyn Dialect,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<(DatalogProgram, PostProcess)> {
        let stmts = Parser::parse_sql(dialect, sql).map_err(|e| anyhow!("SQL parse error: {e}"))?;

        let query = match stmts.into_iter().next() {
            Some(Statement::Query(q)) => q,
            Some(other) => bail!("expected SELECT, got {other:?}"),
            None => bail!("empty SQL"),
        };

        // ── SELECT body ───────────────────────────────────────────────────────
        let select = match *query.body {
            SetExpr::Select(s) => *s,
            _ => bail!("only simple SELECT is supported"),
        };

        // ── Extract PostProcess from TOP / LIMIT / FETCH / ORDER BY ──────────
        // NOTE: TOP is on Select (not Query) in sqlparser 0.47.
        let mut pp = PostProcess::default();

        if let Some(top) = &select.top {
            extract_top(top, &mut pp);
        }
        if let Some(limit) = &query.limit {
            if let Some(n) = expr_to_usize(limit) {
                pp.limit = Some(n);
            }
        }
        if let Some(fetch) = &query.fetch {
            extract_fetch(fetch, &mut pp);
        }
        for ob in &query.order_by {
            if let Some(col) = order_by_col(ob) {
                pp.order_by.push(col);
            }
        }

        let mut state = VarState::new();

        // ── 1. Register all table aliases (FROM + JOINs) ─────────────────────
        let mut table_list: Vec<(String, String)> = Vec::new(); // (table_name, alias)

        for twj in &select.from {
            let (tname, alias) = extract_table_alias(&twj.relation)?;
            let alias = alias.unwrap_or_else(|| tname.clone());
            state.register_entity(&alias);
            table_list.push((tname.clone(), alias.clone()));

            for join in &twj.joins {
                let (jname, jalias) = extract_table_alias(&join.relation)?;
                let jalias = jalias.unwrap_or_else(|| jname.clone());
                state.register_entity(&jalias);
                table_list.push((jname.clone(), jalias.clone()));
            }
        }

        // ── 2. Process JOIN ON conditions ────────────────────────────────────
        for twj in &select.from {
            for join in &twj.joins {
                match &join.join_operator {
                    JoinOperator::Inner(JoinConstraint::On(expr))
                    | JoinOperator::LeftOuter(JoinConstraint::On(expr))
                    | JoinOperator::RightOuter(JoinConstraint::On(expr)) => {
                        apply_join_on(expr, &table_list, schema, &mut state)?;
                    }
                    _ => {}
                }
            }
        }

        // ── 3. Process WHERE ─────────────────────────────────────────────────
        if let Some(w) = &select.selection {
            apply_where(w, &table_list, schema, &mut state)?;
        }

        // ── 4. Build head from SELECT projection ─────────────────────────────
        let head_args = build_head(&select.projection, &table_list, schema, &mut state)?;
        if head_args.len() != 2 {
            bail!(
                "SELECT must project exactly 2 columns for kotoba binary Datalog; got {}",
                head_args.len()
            );
        }

        let head = Atom {
            relation: output.to_string(),
            args: head_args,
        };
        let mut prog = DatalogProgram::new();
        prog.add_rule(DatalogRule {
            head,
            body: state.body,
        });

        Ok((prog, pp))
    }
}

// ── VarState ──────────────────────────────────────────────────────────────────

struct VarState {
    /// alias → entity variable name (e.g. `"E_0"`)
    entity: HashMap<String, String>,
    /// (alias, col) → attribute value variable name (e.g. `"V_1"`)
    attr: HashMap<(String, String), String>,
    /// accumulated body literals
    pub body: Vec<BodyLiteral>,
    counter: usize,
}

impl VarState {
    fn new() -> Self {
        Self {
            entity: HashMap::new(),
            attr: HashMap::new(),
            body: Vec::new(),
            counter: 0,
        }
    }

    fn fresh(&mut self) -> String {
        let n = self.counter;
        self.counter += 1;
        format!("V{n}")
    }

    fn register_entity(&mut self, alias: &str) {
        if !self.entity.contains_key(alias) {
            let v = format!("E{}", self.counter);
            self.counter += 1;
            self.entity.insert(alias.to_string(), v);
        }
    }

    /// Return (or create) the variable for `alias.col`.
    /// If `col` is the entity column, return the entity variable (no new atom).
    /// Otherwise ensure a body atom `predicate(E_alias, V_col)` and return `V_col`.
    fn access_col(
        &mut self,
        alias: &str,
        col: &str,
        table: &str,
        schema: &SchemaMap,
    ) -> anyhow::Result<Term> {
        let sch = schema.effective(table);
        let e_var = self
            .entity
            .get(alias)
            .cloned()
            .ok_or_else(|| anyhow!("unknown alias '{alias}'"))?;

        if sch.is_entity_col(col) {
            return Ok(Term::Variable(e_var));
        }

        let key = (alias.to_string(), col.to_string());
        if let Some(v) = self.attr.get(&key) {
            return Ok(Term::Variable(v.clone()));
        }

        let v = self.fresh();
        self.attr.insert(key, v.clone());

        let predicate = match sch.attr(col) {
            Some(a) => a.predicate.clone(),
            None => SchemaMap::predicate(table, col),
        };

        self.body.push(BodyLiteral::Positive(Atom {
            relation: predicate,
            args: vec![Term::Variable(e_var), Term::Variable(v.clone())],
        }));

        Ok(Term::Variable(v))
    }

    /// Insert a constant-equality body atom: `predicate(E_alias, Const(value))`.
    fn bind_const(
        &mut self,
        alias: &str,
        col: &str,
        table: &str,
        value: String,
        schema: &SchemaMap,
    ) -> anyhow::Result<()> {
        let sch = schema.effective(table);
        let e_var = self
            .entity
            .get(alias)
            .cloned()
            .ok_or_else(|| anyhow!("unknown alias '{alias}'"))?;

        let predicate = match sch.attr(col) {
            Some(a) => a.predicate.clone(),
            None => SchemaMap::predicate(table, col),
        };

        self.body.push(BodyLiteral::Positive(Atom {
            relation: predicate,
            args: vec![Term::Variable(e_var), Term::Constant(value)],
        }));
        Ok(())
    }

    /// Unify two entity variables (for non-FK equi-joins: `a.col = b.col`).
    fn unify_entities(&mut self, alias_a: &str, alias_b: &str) {
        if let (Some(va), Some(vb)) = (
            self.entity.get(alias_a).cloned(),
            self.entity.get(alias_b).cloned(),
        ) {
            let new_v = va.clone();
            // Replace all occurrences of vb → va in all variable maps
            for v in self.entity.values_mut() {
                if *v == vb {
                    *v = new_v.clone();
                }
            }
            for v in self.attr.values_mut() {
                if *v == vb {
                    *v = new_v.clone();
                }
            }
        }
    }

    /// Insert a FK-join atom: `table/col(E_b, E_a)` — b's FK points to a's entity.
    fn add_fk_atom(
        &mut self,
        fk_alias: &str,
        fk_col: &str,
        fk_table: &str,
        pk_alias: &str,
        schema: &SchemaMap,
    ) -> anyhow::Result<()> {
        let sch = schema.effective(fk_table);
        let e_fk = self
            .entity
            .get(fk_alias)
            .cloned()
            .ok_or_else(|| anyhow!("unknown FK alias '{fk_alias}'"))?;
        let e_pk = self
            .entity
            .get(pk_alias)
            .cloned()
            .ok_or_else(|| anyhow!("unknown PK alias '{pk_alias}'"))?;

        let predicate = match sch.attr(fk_col) {
            Some(a) => a.predicate.clone(),
            None => SchemaMap::predicate(fk_table, fk_col),
        };

        self.body.push(BodyLiteral::Positive(Atom {
            relation: predicate,
            args: vec![Term::Variable(e_fk), Term::Variable(e_pk)],
        }));
        Ok(())
    }
}

// ── JOIN ON processing ────────────────────────────────────────────────────────

fn apply_join_on(
    expr: &Expr,
    tables: &[(String, String)],
    schema: &SchemaMap,
    state: &mut VarState,
) -> anyhow::Result<()> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let (la, lc) = extract_alias_col(left)?;
            let (ra, rc) = extract_alias_col(right)?;

            let l_table = find_table(&la, tables).unwrap_or(la.as_str());
            let r_table = find_table(&ra, tables).unwrap_or(ra.as_str());

            let l_sch = schema.effective(l_table);
            let r_sch = schema.effective(r_table);

            let l_is_pk = l_sch.is_entity_col(&lc);
            let r_is_pk = r_sch.is_entity_col(&rc);

            let r_is_fk = r_sch.attr(&rc).is_some_and(|a| a.kind == AttrKind::Entity);
            let l_is_fk = l_sch.attr(&lc).is_some_and(|a| a.kind == AttrKind::Entity);

            match (l_is_pk, r_is_fk, r_is_pk, l_is_fk) {
                // left.pk = right.fk  → `right/fk(E_r, E_l)`
                (true, true, _, _) => {
                    state.add_fk_atom(&ra, &rc, r_table, &la, schema)?;
                }
                // right.pk = left.fk  → `left/fk(E_l, E_r)`
                (_, _, true, true) => {
                    state.add_fk_atom(&la, &lc, l_table, &ra, schema)?;
                }
                // entity = entity  → unify entity vars directly
                (true, _, true, _) => {
                    state.unify_entities(&la, &ra);
                }
                // attr = attr  → shared variable via access_col
                _ => {
                    let lt = state.access_col(&la, &lc, l_table, schema)?;
                    let rt = state.access_col(&ra, &rc, r_table, schema)?;
                    // Merge right var → left var in all maps
                    if let (Term::Variable(lv), Term::Variable(rv)) = (lt, rt) {
                        if lv != rv {
                            for v in state.entity.values_mut() {
                                if *v == rv {
                                    *v = lv.clone();
                                }
                            }
                            for v in state.attr.values_mut() {
                                if *v == rv {
                                    *v = lv.clone();
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            apply_join_on(left, tables, schema, state)?;
            apply_join_on(right, tables, schema, state)
        }
        _ => Ok(()),
    }
}

// ── WHERE processing ──────────────────────────────────────────────────────────

fn apply_where(
    expr: &Expr,
    tables: &[(String, String)],
    schema: &SchemaMap,
    state: &mut VarState,
) -> anyhow::Result<()> {
    match expr {
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let (alias, col) = extract_alias_col(left)?;
            let table = find_table(&alias, tables).unwrap_or(alias.as_str());
            let value = expr_to_const(right)?;
            state.bind_const(&alias, &col, table, value, schema)
        }
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            apply_where(left, tables, schema, state)?;
            apply_where(right, tables, schema, state)
        }
        _ => Ok(()),
    }
}

// ── SELECT projection → head args ────────────────────────────────────────────

fn build_head(
    projection: &[SelectItem],
    tables: &[(String, String)],
    schema: &SchemaMap,
    state: &mut VarState,
) -> anyhow::Result<Vec<Term>> {
    let mut args = Vec::new();
    for item in projection {
        let expr = match item {
            SelectItem::UnnamedExpr(e) => e,
            SelectItem::ExprWithAlias { expr, .. } => expr,
            _ => bail!("SELECT * is not supported; list columns explicitly"),
        };
        args.push(resolve_select_expr(expr, tables, schema, state)?);
    }
    Ok(args)
}

fn resolve_select_expr(
    expr: &Expr,
    tables: &[(String, String)],
    schema: &SchemaMap,
    state: &mut VarState,
) -> anyhow::Result<Term> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            let alias = &parts[0].value;
            let col = &parts[1].value;
            let table = find_table(alias, tables).unwrap_or(alias.as_str());
            state.access_col(alias, col, table, schema)
        }
        Expr::Identifier(ident) => {
            let col = &ident.value;
            // find the unique table that has this column in schema
            let matches: Vec<Term> = tables
                .iter()
                .filter_map(|(tname, alias)| state.access_col(alias, col, tname, schema).ok())
                .collect();
            match matches.len() {
                1 => Ok(matches.into_iter().next().unwrap()),
                0 => bail!("column '{col}' not found in any registered table"),
                _ => bail!("column '{col}' is ambiguous; use alias.col"),
            }
        }
        _ => bail!("unsupported SELECT expression: {expr:?}"),
    }
}

// ── PostProcess extraction ────────────────────────────────────────────────────

fn extract_top(top: &Top, pp: &mut PostProcess) {
    let n_f64 = top.quantity.as_ref().and_then(|q| match q {
        TopQuantity::Expr(e) => expr_to_f64(e),
        TopQuantity::Constant(n) => Some(*n as f64),
    });
    let n_usize = top.quantity.as_ref().and_then(|q| match q {
        TopQuantity::Expr(e) => expr_to_usize(e),
        TopQuantity::Constant(n) => Some(*n as usize),
    });
    if top.percent {
        pp.percent = n_f64;
    } else {
        pp.limit = n_usize;
    }
}

fn extract_fetch(fetch: &Fetch, pp: &mut PostProcess) {
    // sqlparser 0.47: Fetch { with_ties, percent, quantity: Option<Expr> }
    if let Some(qty) = &fetch.quantity {
        if fetch.percent {
            pp.percent = expr_to_f64(qty);
        } else {
            pp.limit = expr_to_usize(qty);
        }
    }
}

fn order_by_col(ob: &OrderByExpr) -> Option<String> {
    match &ob.expr {
        Expr::Identifier(i) => Some(i.value.clone()),
        Expr::CompoundIdentifier(parts) => parts.last().map(|p| p.value.clone()),
        _ => None,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn extract_table_alias(factor: &TableFactor) -> anyhow::Result<(String, Option<String>)> {
    match factor {
        TableFactor::Table { name, alias, .. } => {
            let tname = name
                .0
                .iter()
                .map(|i: &Ident| i.value.as_str())
                .collect::<Vec<_>>()
                .join(".");
            let alias = alias.as_ref().map(|a| a.name.value.clone());
            Ok((tname, alias))
        }
        _ => bail!("only simple table references supported; got {factor:?}"),
    }
}

fn extract_alias_col(expr: &Expr) -> anyhow::Result<(String, String)> {
    match expr {
        Expr::CompoundIdentifier(parts) if parts.len() == 2 => {
            Ok((parts[0].value.clone(), parts[1].value.clone()))
        }
        Expr::Identifier(i) => Ok(("_".to_string(), i.value.clone())),
        _ => bail!("expected alias.col or bare column name; got {expr:?}"),
    }
}

fn expr_to_const(expr: &Expr) -> anyhow::Result<String> {
    match expr {
        Expr::Value(Value::SingleQuotedString(s)) => Ok(s.clone()),
        Expr::Value(Value::Number(n, _)) => Ok(n.clone()),
        _ => bail!("only string/number literals as WHERE constants; got {expr:?}"),
    }
}

fn expr_to_usize(expr: &Expr) -> Option<usize> {
    if let Expr::Value(Value::Number(n, _)) = expr {
        n.parse::<usize>().ok()
    } else {
        None
    }
}

fn expr_to_f64(expr: &Expr) -> Option<f64> {
    if let Expr::Value(Value::Number(n, _)) = expr {
        n.parse::<f64>().ok()
    } else {
        None
    }
}

/// Find the table name for a given alias in the table list.
fn find_table<'a>(alias: &str, tables: &'a [(String, String)]) -> Option<&'a str> {
    tables
        .iter()
        .find(|(_, a)| a == alias)
        .map(|(t, _)| t.as_str())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttrDef, SchemaMap, TableSchema};
    use crate::{
        datom::{Datom, Value},
        delta::Delta,
    };
    use kotoba_core::cid::KotobaCid;
    use sqlparser::dialect::GenericDialect;

    fn cid(s: &str) -> KotobaCid {
        KotobaCid::from_bytes(s.as_bytes())
    }

    fn fact(pred: &str, s: &str, o: &str) -> Delta {
        Delta::assert_datom(Datom::assert(
            cid(s),
            pred.to_string(),
            Value::Cid(cid(o)),
            cid("g"),
        ))
    }

    fn has(derived: &[Delta], pred: &str, s: &str, o: &str) -> bool {
        derived.iter().any(|d| {
            d.attribute() == pred
                && d.entity() == &cid(s)
                && matches!(d.value(), Value::Cid(c) if *c == cid(o))
        })
    }

    fn orders_schema() -> SchemaMap {
        let mut m = SchemaMap::new();
        m.add(
            "customers",
            TableSchema::new("id").with_attr(AttrDef::scalar("name", "customers")),
        );
        m.add(
            "orders",
            TableSchema::new("id")
                .with_attr(AttrDef::entity("customer_id", "orders"))
                .with_attr(AttrDef::numeric("amount", "orders"))
                .with_attr(AttrDef::scalar("status", "orders")),
        );
        m
    }

    #[test]
    fn single_table_attr() {
        let schema = orders_schema();
        let (prog, pp) = SchemaBasedSqlCompiler::compile(
            "SELECT c.id, c.name FROM customers c",
            &GenericDialect {},
            &schema,
            "out",
        )
        .unwrap();
        assert!(pp.limit.is_none());

        // c.id = entity var (no atom), c.name adds customers/name atom
        let input = vec![fact("customers/name", "alice_cid", "alice_name")];
        let derived = prog.evaluate_delta(&input);
        assert!(has(&derived, "out", "alice_cid", "alice_name"));
    }

    #[test]
    fn fk_join() {
        let schema = orders_schema();
        let (prog, _) = SchemaBasedSqlCompiler::compile(
            "SELECT c.name, o.amount \
             FROM customers c JOIN orders o ON c.id = o.customer_id",
            &GenericDialect {},
            &schema,
            "result",
        )
        .unwrap();

        let input = vec![
            fact("customers/name", "c1", "alice"),
            fact("orders/customer_id", "o1", "c1"),
            fact("orders/amount", "o1", "100"),
        ];
        let derived = prog.evaluate_delta(&input);
        assert!(has(&derived, "result", "alice", "100"));
    }

    #[test]
    fn where_constant() {
        let schema = orders_schema();
        let (prog, _) = SchemaBasedSqlCompiler::compile(
            "SELECT o.customer_id, o.amount \
             FROM orders o WHERE o.status = 'active'",
            &GenericDialect {},
            &schema,
            "active_orders",
        )
        .unwrap();

        let input = vec![
            fact("orders/customer_id", "o1", "c1"),
            fact("orders/amount", "o1", "200"),
            fact("orders/status", "o1", "active"),
            // noise: inactive order
            fact("orders/customer_id", "o2", "c2"),
            fact("orders/amount", "o2", "300"),
            fact("orders/status", "o2", "pending"),
        ];
        let derived = prog.evaluate_delta(&input);
        assert!(has(&derived, "active_orders", "c1", "200"));
        assert!(!has(&derived, "active_orders", "c2", "300"));
    }

    #[test]
    fn limit_in_post_process() {
        let schema = orders_schema();
        let (_, pp) = SchemaBasedSqlCompiler::compile(
            "SELECT TOP 10 o.customer_id, o.amount FROM orders o",
            &sqlparser::dialect::MsSqlDialect {},
            &schema,
            "top10",
        )
        .unwrap();
        assert_eq!(pp.limit, Some(10));
    }

    #[test]
    fn binary_fallback_no_schema() {
        // Table without registered schema → falls back to s/o
        let schema = SchemaMap::new();
        let (prog, _) = SchemaBasedSqlCompiler::compile(
            "SELECT k.s, k.o FROM knows k",
            &GenericDialect {},
            &schema,
            "out",
        )
        .unwrap();
        let input = vec![fact("knows/o", "alice", "bob")];
        let derived = prog.evaluate_delta(&input);
        assert!(has(&derived, "out", "alice", "bob"));
    }
}
