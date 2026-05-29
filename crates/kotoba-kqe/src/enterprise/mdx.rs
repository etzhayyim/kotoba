//! MDX (Multidimensional Expressions) dialect compiler.
//!
//! Hand-written recursive-descent parser — MDX is not SQL and has no sqlparser support.
//!
//! # Supported MDX subset
//!
//! ```mdx
//! SELECT
//!   {[Measures].[Sales Amount], [Measures].[Quantity]} ON COLUMNS,
//!   {[Date].[Year].Members} ON ROWS
//! FROM [SalesCube]
//! WHERE ([Geography].[Country].[Japan])
//! ```
//!
//! # Compilation model
//!
//! MDX maps onto the kotoba Quad/Datalog model as follows:
//!
//! | MDX concept | Kotoba mapping |
//! |-------------|----------------|
//! | Cube name | Named-graph CID predicate `"cube/<name>"` |
//! | Measure     | Predicate `"measure/<name>"` |
//! | Dimension member | Subject CID `cid_of_str("dim:<hierarchy>:<member>")` |
//! | Slicer tuple | Additional WHERE constant atoms |
//! | COLUMNS / ROWS axis | Two head variables (binary-relation invariant) |
//!
//! The compiled Datalog rule returns `(column_dim_cid, row_dim_cid)` pairs for
//! cells that have data in both axes after slicer filtering.

use anyhow::{anyhow, bail};

use super::{CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature, PostProcess};
use crate::datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term};
use crate::schema::SchemaMap;

// ── Public types ──────────────────────────────────────────────────────────────

/// Parsed MDX query structure.
#[derive(Debug, Clone)]
pub struct MdxQuery {
    pub cube: String,
    pub columns: Vec<MdxMemberRef>,
    pub rows: Vec<MdxMemberRef>,
    pub slicer: Vec<MdxMemberRef>,
}

/// A single MDX member reference: `[Dimension].[Hierarchy].[Member]`
/// or a `.Members` wildcard.
#[derive(Debug, Clone)]
pub struct MdxMemberRef {
    /// Bracketed path segments, e.g. `["Measures", "Sales Amount"]`
    pub path: Vec<String>,
    /// True when the last segment is `.Members` (all members)
    pub wildcard: bool,
}

impl MdxMemberRef {
    /// Dimension name (first segment).
    pub fn dimension(&self) -> &str {
        self.path.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Predicate name in kotoba space: `"measure/<name>"` or `"dim/<dim>/<member>"`.
    pub fn predicate(&self) -> String {
        if self.dimension().to_uppercase() == "MEASURES" {
            let measure = self.path.last().unwrap_or(&String::new()).clone();
            format!("measure/{measure}")
        } else {
            format!("dim/{}", self.path.join("/"))
        }
    }

    /// Constant string for the CID hash of this member.
    pub fn cid_key(&self) -> String {
        format!("mdx:{}", self.path.join(":"))
    }
}

// ── EnterpriseDialect impl ────────────────────────────────────────────────────

pub struct MdxDialect;

impl EnterpriseDialect for MdxDialect {
    fn dialect_name(&self) -> &'static str {
        "mdx"
    }

    fn compile(
        &self,
        query: &str,
        _schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mdx = parse(query)?;
        let program = compile_mdx(&mdx, output)?;

        Ok(CompiledEnterpriseQuery {
            program,
            output_relation: output.to_string(),
            dialect: self.dialect_name(),
            features: vec![EnterpriseFeature::OlapWindow],
            post_process: PostProcess::default(),
        })
    }
}

// ── Compiler ──────────────────────────────────────────────────────────────────

/// Compile a parsed `MdxQuery` into a `DatalogProgram`.
///
/// Strategy:
/// - One COLUMNS member and one ROWS member are required (binary invariant).
/// - Slicer members become constant-equality body atoms.
/// - The head is `output(col_cid, row_cid)`.
pub fn compile_mdx(mdx: &MdxQuery, output: &str) -> anyhow::Result<DatalogProgram> {
    // Require at least one column and one row member
    let col = mdx
        .columns
        .first()
        .ok_or_else(|| anyhow!("MDX: COLUMNS axis must have at least one member"))?;
    let row = mdx
        .rows
        .first()
        .ok_or_else(|| anyhow!("MDX: ROWS axis must have at least one member"))?;

    let col_var = Term::Variable("ColV".to_string());
    let row_var = Term::Variable("RowV".to_string());

    let mut body: Vec<BodyLiteral> = Vec::new();

    // COLUMNS axis: measure or dimension lookup
    body.push(if col.wildcard {
        // .Members → match any value for this predicate
        BodyLiteral::Positive(Atom {
            relation: col.predicate(),
            args: vec![Term::Variable("RowV".to_string()), col_var.clone()],
        })
    } else {
        // Specific member → constant subject
        BodyLiteral::Positive(Atom {
            relation: col.predicate(),
            args: vec![Term::Constant(col.cid_key()), col_var.clone()],
        })
    });

    // ROWS axis
    body.push(if row.wildcard {
        BodyLiteral::Positive(Atom {
            relation: row.predicate(),
            args: vec![Term::Variable("ColV".to_string()), row_var.clone()],
        })
    } else {
        BodyLiteral::Positive(Atom {
            relation: row.predicate(),
            args: vec![Term::Constant(row.cid_key()), row_var.clone()],
        })
    });

    // Slicer: constant-equality atoms on a shared entity variable
    for member in &mdx.slicer {
        body.push(BodyLiteral::Positive(Atom {
            relation: member.predicate(),
            args: vec![
                Term::Variable("Ctx".to_string()),
                Term::Constant(member.cid_key()),
            ],
        }));
    }

    let head = Atom {
        relation: output.to_string(),
        args: vec![col_var, row_var],
    };

    let mut prog = DatalogProgram::new();
    prog.add_rule(DatalogRule { head, body });
    Ok(prog)
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse a MDX query string into an `MdxQuery`.
pub fn parse(mdx: &str) -> anyhow::Result<MdxQuery> {
    let mut p = Parser {
        input: mdx.trim(),
        pos: 0,
    };
    p.parse_query()
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &str {
        &self.input[self.pos..]
    }

    fn skip_ws(&mut self) {
        while self.pos < self.input.len()
            && self.input[self.pos..].starts_with(|c: char| c.is_whitespace())
        {
            self.pos += 1;
        }
    }

    fn peek_upper(&self, n: usize) -> String {
        self.input[self.pos..]
            .chars()
            .take(n)
            .collect::<String>()
            .to_uppercase()
    }

    fn expect_keyword(&mut self, kw: &str) -> anyhow::Result<()> {
        self.skip_ws();
        if self.rest().to_uppercase().starts_with(kw) {
            self.pos += kw.len();
            Ok(())
        } else {
            bail!(
                "MDX: expected '{}', got '{}'",
                kw,
                &self.rest()[..kw.len().min(self.rest().len())]
            )
        }
    }

    fn try_keyword(&mut self, kw: &str) -> bool {
        self.skip_ws();
        if self.rest().to_uppercase().starts_with(kw) {
            self.pos += kw.len();
            true
        } else {
            false
        }
    }

    fn parse_query(&mut self) -> anyhow::Result<MdxQuery> {
        self.expect_keyword("SELECT")?;

        // Parse axis definitions: {set} ON COLUMNS, {set} ON ROWS
        let mut columns = Vec::new();
        let mut rows = Vec::new();

        loop {
            self.skip_ws();
            let set = self.parse_set()?;
            self.skip_ws();
            self.expect_keyword("ON")?;
            self.skip_ws();

            let upper = self.rest().to_uppercase();
            if upper.starts_with("COLUMNS") || upper.starts_with("0") {
                self.pos += if upper.starts_with("COLUMNS") { 7 } else { 1 };
                columns = set;
            } else if upper.starts_with("ROWS") || upper.starts_with("1") {
                self.pos += if upper.starts_with("ROWS") { 4 } else { 1 };
                rows = set;
            } else {
                bail!(
                    "MDX: expected COLUMNS or ROWS axis, got '{}'",
                    &self.rest()[..10.min(self.rest().len())]
                );
            }

            self.skip_ws();
            if !self.try_keyword(",") {
                break;
            }
        }

        self.expect_keyword("FROM")?;
        self.skip_ws();
        let cube = self.parse_bracketed_name()?;

        let mut slicer = Vec::new();
        if self.try_keyword("WHERE") {
            self.skip_ws();
            slicer = self.parse_slicer()?;
        }

        Ok(MdxQuery {
            cube,
            columns,
            rows,
            slicer,
        })
    }

    /// Parse `{member, member, …}` or a single member without braces.
    fn parse_set(&mut self) -> anyhow::Result<Vec<MdxMemberRef>> {
        self.skip_ws();
        let has_brace = self.try_keyword("{");
        let mut members = Vec::new();

        loop {
            self.skip_ws();
            if self.rest().is_empty() || self.rest().starts_with('}') {
                break;
            }
            // Stop at ON keyword
            if self.peek_upper(2) == "ON" {
                break;
            }
            members.push(self.parse_member()?);
            self.skip_ws();
            if !self.try_keyword(",") {
                break;
            }
        }

        if has_brace {
            self.skip_ws();
            if !self.try_keyword("}") {
                bail!("MDX: expected '}}' to close set");
            }
        }

        Ok(members)
    }

    /// Parse a slicer tuple `(member, …)` or a single member.
    fn parse_slicer(&mut self) -> anyhow::Result<Vec<MdxMemberRef>> {
        let has_paren = self.try_keyword("(");
        let mut members = Vec::new();

        loop {
            self.skip_ws();
            if self.rest().is_empty() || self.rest().starts_with(')') {
                break;
            }
            members.push(self.parse_member()?);
            self.skip_ws();
            if !self.try_keyword(",") {
                break;
            }
        }

        if has_paren {
            self.try_keyword(")");
        }
        Ok(members)
    }

    /// Parse `[Dim].[Hier].[Member]` or `[Dim].[Hier].Members`.
    fn parse_member(&mut self) -> anyhow::Result<MdxMemberRef> {
        self.skip_ws();
        let mut path = Vec::new();
        let mut wildcard = false;

        loop {
            self.skip_ws();
            if !self.rest().starts_with('[') {
                // Check for `.Members` bare keyword
                if self.rest().to_uppercase().starts_with(".MEMBERS") {
                    self.pos += 8;
                    wildcard = true;
                }
                break;
            }
            path.push(self.parse_bracketed_name()?);
            self.skip_ws();
            if self.rest().to_uppercase().starts_with(".MEMBERS") {
                self.pos += 8;
                wildcard = true;
                break;
            }
            if !self.rest().starts_with('.') {
                break;
            }
            self.pos += 1; // consume '.'
        }

        if path.is_empty() {
            bail!(
                "MDX: expected bracketed member at '{}'",
                &self.rest()[..20.min(self.rest().len())]
            );
        }

        Ok(MdxMemberRef { path, wildcard })
    }

    /// Parse `[name]` and return the inner string.
    fn parse_bracketed_name(&mut self) -> anyhow::Result<String> {
        self.skip_ws();
        if !self.rest().starts_with('[') {
            bail!(
                "MDX: expected '[', got '{}'",
                &self.rest()[..5.min(self.rest().len())]
            );
        }
        self.pos += 1;
        let close = self
            .rest()
            .find(']')
            .ok_or_else(|| anyhow!("MDX: unclosed '['"))?;
        let name = self.rest()[..close].to_string();
        self.pos += close + 1;
        Ok(name)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_MDX: &str = "
        SELECT
          {[Measures].[Sales Amount], [Measures].[Quantity]} ON COLUMNS,
          {[Date].[Calendar Year].[2024]} ON ROWS
        FROM [Sales Cube]
        WHERE ([Geography].[Country].[Japan])
    ";

    #[test]
    fn parse_basic_mdx() {
        let q = parse(SAMPLE_MDX).unwrap();
        assert_eq!(q.cube, "Sales Cube");
        assert_eq!(q.columns.len(), 2);
        assert_eq!(q.rows.len(), 1);
        assert_eq!(q.slicer.len(), 1);
    }

    #[test]
    fn measure_predicate() {
        let m = MdxMemberRef {
            path: vec!["Measures".to_string(), "Sales Amount".to_string()],
            wildcard: false,
        };
        assert_eq!(m.predicate(), "measure/Sales Amount");
    }

    #[test]
    fn dim_predicate() {
        let m = MdxMemberRef {
            path: vec![
                "Date".to_string(),
                "Calendar Year".to_string(),
                "2024".to_string(),
            ],
            wildcard: false,
        };
        assert_eq!(m.predicate(), "dim/Date/Calendar Year/2024");
    }

    #[test]
    fn compile_generates_rule() {
        let q = parse(SAMPLE_MDX).unwrap();
        let prog = compile_mdx(&q, "cell_values").unwrap();
        assert_eq!(prog.rules.len(), 1);
        let rule = &prog.rules[0];
        assert_eq!(rule.head.relation, "cell_values");
        assert_eq!(rule.head.args.len(), 2);
    }

    #[test]
    fn mdx_dialect_roundtrip() {
        let schema = SchemaMap::new();
        let result = MdxDialect.compile(SAMPLE_MDX, &schema, "result").unwrap();
        assert_eq!(result.dialect, "mdx");
        assert!(result.features.contains(&EnterpriseFeature::OlapWindow));
    }

    #[test]
    fn parse_members_wildcard() {
        let mdx = "
            SELECT {[Date].[Year].Members} ON COLUMNS,
                   {[Measures].[Revenue]} ON ROWS
            FROM [FinanceCube]
        ";
        let q = parse(mdx).unwrap();
        assert!(q.columns[0].wildcard, "should be wildcard .Members");
        assert!(!q.rows[0].wildcard);
    }

    #[test]
    fn datalog_evaluation() {
        use crate::{
            datom::{Datom, Value},
            delta::Delta,
        };
        use kotoba_core::cid::KotobaCid;

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

        // Compile a simple MDX: measure on columns, dimension member on rows
        let mdx = "
            SELECT {[Measures].[Revenue]} ON COLUMNS,
                   {[Region].[APAC]} ON ROWS
            FROM [FinanceCube]
        ";
        let q = parse(mdx).unwrap();
        let prog = compile_mdx(&q, "cell").unwrap();

        // The compiled rule requires:
        //   measure/Revenue(Constant("mdx:Measures:Revenue"), ColV)  ← col subject = col.cid_key()
        //   dim/Region/APAC(Constant("mdx:Region:APAC"),     RowV)  ← row subject = row.cid_key()
        let col_member = &q.columns[0];
        let row_member = &q.rows[0];

        let input = vec![
            fact(&col_member.predicate(), &col_member.cid_key(), "rev_val"),
            fact(&row_member.predicate(), &row_member.cid_key(), "apac_val"),
        ];
        let derived = prog.evaluate_delta(&input);
        // At least one derived cell
        assert!(!derived.is_empty(), "should derive at least one cell value");
    }
}
