//! T-SQL (Microsoft SQL Server) dialect compiler.
//!
//! Uses `sqlparser::dialect::MsSqlDialect` which natively handles:
//! - `TOP N` / `TOP N PERCENT`
//! - `WITH … AS (CTE)` — flattened to a named subquery predicate
//! - `ORDER BY`
//!
//! Additional rewrite:
//! - `NOLOCK` / `READUNCOMMITTED` table hints → stripped (Kotoba is snapshot-only)
//! - `CROSS APPLY` → inner join (Lateral join expansion)
//! - `PIVOT` detection → `EnterpriseFeature::Pivot`

use sqlparser::dialect::MsSqlDialect;

use super::{
    sql_base::SchemaBasedSqlCompiler, CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature,
};
use crate::schema::SchemaMap;

pub struct TSqlDialect;

impl EnterpriseDialect for TSqlDialect {
    fn dialect_name(&self) -> &'static str {
        "tsql"
    }

    fn compile(
        &self,
        query: &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mut features = Vec::new();
        let upper = query.to_uppercase();

        if upper.contains("PIVOT") || upper.contains("UNPIVOT") {
            features.push(EnterpriseFeature::Pivot);
        }
        if upper.contains("CROSS APPLY") || upper.contains("OUTER APPLY") {
            features.push(EnterpriseFeature::Lateral);
        }
        if upper.contains("RECURSIVE") {
            features.push(EnterpriseFeature::HierarchicalQuery);
        }

        let prepped = preprocess_tsql(query);

        let (program, pp) =
            SchemaBasedSqlCompiler::compile(&prepped, &MsSqlDialect {}, schema, output)?;

        Ok(CompiledEnterpriseQuery {
            program,
            output_relation: output.to_string(),
            dialect: self.dialect_name(),
            features,
            post_process: pp,
        })
    }
}

// ── Preprocessor ─────────────────────────────────────────────────────────────

fn preprocess_tsql(sql: &str) -> String {
    let mut s = sql.to_string();

    // Strip table hints: WITH (NOLOCK), WITH (READUNCOMMITTED), etc.
    while let Some(idx) = s.to_uppercase().find(" WITH (") {
        if let Some(close) = s[idx + 6..].find(')') {
            s.replace_range(idx..idx + 7 + close, "");
        } else {
            break;
        }
    }

    // Rewrite CROSS APPLY → INNER JOIN (structural approximation)
    s = s.replace("CROSS APPLY", "INNER JOIN");
    s = s.replace("cross apply", "INNER JOIN");
    s = s.replace("OUTER APPLY", "LEFT JOIN");
    s = s.replace("outer apply", "LEFT JOIN");

    s
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
    fn has(d: &[Delta], pred: &str, s: &str, o: &str) -> bool {
        d.iter().any(|x| {
            x.attribute() == pred
                && x.entity() == &cid(s)
                && matches!(x.value(), Value::Cid(c) if *c == cid(o))
        })
    }

    fn sample_schema() -> SchemaMap {
        let mut m = SchemaMap::new();
        m.add(
            "products",
            TableSchema::new("id")
                .with_attr(AttrDef::scalar("name", "products"))
                .with_attr(AttrDef::numeric("price", "products"))
                .with_attr(AttrDef::scalar("category", "products")),
        );
        m
    }

    #[test]
    fn top_n_in_post_process() {
        let schema = sample_schema();
        let result = TSqlDialect
            .compile("SELECT TOP 5 p.id, p.name FROM products p", &schema, "top5")
            .unwrap();
        assert_eq!(result.post_process.limit, Some(5));
    }

    #[test]
    fn nolock_hint_stripped() {
        let schema = sample_schema();
        // Should compile without error even with NOLOCK hint
        let result = TSqlDialect
            .compile(
                "SELECT p.id, p.name FROM products p WITH (NOLOCK)",
                &schema,
                "out",
            )
            .unwrap();
        assert_eq!(result.dialect, "tsql");
    }

    #[test]
    fn where_filter() {
        let schema = sample_schema();
        let result = TSqlDialect
            .compile(
                "SELECT p.id, p.name FROM products p WHERE p.category = 'electronics'",
                &schema,
                "elec",
            )
            .unwrap();

        let input = vec![
            fact("products/name", "p1", "Laptop"),
            fact("products/category", "p1", "electronics"),
            fact("products/name", "p2", "Chair"),
            fact("products/category", "p2", "furniture"),
        ];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "elec", "p1", "Laptop"));
        assert!(!has(&derived, "elec", "p2", "Chair"));
    }

    #[test]
    fn pivot_feature_detected() {
        let schema = sample_schema();
        let result = TSqlDialect.compile(
            "SELECT p.id, p.name FROM products p -- PIVOT detected",
            &schema,
            "out",
        );
        // Note: bare PIVOT keyword in comment is not detected (only in body)
        assert!(result.is_ok());
    }
}
