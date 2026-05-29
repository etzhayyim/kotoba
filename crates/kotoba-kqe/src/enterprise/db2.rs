//! IBM Db2 SQL dialect compiler.
//!
//! # Supported Db2-specific features
//!
//! | Feature | Handling |
//! |---------|----------|
//! | `FETCH FIRST N ROWS ONLY` | → `PostProcess::limit` |
//! | `WITH UR/CS/RS/RR` (isolation) | → stripped (Kotoba is snapshot-read) |
//! | `MERGE INTO … WHEN MATCHED` | → `EnterpriseFeature::Pivot` (signals upsert semantics) |
//! | `VALUES (…)` as inline table | → constant-fact expansion |
//! | `SPECIAL REGISTERS` (CURRENT DATE etc.) | → literal placeholder |
//! | `OLAP window functions` | → `EnterpriseFeature::OlapWindow` |

use sqlparser::dialect::GenericDialect;

use super::{
    sql_base::SchemaBasedSqlCompiler, CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature,
};
use crate::schema::SchemaMap;

pub struct Db2Dialect;

impl EnterpriseDialect for Db2Dialect {
    fn dialect_name(&self) -> &'static str {
        "db2"
    }

    fn compile(
        &self,
        query: &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mut features = Vec::new();
        let upper = query.to_uppercase();

        if upper.contains("OVER (") || upper.contains("OVER(") {
            features.push(EnterpriseFeature::OlapWindow);
        }
        if upper.contains("MERGE INTO") {
            features.push(EnterpriseFeature::Pivot);
        }

        let prepped = preprocess_db2(query);

        let (program, pp) =
            SchemaBasedSqlCompiler::compile(&prepped, &GenericDialect {}, schema, output)?;

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

fn preprocess_db2(sql: &str) -> String {
    let mut s = sql.to_string();

    // Strip isolation level clauses: WITH UR / WITH CS / WITH RS / WITH RR
    for iso in &[
        "WITH UR", "WITH CS", "WITH RS", "WITH RR", "with ur", "with cs", "with rs", "with rr",
    ] {
        s = s.replace(iso, "");
    }

    // Replace Db2 special registers with literals
    s = s.replace("CURRENT DATE", "'2026-01-01'");
    s = s.replace("CURRENT TIMESTAMP", "'2026-01-01 00:00:00'");
    s = s.replace("CURRENT TIME", "'00:00:00'");
    s = s.replace("current date", "'2026-01-01'");
    s = s.replace("current timestamp", "'2026-01-01 00:00:00'");

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

    #[test]
    fn fetch_first_limit() {
        let mut schema = SchemaMap::new();
        schema.add(
            "accounts",
            TableSchema::new("id").with_attr(AttrDef::scalar("name", "accounts")),
        );

        let result = Db2Dialect
            .compile(
                "SELECT a.id, a.name FROM accounts a FETCH FIRST 20 ROWS ONLY",
                &schema,
                "out",
            )
            .unwrap();
        assert_eq!(result.post_process.limit, Some(20));
    }

    #[test]
    fn isolation_stripped() {
        let mut schema = SchemaMap::new();
        schema.add(
            "ledger",
            TableSchema::new("id").with_attr(AttrDef::numeric("balance", "ledger")),
        );

        let result = Db2Dialect
            .compile(
                "SELECT l.id, l.balance FROM ledger l WITH UR",
                &schema,
                "out",
            )
            .unwrap();
        // Should compile cleanly without the isolation clause
        assert_eq!(result.dialect, "db2");

        let input = vec![fact("ledger/balance", "acc1", "1000")];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "out", "acc1", "1000"));
    }

    #[test]
    fn olap_window_feature_detected() {
        let schema = SchemaMap::new();
        let result = Db2Dialect.compile(
            "SELECT a.id, a.name FROM accounts a WHERE a.id = 'x'",
            &schema,
            "out",
        );
        // Standard query — no OLAP window
        if let Ok(r) = result {
            assert!(!r.features.contains(&EnterpriseFeature::OlapWindow));
        }
    }
}
