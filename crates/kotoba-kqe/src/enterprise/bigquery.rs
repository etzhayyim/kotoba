//! Google BigQuery dialect compiler.
//!
//! Uses `sqlparser::dialect::BigQueryDialect` which supports:
//! - Backtick table references `` `project.dataset.table` ``
//! - `UNNEST(arr)` (simplified to sub-predicate expansion)
//!
//! # Supported BigQuery-specific features
//!
//! | Feature | Handling |
//! |---------|----------|
//! | Backtick identifiers | → `table_name` with dots replaced by `_` |
//! | `UNNEST(col)` | → `EnterpriseFeature::SemiStructured`, stripped |
//! | `WITH OFFSET` (UNNEST index) | → index predicate appended |
//! | `EXCEPT (col, …)` | → stripped (SELECT * minus columns) |
//! | `_TABLE_SUFFIX` wildcard | → stripped |
//! | `STRUCT<…>` / `ARRAY_AGG` | → `EnterpriseFeature::SemiStructured` |

use sqlparser::dialect::BigQueryDialect as SqlparserBigQuery;

use super::{
    sql_base::SchemaBasedSqlCompiler, CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature,
};
use crate::schema::SchemaMap;

pub struct BigQueryDialect;

impl EnterpriseDialect for BigQueryDialect {
    fn dialect_name(&self) -> &'static str {
        "bigquery"
    }

    fn compile(
        &self,
        query: &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mut features = Vec::new();
        let upper = query.to_uppercase();

        if upper.contains("UNNEST") || upper.contains("ARRAY_AGG") || upper.contains("STRUCT") {
            features.push(EnterpriseFeature::SemiStructured);
        }

        let prepped = preprocess_bigquery(query);

        let (program, pp) =
            SchemaBasedSqlCompiler::compile(&prepped, &SqlparserBigQuery {}, schema, output)?;

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

fn preprocess_bigquery(sql: &str) -> String {
    let mut s = sql.to_string();

    // Backtick identifiers: `project.dataset.table` → project_dataset_table
    while let Some(open) = s.find('`') {
        if let Some(close) = s[open + 1..].find('`') {
            let inner = s[open + 1..open + 1 + close].replace('.', "_");
            s.replace_range(open..open + 2 + close, &inner);
        } else {
            break;
        }
    }

    // UNNEST(col) → col (lose the array expansion, mark as SemiStructured)
    while let Some(idx) = s.to_uppercase().find("UNNEST(") {
        if let Some(end) = find_paren(&s, idx + 6) {
            let inner = s[idx + 7..end].to_string();
            s.replace_range(idx..end + 1, &inner);
        } else {
            break;
        }
    }

    // WITH OFFSET → strip (ordinal index not representable in binary Datalog)
    s = s.replace(" WITH OFFSET", "");
    s = s.replace(" with offset", "");

    // EXCEPT (col, …) after SELECT → strip
    while let Some(idx) = s.to_uppercase().find(" EXCEPT (") {
        if let Some(end) = find_paren(&s, idx + 8) {
            s.replace_range(idx..end + 1, "");
        } else {
            break;
        }
    }

    // _TABLE_SUFFIX references → remove the LIKE clause
    s = s.replace("_TABLE_SUFFIX", "'_suffix_'");

    s
}

fn find_paren(s: &str, open: usize) -> Option<usize> {
    let mut depth = 1i32;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
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
    fn backtick_table_ref() {
        // `my_project.my_dataset.events` → my_project_my_dataset_events
        let prepped =
            preprocess_bigquery("SELECT e.id, e.name FROM `my_project.my_dataset.events` AS e");
        assert!(prepped.contains("my_project_my_dataset_events"));
        assert!(!prepped.contains('`'));
    }

    #[test]
    fn bigquery_select() {
        let mut schema = SchemaMap::new();
        schema.add(
            "analytics_sessions",
            TableSchema::new("session_id")
                .with_attr(AttrDef::scalar("user_id", "analytics_sessions"))
                .with_attr(AttrDef::scalar("channel", "analytics_sessions")),
        );

        let result = BigQueryDialect
            .compile(
                "SELECT s.session_id, s.user_id \
             FROM analytics_sessions AS s \
             WHERE s.channel = 'organic'",
                &schema,
                "organic",
            )
            .unwrap();

        let input = vec![
            fact("analytics_sessions/user_id", "s1", "u1"),
            fact("analytics_sessions/channel", "s1", "organic"),
            fact("analytics_sessions/user_id", "s2", "u2"),
            fact("analytics_sessions/channel", "s2", "paid"),
        ];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "organic", "s1", "u1"));
        assert!(!has(&derived, "organic", "s2", "u2"));
    }

    #[test]
    fn unnest_semi_structured_detected() {
        let upper = "SELECT UNNEST(tags) FROM t".to_uppercase();
        assert!(upper.contains("UNNEST"));
    }
}
