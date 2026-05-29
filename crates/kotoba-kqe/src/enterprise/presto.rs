//! Presto / Trino dialect compiler.
//!
//! # Supported Presto/Trino-specific features
//!
//! | Feature | Handling |
//! |---------|----------|
//! | `TABLESAMPLE BERNOULLI(pct)` | → `PostProcess::percent` |
//! | `TABLESAMPLE SYSTEM(pct)` | → `PostProcess::percent` |
//! | `UNNEST(arr) WITH ORDINALITY` | → `EnterpriseFeature::SemiStructured`, stripped |
//! | `ELEMENT_AT(map, key)` | → map access stripped to map column |
//! | `TRY(expr)` | → wrapped expression stripped |
//! | Lambda `x -> expr` | → `EnterpriseFeature::Lateral` |

use sqlparser::dialect::GenericDialect;

use super::{
    sql_base::SchemaBasedSqlCompiler, CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature,
};
use crate::schema::SchemaMap;

pub struct PrestoDialect;

impl EnterpriseDialect for PrestoDialect {
    fn dialect_name(&self) -> &'static str {
        "presto"
    }

    fn compile(
        &self,
        query: &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mut features = Vec::new();
        let upper = query.to_uppercase();

        let mut pct = None::<f64>;

        if upper.contains("TABLESAMPLE") {
            features.push(EnterpriseFeature::Sampling);
            pct = extract_tablesample(query);
        }
        if upper.contains("UNNEST") {
            features.push(EnterpriseFeature::SemiStructured);
        }
        if upper.contains("->") {
            features.push(EnterpriseFeature::Lateral);
        }

        let prepped = preprocess_presto(query);

        let (program, mut pp) =
            SchemaBasedSqlCompiler::compile(&prepped, &GenericDialect {}, schema, output)?;

        if pp.percent.is_none() {
            pp.percent = pct;
        }

        Ok(CompiledEnterpriseQuery {
            program,
            output_relation: output.to_string(),
            dialect: self.dialect_name(),
            features,
            post_process: pp,
        })
    }
}

// ── TABLESAMPLE extraction ────────────────────────────────────────────────────

fn extract_tablesample(sql: &str) -> Option<f64> {
    let upper = sql.to_uppercase();
    let idx = upper.find("TABLESAMPLE")?;
    let rest = &sql[idx + 11..];
    // BERNOULLI(N) or SYSTEM(N)
    let open = rest.find('(')?;
    let close = rest[open..].find(')')?;
    let inner = &rest[open + 1..open + close];
    inner.trim().parse::<f64>().ok()
}

// ── Preprocessor ─────────────────────────────────────────────────────────────

fn preprocess_presto(sql: &str) -> String {
    let mut s = sql.to_string();

    // TABLESAMPLE BERNOULLI(N) / SYSTEM(N) → strip
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find("TABLESAMPLE") {
        // Find the closing paren of TABLESAMPLE(N) and strip the whole clause
        let start = idx;
        let rest_offset = idx + 11;
        if let Some(open) = s[rest_offset..].find('(') {
            let abs_open = rest_offset + open;
            if let Some(rel_close) = s[abs_open..].find(')') {
                s.replace_range(start..abs_open + rel_close + 1, "");
            }
        }
    }

    // UNNEST(col) WITH ORDINALITY → col (first occurrence only)
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find("UNNEST(") {
        if let Some(end) = find_paren(&s, idx + 6) {
            let inner = s[idx + 7..end].to_string();
            let after = &s[end + 1..];
            let trim_extra = if after.to_uppercase().starts_with(" WITH ORDINALITY") {
                16
            } else {
                0
            };
            s.replace_range(idx..end + 1 + trim_extra, &inner);
        }
    }

    // TRY(expr) → expr
    while let Some(idx) = s.to_uppercase().find("TRY(") {
        if let Some(end) = find_paren(&s, idx + 3) {
            let inner = s[idx + 4..end].to_string();
            s.replace_range(idx..end + 1, &inner);
        } else {
            break;
        }
    }

    // ELEMENT_AT(map, key) → map (access by literal key not representable)
    while let Some(idx) = s.to_uppercase().find("ELEMENT_AT(") {
        if let Some(end) = find_paren(&s, idx + 10) {
            let args = s[idx + 11..end].to_string();
            let map_col = args.split(',').next().unwrap_or("").trim().to_string();
            s.replace_range(idx..end + 1, &map_col);
        } else {
            break;
        }
    }

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
    fn tablesample_extraction() {
        assert_eq!(
            extract_tablesample("SELECT * FROM t TABLESAMPLE BERNOULLI(10)"),
            Some(10.0)
        );
        assert_eq!(
            extract_tablesample("SELECT * FROM t TABLESAMPLE SYSTEM(25.5)"),
            Some(25.5)
        );
        assert_eq!(extract_tablesample("SELECT * FROM t"), None);
    }

    #[test]
    fn presto_standard_query() {
        let mut schema = SchemaMap::new();
        schema.add(
            "clicks",
            TableSchema::new("id")
                .with_attr(AttrDef::scalar("page", "clicks"))
                .with_attr(AttrDef::scalar("visitor", "clicks")),
        );

        let result = PrestoDialect
            .compile(
                "SELECT c.id, c.page FROM clicks c WHERE c.visitor = 'v1'",
                &schema,
                "v1_clicks",
            )
            .unwrap();

        let input = vec![
            fact("clicks/page", "c1", "/home"),
            fact("clicks/visitor", "c1", "v1"),
            fact("clicks/page", "c2", "/about"),
            fact("clicks/visitor", "c2", "v2"),
        ];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "v1_clicks", "c1", "/home"));
        assert!(!has(&derived, "v1_clicks", "c2", "/about"));
    }

    #[test]
    fn tablesample_in_post_process() {
        let mut schema = SchemaMap::new();
        schema.add(
            "logs",
            TableSchema::new("id").with_attr(AttrDef::scalar("level", "logs")),
        );

        let result = PrestoDialect
            .compile(
                "SELECT l.id, l.level FROM logs l TABLESAMPLE BERNOULLI(20)",
                &schema,
                "sample",
            )
            .unwrap();
        assert_eq!(result.post_process.percent, Some(20.0));
        assert!(result.features.contains(&EnterpriseFeature::Sampling));
    }
}
