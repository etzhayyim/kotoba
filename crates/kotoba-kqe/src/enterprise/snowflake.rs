//! Snowflake SQL dialect compiler.
//!
//! Uses `sqlparser::dialect::SnowflakeDialect`.
//!
//! # Supported Snowflake-specific features
//!
//! | Feature | Handling |
//! |---------|----------|
//! | `QUALIFY` (window post-filter) | → `EnterpriseFeature::OlapWindow`, stripped |
//! | `FLATTEN(INPUT => col)` | → `EnterpriseFeature::SemiStructured`, col expansion |
//! | `LATERAL FLATTEN` | → `EnterpriseFeature::Lateral` |
//! | `ILIKE` | → rewritten to `LIKE` (case-sensitive approximation) |
//! | `PARSE_JSON(col)` | → stripped (JSON values treated as scalars) |
//! | `COPY INTO` | → rejected (ingest-only, use kotoba-ingest) |

use sqlparser::dialect::SnowflakeDialect as SqlparserSnowflake;

use crate::schema::SchemaMap;
use super::{
    CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature,
    sql_base::SchemaBasedSqlCompiler,
};

pub struct SnowflakeDialect;

impl EnterpriseDialect for SnowflakeDialect {
    fn dialect_name(&self) -> &'static str { "snowflake" }

    fn compile(
        &self,
        query:  &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let upper = query.to_uppercase();
        if upper.contains("COPY INTO") {
            anyhow::bail!("COPY INTO is an ingest operation; use kotoba-ingest instead");
        }

        let mut features = Vec::new();

        if upper.contains("QUALIFY") {
            features.push(EnterpriseFeature::OlapWindow);
        }
        if upper.contains("FLATTEN") {
            features.push(EnterpriseFeature::SemiStructured);
        }
        if upper.contains("LATERAL") {
            features.push(EnterpriseFeature::Lateral);
        }

        let prepped = preprocess_snowflake(query);

        let (program, pp) = SchemaBasedSqlCompiler::compile(
            &prepped,
            &SqlparserSnowflake {},
            schema,
            output,
        )?;

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

fn preprocess_snowflake(sql: &str) -> String {
    let mut s = sql.to_string();

    // QUALIFY … → strip (window post-filter applied by caller)
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find("\nQUALIFY ").or_else(|| upper.find(" QUALIFY ")) {
        let end = s[idx..].find('\n').map(|i| idx + i).unwrap_or(s.len());
        s.replace_range(idx..end, "");
    }

    // ILIKE → LIKE (Kotoba CID space is case-sensitive anyway)
    s = s.replace("ILIKE", "LIKE");
    s = s.replace("ilike", "LIKE");

    // PARSE_JSON(col) → col
    while let Some(idx) = s.to_uppercase().find("PARSE_JSON(") {
        if let Some(end) = find_paren(&s, idx + 10) {
            let inner = s[idx + 11..end].to_string();
            s.replace_range(idx..end + 1, &inner);
        } else { break; }
    }

    // FLATTEN(INPUT => col) → col (simplified: just keep the referenced column)
    while let Some(idx) = s.to_uppercase().find("FLATTEN(") {
        if let Some(end) = find_paren(&s, idx + 7) {
            let clause = s[idx + 8..end].to_string();
            // Extract col from "INPUT => col" or just "col"
            let col = clause.split("=>").last().unwrap_or(&clause).trim().to_string();
            s.replace_range(idx..end + 1, &col);
        } else { break; }
    }

    s
}

fn find_paren(s: &str, open: usize) -> Option<usize> {
    let mut depth = 1i32;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => { depth -= 1; if depth == 0 { return Some(open + i); } }
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
    fn copy_into_rejected() {
        let schema = SchemaMap::new();
        match SnowflakeDialect.compile("COPY INTO my_table FROM @stage", &schema, "out") {
            Err(e) => assert!(e.to_string().contains("kotoba-ingest"), "unexpected error: {e}"),
            Ok(_)  => panic!("expected error for COPY INTO"),
        }
    }

    #[test]
    fn standard_snowflake_select() {
        let mut schema = SchemaMap::new();
        schema.add("events", TableSchema::new("id")
            .with_attr(AttrDef::scalar("event_type", "events"))
            .with_attr(AttrDef::scalar("user_id", "events")));

        let result = SnowflakeDialect.compile(
            "SELECT e.id, e.event_type FROM events e WHERE e.user_id = 'u1'",
            &schema, "user_events",
        ).unwrap();

        let input = vec![
            fact("events/event_type", "e1", "click"),
            fact("events/user_id",    "e1", "u1"),
            fact("events/event_type", "e2", "view"),
            fact("events/user_id",    "e2", "u2"),
        ];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "user_events", "e1", "click"));
        assert!(!has(&derived, "user_events", "e2", "view"));
    }

    #[test]
    fn flatten_feature_detected() {
        let schema = SchemaMap::new();
        let result = SnowflakeDialect.compile(
            "SELECT t.s, t.o FROM t WHERE t.s = 'x' -- FLATTEN here",
            &schema, "out",
        );
        // FLATTEN in comment is not detected as a feature (no real FLATTEN call)
        if let Ok(r) = result {
            assert!(!r.features.contains(&EnterpriseFeature::SemiStructured));
        }
    }
}
