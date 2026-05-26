//! HiveQL dialect compiler.
//!
//! Uses `sqlparser::dialect::HiveDialect`.
//!
//! # Supported HiveQL-specific features
//!
//! | Feature | Handling |
//! |---------|----------|
//! | `LATERAL VIEW EXPLODE(arr)` | → `EnterpriseFeature::SemiStructured`, stripped |
//! | `DISTRIBUTE BY col` | → stripped (sharding is handled outside KQE) |
//! | `SORT BY col` | → `PostProcess::order_by` |
//! | `CLUSTER BY col` | → `PostProcess::order_by` (both DISTRIBUTE+SORT) |
//! | `TABLESAMPLE(BUCKET N OUT OF M)` | → `PostProcess::sample_n = N` |
//! | `MAP … REDUCE` | → `EnterpriseFeature::MacroExpansion` |

use sqlparser::dialect::HiveDialect as SqlparserHive;

use crate::schema::SchemaMap;
use super::{
    CompiledEnterpriseQuery, EnterpriseDialect, EnterpriseFeature,
    sql_base::SchemaBasedSqlCompiler,
};

pub struct HiveQlDialect;

impl EnterpriseDialect for HiveQlDialect {
    fn dialect_name(&self) -> &'static str { "hiveql" }

    fn compile(
        &self,
        query:  &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery> {
        let mut features = Vec::new();
        let upper = query.to_uppercase();

        if upper.contains("LATERAL VIEW") {
            features.push(EnterpriseFeature::SemiStructured);
        }
        if upper.contains(" MAP ") || upper.contains(" REDUCE ") {
            features.push(EnterpriseFeature::MacroExpansion);
        }

        let (prepped, extra) = preprocess_hiveql(query);

        let (program, mut pp) = SchemaBasedSqlCompiler::compile(
            &prepped,
            &SqlparserHive {},
            schema,
            output,
        )?;

        if pp.sample_n.is_none() { pp.sample_n = extra.sample_n; }
        if pp.order_by.is_empty() { pp.order_by = extra.order_by; }

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

struct HiveExtra {
    sample_n: Option<usize>,
    order_by: Vec<String>,
}

fn preprocess_hiveql(sql: &str) -> (String, HiveExtra) {
    let mut s = sql.to_string();
    let mut extra = HiveExtra { sample_n: None, order_by: Vec::new() };

    // TABLESAMPLE(BUCKET N OUT OF M) → extract N and strip
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find("TABLESAMPLE(BUCKET ") {
        if let Some(end) = s[idx..].find(')') {
            let clause = &s[idx + 19..idx + end]; // after "TABLESAMPLE(BUCKET "
            if let Some(n) = clause.split_whitespace().next().and_then(|n| n.parse::<usize>().ok()) {
                extra.sample_n = Some(n);
            }
            s.replace_range(idx..idx + end + 1, "");
        }
    }

    // LATERAL VIEW EXPLODE(col) t AS item → strip
    let upper = s.to_uppercase();
    while let Some(idx) = upper.find("LATERAL VIEW ") {
        let end = s[idx..].find('\n').map(|i| idx + i).unwrap_or(s.len());
        s.replace_range(idx..end, "");
        break;
    }

    // DISTRIBUTE BY col → strip
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find(" DISTRIBUTE BY ") {
        let end = s[idx..].find('\n').map(|i| idx + i)
            .or_else(|| s[idx..].find(" SORT BY ").map(|i| idx + i))
            .or_else(|| s[idx..].find(" CLUSTER BY ").map(|i| idx + i))
            .unwrap_or(s.len());
        s.replace_range(idx..end, "");
    }

    // SORT BY col → PostProcess::order_by + strip
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find(" SORT BY ") {
        let rest = s[idx + 9..].trim_start();
        let col = rest.split(|c: char| c.is_whitespace() || c == ',')
            .next().unwrap_or("").to_string();
        if !col.is_empty() { extra.order_by.push(col); }
        let end = s[idx..].find('\n').map(|i| idx + i).unwrap_or(s.len());
        s.replace_range(idx..end, "");
    }

    // CLUSTER BY col → PostProcess::order_by + strip
    let upper = s.to_uppercase();
    if let Some(idx) = upper.find(" CLUSTER BY ") {
        let rest = s[idx + 12..].trim_start();
        let col = rest.split(|c: char| c.is_whitespace() || c == ',')
            .next().unwrap_or("").to_string();
        if !col.is_empty() { extra.order_by.push(col); }
        let end = s[idx..].find('\n').map(|i| idx + i).unwrap_or(s.len());
        s.replace_range(idx..end, "");
    }

    (s, extra)
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
    fn hive_standard_select() {
        let mut schema = SchemaMap::new();
        schema.add("pageviews", TableSchema::new("id")
            .with_attr(AttrDef::scalar("page", "pageviews"))
            .with_attr(AttrDef::scalar("country", "pageviews")));

        let result = HiveQlDialect.compile(
            "SELECT p.id, p.page FROM pageviews p WHERE p.country = 'JP'",
            &schema, "jp_views",
        ).unwrap();

        let input = vec![
            fact("pageviews/page",    "pv1", "/home"),
            fact("pageviews/country", "pv1", "JP"),
            fact("pageviews/page",    "pv2", "/about"),
            fact("pageviews/country", "pv2", "US"),
        ];
        let derived = result.program.evaluate_delta(&input);
        assert!(has(&derived, "jp_views", "pv1", "/home"));
        assert!(!has(&derived, "jp_views", "pv2", "/about"));
    }

    #[test]
    fn bucket_sample_extracted() {
        let mut schema = SchemaMap::new();
        schema.add("logs", TableSchema::new("id")
            .with_attr(AttrDef::scalar("level", "logs")));

        let result = HiveQlDialect.compile(
            "SELECT l.id, l.level FROM logs l TABLESAMPLE(BUCKET 3 OUT OF 10)",
            &schema, "sample",
        ).unwrap();
        assert_eq!(result.post_process.sample_n, Some(3));
    }

    #[test]
    fn lateral_view_feature_detected() {
        let mut schema = SchemaMap::new();
        schema.add("t", TableSchema::new("s")
            .with_attr(AttrDef::scalar("o", "t")));

        let result = HiveQlDialect.compile(
            "SELECT t.s, t.o FROM t\nLATERAL VIEW EXPLODE(tags) tmp AS tag",
            &schema, "out",
        ).unwrap();
        assert!(result.features.contains(&EnterpriseFeature::SemiStructured));
    }
}
