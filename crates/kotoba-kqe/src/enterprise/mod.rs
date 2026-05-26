//! Enterprise query dialect support for kotoba-kqe.
//!
//! Each dialect compiles its query language into a `DatalogProgram` +
//! `PostProcess`.  `PostProcess` carries directives that Datalog cannot express
//! (LIMIT, ORDER BY, sampling) and must be applied by the caller after
//! `DatalogProgram::evaluate_delta()`.
//!
//! # Supported dialects
//!
//! | Dialect              | Module      | sqlparser dialect       |
//! |----------------------|-------------|-------------------------|
//! | Oracle SQL           | oracle      | GenericDialect + rewrite |
//! | T-SQL (SQL Server)   | tsql        | MsSqlDialect            |
//! | SAP HANA SQL         | hana        | GenericDialect + rewrite |
//! | IBM Db2 SQL          | db2         | GenericDialect + rewrite |
//! | Teradata SQL         | teradata    | GenericDialect + rewrite |
//! | Snowflake SQL        | snowflake   | SnowflakeDialect        |
//! | Google BigQuery      | bigquery    | BigQueryDialect         |
//! | Presto / Trino       | presto      | GenericDialect + rewrite |
//! | MDX (OLAP)           | mdx         | hand-written parser     |
//! | HiveQL               | hiveql      | HiveDialect             |

pub mod sql_base;
pub mod oracle;
pub mod tsql;
pub mod hana;
pub mod db2;
pub mod teradata;
pub mod snowflake;
pub mod bigquery;
pub mod presto;
pub mod mdx;
pub mod hiveql;

pub use oracle::OracleDialect;
pub use tsql::TSqlDialect;
pub use hana::HanaDialect;
pub use db2::Db2Dialect;
pub use teradata::TeradataDialect;
pub use snowflake::SnowflakeDialect;
pub use bigquery::BigQueryDialect;
pub use presto::PrestoDialect;
pub use mdx::MdxDialect;
pub use hiveql::HiveQlDialect;

use crate::datalog::DatalogProgram;
use crate::schema::SchemaMap;

// ── EnterpriseFeature ────────────────────────────────────────────────────────

/// Dialect-specific features detected during compilation.
/// Informational — callers may use these to log or reject unsupported features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseFeature {
    HierarchicalQuery, // CONNECT BY / recursive CTE → multiple Datalog rules
    Pivot,             // PIVOT / UNPIVOT → predicate-per-column expansion
    OlapWindow,        // OVER (PARTITION BY … ORDER BY) → post-process ranking
    Sampling,          // TABLESAMPLE / SAMPLE → PostProcess::percent / sample_n
    SemiStructured,    // VARIANT / STRUCT / ARRAY → sub-predicate expansion
    Temporal,          // AS OF / FOR SYSTEM_TIME → graph CID binding
    Lateral,           // LATERAL / CROSS APPLY → join expansion
    MacroExpansion,    // BTEQ MACRO / HANA calculation view → pre-expansion
}

// ── PostProcess ───────────────────────────────────────────────────────────────

/// Directives applied **after** `evaluate_delta()` by the caller.
#[derive(Debug, Default, Clone)]
pub struct PostProcess {
    /// Maximum rows (TOP N / LIMIT / FETCH FIRST N ROWS ONLY / ROWNUM <= N).
    pub limit:    Option<usize>,
    /// Skip first N rows (OFFSET).
    pub offset:   Option<usize>,
    /// Percentage-based row cap (TOP N PERCENT / TABLESAMPLE BERNOULLI(N)).
    pub percent:  Option<f64>,
    /// Column names for deterministic ordering (ascending).
    pub order_by: Vec<String>,
    /// Reservoir sampling target (SAMPLE N / TABLESAMPLE(BUCKET …)).
    pub sample_n: Option<usize>,
}

// ── CompiledEnterpriseQuery ───────────────────────────────────────────────────

#[allow(dead_code)]
pub struct CompiledEnterpriseQuery {
    pub program:         DatalogProgram,
    pub output_relation: String,
    pub dialect:         &'static str,
    pub features:        Vec<EnterpriseFeature>,
    pub post_process:    PostProcess,
}

// ── EnterpriseDialect trait ───────────────────────────────────────────────────

pub trait EnterpriseDialect {
    fn dialect_name(&self) -> &'static str;

    /// Compile `query` into a `CompiledEnterpriseQuery`.
    ///
    /// `schema` maps enterprise table names to their N-column definitions.
    /// `output` is the head predicate of the generated Datalog rule.
    fn compile(
        &self,
        query:  &str,
        schema: &SchemaMap,
        output: &str,
    ) -> anyhow::Result<CompiledEnterpriseQuery>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_process_default_all_none() {
        let pp = PostProcess::default();
        assert!(pp.limit.is_none());
        assert!(pp.offset.is_none());
        assert!(pp.percent.is_none());
        assert!(pp.order_by.is_empty());
        assert!(pp.sample_n.is_none());
    }

    #[test]
    fn post_process_limit_and_offset_set() {
        let pp = PostProcess {
            limit:    Some(100),
            offset:   Some(10),
            percent:  None,
            order_by: vec!["name".to_string()],
            sample_n: None,
        };
        assert_eq!(pp.limit, Some(100));
        assert_eq!(pp.offset, Some(10));
        assert_eq!(pp.order_by, vec!["name"]);
    }

    #[test]
    fn enterprise_feature_equality() {
        assert_eq!(EnterpriseFeature::Pivot, EnterpriseFeature::Pivot);
        assert_ne!(EnterpriseFeature::Pivot, EnterpriseFeature::OlapWindow);
    }

    #[test]
    fn enterprise_feature_debug_contains_variant_name() {
        let s = format!("{:?}", EnterpriseFeature::HierarchicalQuery);
        assert!(s.contains("HierarchicalQuery"));
    }

    #[test]
    fn enterprise_feature_clone() {
        let f = EnterpriseFeature::Temporal;
        let g = f.clone();
        assert_eq!(f, g);
    }
}
