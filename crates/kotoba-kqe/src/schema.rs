//! EAV schema mapping — translates N-column enterprise tables into kotoba
//! binary predicates `(Subject CID, predicate_string, Object CID)`.
//!
//! # Mapping rule
//!
//! For `orders(id, customer_id, amount, status)` with `entity_col = "id"`:
//!
//! ```text
//! orders/customer_id(entity_cid, ref_cid)   — AttrKind::Entity  (FK)
//! orders/amount(entity_cid, amount_cid)     — AttrKind::Numeric
//! orders/status(entity_cid, status_cid)     — AttrKind::Scalar
//! ```
//!
//! If no schema is registered for a table the compiler falls back to the
//! two-column binary assumption (`s` = subject, `o` = object) used by the
//! original `SqlMvCompiler`.

use std::collections::HashMap;

// ── AttrKind ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrKind {
    /// Foreign-key reference — object = entity CID of the referenced row.
    Entity,
    /// String literal — object = `cid_of_str(value)`.
    Scalar,
    /// Numeric (integer or float) — object = `cid_of_str(n.to_string())`.
    Numeric,
    /// ISO 8601 timestamp — object = `cid_of_str(iso_string)`.
    Temporal,
}

// ── AttrDef ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttrDef {
    pub col:       String,
    pub predicate: String,
    pub kind:      AttrKind,
}

impl AttrDef {
    fn make(col: &str, table: &str, kind: AttrKind) -> Self {
        Self {
            col:       col.to_string(),
            predicate: format!("{table}/{col}"),
            kind,
        }
    }

    pub fn entity(col: &str, table: &str)   -> Self { Self::make(col, table, AttrKind::Entity) }
    pub fn scalar(col: &str, table: &str)   -> Self { Self::make(col, table, AttrKind::Scalar) }
    pub fn numeric(col: &str, table: &str)  -> Self { Self::make(col, table, AttrKind::Numeric) }
    pub fn temporal(col: &str, table: &str) -> Self { Self::make(col, table, AttrKind::Temporal) }

    /// Override the default `"{table}/{col}"` predicate name.
    pub fn with_predicate(mut self, predicate: &str) -> Self {
        self.predicate = predicate.to_string();
        self
    }
}

// ── TableSchema ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TableSchema {
    /// Primary key column — rows are identified by this value (becomes Subject CID).
    pub entity_col: String,
    /// Non-PK attribute columns.
    pub attrs: Vec<AttrDef>,
}

impl TableSchema {
    pub fn new(entity_col: &str) -> Self {
        Self { entity_col: entity_col.to_string(), attrs: Vec::new() }
    }

    pub fn with_attr(mut self, attr: AttrDef) -> Self {
        self.attrs.push(attr);
        self
    }

    pub fn attr(&self, col: &str) -> Option<&AttrDef> {
        self.attrs.iter().find(|a| a.col == col)
    }

    pub fn is_entity_col(&self, col: &str) -> bool {
        self.entity_col == col
    }
}

// ── SchemaMap ─────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct SchemaMap {
    tables: HashMap<String, TableSchema>,
}

impl SchemaMap {
    pub fn new() -> Self { Self::default() }

    pub fn add(&mut self, name: &str, schema: TableSchema) -> &mut Self {
        self.tables.insert(name.to_string(), schema);
        self
    }

    pub fn get(&self, name: &str) -> Option<&TableSchema> {
        self.tables.get(name)
    }

    /// Returns the registered schema, or a synthetic binary schema (`s`/`o`)
    /// for backward compatibility with unregistered tables.
    pub fn effective(&self, table: &str) -> std::borrow::Cow<'_, TableSchema> {
        match self.tables.get(table) {
            Some(s) => std::borrow::Cow::Borrowed(s),
            None => std::borrow::Cow::Owned(
                TableSchema::new("s")
                    .with_attr(AttrDef::scalar("o", table)),
            ),
        }
    }

    pub fn is_registered(&self, table: &str) -> bool {
        self.tables.contains_key(table)
    }

    /// Canonical predicate name: `"{table}/{col}"`.
    pub fn predicate(table: &str, col: &str) -> String {
        format!("{table}/{col}")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_registered() {
        let mut m = SchemaMap::new();
        m.add("orders",
            TableSchema::new("id")
                .with_attr(AttrDef::entity("customer_id", "orders"))
                .with_attr(AttrDef::numeric("amount", "orders"))
                .with_attr(AttrDef::scalar("status", "orders")),
        );

        let s = m.get("orders").unwrap();
        assert_eq!(s.entity_col, "id");
        assert_eq!(s.attr("amount").unwrap().predicate, "orders/amount");
        assert_eq!(s.attr("customer_id").unwrap().kind, AttrKind::Entity);
    }

    #[test]
    fn effective_fallback_binary() {
        let m = SchemaMap::new();
        let schema = m.effective("unknown_table");
        assert_eq!(schema.entity_col, "s");
        assert!(schema.attr("o").is_some());
    }

    #[test]
    fn predicate_name() {
        assert_eq!(SchemaMap::predicate("orders", "status"), "orders/status");
    }
}
