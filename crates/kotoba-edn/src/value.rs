use ordered_float::OrderedFloat;
use std::collections::{BTreeMap, BTreeSet};

/// A namespaced symbol. `namespace` is `None` for bare symbols.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Symbol {
    pub namespace: Option<String>,
    pub name: String,
}

impl Symbol {
    pub fn bare<S: Into<String>>(name: S) -> Self {
        Self {
            namespace: None,
            name: name.into(),
        }
    }
    pub fn namespaced<N: Into<String>, S: Into<String>>(ns: N, name: S) -> Self {
        Self {
            namespace: Some(ns.into()),
            name: name.into(),
        }
    }
    /// Parse a `ns/name` or `name` string into a Symbol.
    pub fn parse(s: &str) -> Self {
        match s.find('/') {
            Some(i) if i > 0 && i < s.len() - 1 => Self {
                namespace: Some(s[..i].to_string()),
                name: s[i + 1..].to_string(),
            },
            _ => Self::bare(s),
        }
    }
    pub fn to_qualified(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}/{}", ns, self.name),
            None => self.name.clone(),
        }
    }
}

/// A namespaced keyword (`:ns/name` or `:name`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Keyword(pub Symbol);

impl Keyword {
    pub fn bare<S: Into<String>>(name: S) -> Self {
        Self(Symbol::bare(name))
    }
    pub fn namespaced<N: Into<String>, S: Into<String>>(ns: N, name: S) -> Self {
        Self(Symbol::namespaced(ns, name))
    }
    pub fn parse(s: &str) -> Self {
        Self(Symbol::parse(s))
    }
    pub fn to_qualified(&self) -> String {
        self.0.to_qualified()
    }
    pub fn namespace(&self) -> Option<&str> {
        self.0.namespace.as_deref()
    }
    pub fn name(&self) -> &str {
        &self.0.name
    }
}

/// EDN values. `Map` and `Set` use ordered collections so equality and CID
/// hashing are deterministic regardless of insertion order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdnValue {
    Nil,
    Bool(bool),
    Integer(i64),
    /// Arbitrary-precision integer (decimal string with optional leading `-` and
    /// trailing `N`). Preserved verbatim — interop layers convert as needed.
    BigInt(String),
    Float(OrderedFloat<f64>),
    /// Arbitrary-precision decimal (string with trailing `M`).
    BigDec(String),
    Char(char),
    String(String),
    Symbol(Symbol),
    Keyword(Keyword),
    List(Vec<EdnValue>),
    Vector(Vec<EdnValue>),
    Map(BTreeMap<EdnValue, EdnValue>),
    Set(BTreeSet<EdnValue>),
    /// `#tag value` — tag is a Symbol.
    Tagged {
        tag: Symbol,
        value: Box<EdnValue>,
    },
}

impl EdnValue {
    pub fn kw<N: Into<String>, S: Into<String>>(ns: N, name: S) -> Self {
        Self::Keyword(Keyword::namespaced(ns, name))
    }
    pub fn kw_bare<S: Into<String>>(name: S) -> Self {
        Self::Keyword(Keyword::bare(name))
    }
    pub fn sym<S: Into<String>>(name: S) -> Self {
        Self::Symbol(Symbol::bare(name))
    }
    pub fn string<S: Into<String>>(s: S) -> Self {
        Self::String(s.into())
    }
    pub fn int(i: i64) -> Self {
        Self::Integer(i)
    }
    pub fn float(f: f64) -> Self {
        Self::Float(OrderedFloat(f))
    }
    pub fn nil() -> Self {
        Self::Nil
    }
    pub fn bool(b: bool) -> Self {
        Self::Bool(b)
    }
    pub fn vector<I: IntoIterator<Item = EdnValue>>(items: I) -> Self {
        Self::Vector(items.into_iter().collect())
    }
    pub fn list<I: IntoIterator<Item = EdnValue>>(items: I) -> Self {
        Self::List(items.into_iter().collect())
    }
    pub fn map<I: IntoIterator<Item = (EdnValue, EdnValue)>>(items: I) -> Self {
        Self::Map(items.into_iter().collect())
    }
    pub fn set<I: IntoIterator<Item = EdnValue>>(items: I) -> Self {
        Self::Set(items.into_iter().collect())
    }
    pub fn tagged<S: Into<String>>(tag: S, value: EdnValue) -> Self {
        Self::Tagged {
            tag: Symbol::parse(&tag.into()),
            value: Box::new(value),
        }
    }

    pub fn as_keyword(&self) -> Option<&Keyword> {
        if let Self::Keyword(k) = self {
            Some(k)
        } else {
            None
        }
    }
    pub fn as_symbol(&self) -> Option<&Symbol> {
        if let Self::Symbol(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_string(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
    pub fn as_integer(&self) -> Option<i64> {
        if let Self::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }
    pub fn as_float(&self) -> Option<f64> {
        if let Self::Float(f) = self {
            Some(f.0)
        } else {
            None
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
    pub fn as_vector(&self) -> Option<&[EdnValue]> {
        if let Self::Vector(v) = self {
            Some(v.as_slice())
        } else {
            None
        }
    }
    pub fn as_list(&self) -> Option<&[EdnValue]> {
        if let Self::List(v) = self {
            Some(v.as_slice())
        } else {
            None
        }
    }
    pub fn as_seq(&self) -> Option<&[EdnValue]> {
        match self {
            Self::Vector(v) | Self::List(v) => Some(v.as_slice()),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&BTreeMap<EdnValue, EdnValue>> {
        if let Self::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }
    pub fn as_set(&self) -> Option<&BTreeSet<EdnValue>> {
        if let Self::Set(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn is_nil(&self) -> bool {
        matches!(self, Self::Nil)
    }
}
