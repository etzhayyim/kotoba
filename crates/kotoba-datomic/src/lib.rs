//! Datomic-compatible facade for kotoba.
//!
//! The atomic storage unit is a Datom, exactly the 5-tuple
//! `(E, A, V, T, Added)`.

pub mod distributed;

use kotoba_core::cid::KotobaCid;
use kotoba_edn::{to_string as edn_to_string, EdnValue, Keyword, Symbol};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

pub type Entity = KotobaCid;
pub type Attribute = String;
pub type Value = EdnValue;
pub type Transaction = KotobaCid;
pub type TxFn = Arc<dyn Fn(&Db, &[EdnValue]) -> Result<EdnValue> + Send + Sync + 'static>;

type TxFnRegistry = BTreeMap<String, TxFn>;

const DB_ADD: &str = ":db/add";
const DB_RETRACT: &str = ":db/retract";
const DB_FN_CAS: &str = ":db.fn/cas";
const DB_FN_RETRACT_ENTITY: &str = ":db.fn/retractEntity";
const DB_FN_RETRACT_ATTRIBUTE: &str = ":db.fn/retractAttribute";
const DB_IDENT: &str = ":db/ident";
const DB_CARDINALITY: &str = ":db/cardinality";
const DB_CARDINALITY_ONE: &str = ":db.cardinality/one";
const DB_CARDINALITY_MANY: &str = ":db.cardinality/many";
const DB_UNIQUE: &str = ":db/unique";
const DB_UNIQUE_IDENTITY: &str = ":db.unique/identity";
const DB_UNIQUE_VALUE: &str = ":db.unique/value";
const DB_VALUE_TYPE: &str = ":db/valueType";
const DB_INDEX: &str = ":db/index";
const DB_IS_COMPONENT: &str = ":db/isComponent";
const DB_NO_HISTORY: &str = ":db/noHistory";
const DB_DOC: &str = ":db/doc";
const DB_EXCISE: &str = ":db/excise";
const DB_EXCISE_BEFORE: &str = ":db.excise/before";
const DB_TYPE_REF: &str = ":db.type/ref";
const DB_TYPE_STRING: &str = ":db.type/string";
const DB_TYPE_LONG: &str = ":db.type/long";
const DB_TYPE_BOOLEAN: &str = ":db.type/boolean";
const DB_TYPE_DOUBLE: &str = ":db.type/double";
const DB_TYPE_KEYWORD: &str = ":db.type/keyword";
const DB_TYPE_SYMBOL: &str = ":db.type/symbol";
const DB_TYPE_BIGINT: &str = ":db.type/bigint";
const DB_TYPE_BIGDEC: &str = ":db.type/bigdec";
const DB_TYPE_INSTANT: &str = ":db.type/instant";
const DB_TYPE_UUID: &str = ":db.type/uuid";
const DB_TYPE_BYTES: &str = ":db.type/bytes";
const DB_TYPE_TUPLE: &str = ":db.type/tuple";
const DB_TX_INSTANT: &str = ":db/txInstant";
const DATOMIC_TX_TEMPID: &str = "datomic.tx";

#[derive(Debug, thiserror::Error)]
pub enum DatomicError {
    #[error("transaction data must be an EDN vector")]
    TxDataMustBeVector,
    #[error("transaction op must be a vector/list")]
    InvalidOpForm,
    #[error("entity map must contain :db/id")]
    MissingDbId,
    #[error("attribute must be a keyword")]
    AttributeMustBeKeyword,
    #[error("unsupported value for substrate datom: {0}")]
    UnsupportedValue(String),
    #[error("lookup ref not found: {0}")]
    LookupRefNotFound(String),
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),
    #[error("query error: {0}")]
    Query(String),
    #[error("unsupported operation {0}")]
    UnsupportedOperation(String),
    #[error("lock poisoned")]
    LockPoisoned,
}

pub type Result<T> = std::result::Result<T, DatomicError>;

/// Atomic fact: `(E, A, V, T, Added)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datom {
    pub e: Entity,
    pub a: Attribute,
    pub v: Value,
    pub t: Transaction,
    pub added: bool,
}

impl Datom {
    pub fn assert(e: Entity, a: Attribute, v: Value, t: Transaction) -> Self {
        Self {
            e,
            a,
            v,
            t,
            added: true,
        }
    }

    pub fn retract(e: Entity, a: Attribute, v: Value, t: Transaction) -> Self {
        Self {
            e,
            a,
            v,
            t,
            added: false,
        }
    }

    pub fn as_tuple(&self) -> (&Entity, &Attribute, &Value, &Transaction, bool) {
        (&self.e, &self.a, &self.v, &self.t, self.added)
    }

    pub fn to_kqe(&self) -> Result<kotoba_kqe::Datom> {
        Ok(kotoba_kqe::Datom {
            e: self.e.clone(),
            a: self.a.clone(),
            v: edn_to_kqe_value(&self.v)?,
            tx: self.t.clone(),
            op: self.added,
        })
    }

    pub fn from_kqe(datom: kotoba_kqe::Datom) -> Self {
        Self {
            e: datom.e,
            a: datom.a,
            v: kqe_value_to_edn(datom.v),
            t: datom.tx,
            added: datom.op,
        }
    }
}

#[derive(Clone, Default)]
pub struct Connection {
    store: Arc<RwLock<DatomStore>>,
    tx_fns: Arc<RwLock<TxFnRegistry>>,
}

#[derive(Default)]
struct DatomStore {
    datoms: Vec<Datom>,
    last_tx: Option<KotobaCid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExcisionDirective {
    Entity(Entity, Option<KotobaCid>),
    Attribute(Attribute, Option<KotobaCid>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactReport {
    pub db_before: Db,
    pub db_after: Db,
    pub tx_cid: KotobaCid,
    pub tx_data: Vec<Datom>,
    pub tempids: BTreeMap<String, KotobaCid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Db {
    pub basis_t: Option<KotobaCid>,
    datoms: Vec<Datom>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryDb {
    pub basis_t: Option<KotobaCid>,
    datoms: Vec<Datom>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatomIndex {
    Eavt,
    Aevt,
    Avet,
    Vaet,
    Tea,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub tx: KotobaCid,
    pub datoms: Vec<Datom>,
}

#[derive(Debug, Clone)]
pub struct LogIterator {
    entries: Vec<LogEntry>,
    pos: usize,
}

impl Connection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_datoms(datoms: Vec<Datom>) -> Self {
        let last_tx = datoms.last().map(|d| d.t.clone());
        Self {
            store: Arc::new(RwLock::new(DatomStore { datoms, last_tx })),
            tx_fns: Arc::default(),
        }
    }

    pub fn register_tx_fn<F>(&self, ident: impl Into<String>, f: F) -> Result<()>
    where
        F: Fn(&Db, &[EdnValue]) -> Result<EdnValue> + Send + Sync + 'static,
    {
        let mut tx_fns = self
            .tx_fns
            .write()
            .map_err(|_| DatomicError::LockPoisoned)?;
        tx_fns.insert(normalize_tx_fn_ident(ident.into()), Arc::new(f));
        Ok(())
    }

    pub fn db(&self) -> Db {
        let store = self.store.read().expect("datom store lock poisoned");
        Db {
            basis_t: store.last_tx.clone(),
            datoms: store.datoms.clone(),
        }
    }

    pub async fn transact(&self, tx_data: EdnValue) -> Result<TransactReport> {
        let db_before = self.db();
        let tx_placeholder = tx_placeholder_cid();
        let mut tempids = BTreeMap::new();
        let (tx_data, excisions) = split_excision_forms(&tx_data, &mut tempids, &db_before)?;
        let tx_fns = self
            .tx_fns
            .read()
            .map_err(|_| DatomicError::LockPoisoned)?
            .clone();
        let mut datoms = tx_data_to_datoms(
            &tx_data,
            tx_placeholder.clone(),
            &mut tempids,
            &db_before,
            &tx_fns,
        )?;
        let tx_instant = current_tx_instant();
        datoms.push(tx_instant_datom(tx_placeholder.clone(), tx_instant.clone()));
        let schema = Schema::from_datoms(&db_before.datoms);
        datoms = enforce_schema(datoms, tx_placeholder.clone(), &db_before, &schema)?;
        let tx_cid = tx_cid_for_datoms(
            &datoms,
            &tx_placeholder,
            &tx_instant,
            db_before.basis_t.as_ref(),
        );
        rewrite_tx_placeholder(&mut datoms, &tx_placeholder, &tx_cid);
        rewrite_tempid_placeholder(&mut tempids, &tx_placeholder, &tx_cid);

        let mut store = self.store.write().map_err(|_| DatomicError::LockPoisoned)?;
        apply_excision_directives(&mut store.datoms, &excisions);
        if !schema.no_history.is_empty() {
            for datom in &datoms {
                if schema.no_history.contains(&datom.a) {
                    store
                        .datoms
                        .retain(|old| !(old.e == datom.e && old.a == datom.a));
                }
            }
        }
        store.datoms.extend(datoms.clone());
        store.last_tx = Some(tx_cid.clone());
        let db_after = Db {
            basis_t: store.last_tx.clone(),
            datoms: store.datoms.clone(),
        };

        Ok(TransactReport {
            db_before,
            db_after,
            tx_cid,
            tx_data: datoms,
            tempids,
        })
    }

    pub fn log(&self) -> LogIterator {
        let datoms = self
            .store
            .read()
            .expect("datom store lock poisoned")
            .datoms
            .clone();
        LogIterator::new(datoms)
    }

    pub fn excise_entity(&self, eid: &Entity) -> Result<usize> {
        let mut store = self.store.write().map_err(|_| DatomicError::LockPoisoned)?;
        let before = store.datoms.len();
        store.datoms.retain(|datom| &datom.e != eid);
        Ok(before - store.datoms.len())
    }

    pub fn excise_attribute(&self, attr: &str) -> Result<usize> {
        let mut store = self.store.write().map_err(|_| DatomicError::LockPoisoned)?;
        let before = store.datoms.len();
        store.datoms.retain(|datom| datom.a != attr);
        Ok(before - store.datoms.len())
    }

    pub fn release(self) {}
}

impl Db {
    pub fn from_datoms(datoms: Vec<Datom>, basis_t: Option<KotobaCid>) -> Self {
        Self { basis_t, datoms }
    }

    pub fn all_datoms(&self) -> Vec<Datom> {
        self.datoms.clone()
    }

    /// Current true facts at this database basis.
    pub fn datoms(&self) -> Vec<Datom> {
        current_datoms(&self.datoms)
    }

    /// Datomic-like indexed datom scan over current facts.
    ///
    /// Component order follows Datomic index names:
    /// EAVT = e,a,v,t; AEVT = a,e,v,t; AVET = a,v,e,t;
    /// VAET = v,a,e,t; TEA = t,e,a,v.
    pub fn datoms_index(&self, index: DatomIndex, components: &[EdnValue]) -> Result<Vec<Datom>> {
        datoms_index(current_datoms(&self.datoms), index, components)
    }

    /// Datomic-like seek over current facts.
    ///
    /// Returns datoms in index order starting at the lexicographic lower bound
    /// described by `components`.
    pub fn seek_datoms(&self, index: DatomIndex, components: &[EdnValue]) -> Result<Vec<Datom>> {
        seek_datoms_index(current_datoms(&self.datoms), index, components)
    }

    /// Datomic-like AVET range scan for a single attribute.
    ///
    /// `start` is inclusive and `end` is exclusive. `None` leaves the bound
    /// open, matching Datomic's `index-range` shape.
    pub fn index_range(
        &self,
        attr: impl AsRef<str>,
        start: Option<&EdnValue>,
        end: Option<&EdnValue>,
    ) -> Result<Vec<Datom>> {
        index_range_datoms(current_datoms(&self.datoms), attr.as_ref(), start, end)
    }

    /// Full Datomic history, including retract tombstones.
    pub fn history(&self) -> HistoryDb {
        HistoryDb {
            basis_t: self.basis_t.clone(),
            datoms: history_datoms(&self.datoms),
        }
    }

    pub fn as_of(&self, t: &KotobaCid) -> Db {
        let mut out = Vec::new();
        for datom in &self.datoms {
            out.push(datom.clone());
            if &datom.t == t {
                let remaining_same_tx = self.datoms.iter().filter(|d| &d.t == t).count();
                if out.iter().filter(|d| &d.t == t).count() == remaining_same_tx {
                    break;
                }
            }
        }
        Db {
            basis_t: Some(t.clone()),
            datoms: out,
        }
    }

    pub fn since(&self, t: &KotobaCid) -> Db {
        let mut seen = false;
        let mut out = Vec::new();
        for datom in &self.datoms {
            if &datom.t == t {
                seen = true;
                continue;
            }
            if seen {
                out.push(datom.clone());
            }
        }
        Db {
            basis_t: self.basis_t.clone(),
            datoms: out,
        }
    }

    pub fn pull(&self, pattern: EdnValue, eid: Entity) -> Result<EdnValue> {
        pull_entity(self, &pattern, &eid)
    }

    pub fn pull_many(&self, pattern: EdnValue, eids: Vec<Entity>) -> Result<Vec<EdnValue>> {
        eids.into_iter()
            .map(|eid| self.pull(pattern.clone(), eid))
            .collect()
    }

    pub fn entity(&self, eid: Entity) -> Result<EdnValue> {
        self.pull(EdnValue::Vector(vec![]), eid)
    }
}

impl HistoryDb {
    pub fn datoms(&self) -> &[Datom] {
        &self.datoms
    }

    /// Datomic-like indexed datom scan over history facts, including retract tombstones.
    pub fn datoms_index(&self, index: DatomIndex, components: &[EdnValue]) -> Result<Vec<Datom>> {
        datoms_index(self.datoms.clone(), index, components)
    }

    pub fn seek_datoms(&self, index: DatomIndex, components: &[EdnValue]) -> Result<Vec<Datom>> {
        seek_datoms_index(self.datoms.clone(), index, components)
    }

    pub fn index_range(
        &self,
        attr: impl AsRef<str>,
        start: Option<&EdnValue>,
        end: Option<&EdnValue>,
    ) -> Result<Vec<Datom>> {
        index_range_datoms(self.datoms.clone(), attr.as_ref(), start, end)
    }
}

impl LogIterator {
    fn new(datoms: Vec<Datom>) -> Self {
        let mut entries = Vec::<LogEntry>::new();
        for datom in datoms {
            match entries.last_mut() {
                Some(entry) if entry.tx == datom.t => entry.datoms.push(datom),
                _ => entries.push(LogEntry {
                    tx: datom.t.clone(),
                    datoms: vec![datom],
                }),
            }
        }
        Self { entries, pos: 0 }
    }

    pub fn entries(&self) -> &[LogEntry] {
        &self.entries
    }
}

impl Iterator for LogIterator {
    type Item = LogEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.get(self.pos).cloned()?;
        self.pos += 1;
        Some(entry)
    }
}

pub fn q(query: EdnValue, db: &Db, inputs: &[EdnValue]) -> Result<Vec<Vec<EdnValue>>> {
    let facts = db.datoms();
    q_with_facts(query, db, inputs, &facts)
}

pub fn q_history(
    query: EdnValue,
    db: &HistoryDb,
    inputs: &[EdnValue],
) -> Result<Vec<Vec<EdnValue>>> {
    let context = Db::from_datoms(db.datoms.clone(), db.basis_t.clone());
    q_with_facts(query, &context, inputs, &db.datoms)
}

fn q_with_facts(
    query: EdnValue,
    db: &Db,
    inputs: &[EdnValue],
    facts: &[Datom],
) -> Result<Vec<Vec<EdnValue>>> {
    let query = query_map(&query)?;
    let find = query_vec(&query, ":find")?;
    let find_items = parse_find_items(find)?;
    let with_items = query
        .get(&kw("with"))
        .map(query_with_items)
        .transpose()?
        .unwrap_or_default();
    let where_clauses = query_vec(&query, ":where")?;
    let rules = if let Some(in_forms) = query.get(&kw("in")) {
        rules_from_inputs(in_forms, inputs)?
    } else {
        Vec::new()
    };
    let mut bindings = vec![BTreeMap::<String, EdnValue>::new()];
    if let Some(in_forms) = query.get(&kw("in")) {
        bindings = bind_inputs(in_forms, inputs, bindings)?;
    }

    for clause in where_clauses {
        bindings = eval_clause(clause, db, facts, &rules, bindings)?;
    }

    if find_items.iter().any(|item| item.is_aggregate()) {
        let rows = aggregate_rows(&find_items, &with_items, bindings, db)?;
        return query_result_window(&query, find, rows);
    }

    let mut rows = BTreeSet::new();
    for binding in bindings {
        let mut row = Vec::new();
        for item in &find_items {
            row.push(item.resolve(&binding, db)?);
        }
        rows.insert(row);
    }
    query_result_window(&query, find, rows.into_iter().collect())
}

pub fn query_map(query: &EdnValue) -> Result<BTreeMap<EdnValue, EdnValue>> {
    if let EdnValue::Map(map) = query {
        return Ok(map.clone());
    }
    let seq = query
        .as_seq()
        .ok_or_else(|| DatomicError::Query("query must be a map, vector, or list".into()))?;
    let mut out = BTreeMap::new();
    let mut idx = 0;
    while idx < seq.len() {
        let key = seq[idx]
            .as_keyword()
            .map(Keyword::to_qualified)
            .ok_or_else(|| {
                DatomicError::Query(format!(
                    "query clause key must be a keyword, got {}",
                    edn_to_string(&seq[idx])
                ))
            })?;
        idx += 1;
        let start = idx;
        while idx < seq.len() && seq[idx].as_keyword().is_none() {
            idx += 1;
        }
        if start == idx {
            return Err(DatomicError::Query(format!(
                "query clause :{key} requires a value"
            )));
        }
        let values = &seq[start..idx];
        let value = match key.as_str() {
            "find" => EdnValue::Vector(values.to_vec()),
            "limit" | "offset" => {
                if values.len() != 1 {
                    return Err(DatomicError::Query(format!(
                        "query clause :{key} expects one value"
                    )));
                }
                values[0].clone()
            }
            "where" | "in" | "with" | "keys" | "strs" | "syms" | "order-by" => {
                if values.len() == 1 {
                    if let Some(items) = values[0].as_seq() {
                        EdnValue::Vector(items.to_vec())
                    } else {
                        EdnValue::Vector(values.to_vec())
                    }
                } else {
                    EdnValue::Vector(values.to_vec())
                }
            }
            _ => {
                if values.len() == 1 {
                    values[0].clone()
                } else {
                    EdnValue::Vector(values.to_vec())
                }
            }
        };
        out.insert(kw(&key), value);
    }
    Ok(out)
}

pub(crate) fn query_result_window(
    query: &BTreeMap<EdnValue, EdnValue>,
    find: &[EdnValue],
    mut rows: Vec<Vec<EdnValue>>,
) -> Result<Vec<Vec<EdnValue>>> {
    apply_query_order(query, find, &mut rows)?;
    let offset = query
        .get(&kw("offset"))
        .map(|value| query_non_negative_usize(value, ":offset"))
        .transpose()?
        .unwrap_or(0);
    let limit = query
        .get(&kw("limit"))
        .map(|value| query_non_negative_usize(value, ":limit"))
        .transpose()?;
    let iter = rows.into_iter().skip(offset);
    let rows = match limit {
        Some(limit) => iter.take(limit).collect(),
        None => iter.collect(),
    };
    project_query_named_results(query, rows)
}

fn project_query_named_results(
    query: &BTreeMap<EdnValue, EdnValue>,
    rows: Vec<Vec<EdnValue>>,
) -> Result<Vec<Vec<EdnValue>>> {
    let projections = [
        ("keys", QueryNamedProjection::Keys),
        ("strs", QueryNamedProjection::Strs),
        ("syms", QueryNamedProjection::Syms),
    ]
    .into_iter()
    .filter_map(|(name, projection)| query.get(&kw(name)).map(|value| (projection, value)))
    .collect::<Vec<_>>();
    if projections.is_empty() {
        return Ok(rows);
    }
    if projections.len() > 1 {
        return Err(DatomicError::Query(
            "only one of :keys, :strs, or :syms may be used".into(),
        ));
    }
    let (projection, aliases) = projections[0];
    let aliases = aliases
        .as_seq()
        .ok_or_else(|| DatomicError::Query(":keys/:strs/:syms must be a vector/list".into()))?;
    for row in &rows {
        if row.len() != aliases.len() {
            return Err(DatomicError::Query(format!(
                ":keys/:strs/:syms count {} must match :find result width {}",
                aliases.len(),
                row.len()
            )));
        }
    }
    let keys = aliases
        .iter()
        .map(|alias| query_named_projection_key(projection, alias))
        .collect::<Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .map(|row| {
            vec![EdnValue::Map(
                keys.iter().cloned().zip(row).collect::<BTreeMap<_, _>>(),
            )]
        })
        .collect())
}

#[derive(Debug, Clone, Copy)]
enum QueryNamedProjection {
    Keys,
    Strs,
    Syms,
}

fn query_named_projection_key(
    projection: QueryNamedProjection,
    alias: &EdnValue,
) -> Result<EdnValue> {
    let name = match alias {
        EdnValue::Symbol(symbol) => symbol.to_qualified(),
        EdnValue::Keyword(keyword) => keyword.to_qualified(),
        EdnValue::String(value) => value.clone(),
        other => {
            return Err(DatomicError::Query(format!(
                ":keys/:strs/:syms aliases must be symbols, keywords, or strings, got {}",
                edn_to_string(other)
            )))
        }
    };
    Ok(match projection {
        QueryNamedProjection::Keys => {
            EdnValue::Keyword(Keyword::parse(name.trim_start_matches(':')))
        }
        QueryNamedProjection::Strs => EdnValue::String(name.trim_start_matches(':').to_string()),
        QueryNamedProjection::Syms => EdnValue::Symbol(Symbol::parse(name.trim_start_matches(':'))),
    })
}

fn apply_query_order(
    query: &BTreeMap<EdnValue, EdnValue>,
    find: &[EdnValue],
    rows: &mut [Vec<EdnValue>],
) -> Result<()> {
    let Some(order_by) = query.get(&kw("order-by")) else {
        return Ok(());
    };
    let specs = query_order_specs(order_by, find)?;
    rows.sort_by(|left, right| {
        for spec in &specs {
            let ordering = query_sort_order(&left[spec.index], &right[spec.index]);
            let ordering = if spec.desc {
                ordering.reverse()
            } else {
                ordering
            };
            if ordering != std::cmp::Ordering::Equal {
                return ordering;
            }
        }
        left.cmp(right)
    });
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct QueryOrderSpec {
    index: usize,
    desc: bool,
}

fn query_order_specs(order_by: &EdnValue, find: &[EdnValue]) -> Result<Vec<QueryOrderSpec>> {
    let items = order_by
        .as_seq()
        .ok_or_else(|| DatomicError::Query(":order-by must be a vector/list".into()))?;
    items
        .iter()
        .map(|item| {
            let (term, desc) = match item.as_seq() {
                Some(pair) if pair.len() == 2 => {
                    let direction = pair[1]
                        .as_keyword()
                        .map(keyword_to_attr)
                        .or_else(|| pair[1].as_symbol().map(|symbol| symbol.to_qualified()))
                        .ok_or_else(|| {
                            DatomicError::Query(format!(
                                ":order-by direction must be :asc or :desc, got {}",
                                edn_to_string(&pair[1])
                            ))
                        })?;
                    let desc = match direction.as_str() {
                        ":asc" | "asc" => false,
                        ":desc" | "desc" => true,
                        _ => {
                            return Err(DatomicError::Query(format!(
                                ":order-by direction must be :asc or :desc, got {}",
                                edn_to_string(&pair[1])
                            )));
                        }
                    };
                    (&pair[0], desc)
                }
                Some(_) => {
                    return Err(DatomicError::Query(format!(
                        ":order-by item must be ?var or [?var :asc|:desc], got {}",
                        edn_to_string(item)
                    )));
                }
                None => (item, false),
            };
            let index = if let Some(var) = variable_name(term) {
                find.iter()
                    .position(|find_item| variable_name(find_item) == Some(var))
                    .ok_or_else(|| {
                        DatomicError::Query(format!(
                            ":order-by variable ?{var} must appear directly in :find"
                        ))
                    })?
            } else {
                find.iter()
                    .position(|find_item| find_item == term)
                    .ok_or_else(|| {
                        DatomicError::Query(format!(
                            ":order-by item must appear directly in :find, got {}",
                            edn_to_string(term)
                        ))
                    })?
            };
            Ok(QueryOrderSpec { index, desc })
        })
        .collect()
}

pub fn plan_datom_lookup_for_triple(
    triple: &EdnValue,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<distributed::DatomIndexLookup> {
    let seq = triple
        .as_seq()
        .ok_or_else(|| DatomicError::Query("triple clause must be vector/list".into()))?;
    let Some(seq) = data_pattern_terms(seq) else {
        return Err(DatomicError::Query(format!(
            "triple clause must have 3 terms or source plus 3 terms, got {}",
            seq.len()
        )));
    };
    datom_lookup_for_triple(seq, binding)
}

fn query_with_items(value: &EdnValue) -> Result<Vec<EdnValue>> {
    value
        .as_vector()
        .ok_or_else(|| DatomicError::Query(":with must be a vector".into()))
        .map(|items| items.to_vec())
}

fn tx_data_to_datoms(
    tx_data: &EdnValue,
    tx_cid: KotobaCid,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    tx_fns: &TxFnRegistry,
) -> Result<Vec<Datom>> {
    let EdnValue::Vector(forms) = tx_data else {
        return Err(DatomicError::TxDataMustBeVector);
    };
    let schema = Schema::from_datoms(&db.datoms);
    tx_forms_to_datoms(forms, tx_cid, tempids, db, &[], &schema, tx_fns)
}

fn tx_forms_to_datoms(
    forms: &[EdnValue],
    tx_cid: KotobaCid,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    base_pending: &[Datom],
    schema: &Schema,
    tx_fns: &TxFnRegistry,
) -> Result<Vec<Datom>> {
    let mut out = Vec::new();
    for form in forms {
        let mut pending = Vec::with_capacity(base_pending.len() + out.len());
        pending.extend_from_slice(base_pending);
        pending.extend_from_slice(&out);
        match form {
            EdnValue::Map(entity) => out.extend(entity_map_to_datoms(
                entity.clone(),
                tx_cid.clone(),
                tempids,
                db,
                schema,
                &pending,
            )?),
            EdnValue::Vector(op) | EdnValue::List(op) => out.extend(op_form_to_datoms(
                op.clone(),
                tx_cid.clone(),
                tempids,
                db,
                &pending,
                schema,
                tx_fns,
            )?),
            _ => return Err(DatomicError::InvalidOpForm),
        }
    }
    Ok(out)
}

fn split_excision_forms(
    tx_data: &EdnValue,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
) -> Result<(EdnValue, Vec<ExcisionDirective>)> {
    let EdnValue::Vector(forms) = tx_data else {
        return Err(DatomicError::TxDataMustBeVector);
    };
    let mut retained = Vec::new();
    let mut excisions = Vec::new();
    for form in forms {
        if let EdnValue::Map(map) = form {
            if let Some(targets) = map.get(&kw_value(DB_EXCISE)) {
                let before = map
                    .get(&kw_value(DB_EXCISE_BEFORE))
                    .map(|value| entity_ref_to_cid(value, tempids, db))
                    .transpose()?;
                let targets = match targets {
                    EdnValue::Vector(items) | EdnValue::List(items) => items.clone(),
                    target => vec![target.clone()],
                };
                for target in targets {
                    if let EdnValue::Keyword(keyword) = &target {
                        excisions.push(ExcisionDirective::Attribute(
                            keyword_to_attr(keyword),
                            before.clone(),
                        ));
                    } else {
                        excisions.push(ExcisionDirective::Entity(
                            entity_ref_to_cid(&target, tempids, db)?,
                            before.clone(),
                        ));
                    }
                }
                continue;
            }
        }
        retained.push(form.clone());
    }
    Ok((EdnValue::Vector(retained), excisions))
}

fn apply_excision_directives(datoms: &mut Vec<Datom>, excisions: &[ExcisionDirective]) -> usize {
    if excisions.is_empty() {
        return 0;
    }
    let history = datoms.clone();
    let before = datoms.len();
    datoms.retain(|datom| {
        !excisions.iter().any(|excision| match excision {
            ExcisionDirective::Entity(entity, before_tx) => {
                datom.e == *entity && tx_before_filter_matches(&history, &datom.t, before_tx)
            }
            ExcisionDirective::Attribute(attr, before_tx) => {
                datom.a == *attr && tx_before_filter_matches(&history, &datom.t, before_tx)
            }
        })
    });
    before - datoms.len()
}

fn tx_before_filter_matches(
    history: &[Datom],
    tx: &KotobaCid,
    before_tx: &Option<KotobaCid>,
) -> bool {
    let Some(before_tx) = before_tx else {
        return true;
    };
    for datom in history {
        if &datom.t == tx {
            return true;
        }
        if &datom.t == before_tx {
            return false;
        }
    }
    false
}

fn entity_map_to_datoms(
    mut entity: BTreeMap<EdnValue, EdnValue>,
    tx_cid: KotobaCid,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    schema: &Schema,
    pending: &[Datom],
) -> Result<Vec<Datom>> {
    let db_id_key = EdnValue::Keyword(Keyword::namespaced("db", "id"));
    let db_ident_key = EdnValue::Keyword(Keyword::namespaced("db", "ident"));
    let eid_value = entity
        .remove(&db_id_key)
        .or_else(|| entity.get(&db_ident_key).cloned())
        .ok_or(DatomicError::MissingDbId)?;
    bind_unique_identity_tempid(&eid_value, &entity, tempids, db, schema, pending)?;
    let eid = entity_ref_to_cid_for_tx(&eid_value, tempids, db, &tx_cid)?;
    let mut out = Vec::new();
    for (a, v) in entity {
        let a = attr_to_string(&a)?;
        if schema.cardinality_many.contains(&a) {
            for v in cardinality_many_tx_values(v) {
                append_entity_attr_datoms(
                    &mut out,
                    eid.clone(),
                    a.clone(),
                    v,
                    tx_cid.clone(),
                    tempids,
                    db,
                    schema,
                    pending,
                )?;
            }
            continue;
        }
        append_entity_attr_datoms(
            &mut out,
            eid.clone(),
            a,
            v,
            tx_cid.clone(),
            tempids,
            db,
            schema,
            pending,
        )?;
    }
    Ok(out)
}

fn append_entity_attr_datoms(
    out: &mut Vec<Datom>,
    eid: KotobaCid,
    attr: String,
    value: EdnValue,
    tx_cid: KotobaCid,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    schema: &Schema,
    pending: &[Datom],
) -> Result<()> {
    if schema.value_types.get(&attr) == Some(&ValueType::Ref) {
        if let EdnValue::Map(mut nested_entity) = value {
            let nested_eid_value =
                ensure_nested_entity_id(&mut nested_entity, &eid, &attr, out.len());
            let nested_eid = entity_ref_to_cid_for_tx(&nested_eid_value, tempids, db, &tx_cid)?;
            let mut nested_pending = Vec::with_capacity(pending.len() + out.len());
            nested_pending.extend_from_slice(pending);
            nested_pending.extend_from_slice(out);
            out.extend(entity_map_to_datoms(
                nested_entity,
                tx_cid.clone(),
                tempids,
                db,
                schema,
                &nested_pending,
            )?);
            out.push(Datom::assert(eid, attr, cid_value(&nested_eid), tx_cid));
            return Ok(());
        }
    }
    out.push(Datom::assert(eid, attr, value, tx_cid));
    Ok(())
}

fn ensure_nested_entity_id(
    entity: &mut BTreeMap<EdnValue, EdnValue>,
    parent: &KotobaCid,
    attr: &str,
    ordinal: usize,
) -> EdnValue {
    let db_id_key = EdnValue::Keyword(Keyword::namespaced("db", "id"));
    if let Some(id) = entity.get(&db_id_key) {
        return id.clone();
    }
    let db_ident_key = EdnValue::Keyword(Keyword::namespaced("db", "ident"));
    if let Some(ident) = entity.get(&db_ident_key) {
        return ident.clone();
    }
    let tempid = EdnValue::String(format!(
        "__kotoba_nested:{}:{}:{}",
        parent.to_multibase(),
        attr,
        ordinal
    ));
    entity.insert(db_id_key, tempid.clone());
    tempid
}

fn cardinality_many_tx_values(value: EdnValue) -> Vec<EdnValue> {
    match value {
        EdnValue::Vector(values) | EdnValue::List(values) => values,
        EdnValue::Set(values) => values.into_iter().collect(),
        value => vec![value],
    }
}

fn op_form_to_datoms(
    op: Vec<EdnValue>,
    tx_cid: KotobaCid,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    pending: &[Datom],
    schema: &Schema,
    tx_fns: &TxFnRegistry,
) -> Result<Vec<Datom>> {
    let Some(op_kw) = op
        .first()
        .and_then(EdnValue::as_keyword)
        .map(keyword_to_attr)
    else {
        return Err(DatomicError::InvalidOpForm);
    };
    match op_kw.as_str() {
        DB_ADD | DB_RETRACT => {
            if op.len() != 4 {
                return Err(DatomicError::InvalidOpForm);
            }
            let a = attr_to_string(&op[2])?;
            let v = op[3].clone();
            if op_kw == DB_ADD && schema.unique_identity.contains(&a) {
                bind_tempid_to_unique_identity(&op[1], &a, &v, tempids, db, pending)?;
            }
            let e = entity_ref_to_cid_for_tx(&op[1], tempids, db, &tx_cid)?;
            let datom = if op_kw == DB_ADD {
                Datom::assert(e, a, v, tx_cid)
            } else {
                Datom::retract(e, a, v, tx_cid)
            };
            Ok(vec![datom])
        }
        DB_FN_CAS => {
            if op.len() != 5 {
                return Err(DatomicError::InvalidOpForm);
            }
            let e = entity_ref_to_cid_for_tx(&op[1], tempids, db, &tx_cid)?;
            let a = attr_to_string(&op[2])?;
            let mut old = op[3].clone();
            let mut new = op[4].clone();
            normalize_ref_edn_value(&mut old, schema, &a, db, pending)?;
            normalize_ref_edn_value(&mut new, schema, &a, db, pending)?;
            let current = current_value_with_pending(db, pending, &e, &a);
            if current.as_ref() != Some(&old) {
                return Err(DatomicError::ConstraintViolation(format!(
                    "cas failed for {a}: expected {}, got {}",
                    edn_to_string(&old),
                    current
                        .as_ref()
                        .map(edn_to_string)
                        .unwrap_or_else(|| "nil".to_string())
                )));
            }
            Ok(vec![
                Datom::retract(e.clone(), a.clone(), old, tx_cid.clone()),
                Datom::assert(e, a, new, tx_cid),
            ])
        }
        DB_FN_RETRACT_ENTITY => {
            if op.len() != 2 {
                return Err(DatomicError::InvalidOpForm);
            }
            let e = entity_ref_to_cid_for_tx(&op[1], tempids, db, &tx_cid)?;
            Ok(retract_entity_datoms(db, schema, &e, tx_cid))
        }
        DB_FN_RETRACT_ATTRIBUTE => {
            if op.len() != 3 {
                return Err(DatomicError::InvalidOpForm);
            }
            let e = entity_ref_to_cid_for_tx(&op[1], tempids, db, &tx_cid)?;
            let a = attr_to_string(&op[2])?;
            Ok(current_datoms(&db.datoms())
                .into_iter()
                .filter(|d| d.e == e && d.a == a)
                .map(|d| Datom::retract(d.e, d.a, d.v, tx_cid.clone()))
                .collect())
        }
        other => {
            let Some(tx_fn) = tx_fns.get(other) else {
                return Err(DatomicError::UnsupportedOperation(other.into()));
            };
            let expanded = tx_fn(db, &op[1..])?;
            let EdnValue::Vector(forms) = expanded else {
                return Err(DatomicError::InvalidOpForm);
            };
            tx_forms_to_datoms(&forms, tx_cid, tempids, db, pending, schema, tx_fns)
        }
    }
}

fn entity_ref_to_cid(
    value: &EdnValue,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
) -> Result<KotobaCid> {
    match value {
        EdnValue::String(s) => Ok(KotobaCid::from_multibase(s).unwrap_or_else(|| {
            tempids
                .entry(s.clone())
                .or_insert_with(|| KotobaCid::from_bytes(s.as_bytes()))
                .clone()
        })),
        EdnValue::Integer(i) => Ok(KotobaCid::from_bytes(i.to_string().as_bytes())),
        EdnValue::Keyword(k) => Ok(KotobaCid::from_bytes(keyword_to_attr(k).as_bytes())),
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "db/id" => {
            entity_ref_to_cid(value, tempids, db)
        }
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "cid" => value
            .as_string()
            .and_then(KotobaCid::from_multibase)
            .ok_or_else(|| DatomicError::UnsupportedValue(edn_to_string(value))),
        EdnValue::Vector(items) if items.len() == 2 => {
            let a = attr_to_string(&items[0])?;
            lookup_ref(db, &a, &items[1])?.ok_or_else(|| {
                DatomicError::LookupRefNotFound(format!("[{} {}]", a, edn_to_string(&items[1])))
            })
        }
        _ => Ok(KotobaCid::from_bytes(edn_to_string(value).as_bytes())),
    }
}

fn entity_ref_to_cid_for_tx(
    value: &EdnValue,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    tx_cid: &KotobaCid,
) -> Result<KotobaCid> {
    if is_tx_tempid(value) {
        tempids.insert(tx_tempid_key(value), tx_cid.clone());
        return Ok(tx_cid.clone());
    }
    match value {
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "db/id" => {
            entity_ref_to_cid_for_tx(value, tempids, db, tx_cid)
        }
        _ => entity_ref_to_cid(value, tempids, db),
    }
}

fn is_tx_tempid(value: &EdnValue) -> bool {
    match value {
        EdnValue::String(s) => s == DATOMIC_TX_TEMPID,
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "db/id" => is_tx_tempid(value),
        EdnValue::Vector(items) | EdnValue::List(items) => {
            items.len() == 1 && items[0] == kw_value(":db.part/tx")
        }
        _ => false,
    }
}

fn tx_tempid_key(value: &EdnValue) -> String {
    match value {
        EdnValue::String(s) => s.clone(),
        _ => edn_to_string(value),
    }
}

fn attr_to_string(value: &EdnValue) -> Result<String> {
    value
        .as_keyword()
        .map(keyword_to_attr)
        .or_else(|| value.as_string().map(str::to_string))
        .ok_or(DatomicError::AttributeMustBeKeyword)
}

fn keyword_to_attr(k: &Keyword) -> String {
    format!(":{}", k.to_qualified())
}

fn attr_to_keyword(a: &str) -> Keyword {
    Keyword::parse(a.strip_prefix(':').unwrap_or(a))
}

fn normalize_tx_fn_ident(ident: String) -> String {
    if ident.starts_with(':') {
        ident
    } else {
        format!(":{ident}")
    }
}

fn tx_placeholder_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"kotoba-tx:v1:pending-self-reference")
}

fn tx_cid_for_datoms(
    datoms: &[Datom],
    tx_placeholder: &KotobaCid,
    tx_instant: &str,
    prev: Option<&KotobaCid>,
) -> KotobaCid {
    let mut seed = b"kotoba-tx:v2\n".to_vec();
    let mut datom_cids = datoms
        .iter()
        .map(|datom| datom_content_cid(datom, tx_placeholder).to_multibase())
        .collect::<Vec<_>>();
    datom_cids.sort();
    for cid in datom_cids {
        seed.extend_from_slice(cid.as_bytes());
        seed.push(b'\n');
    }
    seed.extend_from_slice(tx_instant.as_bytes());
    seed.push(b'\n');
    if let Some(prev) = prev {
        seed.extend_from_slice(&prev.0);
    }
    KotobaCid::from_bytes(&seed)
}

fn datom_content_cid(datom: &Datom, tx_placeholder: &KotobaCid) -> KotobaCid {
    KotobaCid::from_bytes(datom_canonical_bytes(datom, tx_placeholder).as_bytes())
}

fn datom_canonical_bytes(datom: &Datom, tx_placeholder: &KotobaCid) -> String {
    format!(
        "e={}\na={}\nv={}\nt={}\nadded={}\n",
        canonical_tx_cid(&datom.e, tx_placeholder),
        datom.a,
        canonical_tx_value(&datom.v, tx_placeholder),
        canonical_tx_cid(&datom.t, tx_placeholder),
        datom.added
    )
}

fn canonical_tx_cid(cid: &KotobaCid, tx_placeholder: &KotobaCid) -> String {
    if cid == tx_placeholder {
        "<tx-self>".to_string()
    } else {
        cid.to_multibase()
    }
}

fn canonical_tx_value(value: &EdnValue, tx_placeholder: &KotobaCid) -> String {
    match value {
        EdnValue::String(s) if s == &tx_placeholder.to_multibase() => "\"<tx-self>\"".to_string(),
        EdnValue::Tagged { tag, value }
            if tag.to_qualified() == "cid"
                && value.as_string().as_deref() == Some(&tx_placeholder.to_multibase()) =>
        {
            "#cid \"<tx-self>\"".to_string()
        }
        _ => edn_to_string(value),
    }
}

fn rewrite_tx_placeholder(datoms: &mut [Datom], tx_placeholder: &KotobaCid, tx_cid: &KotobaCid) {
    for datom in datoms {
        if datom.e == *tx_placeholder {
            datom.e = tx_cid.clone();
        }
        if datom.t == *tx_placeholder {
            datom.t = tx_cid.clone();
        }
        rewrite_tx_placeholder_value(&mut datom.v, tx_placeholder, tx_cid);
    }
}

fn rewrite_tx_placeholder_value(
    value: &mut EdnValue,
    tx_placeholder: &KotobaCid,
    tx_cid: &KotobaCid,
) {
    let placeholder = tx_placeholder.to_multibase();
    if let EdnValue::String(s) = value {
        if s == &placeholder {
            *s = tx_cid.to_multibase();
        }
        return;
    }
    if let EdnValue::Tagged { tag, value } = value {
        if tag.to_qualified() == "cid" && value.as_string().as_deref() == Some(&placeholder) {
            *value = Box::new(EdnValue::String(tx_cid.to_multibase()));
        }
    }
}

fn rewrite_tempid_placeholder(
    tempids: &mut BTreeMap<String, KotobaCid>,
    tx_placeholder: &KotobaCid,
    tx_cid: &KotobaCid,
) {
    for value in tempids.values_mut() {
        if value == tx_placeholder {
            *value = tx_cid.clone();
        }
    }
}

fn current_tx_instant() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_seconds_to_rfc3339(now)
}

fn tx_instant_datom(tx_cid: KotobaCid, tx_instant: String) -> Datom {
    Datom::assert(
        tx_cid.clone(),
        DB_TX_INSTANT.to_string(),
        EdnValue::Tagged {
            tag: Symbol::bare("inst"),
            value: Box::new(EdnValue::String(tx_instant)),
        },
        tx_cid,
    )
}

fn unix_seconds_to_rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let secs_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_unix_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_unix_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

pub fn current_datoms(datoms: &[Datom]) -> Vec<Datom> {
    let mut out = Vec::new();
    let mut seen = Vec::<(Entity, Attribute, Value)>::new();
    for datom in datoms.iter().rev() {
        let key = (datom.e.clone(), datom.a.clone(), datom.v.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        if datom.added {
            out.push(datom.clone());
        }
    }
    out.reverse();
    out
}

fn datoms_index(
    mut datoms: Vec<Datom>,
    index: DatomIndex,
    components: &[EdnValue],
) -> Result<Vec<Datom>> {
    if components.len() > 4 {
        return Err(DatomicError::Query(format!(
            "{index:?} index supports at most 4 components"
        )));
    }
    datoms.retain(|datom| datom_index_prefix_matches(datom, index, components));
    datoms.sort_by(|left, right| datom_index_cmp(left, right, index));
    Ok(datoms)
}

pub(crate) fn seek_datoms_index(
    mut datoms: Vec<Datom>,
    index: DatomIndex,
    components: &[EdnValue],
) -> Result<Vec<Datom>> {
    if components.len() > 4 {
        return Err(DatomicError::Query(format!(
            "{index:?} index supports at most 4 components"
        )));
    }
    datoms.sort_by(|left, right| datom_index_cmp(left, right, index));
    datoms.retain(|datom| datom_index_seek_cmp(datom, index, components).is_ge());
    Ok(datoms)
}

pub(crate) fn index_range_datoms(
    mut datoms: Vec<Datom>,
    attr: &str,
    start: Option<&EdnValue>,
    end: Option<&EdnValue>,
) -> Result<Vec<Datom>> {
    datoms.retain(|datom| {
        attr_matches(&datom.a, attr)
            && start.is_none_or(|start| query_sort_order(&datom.v, start).is_ge())
            && end.is_none_or(|end| query_sort_order(&datom.v, end).is_lt())
    });
    datoms.sort_by(|left, right| datom_index_cmp(left, right, DatomIndex::Avet));
    Ok(datoms)
}

fn datom_index_prefix_matches(datom: &Datom, index: DatomIndex, components: &[EdnValue]) -> bool {
    components
        .iter()
        .enumerate()
        .all(|(position, component)| match (index, position) {
            (DatomIndex::Eavt, 0) | (DatomIndex::Aevt, 1) | (DatomIndex::Avet, 2) => {
                component_matches_cid(component, &datom.e)
            }
            (DatomIndex::Tea, 1) | (DatomIndex::Vaet, 2) => {
                component_matches_cid(component, &datom.e)
            }
            (DatomIndex::Eavt, 1)
            | (DatomIndex::Aevt, 0)
            | (DatomIndex::Avet, 0)
            | (DatomIndex::Vaet, 1)
            | (DatomIndex::Tea, 2) => component_matches_attr(component, &datom.a),
            (DatomIndex::Eavt, 2)
            | (DatomIndex::Aevt, 2)
            | (DatomIndex::Avet, 1)
            | (DatomIndex::Vaet, 0)
            | (DatomIndex::Tea, 3) => component == &datom.v,
            (DatomIndex::Eavt, 3)
            | (DatomIndex::Aevt, 3)
            | (DatomIndex::Avet, 3)
            | (DatomIndex::Vaet, 3)
            | (DatomIndex::Tea, 0) => component_matches_cid(component, &datom.t),
            _ => false,
        })
}

fn datom_index_seek_cmp(
    datom: &Datom,
    index: DatomIndex,
    components: &[EdnValue],
) -> std::cmp::Ordering {
    let mut ordering = std::cmp::Ordering::Equal;
    for (position, component) in components.iter().enumerate() {
        ordering = match (index, position) {
            (DatomIndex::Eavt, 0) | (DatomIndex::Aevt, 1) | (DatomIndex::Avet, 2) => {
                cmp_cid(&datom.e, &component_to_cid(component))
            }
            (DatomIndex::Tea, 1) | (DatomIndex::Vaet, 2) => {
                cmp_cid(&datom.e, &component_to_cid(component))
            }
            (DatomIndex::Eavt, 1)
            | (DatomIndex::Aevt, 0)
            | (DatomIndex::Avet, 0)
            | (DatomIndex::Vaet, 1)
            | (DatomIndex::Tea, 2) => datom
                .a
                .cmp(&attr_to_string(component).unwrap_or_else(|_| edn_to_string(component))),
            (DatomIndex::Eavt, 2)
            | (DatomIndex::Aevt, 2)
            | (DatomIndex::Avet, 1)
            | (DatomIndex::Vaet, 0)
            | (DatomIndex::Tea, 3) => query_sort_order(&datom.v, component),
            (DatomIndex::Eavt, 3)
            | (DatomIndex::Aevt, 3)
            | (DatomIndex::Avet, 3)
            | (DatomIndex::Vaet, 3)
            | (DatomIndex::Tea, 0) => cmp_cid(&datom.t, &component_to_cid(component)),
            _ => std::cmp::Ordering::Equal,
        };
        if !ordering.is_eq() {
            break;
        }
    }
    ordering
}

fn datom_index_cmp(left: &Datom, right: &Datom, index: DatomIndex) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let ordering = match index {
        DatomIndex::Eavt => cmp_cid(&left.e, &right.e)
            .then_with(|| left.a.cmp(&right.a))
            .then_with(|| query_sort_order(&left.v, &right.v))
            .then_with(|| cmp_cid(&left.t, &right.t)),
        DatomIndex::Aevt => left
            .a
            .cmp(&right.a)
            .then_with(|| cmp_cid(&left.e, &right.e))
            .then_with(|| query_sort_order(&left.v, &right.v))
            .then_with(|| cmp_cid(&left.t, &right.t)),
        DatomIndex::Avet => left
            .a
            .cmp(&right.a)
            .then_with(|| query_sort_order(&left.v, &right.v))
            .then_with(|| cmp_cid(&left.e, &right.e))
            .then_with(|| cmp_cid(&left.t, &right.t)),
        DatomIndex::Vaet => query_sort_order(&left.v, &right.v)
            .then_with(|| left.a.cmp(&right.a))
            .then_with(|| cmp_cid(&left.e, &right.e))
            .then_with(|| cmp_cid(&left.t, &right.t)),
        DatomIndex::Tea => cmp_cid(&left.t, &right.t)
            .then_with(|| cmp_cid(&left.e, &right.e))
            .then_with(|| left.a.cmp(&right.a))
            .then_with(|| query_sort_order(&left.v, &right.v)),
    };
    if ordering == Ordering::Equal {
        left.added.cmp(&right.added)
    } else {
        ordering
    }
}

fn cmp_cid(left: &KotobaCid, right: &KotobaCid) -> std::cmp::Ordering {
    left.to_multibase().cmp(&right.to_multibase())
}

fn component_matches_cid(component: &EdnValue, cid: &KotobaCid) -> bool {
    edn_entity_value_to_cid(component).is_some_and(|value| &value == cid)
        || component == &cid_value(cid)
}

fn component_to_cid(component: &EdnValue) -> KotobaCid {
    edn_entity_value_to_cid(component).unwrap_or_else(|| match component {
        EdnValue::String(value) => KotobaCid::from_bytes(value.as_bytes()),
        _ => KotobaCid::from_bytes(edn_to_string(component).as_bytes()),
    })
}

fn component_matches_attr(component: &EdnValue, attr: &str) -> bool {
    attr_to_string(component).is_ok_and(|value| attr_matches(attr, &value))
}

fn history_datoms(datoms: &[Datom]) -> Vec<Datom> {
    let schema = Schema::from_datoms(datoms);
    if schema.no_history.is_empty() {
        return datoms.to_vec();
    }
    let current = current_datoms(datoms);
    datoms
        .iter()
        .filter(|datom| {
            !schema.no_history.contains(&datom.a)
                || (datom.added
                    && current.iter().any(|current| {
                        current.e == datom.e && current.a == datom.a && current.v == datom.v
                    }))
        })
        .cloned()
        .collect()
}

fn current_value_with_pending(db: &Db, pending: &[Datom], e: &Entity, a: &str) -> Option<EdnValue> {
    let mut datoms = db.datoms.clone();
    datoms.extend_from_slice(pending);
    current_datoms(&datoms)
        .into_iter()
        .rev()
        .find(|d| &d.e == e && d.a == a)
        .map(|d| d.v)
}

fn lookup_ref(db: &Db, a: &str, v: &EdnValue) -> Result<Option<KotobaCid>> {
    let schema = Schema::from_datoms(&db.datoms);
    if !schema.unique.contains(a) {
        return Err(DatomicError::ConstraintViolation(format!(
            "lookup ref attr {a} is not unique"
        )));
    }
    Ok(db
        .datoms()
        .into_iter()
        .find(|d| d.a == a && &d.v == v)
        .map(|d| d.e))
}

fn lookup_ref_entity_term(
    term: &EdnValue,
    db: &Db,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Option<KotobaCid>> {
    let Some((attr, value)) = lookup_ref_parts(term, binding)? else {
        return Ok(None);
    };
    lookup_ref(db, &attr, &value)
}

fn lookup_ref_parts(
    term: &EdnValue,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Option<(String, EdnValue)>> {
    let value = match variable_name(term) {
        Some(var) => binding.get(var).unwrap_or(term),
        None => term,
    };
    let Some(items) = value.as_seq() else {
        return Ok(None);
    };
    if items.len() != 2 {
        return Ok(None);
    }
    let attr = attr_to_string(&items[0])?;
    let value = resolve_query_value(&items[1], binding)?;
    Ok(Some((attr, value)))
}

fn is_lookup_ref_term(term: &EdnValue, binding: &BTreeMap<String, EdnValue>) -> bool {
    lookup_ref_parts(term, binding).is_ok_and(|parts| parts.is_some())
}

#[derive(Default)]
struct Schema {
    cardinality_one: BTreeSet<String>,
    cardinality_many: BTreeSet<String>,
    unique: BTreeSet<String>,
    unique_identity: BTreeSet<String>,
    indexed: BTreeSet<String>,
    components: BTreeSet<String>,
    no_history: BTreeSet<String>,
    docs: BTreeMap<String, String>,
    value_types: BTreeMap<String, ValueType>,
}

impl Schema {
    fn from_datoms(datoms: &[Datom]) -> Self {
        let current = current_datoms(datoms);
        let mut attr_entities = HashMap::new();
        for d in &current {
            if d.a == DB_IDENT {
                if let EdnValue::Keyword(k) = &d.v {
                    attr_entities.insert(d.e.clone(), keyword_to_attr(k));
                }
            }
        }
        let mut schema = Schema::default();
        for d in &current {
            let Some(attr) = attr_entities.get(&d.e) else {
                continue;
            };
            if d.a == DB_CARDINALITY && d.v == kw_value(DB_CARDINALITY_ONE) {
                schema.cardinality_one.insert(attr.clone());
            }
            if d.a == DB_CARDINALITY && d.v == kw_value(DB_CARDINALITY_MANY) {
                schema.cardinality_many.insert(attr.clone());
            }
            if d.a == DB_UNIQUE {
                if d.v == kw_value(DB_UNIQUE_IDENTITY) {
                    schema.unique.insert(attr.clone());
                    schema.unique_identity.insert(attr.clone());
                } else if d.v == kw_value(DB_UNIQUE_VALUE) {
                    schema.unique.insert(attr.clone());
                }
            }
            if d.a == DB_VALUE_TYPE {
                if let Some(value_type) = ValueType::from_edn(&d.v) {
                    schema.value_types.insert(attr.clone(), value_type);
                }
            }
            if d.a == DB_INDEX && d.v == EdnValue::Bool(true) {
                schema.indexed.insert(attr.clone());
            }
            if d.a == DB_IS_COMPONENT && d.v == EdnValue::Bool(true) {
                schema.components.insert(attr.clone());
            }
            if d.a == DB_NO_HISTORY && d.v == EdnValue::Bool(true) {
                schema.no_history.insert(attr.clone());
            }
            if d.a == DB_DOC {
                if let EdnValue::String(doc) = &d.v {
                    schema.docs.insert(attr.clone(), doc.clone());
                }
            }
        }
        schema
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueType {
    Ref,
    String,
    Long,
    Boolean,
    Double,
    Keyword,
    Symbol,
    BigInt,
    BigDec,
    Instant,
    Uuid,
    Bytes,
    Tuple,
}

impl ValueType {
    fn from_edn(value: &EdnValue) -> Option<Self> {
        let attr = value.as_keyword().map(keyword_to_attr)?;
        match attr.as_str() {
            DB_TYPE_REF => Some(Self::Ref),
            DB_TYPE_STRING => Some(Self::String),
            DB_TYPE_LONG => Some(Self::Long),
            DB_TYPE_BOOLEAN => Some(Self::Boolean),
            DB_TYPE_DOUBLE => Some(Self::Double),
            DB_TYPE_KEYWORD => Some(Self::Keyword),
            DB_TYPE_SYMBOL => Some(Self::Symbol),
            DB_TYPE_BIGINT => Some(Self::BigInt),
            DB_TYPE_BIGDEC => Some(Self::BigDec),
            DB_TYPE_INSTANT => Some(Self::Instant),
            DB_TYPE_UUID => Some(Self::Uuid),
            DB_TYPE_BYTES => Some(Self::Bytes),
            DB_TYPE_TUPLE => Some(Self::Tuple),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Ref => DB_TYPE_REF,
            Self::String => DB_TYPE_STRING,
            Self::Long => DB_TYPE_LONG,
            Self::Boolean => DB_TYPE_BOOLEAN,
            Self::Double => DB_TYPE_DOUBLE,
            Self::Keyword => DB_TYPE_KEYWORD,
            Self::Symbol => DB_TYPE_SYMBOL,
            Self::BigInt => DB_TYPE_BIGINT,
            Self::BigDec => DB_TYPE_BIGDEC,
            Self::Instant => DB_TYPE_INSTANT,
            Self::Uuid => DB_TYPE_UUID,
            Self::Bytes => DB_TYPE_BYTES,
            Self::Tuple => DB_TYPE_TUPLE,
        }
    }

    fn matches(self, value: &EdnValue) -> bool {
        match self {
            Self::Ref => is_ref_value(value),
            Self::String => matches!(value, EdnValue::String(_)),
            Self::Long => matches!(value, EdnValue::Integer(_)),
            Self::Boolean => matches!(value, EdnValue::Bool(_)),
            Self::Double => matches!(value, EdnValue::Float(_)),
            Self::Keyword => matches!(value, EdnValue::Keyword(_)),
            Self::Symbol => matches!(value, EdnValue::Symbol(_)),
            Self::BigInt => matches!(value, EdnValue::BigInt(_)),
            Self::BigDec => matches!(value, EdnValue::BigDec(_)),
            Self::Instant => {
                matches!(value, EdnValue::Tagged { tag, .. } if tag.to_qualified() == "inst")
            }
            Self::Uuid => {
                matches!(value, EdnValue::Tagged { tag, .. } if tag.to_qualified() == "uuid")
            }
            Self::Bytes => matches!(value, EdnValue::Tagged { tag, value }
                if tag.to_qualified() == "bytes"
                    && value.as_string().is_some_and(|s| hex::decode(s).is_ok())),
            Self::Tuple => matches!(value, EdnValue::Vector(_) | EdnValue::List(_)),
        }
    }
}

fn is_ref_value(value: &EdnValue) -> bool {
    match value {
        EdnValue::String(_) | EdnValue::Integer(_) | EdnValue::Keyword(_) => true,
        EdnValue::Tagged { tag, .. } => {
            matches!(tag.to_qualified().as_str(), "cid" | "db/id")
        }
        EdnValue::Vector(items) => items.len() == 2 && attr_to_string(&items[0]).is_ok(),
        _ => false,
    }
}

fn bind_unique_identity_tempid(
    eid_value: &EdnValue,
    entity: &BTreeMap<EdnValue, EdnValue>,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    schema: &Schema,
    pending: &[Datom],
) -> Result<()> {
    for (attr, value) in entity {
        let attr = attr_to_string(attr)?;
        if schema.unique_identity.contains(&attr) {
            bind_tempid_to_unique_identity(eid_value, &attr, value, tempids, db, pending)?;
        }
    }
    Ok(())
}

fn bind_tempid_to_unique_identity(
    eid_value: &EdnValue,
    attr: &str,
    value: &EdnValue,
    tempids: &mut BTreeMap<String, KotobaCid>,
    db: &Db,
    pending: &[Datom],
) -> Result<()> {
    let EdnValue::String(tempid) = eid_value else {
        return Ok(());
    };
    let Some(existing) = lookup_ref_with_pending(db, pending, attr, value) else {
        return Ok(());
    };
    match tempids.get(tempid) {
        Some(bound) if bound != &existing => Err(DatomicError::ConstraintViolation(format!(
            "tempid {tempid} resolves to conflicting unique identity entities"
        ))),
        Some(_) => Ok(()),
        None => {
            tempids.insert(tempid.clone(), existing);
            Ok(())
        }
    }
}

fn lookup_ref_with_pending(db: &Db, pending: &[Datom], a: &str, v: &EdnValue) -> Option<KotobaCid> {
    let mut datoms = db.datoms.clone();
    datoms.extend_from_slice(pending);
    current_datoms(&datoms)
        .into_iter()
        .find(|d| d.a == a && &d.v == v)
        .map(|d| d.e)
}

fn enforce_schema(
    datoms: Vec<Datom>,
    tx_cid: KotobaCid,
    db: &Db,
    schema: &Schema,
) -> Result<Vec<Datom>> {
    let mut out = Vec::new();
    let mut working = db.datoms.clone();
    for mut datom in datoms {
        normalize_schema_value(&mut datom, schema, &working)?;
        if datom.added {
            if let Some(value_type) = schema.value_types.get(&datom.a) {
                if !value_type.matches(&datom.v) {
                    return Err(DatomicError::ConstraintViolation(format!(
                        "{} expects {}, got {}",
                        datom.a,
                        value_type.name(),
                        edn_to_string(&datom.v)
                    )));
                }
            }
            if schema.unique.contains(&datom.a) {
                for existing in current_datoms(&working) {
                    if existing.a == datom.a && existing.v == datom.v && existing.e != datom.e {
                        return Err(DatomicError::ConstraintViolation(format!(
                            "unique attr {} already has value {}",
                            datom.a,
                            edn_to_string(&datom.v)
                        )));
                    }
                }
            }
            if schema.cardinality_one.contains(&datom.a)
                || (!schema.cardinality_many.contains(&datom.a)
                    && !datom.a.starts_with(":db/")
                    && !datom.a.starts_with(":db."))
            {
                for existing in current_datoms(&working) {
                    if existing.e == datom.e && existing.a == datom.a && existing.v != datom.v {
                        let retract =
                            Datom::retract(existing.e, existing.a, existing.v, tx_cid.clone());
                        working.push(retract.clone());
                        out.push(retract);
                    }
                }
            }
        }
        working.push(datom.clone());
        out.push(datom);
    }
    Ok(out)
}

fn normalize_schema_value(datom: &mut Datom, schema: &Schema, working: &[Datom]) -> Result<()> {
    if schema.value_types.get(&datom.a) != Some(&ValueType::Ref) {
        return Ok(());
    }
    if !ValueType::Ref.matches(&datom.v) {
        return Err(DatomicError::ConstraintViolation(format!(
            "{} expects {}, got {}",
            datom.a,
            ValueType::Ref.name(),
            edn_to_string(&datom.v)
        )));
    }
    let db = Db::from_datoms(working.to_vec(), None);
    let mut tempids = BTreeMap::new();
    let cid = entity_ref_to_cid(&datom.v, &mut tempids, &db)?;
    datom.v = cid_value(&cid);
    Ok(())
}

fn normalize_ref_edn_value(
    value: &mut EdnValue,
    schema: &Schema,
    attr: &str,
    db: &Db,
    pending: &[Datom],
) -> Result<()> {
    if schema.value_types.get(attr) != Some(&ValueType::Ref) {
        return Ok(());
    }
    if !ValueType::Ref.matches(value) {
        return Err(DatomicError::ConstraintViolation(format!(
            "{} expects {}, got {}",
            attr,
            ValueType::Ref.name(),
            edn_to_string(value)
        )));
    }
    let mut datoms = db.datoms.clone();
    datoms.extend_from_slice(pending);
    let lookup_db = Db::from_datoms(datoms, db.basis_t.clone());
    let mut tempids = BTreeMap::new();
    let cid = entity_ref_to_cid(value, &mut tempids, &lookup_db)?;
    *value = cid_value(&cid);
    Ok(())
}

fn retract_entity_datoms(db: &Db, schema: &Schema, root: &Entity, tx_cid: KotobaCid) -> Vec<Datom> {
    let current = db.datoms();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    let mut visited = Vec::new();

    while let Some(eid) = stack.pop() {
        if visited.contains(&eid) {
            continue;
        }
        visited.push(eid.clone());
        for datom in current.iter().filter(|d| d.e == eid) {
            if schema.components.contains(&datom.a) {
                if let Some(component_eid) = pull_ref_cid(&datom.v) {
                    stack.push(component_eid);
                }
            }
            out.push(Datom::retract(
                datom.e.clone(),
                datom.a.clone(),
                datom.v.clone(),
                tx_cid.clone(),
            ));
        }
    }

    out
}

fn pull_entity(db: &Db, pattern: &EdnValue, eid: &Entity) -> Result<EdnValue> {
    pull_entity_inner(db, pattern, eid, 0)
}

fn pull_entity_inner(db: &Db, pattern: &EdnValue, eid: &Entity, depth: usize) -> Result<EdnValue> {
    if depth > 16 {
        return Err(DatomicError::Query("pull recursion limit exceeded".into()));
    }
    let pattern = PullPattern::parse(pattern)?;
    let schema = Schema::from_datoms(&db.datoms);
    let mut map = BTreeMap::new();
    for datom in db.datoms().into_iter().filter(|d| &d.e == eid) {
        if !pattern.wants(&datom.a) {
            continue;
        }
        let value = if let Some(nested_pattern) = pattern.nested.get(&datom.a) {
            match pull_ref_cid(&datom.v) {
                Some(ref_eid) => pull_entity_inner(db, nested_pattern, &ref_eid, depth + 1)?,
                None => datom.v.clone(),
            }
        } else {
            datom.v.clone()
        };
        let value = pattern.apply_xform(&datom.a, value)?;
        let key = pattern.attr_key(&datom.a);
        if schema.cardinality_many.contains(&datom.a) {
            match map.get_mut(&key) {
                Some(EdnValue::Vector(values)) => {
                    if pattern
                        .limit_for(&datom.a)
                        .is_none_or(|limit| values.len() < limit)
                    {
                        values.push(value);
                    }
                }
                Some(existing) => {
                    let first = existing.clone();
                    let mut values = vec![first];
                    if pattern.limit_for(&datom.a).is_none_or(|limit| limit > 1) {
                        values.push(value);
                    }
                    *existing = EdnValue::Vector(values);
                }
                None => {
                    let values = if pattern.limit_for(&datom.a) == Some(0) {
                        Vec::new()
                    } else {
                        vec![value]
                    };
                    map.insert(key, EdnValue::Vector(values));
                }
            }
        } else {
            map.insert(key, value);
        }
    }
    for (reverse_attr, forward_attr) in &pattern.reverse_attrs {
        let nested_pattern = pattern.nested.get(reverse_attr);
        let mut values = db
            .datoms()
            .into_iter()
            .filter(|datom| &datom.a == forward_attr)
            .filter(|datom| pull_ref_cid(&datom.v).as_ref() == Some(eid))
            .map(|datom| {
                if let Some(nested_pattern) = nested_pattern {
                    pull_entity_inner(db, nested_pattern, &datom.e, depth + 1)
                } else {
                    Ok(pattern.apply_xform(reverse_attr, cid_value(&datom.e))?)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(limit) = pattern.limit_for(reverse_attr) {
            values.truncate(limit);
        }
        map.insert(pattern.attr_key(reverse_attr), EdnValue::Vector(values));
    }
    for (attr, value) in &pattern.defaults {
        let key = pattern.attr_key(attr);
        if !map.contains_key(&key) {
            map.insert(key, pattern.apply_xform(attr, value.clone())?);
        }
    }
    Ok(EdnValue::Map(map))
}

#[derive(Debug, Default)]
struct PullPattern {
    all: bool,
    attrs: BTreeSet<String>,
    reverse_attrs: BTreeMap<String, String>,
    nested: BTreeMap<String, EdnValue>,
    aliases: BTreeMap<String, EdnValue>,
    defaults: BTreeMap<String, EdnValue>,
    limits: BTreeMap<String, usize>,
    xforms: BTreeMap<String, String>,
}

impl PullPattern {
    fn parse(pattern: &EdnValue) -> Result<Self> {
        let Some(seq) = pattern.as_seq() else {
            return Ok(Self::default_all());
        };
        if seq.is_empty() {
            return Ok(Self::default_all());
        }
        let mut out = Self::default();
        for item in seq {
            if matches!(item.as_symbol(), Some(symbol) if symbol.name == "*") {
                out.all = true;
                continue;
            }
            if let Some(attr) = item.as_keyword().map(keyword_to_attr) {
                out.insert_attr(attr);
                continue;
            }
            if let Some(expr) = item.as_seq() {
                if let Some(attr) = expr
                    .first()
                    .and_then(EdnValue::as_keyword)
                    .map(keyword_to_attr)
                {
                    out.insert_attr_expr(attr, &expr[1..])?;
                    continue;
                }
            }
            if let Some(map) = item.as_map() {
                for (key, value) in map {
                    let attr = attr_to_string(key)?;
                    out.insert_attr(attr.clone());
                    out.nested.insert(attr, value.clone());
                }
                continue;
            }
            return Err(DatomicError::UnsupportedOperation(format!(
                "unsupported pull pattern item {}",
                edn_to_string(item)
            )));
        }
        Ok(out)
    }

    fn default_all() -> Self {
        Self {
            all: true,
            ..Self::default()
        }
    }

    fn wants(&self, attr: &str) -> bool {
        self.all || self.attrs.contains(attr)
    }

    fn insert_attr(&mut self, attr: String) {
        if let Some(forward_attr) = reverse_pull_attr(&attr) {
            self.reverse_attrs.insert(attr, forward_attr);
        } else {
            self.attrs.insert(attr);
        }
    }

    fn insert_attr_expr(&mut self, attr: String, options: &[EdnValue]) -> Result<()> {
        self.insert_attr(attr.clone());
        let mut options = options.iter();
        while let Some(option) = options.next() {
            let option = option
                .as_keyword()
                .map(keyword_to_attr)
                .ok_or_else(|| DatomicError::Query("pull attr option must be a keyword".into()))?;
            let value = options.next().ok_or_else(|| {
                DatomicError::Query(format!("pull attr option {option} requires a value"))
            })?;
            match option.as_str() {
                ":as" => {
                    self.aliases.insert(attr.clone(), pull_alias_key(value)?);
                }
                ":default" => {
                    self.defaults.insert(attr.clone(), value.clone());
                }
                ":limit" => {
                    self.limits.insert(attr.clone(), pull_limit(value)?);
                }
                ":xform" => {
                    self.xforms.insert(attr.clone(), pull_xform_name(value)?);
                }
                other => {
                    return Err(DatomicError::UnsupportedOperation(format!(
                        "unsupported pull attr option {other}"
                    )));
                }
            }
        }
        Ok(())
    }

    fn attr_key(&self, attr: &str) -> EdnValue {
        self.aliases
            .get(attr)
            .cloned()
            .unwrap_or_else(|| EdnValue::Keyword(attr_to_keyword(attr)))
    }

    fn limit_for(&self, attr: &str) -> Option<usize> {
        self.limits.get(attr).copied()
    }

    fn apply_xform(&self, attr: &str, value: EdnValue) -> Result<EdnValue> {
        let Some(xform) = self.xforms.get(attr) else {
            return Ok(value);
        };
        apply_pull_xform(xform, value)
    }
}

fn pull_alias_key(value: &EdnValue) -> Result<EdnValue> {
    match value {
        EdnValue::Keyword(_) | EdnValue::String(_) | EdnValue::Symbol(_) => Ok(value.clone()),
        other => Err(DatomicError::Query(format!(
            "pull :as value must be a keyword, string, or symbol, got {}",
            edn_to_string(other)
        ))),
    }
}

fn pull_limit(value: &EdnValue) -> Result<usize> {
    match value {
        EdnValue::Integer(i) if *i >= 0 => Ok(*i as usize),
        other => Err(DatomicError::Query(format!(
            "pull :limit value must be a non-negative integer, got {}",
            edn_to_string(other)
        ))),
    }
}

fn pull_xform_name(value: &EdnValue) -> Result<String> {
    value
        .as_symbol()
        .map(Symbol::to_qualified)
        .or_else(|| value.as_keyword().map(keyword_to_attr))
        .or_else(|| value.as_string().map(str::to_string))
        .ok_or_else(|| {
            DatomicError::Query(format!(
                "pull :xform value must be a symbol, keyword, or string, got {}",
                edn_to_string(value)
            ))
        })
}

fn apply_pull_xform(xform: &str, value: EdnValue) -> Result<EdnValue> {
    match xform {
        "identity" | ":identity" => Ok(value),
        "str" | ":str" => Ok(EdnValue::String(match value {
            EdnValue::String(s) => s,
            other => edn_to_string(&other),
        })),
        "name" | ":name" => pull_name_value(value),
        "namespace" | ":namespace" => pull_namespace_value(value),
        other => Err(DatomicError::UnsupportedOperation(format!(
            "unsupported pull :xform {other}"
        ))),
    }
}

pub(crate) fn pull_name_value(value: EdnValue) -> Result<EdnValue> {
    match value {
        EdnValue::Keyword(k) => Ok(EdnValue::String(k.name().to_string())),
        EdnValue::Symbol(s) => Ok(EdnValue::String(s.name)),
        EdnValue::String(s) => Ok(EdnValue::String(
            s.rsplit_once('/')
                .map(|(_, name)| name)
                .unwrap_or(&s)
                .to_string(),
        )),
        other => Err(DatomicError::Query(format!(
            "pull name xform expects keyword, symbol, or string, got {}",
            edn_to_string(&other)
        ))),
    }
}

pub(crate) fn pull_namespace_value(value: EdnValue) -> Result<EdnValue> {
    match value {
        EdnValue::Keyword(k) => Ok(k
            .namespace()
            .map(|ns| EdnValue::String(ns.to_string()))
            .unwrap_or(EdnValue::Nil)),
        EdnValue::Symbol(s) => Ok(s.namespace.map(EdnValue::String).unwrap_or(EdnValue::Nil)),
        EdnValue::String(s) => Ok(s
            .rsplit_once('/')
            .map(|(ns, _)| EdnValue::String(ns.to_string()))
            .unwrap_or(EdnValue::Nil)),
        other => Err(DatomicError::Query(format!(
            "pull namespace xform expects keyword, symbol, or string, got {}",
            edn_to_string(&other)
        ))),
    }
}

pub(crate) fn query_str_value(values: Vec<EdnValue>) -> EdnValue {
    EdnValue::String(
        values
            .into_iter()
            .map(query_string_fragment)
            .collect::<Vec<_>>()
            .join(""),
    )
}

pub(crate) fn query_subs_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (value, start, end) = match args.as_slice() {
        [value, start] => (value, start, None),
        [value, start, end] => (value, start, Some(end)),
        _ => {
            return Err(DatomicError::Query(
                "subs expects string, start, and optional end".into(),
            ))
        }
    };
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "subs expects a string value, got {}",
            edn_to_string(value)
        )));
    };
    let start = query_non_negative_usize(start, "subs")?;
    let end = end
        .map(|value| query_non_negative_usize(value, "subs"))
        .transpose()?;
    let len = value.chars().count();
    let end = end.unwrap_or(len);
    if start > end || end > len {
        return Err(DatomicError::Query(format!(
            "subs range {start}..{end} out of bounds"
        )));
    }
    Ok(EdnValue::String(
        value.chars().skip(start).take(end - start).collect(),
    ))
}

pub(crate) fn query_split_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (value, delimiter, limit) = match args.as_slice() {
        [value, delimiter] => (value, delimiter, None),
        [value, delimiter, limit] => (value, delimiter, Some(limit)),
        _ => {
            return Err(DatomicError::Query(
                "split expects string, delimiter, and optional limit".into(),
            ))
        }
    };
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "split expects a string value, got {}",
            edn_to_string(value)
        )));
    };
    let EdnValue::String(delimiter) = delimiter else {
        return Err(DatomicError::Query(format!(
            "split expects a string delimiter, got {}",
            edn_to_string(delimiter)
        )));
    };
    if delimiter.is_empty() {
        return Err(DatomicError::Query(
            "split delimiter must not be empty".into(),
        ));
    }
    let parts = match limit {
        Some(limit) => {
            let limit = query_non_negative_usize(limit, "split")?;
            if limit == 0 {
                value.split(delimiter).collect::<Vec<_>>()
            } else {
                value.splitn(limit, delimiter).collect::<Vec<_>>()
            }
        }
        None => value.split(delimiter).collect::<Vec<_>>(),
    };
    Ok(EdnValue::Vector(
        parts
            .into_iter()
            .map(|part| EdnValue::String(part.to_string()))
            .collect(),
    ))
}

pub(crate) fn query_join_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (separator, collection) = match args.as_slice() {
        [collection] => (String::new(), collection),
        [separator, collection] => {
            let EdnValue::String(separator) = separator else {
                return Err(DatomicError::Query(format!(
                    "join expects a string separator, got {}",
                    edn_to_string(separator)
                )));
            };
            (separator.clone(), collection)
        }
        _ => {
            return Err(DatomicError::Query(
                "join expects collection or separator and collection".into(),
            ))
        }
    };
    let values = query_seq_values(collection.clone())?;
    Ok(EdnValue::String(
        values
            .into_iter()
            .map(query_string_fragment)
            .collect::<Vec<_>>()
            .join(&separator),
    ))
}

pub(crate) fn query_replace_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let [value, pattern, replacement]: [EdnValue; 3] = args
        .try_into()
        .map_err(|_| DatomicError::Query("replace expects three arguments".into()))?;
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "replace expects a string value, got {}",
            edn_to_string(&value)
        )));
    };
    let EdnValue::String(pattern) = pattern else {
        return Err(DatomicError::Query(format!(
            "replace expects a string match value, got {}",
            edn_to_string(&pattern)
        )));
    };
    let EdnValue::String(replacement) = replacement else {
        return Err(DatomicError::Query(format!(
            "replace expects a string replacement, got {}",
            edn_to_string(&replacement)
        )));
    };
    Ok(EdnValue::String(value.replace(&pattern, &replacement)))
}

pub(crate) fn query_regex_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let [pattern, value]: [EdnValue; 2] = args
        .try_into()
        .map_err(|_| DatomicError::Query(format!("{op} expects pattern and string")))?;
    let EdnValue::String(pattern) = pattern else {
        return Err(DatomicError::Query(format!(
            "{op} expects a string pattern, got {}",
            edn_to_string(&pattern)
        )));
    };
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "{op} expects a string value, got {}",
            edn_to_string(&value)
        )));
    };
    let regex = regex::Regex::new(&pattern)
        .map_err(|err| DatomicError::Query(format!("{op} invalid regex: {err}")))?;
    let Some(captures) = regex.captures(&value) else {
        return Ok(EdnValue::Nil);
    };
    if matches!(op, "re-matches" | "clojure.core/re-matches") {
        let whole = captures
            .get(0)
            .expect("regex captures always include whole match");
        if whole.start() != 0 || whole.end() != value.len() {
            return Ok(EdnValue::Nil);
        }
    }
    if captures.len() == 1 {
        return Ok(captures
            .get(0)
            .map(|matched| EdnValue::String(matched.as_str().to_string()))
            .unwrap_or(EdnValue::Nil));
    }
    Ok(EdnValue::Vector(
        (0..captures.len())
            .map(|idx| {
                captures
                    .get(idx)
                    .map(|matched| EdnValue::String(matched.as_str().to_string()))
                    .unwrap_or(EdnValue::Nil)
            })
            .collect(),
    ))
}

pub(crate) fn query_string_case_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let [value]: [EdnValue; 1] = args
        .try_into()
        .map_err(|_| DatomicError::Query(format!("{op} expects one argument")))?;
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "{op} expects a string value, got {}",
            edn_to_string(&value)
        )));
    };
    match op {
        "lower-case" | "clojure.string/lower-case" | "str/lower-case" => {
            Ok(EdnValue::String(value.to_lowercase()))
        }
        "upper-case" | "clojure.string/upper-case" | "str/upper-case" => {
            Ok(EdnValue::String(value.to_uppercase()))
        }
        "capitalize" | "clojure.string/capitalize" | "str/capitalize" => {
            let mut chars = value.chars();
            let Some(first) = chars.next() else {
                return Ok(EdnValue::String(String::new()));
            };
            Ok(EdnValue::String(format!(
                "{}{}",
                first.to_uppercase(),
                chars.as_str().to_lowercase()
            )))
        }
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

pub(crate) fn query_trim_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let [value]: [EdnValue; 1] = args
        .try_into()
        .map_err(|_| DatomicError::Query(format!("{op} expects one argument")))?;
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "{op} expects a string value, got {}",
            edn_to_string(&value)
        )));
    };
    match op {
        "trim" | "clojure.string/trim" | "str/trim" => {
            Ok(EdnValue::String(value.trim().to_string()))
        }
        "triml" | "clojure.string/triml" | "str/triml" => {
            Ok(EdnValue::String(value.trim_start().to_string()))
        }
        "trimr" | "clojure.string/trimr" | "str/trimr" => {
            Ok(EdnValue::String(value.trim_end().to_string()))
        }
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

pub(crate) fn query_keyword_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    match args.as_slice() {
        [EdnValue::Keyword(keyword)] => Ok(EdnValue::Keyword(keyword.clone())),
        [value] => Ok(EdnValue::Keyword(Keyword::parse(
            query_keyword_part(value)?.trim_start_matches(':'),
        ))),
        [namespace, name] => Ok(EdnValue::Keyword(Keyword::namespaced(
            query_keyword_part(namespace)?.trim_start_matches(':'),
            query_keyword_part(name)?.trim_start_matches(':'),
        ))),
        _ => Err(DatomicError::Query(
            "keyword expects one or two arguments".into(),
        )),
    }
}

pub(crate) fn query_get_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (collection, key, default) = match args.as_slice() {
        [collection, key] => (collection, key, EdnValue::Nil),
        [collection, key, default] => (collection, key, default.clone()),
        _ => {
            return Err(DatomicError::Query(
                "get expects two or three arguments".into(),
            ))
        }
    };
    Ok(match collection {
        EdnValue::Map(values) => values.get(key).cloned().unwrap_or(default),
        EdnValue::Set(values) => {
            if values.contains(key) {
                key.clone()
            } else {
                default
            }
        }
        EdnValue::Vector(values) | EdnValue::List(values) => match key {
            EdnValue::Integer(index) if *index >= 0 => {
                values.get(*index as usize).cloned().unwrap_or(default)
            }
            _ => default,
        },
        EdnValue::String(value) => match key {
            EdnValue::Integer(index) if *index >= 0 => value
                .chars()
                .nth(*index as usize)
                .map(EdnValue::Char)
                .unwrap_or(default),
            _ => default,
        },
        other => {
            return Err(DatomicError::Query(format!(
                "get expects a map, set, vector, list, or string, got {}",
                edn_to_string(other)
            )))
        }
    })
}

pub(crate) fn query_get_in_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (collection, path, default) = match args.as_slice() {
        [collection, path] => (collection, path, EdnValue::Nil),
        [collection, path, default] => (collection, path, default.clone()),
        _ => {
            return Err(DatomicError::Query(
                "get-in expects two or three arguments".into(),
            ))
        }
    };
    let path = match path {
        EdnValue::Vector(values) | EdnValue::List(values) => values,
        other => {
            return Err(DatomicError::Query(format!(
                "get-in path expects a vector or list, got {}",
                edn_to_string(other)
            )))
        }
    };
    let mut current = collection.clone();
    for key in path {
        current = query_get_value(vec![current, key.clone(), default.clone()])?;
        if current == default {
            return Ok(default);
        }
    }
    Ok(current)
}

pub(crate) fn query_assoc_in_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let [collection, path, value]: [EdnValue; 3] = args
        .try_into()
        .map_err(|_| DatomicError::Query("assoc-in expects three arguments".into()))?;
    let path = match path {
        EdnValue::Vector(values) | EdnValue::List(values) => values,
        other => {
            return Err(DatomicError::Query(format!(
                "assoc-in path expects a vector or list, got {}",
                edn_to_string(&other)
            )))
        }
    };
    if path.is_empty() {
        return Ok(value);
    }
    assoc_in_path(collection, &path, value)
}

pub(crate) fn query_update_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    if args.len() < 3 {
        return Err(DatomicError::Query(
            "update expects collection, key, function, and optional arguments".into(),
        ));
    }
    let collection = args[0].clone();
    let key = args[1].clone();
    let op = query_function_name(&args[2])?;
    let current = query_get_value(vec![collection.clone(), key.clone()])?;
    let mut fn_args = vec![current];
    fn_args.extend(args[3..].iter().cloned());
    let updated = query_apply_value_function(&op, fn_args)?;
    query_assoc_value(vec![collection, key, updated])
}

pub(crate) fn query_update_in_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    if args.len() < 3 {
        return Err(DatomicError::Query(
            "update-in expects collection, path, function, and optional arguments".into(),
        ));
    }
    let collection = args[0].clone();
    let path = args[1].clone();
    let op = query_function_name(&args[2])?;
    let current = query_get_in_value(vec![collection.clone(), path.clone()])?;
    let mut fn_args = vec![current];
    fn_args.extend(args[3..].iter().cloned());
    let updated = query_apply_value_function(&op, fn_args)?;
    query_assoc_in_value(vec![collection, path, updated])
}

fn query_function_name(value: &EdnValue) -> Result<String> {
    match value {
        EdnValue::Symbol(symbol) => Ok(symbol.to_qualified()),
        EdnValue::Keyword(keyword) => Ok(keyword.to_qualified()),
        EdnValue::String(value) => Ok(value.clone()),
        other => Err(DatomicError::Query(format!(
            "update function must be a symbol, keyword, or string, got {}",
            edn_to_string(other)
        ))),
    }
}

fn query_predicate_name(value: &EdnValue) -> Result<String> {
    match value {
        EdnValue::Symbol(symbol) => Ok(symbol.to_qualified()),
        EdnValue::Keyword(keyword) => Ok(keyword.to_qualified()),
        EdnValue::String(value) => Ok(value.clone()),
        other => Err(DatomicError::Query(format!(
            "collection predicate expects a predicate symbol, keyword, or string, got {}",
            edn_to_string(other)
        ))),
    }
}

fn query_apply_value_function(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let op = query_core_op(op);
    match op {
        "identity" => match args.as_slice() {
            [value] => Ok(value.clone()),
            _ => Err(DatomicError::Query("identity expects one argument".into())),
        },
        "str" => Ok(query_str_value(args)),
        "subs" | "clojure.core/subs" => query_subs_value(args),
        "split" | "clojure.string/split" | "str/split" => query_split_value(args),
        "join" | "clojure.string/join" | "str/join" => query_join_value(args),
        "replace" | "clojure.string/replace" | "str/replace" => query_replace_value(args),
        "re-find" | "clojure.core/re-find" | "re-matches" | "clojure.core/re-matches" => {
            query_regex_value(op, args)
        }
        "lower-case"
        | "clojure.string/lower-case"
        | "str/lower-case"
        | "upper-case"
        | "clojure.string/upper-case"
        | "str/upper-case"
        | "capitalize"
        | "clojure.string/capitalize"
        | "str/capitalize" => query_string_case_value(op, args),
        "trim"
        | "clojure.string/trim"
        | "str/trim"
        | "triml"
        | "clojure.string/triml"
        | "str/triml"
        | "trimr"
        | "clojure.string/trimr"
        | "str/trimr" => query_trim_value(op, args),
        "keyword" => query_keyword_value(args),
        "get" => query_get_value(args),
        "get-in" => query_get_in_value(args),
        "assoc-in" => query_assoc_in_value(args),
        "vector" => Ok(EdnValue::Vector(args)),
        "list" => Ok(EdnValue::List(args)),
        "hash-set" => Ok(query_hash_set_value(args)),
        "union"
        | "clojure.set/union"
        | "set/union"
        | "intersection"
        | "clojure.set/intersection"
        | "set/intersection"
        | "difference"
        | "clojure.set/difference"
        | "set/difference" => query_set_operation_value(op, args),
        "hash-map" => query_hash_map_value(args),
        "keys" | "vals" | "merge" | "select-keys" => query_map_operation_value(op, args),
        "every?" | "not-every?" | "not-any?" => {
            query_collection_predicate_value(op, args).map(EdnValue::Bool)
        }
        "count" => match args.as_slice() {
            [value] => query_count_value(value.clone()),
            _ => Err(DatomicError::Query("count expects one argument".into())),
        },
        "not-empty" => match args.as_slice() {
            [value] => query_not_empty_value(value.clone()),
            _ => Err(DatomicError::Query("not-empty expects one argument".into())),
        },
        "map" | "filter" | "remove" | "keep" => query_collection_transform_value(op, args),
        "reduce" => query_reduce_value(args),
        "apply" => query_apply_function_value(args),
        "seq" | "first" | "last" | "rest" | "next" => match args.as_slice() {
            [value] => query_collection_value(op, value.clone()),
            _ => Err(DatomicError::Query(format!("{op} expects one argument"))),
        },
        "nth" => query_nth_value(args),
        "take" | "drop" | "take-while" | "drop-while" | "split-at" | "split-with" | "partition"
        | "partition-all" | "subvec" => query_collection_slice_value(op, args),
        "reverse" | "sort" | "flatten" | "interpose" | "interleave" => {
            query_collection_order_value(op, args)
        }
        "cons" => query_cons_value(args),
        "conj" => query_conj_value(args),
        "assoc" => query_assoc_value(args),
        "dissoc" => query_dissoc_value(args),
        "disj" => query_disj_value(args),
        "inc" | "dec" | "abs" | "+" | "-" | "*" | "quot" | "rem" | "mod" | "min" | "max" => {
            query_arithmetic_value(op, args)
        }
        "not" | "boolean" => query_truth_function_value(op, args),
        _ if is_query_unary_predicate_op(op) || is_query_variadic_predicate_op(op) => {
            query_predicate_function_value(op, args)
        }
        other => Err(DatomicError::UnsupportedOperation(format!(
            "update function {other}"
        ))),
    }
}

pub(crate) fn query_core_op(op: &str) -> &str {
    op.strip_prefix("clojure.core/").unwrap_or(op)
}

pub(crate) fn query_truthy(value: &EdnValue) -> bool {
    !matches!(value, EdnValue::Nil | EdnValue::Bool(false))
}

pub(crate) fn query_truth_function_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    if args.len() != 1 {
        return Err(DatomicError::Query(format!("{op} expects one argument")));
    }
    let truthy = query_truthy(&args[0]);
    Ok(EdnValue::Bool(match op {
        "not" => !truthy,
        "boolean" => truthy,
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    }))
}

pub(crate) fn query_collection_transform_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    if args.len() != 2 {
        return Err(DatomicError::Query(format!(
            "{op} expects a function and one collection"
        )));
    }
    let function = query_function_name(&args[0])?;
    let values = query_seq_values(args[1].clone())?;
    let out = match op {
        "map" => values
            .into_iter()
            .map(|value| query_apply_value_function(&function, vec![value]))
            .collect::<Result<Vec<_>>>()?,
        "filter" | "remove" => {
            let keep_matching = op == "filter";
            values
                .into_iter()
                .filter_map(|value| {
                    match query_apply_value_function(&function, vec![value.clone()]) {
                        Ok(result) if query_truthy(&result) == keep_matching => Some(Ok(value)),
                        Ok(_) => None,
                        Err(err) => Some(Err(err)),
                    }
                })
                .collect::<Result<Vec<_>>>()?
        }
        "keep" => values
            .into_iter()
            .filter_map(
                |value| match query_apply_value_function(&function, vec![value]) {
                    Ok(EdnValue::Nil) => None,
                    Ok(value) => Some(Ok(value)),
                    Err(err) => Some(Err(err)),
                },
            )
            .collect::<Result<Vec<_>>>()?,
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    };
    Ok(EdnValue::Vector(out))
}

pub(crate) fn query_reduce_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (function, mut values, mut acc) = match args.as_slice() {
        [function, collection] => {
            let mut values = query_seq_values(collection.clone())?.into_iter();
            let acc = values.next().map(Ok).unwrap_or_else(|| {
                query_apply_value_function(&query_function_name(function)?, vec![])
            })?;
            (
                query_function_name(function)?,
                values.collect::<Vec<_>>(),
                acc,
            )
        }
        [function, init, collection] => (
            query_function_name(function)?,
            query_seq_values(collection.clone())?,
            init.clone(),
        ),
        _ => {
            return Err(DatomicError::Query(
                "reduce expects a function, optional init, and one collection".into(),
            ))
        }
    };
    for value in values.drain(..) {
        acc = query_apply_value_function(&function, vec![acc, value])?;
    }
    Ok(acc)
}

pub(crate) fn query_apply_function_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    if args.len() < 2 {
        return Err(DatomicError::Query(
            "apply expects a function and at least one collection argument".into(),
        ));
    }
    let function = query_function_name(&args[0])?;
    let mut fn_args = args[1..args.len() - 1].to_vec();
    fn_args.extend(query_seq_values(args[args.len() - 1].clone())?);
    query_apply_value_function(&function, fn_args)
}

fn assoc_in_path(collection: EdnValue, path: &[EdnValue], value: EdnValue) -> Result<EdnValue> {
    if path.len() == 1 {
        return query_assoc_value(vec![collection, path[0].clone(), value]);
    }
    let next = match &collection {
        EdnValue::Nil | EdnValue::Map(_) | EdnValue::Vector(_) => {
            query_get_value(vec![collection.clone(), path[0].clone()])?
        }
        other => {
            return Err(DatomicError::Query(format!(
                "assoc-in expects nil, map, or vector along path, got {}",
                edn_to_string(other)
            )))
        }
    };
    let next = if matches!(next, EdnValue::Nil) {
        EdnValue::Map(BTreeMap::new())
    } else {
        next
    };
    let updated = assoc_in_path(next, &path[1..], value)?;
    query_assoc_value(vec![collection, path[0].clone(), updated])
}

pub(crate) fn query_hash_set_value(args: Vec<EdnValue>) -> EdnValue {
    EdnValue::Set(args.into_iter().collect())
}

fn query_set_arg(op: &str, value: EdnValue) -> Result<BTreeSet<EdnValue>> {
    match value {
        EdnValue::Set(values) => Ok(values),
        other => Err(DatomicError::Query(format!(
            "{op} expects set arguments, got {}",
            edn_to_string(&other)
        ))),
    }
}

pub(crate) fn query_set_operation_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    match op {
        "union" | "clojure.set/union" | "set/union" => {
            let mut out = BTreeSet::new();
            for arg in args {
                out.extend(query_set_arg(op, arg)?);
            }
            Ok(EdnValue::Set(out))
        }
        "intersection" | "clojure.set/intersection" | "set/intersection" => {
            let Some((first, rest)) = args.split_first() else {
                return Err(DatomicError::Query(
                    "intersection expects at least one argument".into(),
                ));
            };
            let mut out = query_set_arg(op, first.clone())?;
            for arg in rest {
                let set = query_set_arg(op, arg.clone())?;
                out.retain(|value| set.contains(value));
            }
            Ok(EdnValue::Set(out))
        }
        "difference" | "clojure.set/difference" | "set/difference" => {
            let Some((first, rest)) = args.split_first() else {
                return Err(DatomicError::Query(
                    "difference expects at least one argument".into(),
                ));
            };
            let mut out = query_set_arg(op, first.clone())?;
            for arg in rest {
                for value in query_set_arg(op, arg.clone())? {
                    out.remove(&value);
                }
            }
            Ok(EdnValue::Set(out))
        }
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

pub(crate) fn query_hash_map_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    if args.len() % 2 != 0 {
        return Err(DatomicError::Query(
            "hash-map expects an even number of arguments".into(),
        ));
    }
    Ok(EdnValue::Map(
        args.chunks(2)
            .map(|pair| (pair[0].clone(), pair[1].clone()))
            .collect(),
    ))
}

pub(crate) fn query_map_operation_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    match op {
        "keys" => {
            let [value]: [EdnValue; 1] = args
                .try_into()
                .map_err(|_| DatomicError::Query("keys expects one argument".into()))?;
            match value {
                EdnValue::Map(values) => Ok(EdnValue::Vector(values.into_keys().collect())),
                other => Err(DatomicError::Query(format!(
                    "keys expects a map, got {}",
                    edn_to_string(&other)
                ))),
            }
        }
        "vals" => {
            let [value]: [EdnValue; 1] = args
                .try_into()
                .map_err(|_| DatomicError::Query("vals expects one argument".into()))?;
            match value {
                EdnValue::Map(values) => Ok(EdnValue::Vector(values.into_values().collect())),
                other => Err(DatomicError::Query(format!(
                    "vals expects a map, got {}",
                    edn_to_string(&other)
                ))),
            }
        }
        "merge" => {
            let mut out = BTreeMap::new();
            for arg in args {
                match arg {
                    EdnValue::Nil => {}
                    EdnValue::Map(values) => out.extend(values),
                    other => {
                        return Err(DatomicError::Query(format!(
                            "merge expects map or nil arguments, got {}",
                            edn_to_string(&other)
                        )))
                    }
                }
            }
            Ok(EdnValue::Map(out))
        }
        "select-keys" => {
            let [value, keys]: [EdnValue; 2] = args
                .try_into()
                .map_err(|_| DatomicError::Query("select-keys expects map and keys".into()))?;
            let EdnValue::Map(values) = value else {
                return Err(DatomicError::Query(format!(
                    "select-keys expects a map, got {}",
                    edn_to_string(&value)
                )));
            };
            let mut out = BTreeMap::new();
            for key in query_seq_values(keys)? {
                if let Some(value) = values.get(&key) {
                    out.insert(key, value.clone());
                }
            }
            Ok(EdnValue::Map(out))
        }
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

pub(crate) fn query_count_value(value: EdnValue) -> Result<EdnValue> {
    let count = match value {
        EdnValue::Nil => 0,
        EdnValue::String(value) => value.chars().count(),
        EdnValue::List(values) | EdnValue::Vector(values) => values.len(),
        EdnValue::Set(values) => values.len(),
        EdnValue::Map(values) => values.len(),
        other => {
            return Err(DatomicError::Query(format!(
                "count expects nil, string, list, vector, set, or map, got {}",
                edn_to_string(&other)
            )))
        }
    };
    Ok(EdnValue::Integer(count as i64))
}

pub(crate) fn query_collection_value(op: &str, value: EdnValue) -> Result<EdnValue> {
    let values = query_seq_values(value)?;
    Ok(match op {
        "seq" => {
            if values.is_empty() {
                EdnValue::Nil
            } else {
                EdnValue::Vector(values)
            }
        }
        "first" => values.into_iter().next().unwrap_or(EdnValue::Nil),
        "last" => values.into_iter().next_back().unwrap_or(EdnValue::Nil),
        "rest" => EdnValue::Vector(values.into_iter().skip(1).collect()),
        "next" => {
            let rest = values.into_iter().skip(1).collect::<Vec<_>>();
            if rest.is_empty() {
                EdnValue::Nil
            } else {
                EdnValue::Vector(rest)
            }
        }
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    })
}

pub(crate) fn query_nth_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let (collection, index, default) = match args.as_slice() {
        [collection, index] => (collection, index, None),
        [collection, index, default] => (collection, index, Some(default.clone())),
        _ => {
            return Err(DatomicError::Query(
                "nth expects collection, index, and optional default".into(),
            ))
        }
    };
    let index = query_non_negative_usize(index, "nth")?;
    let value = match collection {
        EdnValue::Vector(values) | EdnValue::List(values) => values.get(index).cloned(),
        EdnValue::String(value) => value.chars().nth(index).map(EdnValue::Char),
        other => {
            return Err(DatomicError::Query(format!(
                "nth expects a string, vector, or list, got {}",
                edn_to_string(other)
            )))
        }
    };
    match (value, default) {
        (Some(value), _) => Ok(value),
        (None, Some(default)) => Ok(default),
        (None, None) => Err(DatomicError::Query(format!(
            "nth index {index} out of bounds"
        ))),
    }
}

pub(crate) fn query_cons_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let [head, tail]: [EdnValue; 2] = args
        .try_into()
        .map_err(|_| DatomicError::Query("cons expects two arguments".into()))?;
    let mut values = vec![head];
    values.extend(query_seq_values(tail)?);
    Ok(EdnValue::Vector(values))
}

pub(crate) fn query_collection_slice_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    match op {
        "take" | "drop" => {
            let [n, collection]: [EdnValue; 2] = args
                .try_into()
                .map_err(|_| DatomicError::Query(format!("{op} expects two arguments")))?;
            let n = query_non_negative_usize(&n, op)?;
            let values = query_seq_values(collection)?;
            let values = if op == "take" {
                values.into_iter().take(n).collect()
            } else {
                values.into_iter().skip(n).collect()
            };
            Ok(EdnValue::Vector(values))
        }
        "split-at" => {
            let [n, collection]: [EdnValue; 2] = args
                .try_into()
                .map_err(|_| DatomicError::Query("split-at expects two arguments".into()))?;
            let n = query_non_negative_usize(&n, "split-at")?;
            let values = query_seq_values(collection)?;
            let split = n.min(values.len());
            Ok(EdnValue::Vector(vec![
                EdnValue::Vector(values[..split].to_vec()),
                EdnValue::Vector(values[split..].to_vec()),
            ]))
        }
        "subvec" => {
            let (collection, start, end) = match args.as_slice() {
                [collection, start] => (collection.clone(), start, None),
                [collection, start, end] => (collection.clone(), start, Some(end)),
                _ => {
                    return Err(DatomicError::Query(
                        "subvec expects two or three arguments".into(),
                    ))
                }
            };
            let values = match collection {
                EdnValue::Vector(values) => values,
                other => {
                    return Err(DatomicError::Query(format!(
                        "subvec expects a vector, got {}",
                        edn_to_string(&other)
                    )))
                }
            };
            let start = query_non_negative_usize(start, "subvec")?;
            let end = end
                .map(|value| query_non_negative_usize(value, "subvec"))
                .transpose()?
                .unwrap_or(values.len());
            if start > end || end > values.len() {
                return Err(DatomicError::Query(format!(
                    "subvec range {start}..{end} out of bounds"
                )));
            }
            Ok(EdnValue::Vector(values[start..end].to_vec()))
        }
        "take-while" | "drop-while" => {
            let [predicate, collection]: [EdnValue; 2] = args
                .try_into()
                .map_err(|_| DatomicError::Query(format!("{op} expects two arguments")))?;
            let predicate = query_function_name(&predicate)?;
            let mut out = Vec::new();
            let mut dropping = op == "drop-while";
            for value in query_seq_values(collection)? {
                let matched = query_truthy(&query_apply_value_function(
                    &predicate,
                    vec![value.clone()],
                )?);
                if op == "take-while" {
                    if !matched {
                        break;
                    }
                    out.push(value);
                } else if dropping && matched {
                    continue;
                } else {
                    dropping = false;
                    out.push(value);
                }
            }
            Ok(EdnValue::Vector(out))
        }
        "split-with" => {
            let [predicate, collection]: [EdnValue; 2] = args
                .try_into()
                .map_err(|_| DatomicError::Query("split-with expects two arguments".into()))?;
            let predicate = query_function_name(&predicate)?;
            let values = query_seq_values(collection)?;
            let mut split = values.len();
            for (index, value) in values.iter().enumerate() {
                let matched = query_truthy(&query_apply_value_function(
                    &predicate,
                    vec![value.clone()],
                )?);
                if !matched {
                    split = index;
                    break;
                }
            }
            Ok(EdnValue::Vector(vec![
                EdnValue::Vector(values[..split].to_vec()),
                EdnValue::Vector(values[split..].to_vec()),
            ]))
        }
        "partition" | "partition-all" => query_partition_value(op, args),
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

fn query_partition_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let (n, step, pad, collection) = match args.as_slice() {
        [n, collection] => (
            query_positive_usize(n, op)?,
            query_positive_usize(n, op)?,
            None,
            collection.clone(),
        ),
        [n, step, collection] => (
            query_positive_usize(n, op)?,
            query_positive_usize(step, op)?,
            None,
            collection.clone(),
        ),
        [n, step, pad, collection] if op == "partition" => (
            query_positive_usize(n, op)?,
            query_positive_usize(step, op)?,
            Some(query_seq_values(pad.clone())?),
            collection.clone(),
        ),
        _ => {
            return Err(DatomicError::Query(format!(
                "{op} expects n, optional step, optional pad, and a collection"
            )))
        }
    };
    let values = query_seq_values(collection)?;
    let mut out = Vec::new();
    let mut start = 0;
    while start < values.len() {
        let end = (start + n).min(values.len());
        let mut chunk = values[start..end].to_vec();
        if chunk.len() == n {
            out.push(EdnValue::Vector(chunk));
        } else if op == "partition-all" {
            out.push(EdnValue::Vector(chunk));
        } else if let Some(pad) = &pad {
            chunk.extend(pad.iter().take(n - chunk.len()).cloned());
            out.push(EdnValue::Vector(chunk));
        }
        start += step;
    }
    Ok(EdnValue::Vector(out))
}

pub(crate) fn query_collection_order_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    match op {
        "reverse" | "sort" | "flatten" => {
            let [collection]: [EdnValue; 1] = args
                .try_into()
                .map_err(|_| DatomicError::Query(format!("{op} expects one argument")))?;
            let mut values = query_seq_values(collection)?;
            match op {
                "reverse" => values.reverse(),
                "sort" => values.sort_by(query_sort_order),
                "flatten" => {
                    let mut out = Vec::new();
                    query_flatten_into(values, &mut out);
                    values = out;
                }
                _ => unreachable!("matched collection order op"),
            }
            Ok(EdnValue::Vector(values))
        }
        "interpose" => {
            let [separator, collection]: [EdnValue; 2] = args
                .try_into()
                .map_err(|_| DatomicError::Query("interpose expects two arguments".into()))?;
            let values = query_seq_values(collection)?;
            let mut out = Vec::with_capacity(values.len().saturating_mul(2).saturating_sub(1));
            for (idx, value) in values.into_iter().enumerate() {
                if idx > 0 {
                    out.push(separator.clone());
                }
                out.push(value);
            }
            Ok(EdnValue::Vector(out))
        }
        "interleave" => {
            if args.is_empty() {
                return Err(DatomicError::Query(
                    "interleave expects at least one collection".into(),
                ));
            }
            let columns = args
                .into_iter()
                .map(query_seq_values)
                .collect::<Result<Vec<_>>>()?;
            let min_len = columns.iter().map(Vec::len).min().unwrap_or(0);
            let mut out = Vec::with_capacity(min_len.saturating_mul(columns.len()));
            for idx in 0..min_len {
                for column in &columns {
                    out.push(column[idx].clone());
                }
            }
            Ok(EdnValue::Vector(out))
        }
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

fn query_flatten_into(values: Vec<EdnValue>, out: &mut Vec<EdnValue>) {
    for value in values {
        match value {
            EdnValue::Vector(values) | EdnValue::List(values) => query_flatten_into(values, out),
            EdnValue::Set(values) => query_flatten_into(values.into_iter().collect(), out),
            other => out.push(other),
        }
    }
}

fn query_sort_order(left: &EdnValue, right: &EdnValue) -> std::cmp::Ordering {
    match (left, right) {
        (EdnValue::Integer(left), EdnValue::Integer(right)) => left.cmp(right),
        (EdnValue::String(left), EdnValue::String(right)) => left.cmp(right),
        (EdnValue::Keyword(left), EdnValue::Keyword(right)) => {
            left.to_qualified().cmp(&right.to_qualified())
        }
        (EdnValue::Symbol(left), EdnValue::Symbol(right)) => {
            left.to_qualified().cmp(&right.to_qualified())
        }
        _ => query_sort_key(left).cmp(&query_sort_key(right)),
    }
}

fn query_sort_key(value: &EdnValue) -> (u8, String) {
    match value {
        EdnValue::Integer(value) => (0, value.to_string()),
        EdnValue::String(value) => (1, value.clone()),
        EdnValue::Keyword(value) => (2, value.to_qualified()),
        EdnValue::Symbol(value) => (3, value.to_qualified()),
        other => (4, edn_to_string(other)),
    }
}

fn query_non_negative_usize(value: &EdnValue, op: &str) -> Result<usize> {
    let EdnValue::Integer(value) = value else {
        return Err(DatomicError::Query(format!(
            "{op} index expects an integer, got {}",
            edn_to_string(value)
        )));
    };
    usize::try_from(*value)
        .map_err(|_| DatomicError::Query(format!("{op} index must be non-negative, got {value}")))
}

fn query_positive_usize(value: &EdnValue, op: &str) -> Result<usize> {
    let value = query_non_negative_usize(value, op)?;
    if value == 0 {
        return Err(DatomicError::Query(format!("{op} size must be positive")));
    }
    Ok(value)
}

pub(crate) fn query_conj_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let Some((collection, values)) = args.split_first() else {
        return Err(DatomicError::Query(
            "conj expects at least one argument".into(),
        ));
    };
    Ok(match collection {
        EdnValue::Nil => EdnValue::List(values.iter().rev().cloned().collect()),
        EdnValue::Vector(existing) => {
            let mut out = existing.clone();
            out.extend(values.iter().cloned());
            EdnValue::Vector(out)
        }
        EdnValue::List(existing) => {
            let mut out = values.iter().rev().cloned().collect::<Vec<_>>();
            out.extend(existing.iter().cloned());
            EdnValue::List(out)
        }
        EdnValue::Set(existing) => {
            let mut out = existing.clone();
            out.extend(values.iter().cloned());
            EdnValue::Set(out)
        }
        EdnValue::Map(existing) => {
            let mut out = existing.clone();
            for value in values {
                let pair = value.as_seq().ok_or_else(|| {
                    DatomicError::Query(format!(
                        "conj map expects pair values, got {}",
                        edn_to_string(value)
                    ))
                })?;
                let [key, map_value]: &[EdnValue; 2] = pair.try_into().map_err(|_| {
                    DatomicError::Query(format!(
                        "conj map expects pair values, got {}",
                        edn_to_string(value)
                    ))
                })?;
                out.insert(key.clone(), map_value.clone());
            }
            EdnValue::Map(out)
        }
        other => {
            return Err(DatomicError::Query(format!(
                "conj expects nil, list, vector, set, or map, got {}",
                edn_to_string(other)
            )))
        }
    })
}

pub(crate) fn query_assoc_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let Some((collection, pairs)) = args.split_first() else {
        return Err(DatomicError::Query(
            "assoc expects at least three arguments".into(),
        ));
    };
    if pairs.is_empty() || pairs.len() % 2 != 0 {
        return Err(DatomicError::Query("assoc expects key/value pairs".into()));
    }
    Ok(match collection {
        EdnValue::Nil | EdnValue::Map(_) => {
            let mut out = match collection {
                EdnValue::Map(existing) => existing.clone(),
                _ => BTreeMap::new(),
            };
            for pair in pairs.chunks(2) {
                out.insert(pair[0].clone(), pair[1].clone());
            }
            EdnValue::Map(out)
        }
        EdnValue::Vector(existing) => {
            let mut out = existing.clone();
            for pair in pairs.chunks(2) {
                let EdnValue::Integer(index) = pair[0] else {
                    return Err(DatomicError::Query(format!(
                        "assoc vector key must be an integer, got {}",
                        edn_to_string(&pair[0])
                    )));
                };
                let index = usize::try_from(index).map_err(|_| {
                    DatomicError::Query(format!(
                        "assoc vector index must be non-negative, got {index}"
                    ))
                })?;
                if index > out.len() {
                    return Err(DatomicError::Query(format!(
                        "assoc vector index {index} out of bounds"
                    )));
                }
                if index == out.len() {
                    out.push(pair[1].clone());
                } else {
                    out[index] = pair[1].clone();
                }
            }
            EdnValue::Vector(out)
        }
        other => {
            return Err(DatomicError::Query(format!(
                "assoc expects nil, map, or vector, got {}",
                edn_to_string(other)
            )))
        }
    })
}

pub(crate) fn query_dissoc_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let Some((collection, keys)) = args.split_first() else {
        return Err(DatomicError::Query(
            "dissoc expects at least one argument".into(),
        ));
    };
    let mut out = match collection {
        EdnValue::Nil => BTreeMap::new(),
        EdnValue::Map(existing) => existing.clone(),
        other => {
            return Err(DatomicError::Query(format!(
                "dissoc expects nil or map, got {}",
                edn_to_string(other)
            )))
        }
    };
    for key in keys {
        out.remove(key);
    }
    Ok(EdnValue::Map(out))
}

pub(crate) fn query_disj_value(args: Vec<EdnValue>) -> Result<EdnValue> {
    let Some((collection, values)) = args.split_first() else {
        return Err(DatomicError::Query(
            "disj expects at least one argument".into(),
        ));
    };
    let mut out = match collection {
        EdnValue::Nil => BTreeSet::new(),
        EdnValue::Set(existing) => existing.clone(),
        other => {
            return Err(DatomicError::Query(format!(
                "disj expects nil or set, got {}",
                edn_to_string(other)
            )))
        }
    };
    for value in values {
        out.remove(value);
    }
    Ok(EdnValue::Set(out))
}

fn query_seq_values(value: EdnValue) -> Result<Vec<EdnValue>> {
    match value {
        EdnValue::Nil => Ok(Vec::new()),
        EdnValue::Vector(values) | EdnValue::List(values) => Ok(values),
        EdnValue::Set(values) => Ok(values.into_iter().collect()),
        EdnValue::Map(values) => Ok(values
            .into_iter()
            .map(|(key, value)| EdnValue::Vector(vec![key, value]))
            .collect()),
        EdnValue::String(value) => Ok(value
            .chars()
            .map(|ch| EdnValue::String(ch.to_string()))
            .collect()),
        other => Err(DatomicError::Query(format!(
            "seq expects nil, string, list, vector, set, or map, got {}",
            edn_to_string(&other)
        ))),
    }
}

pub(crate) fn query_arithmetic_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let mut ints = args
        .into_iter()
        .map(|value| match value {
            EdnValue::Integer(value) => Ok(value),
            other => Err(DatomicError::Query(format!(
                "{op} expects integer arguments, got {}",
                edn_to_string(&other)
            ))),
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter();
    let value = match op {
        "+" => ints.try_fold(0_i64, |acc, value| {
            acc.checked_add(value)
                .ok_or_else(|| DatomicError::Query("+ integer overflow".into()))
        })?,
        "inc" => {
            if ints.len() != 1 {
                return Err(DatomicError::Query("inc expects one argument".into()));
            }
            ints.next()
                .expect("arity checked")
                .checked_add(1)
                .ok_or_else(|| DatomicError::Query("inc integer overflow".into()))?
        }
        "dec" => {
            if ints.len() != 1 {
                return Err(DatomicError::Query("dec expects one argument".into()));
            }
            ints.next()
                .expect("arity checked")
                .checked_sub(1)
                .ok_or_else(|| DatomicError::Query("dec integer overflow".into()))?
        }
        "abs" => {
            if ints.len() != 1 {
                return Err(DatomicError::Query("abs expects one argument".into()));
            }
            ints.next()
                .expect("arity checked")
                .checked_abs()
                .ok_or_else(|| DatomicError::Query("abs integer overflow".into()))?
        }
        "*" => ints.try_fold(1_i64, |acc, value| {
            acc.checked_mul(value)
                .ok_or_else(|| DatomicError::Query("* integer overflow".into()))
        })?,
        "min" => {
            let Some(first) = ints.next() else {
                return Err(DatomicError::Query(
                    "min expects at least one argument".into(),
                ));
            };
            ints.fold(first, i64::min)
        }
        "max" => {
            let Some(first) = ints.next() else {
                return Err(DatomicError::Query(
                    "max expects at least one argument".into(),
                ));
            };
            ints.fold(first, i64::max)
        }
        "-" => {
            let Some(first) = ints.next() else {
                return Err(DatomicError::Query(
                    "- expects at least one argument".into(),
                ));
            };
            if ints.len() == 0 {
                first
                    .checked_neg()
                    .ok_or_else(|| DatomicError::Query("- integer overflow".into()))?
            } else {
                ints.try_fold(first, |acc, value| {
                    acc.checked_sub(value)
                        .ok_or_else(|| DatomicError::Query("- integer overflow".into()))
                })?
            }
        }
        "quot" | "rem" | "mod" => {
            if ints.len() != 2 {
                return Err(DatomicError::Query(format!("{op} expects two arguments")));
            }
            let lhs = ints.next().expect("arity checked");
            let rhs = ints.next().expect("arity checked");
            if rhs == 0 {
                return Err(DatomicError::Query(format!("{op} division by zero")));
            }
            match op {
                "quot" => lhs
                    .checked_div(rhs)
                    .ok_or_else(|| DatomicError::Query("quot integer overflow".into()))?,
                "rem" => lhs
                    .checked_rem(rhs)
                    .ok_or_else(|| DatomicError::Query("rem integer overflow".into()))?,
                "mod" => {
                    let rem = lhs
                        .checked_rem(rhs)
                        .ok_or_else(|| DatomicError::Query("mod integer overflow".into()))?;
                    if rem != 0 && ((rem < 0) != (rhs < 0)) {
                        rem.checked_add(rhs)
                            .ok_or_else(|| DatomicError::Query("mod integer overflow".into()))?
                    } else {
                        rem
                    }
                }
                _ => unreachable!("matched arithmetic op"),
            }
        }
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    };
    Ok(EdnValue::Integer(value))
}

pub(crate) fn query_empty_predicate(value: &EdnValue) -> Result<bool> {
    Ok(match value {
        EdnValue::Nil => true,
        EdnValue::String(value) => value.is_empty(),
        EdnValue::List(values) | EdnValue::Vector(values) => values.is_empty(),
        EdnValue::Set(values) => values.is_empty(),
        EdnValue::Map(values) => values.is_empty(),
        other => {
            return Err(DatomicError::Query(format!(
                "empty? expects nil, string, list, vector, set, or map, got {}",
                edn_to_string(other)
            )))
        }
    })
}

pub(crate) fn query_not_empty_value(value: EdnValue) -> Result<EdnValue> {
    if query_empty_predicate(&value)? {
        Ok(EdnValue::Nil)
    } else {
        Ok(value)
    }
}

fn query_string_fragment(value: EdnValue) -> String {
    match value {
        EdnValue::Nil => String::new(),
        EdnValue::String(s) => s,
        EdnValue::Keyword(keyword) => format!(":{}", keyword.to_qualified()),
        EdnValue::Symbol(symbol) => symbol.to_qualified(),
        other => edn_to_string(&other),
    }
}

fn query_keyword_part(value: &EdnValue) -> Result<&str> {
    match value {
        EdnValue::String(s) => Ok(s),
        EdnValue::Keyword(keyword) => Ok(keyword.name()),
        EdnValue::Symbol(symbol) => Ok(&symbol.name),
        other => Err(DatomicError::Query(format!(
            "keyword expects string, keyword, or symbol arguments, got {}",
            edn_to_string(other)
        ))),
    }
}

pub(crate) fn query_contains_predicate(collection: &EdnValue, key: &EdnValue) -> Result<bool> {
    match collection {
        EdnValue::Set(values) => Ok(values.contains(key)),
        EdnValue::Map(values) => Ok(values.contains_key(key)),
        EdnValue::Vector(values) | EdnValue::List(values) => match key {
            EdnValue::Integer(index) if *index >= 0 => Ok((*index as usize) < values.len()),
            _ => Ok(false),
        },
        other => Err(DatomicError::Query(format!(
            "contains? expects a set, map, vector, or list, got {}",
            edn_to_string(other)
        ))),
    }
}

pub(crate) fn query_starts_with_predicate(value: &EdnValue, prefix: &EdnValue) -> Result<bool> {
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "starts-with? expects a string value, got {}",
            edn_to_string(value)
        )));
    };
    let EdnValue::String(prefix) = prefix else {
        return Err(DatomicError::Query(format!(
            "starts-with? expects a string prefix, got {}",
            edn_to_string(prefix)
        )));
    };
    Ok(value.starts_with(prefix))
}

pub(crate) fn query_string_search_predicate(
    op: &str,
    value: &EdnValue,
    needle: &EdnValue,
) -> Result<bool> {
    let EdnValue::String(value) = value else {
        return Err(DatomicError::Query(format!(
            "{op} expects a string value, got {}",
            edn_to_string(value)
        )));
    };
    let EdnValue::String(needle) = needle else {
        return Err(DatomicError::Query(format!(
            "{op} expects a string argument, got {}",
            edn_to_string(needle)
        )));
    };
    match op {
        "includes?" | "clojure.string/includes?" | "str/includes?" => Ok(value.contains(needle)),
        "ends-with?" | "clojure.string/ends-with?" | "str/ends-with?" => {
            Ok(value.ends_with(needle))
        }
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

pub(crate) fn query_variadic_predicate(op: &str, args: &[EdnValue]) -> Result<bool> {
    let op = query_core_op(op);
    Ok(match op {
        "=" => args.windows(2).all(|pair| pair[0] == pair[1]),
        "!=" | "not=" => !args.windows(2).all(|pair| pair[0] == pair[1]),
        "distinct?" => {
            let mut seen = BTreeSet::new();
            args.iter().all(|value| seen.insert(value))
        }
        ">" => query_chained_numbers(args, |a, b| a > b),
        "<" => query_chained_numbers(args, |a, b| a < b),
        ">=" => query_chained_numbers(args, |a, b| a >= b),
        "<=" => query_chained_numbers(args, |a, b| a <= b),
        "contains?" => {
            if args.len() != 2 {
                return Err(DatomicError::Query(
                    "contains? expects two arguments".into(),
                ));
            }
            query_contains_predicate(&args[0], &args[1])?
        }
        "subset?" | "clojure.set/subset?" | "set/subset?" => {
            if args.len() != 2 {
                return Err(DatomicError::Query(format!("{op} expects two arguments")));
            }
            let left = query_set_arg(op, args[0].clone())?;
            let right = query_set_arg(op, args[1].clone())?;
            left.is_subset(&right)
        }
        "superset?" | "clojure.set/superset?" | "set/superset?" => {
            if args.len() != 2 {
                return Err(DatomicError::Query(format!("{op} expects two arguments")));
            }
            let left = query_set_arg(op, args[0].clone())?;
            let right = query_set_arg(op, args[1].clone())?;
            left.is_superset(&right)
        }
        "starts-with?" | "clojure.string/starts-with?" | "str/starts-with?" => {
            if args.len() != 2 {
                return Err(DatomicError::Query(
                    "starts-with? expects two arguments".into(),
                ));
            }
            query_starts_with_predicate(&args[0], &args[1])?
        }
        "includes?"
        | "clojure.string/includes?"
        | "str/includes?"
        | "ends-with?"
        | "clojure.string/ends-with?"
        | "str/ends-with?" => {
            if args.len() != 2 {
                return Err(DatomicError::Query(format!("{op} expects two arguments")));
            }
            query_string_search_predicate(op, &args[0], &args[1])?
        }
        "every?" | "not-every?" | "not-any?" => {
            query_collection_predicate_value(op, args.iter().cloned().collect::<Vec<_>>())?
        }
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    })
}

pub(crate) fn query_collection_predicate_value(op: &str, args: Vec<EdnValue>) -> Result<bool> {
    if args.len() != 2 {
        return Err(DatomicError::Query(format!(
            "{op} expects a predicate and a collection"
        )));
    }
    let predicate = query_predicate_name(&args[0])?;
    let values = query_seq_values(args[1].clone())?;
    let matches = values
        .iter()
        .map(|value| query_unary_predicate(&predicate, value))
        .collect::<Result<Vec<_>>>()?;
    Ok(match op {
        "every?" => matches.into_iter().all(|matched| matched),
        "not-every?" => !matches.into_iter().all(|matched| matched),
        "not-any?" => !matches.into_iter().any(|matched| matched),
        other => return Err(DatomicError::UnsupportedOperation(other.into())),
    })
}

pub(crate) fn query_predicate_function_value(op: &str, args: Vec<EdnValue>) -> Result<EdnValue> {
    let op = query_core_op(op);
    if is_query_unary_predicate_op(op) {
        if args.len() != 1 {
            return Err(DatomicError::Query(format!("{op} expects one argument")));
        }
        return query_unary_predicate(op, &args[0]).map(EdnValue::Bool);
    }
    if is_query_variadic_predicate_op(op) {
        return query_variadic_predicate(op, &args).map(EdnValue::Bool);
    }
    Err(DatomicError::UnsupportedOperation(op.into()))
}

pub(crate) fn is_query_predicate_function_op(op: &str) -> bool {
    is_query_unary_predicate_op(op) || is_query_variadic_predicate_op(op)
}

fn is_query_variadic_predicate_op(op: &str) -> bool {
    matches!(
        query_core_op(op),
        "=" | "!="
            | "not="
            | "distinct?"
            | ">"
            | "<"
            | ">="
            | "<="
            | "contains?"
            | "subset?"
            | "clojure.set/subset?"
            | "set/subset?"
            | "superset?"
            | "clojure.set/superset?"
            | "set/superset?"
            | "starts-with?"
            | "clojure.string/starts-with?"
            | "str/starts-with?"
            | "includes?"
            | "clojure.string/includes?"
            | "str/includes?"
            | "ends-with?"
            | "clojure.string/ends-with?"
            | "str/ends-with?"
            | "every?"
            | "not-every?"
            | "not-any?"
    )
}

fn query_number_as_f64(value: &EdnValue) -> Option<f64> {
    match value {
        EdnValue::Integer(value) => Some(*value as f64),
        EdnValue::BigInt(value) | EdnValue::BigDec(value) => value.parse().ok(),
        EdnValue::Float(value) if value.0.is_finite() => Some(value.0),
        EdnValue::Float(_) => None,
        _ => None,
    }
}

fn query_chained_numbers(args: &[EdnValue], f: impl Fn(f64, f64) -> bool) -> bool {
    args.windows(2).all(|pair| {
        matches!(
            (query_number_as_f64(&pair[0]), query_number_as_f64(&pair[1])),
            (Some(a), Some(b)) if f(a, b)
        )
    })
}

fn is_query_unary_predicate_op(op: &str) -> bool {
    matches!(
        query_core_op(op),
        "nil?"
            | "some?"
            | "true?"
            | "false?"
            | "empty?"
            | "boolean?"
            | "integer?"
            | "number?"
            | "zero?"
            | "pos?"
            | "neg?"
            | "even?"
            | "odd?"
            | "string?"
            | "clojure.string/blank?"
            | "str/blank?"
            | "keyword?"
            | "symbol?"
            | "vector?"
            | "list?"
            | "map?"
            | "set?"
            | "coll?"
            | "colls?"
    )
}

pub(crate) fn query_unary_predicate(op: &str, value: &EdnValue) -> Result<bool> {
    let op = query_core_op(op);
    match op {
        "nil?" => Ok(matches!(value, EdnValue::Nil)),
        "some?" => Ok(!matches!(value, EdnValue::Nil)),
        "true?" => Ok(matches!(value, EdnValue::Bool(true))),
        "false?" => Ok(matches!(value, EdnValue::Bool(false))),
        "empty?" => query_empty_predicate(value),
        "boolean?" => Ok(matches!(value, EdnValue::Bool(_))),
        "integer?" => Ok(matches!(value, EdnValue::Integer(_))),
        "number?" => Ok(matches!(
            value,
            EdnValue::Integer(_) | EdnValue::BigInt(_) | EdnValue::Float(_) | EdnValue::BigDec(_)
        )),
        "zero?" => Ok(matches!(value, EdnValue::Integer(0))),
        "pos?" => Ok(matches!(value, EdnValue::Integer(value) if *value > 0)),
        "neg?" => Ok(matches!(value, EdnValue::Integer(value) if *value < 0)),
        "even?" => Ok(matches!(value, EdnValue::Integer(value) if value % 2 == 0)),
        "odd?" => Ok(matches!(value, EdnValue::Integer(value) if value % 2 != 0)),
        "string?" => Ok(matches!(value, EdnValue::String(_))),
        "clojure.string/blank?" | "str/blank?" => match value {
            EdnValue::Nil => Ok(true),
            EdnValue::String(value) => Ok(value.trim().is_empty()),
            other => Err(DatomicError::Query(format!(
                "{op} expects nil or a string, got {}",
                edn_to_string(other)
            ))),
        },
        "keyword?" => Ok(matches!(value, EdnValue::Keyword(_))),
        "symbol?" => Ok(matches!(value, EdnValue::Symbol(_))),
        "vector?" => Ok(matches!(value, EdnValue::Vector(_))),
        "list?" => Ok(matches!(value, EdnValue::List(_))),
        "map?" => Ok(matches!(value, EdnValue::Map(_))),
        "set?" => Ok(matches!(value, EdnValue::Set(_))),
        "coll?" | "colls?" => Ok(matches!(
            value,
            EdnValue::List(_) | EdnValue::Vector(_) | EdnValue::Map(_) | EdnValue::Set(_)
        )),
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

fn reverse_pull_attr(attr: &str) -> Option<String> {
    let attr = attr.strip_prefix(':')?;
    match attr.rsplit_once('/') {
        Some((ns, name)) => name
            .strip_prefix('_')
            .map(|forward| format!(":{ns}/{forward}")),
        None => attr.strip_prefix('_').map(|forward| format!(":{forward}")),
    }
}

fn pull_ref_cid(value: &EdnValue) -> Option<KotobaCid> {
    match value {
        EdnValue::String(value) => KotobaCid::from_multibase(value)
            .or_else(|| Some(KotobaCid::from_bytes(value.as_bytes()))),
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "cid" => {
            value.as_string().and_then(KotobaCid::from_multibase)
        }
        _ => None,
    }
}

fn edn_entity_value_to_cid(value: &EdnValue) -> Option<KotobaCid> {
    pull_ref_cid(value)
}

fn query_vec<'a>(query: &'a BTreeMap<EdnValue, EdnValue>, key: &str) -> Result<&'a [EdnValue]> {
    query
        .get(&kw(key.trim_start_matches(':')))
        .and_then(EdnValue::as_vector)
        .ok_or_else(|| DatomicError::Query(format!("missing {key} vector")))
}

pub(crate) fn is_query_source_symbol(value: &EdnValue) -> bool {
    matches!(value.as_symbol(), Some(symbol) if symbol.name.starts_with('$'))
}

pub(crate) fn data_pattern_terms(seq: &[EdnValue]) -> Option<&[EdnValue]> {
    match (seq.len(), seq.first().is_some_and(is_query_source_symbol)) {
        (3..=5, false) => Some(seq),
        (4..=6, true) => Some(&seq[1..]),
        _ => None,
    }
}

fn bind_inputs(
    in_forms: &EdnValue,
    inputs: &[EdnValue],
    mut bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    let forms = in_forms
        .as_vector()
        .ok_or_else(|| DatomicError::Query(":in must be a vector".into()))?;
    let mut input_idx = 0;
    for form in forms {
        if is_query_source_symbol(form) {
            if inputs.get(input_idx).is_some_and(is_query_source_symbol) {
                input_idx += 1;
            }
            continue;
        }
        if matches!(form.as_symbol(), Some(s) if s.name == "%") {
            input_idx += 1;
            continue;
        }
        if let Some(terms) = tuple_binding_terms(form) {
            let value = inputs
                .get(input_idx)
                .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
            input_idx += 1;
            let tuple = input_tuple_values(value, terms.len())?;
            for binding in bindings.iter_mut() {
                for (term, value) in terms.iter().zip(&tuple) {
                    if !bind_term(term, value.clone(), binding)? {
                        return Err(DatomicError::Query(format!(
                            "tuple binding value conflicts with existing binding for {}",
                            edn_to_string(term)
                        )));
                    }
                }
            }
            continue;
        }
        if let Some(terms) = relation_binding_terms(form) {
            let value = inputs
                .get(input_idx)
                .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
            input_idx += 1;
            let tuples = input_relation_tuples(value, terms.len())?;
            let mut expanded = Vec::new();
            for binding in &bindings {
                for tuple in &tuples {
                    let mut next = binding.clone();
                    let mut keep = true;
                    for (term, value) in terms.iter().zip(tuple) {
                        if !bind_term(term, value.clone(), &mut next)? {
                            keep = false;
                            break;
                        }
                    }
                    if keep {
                        expanded.push(next);
                    }
                }
            }
            bindings = expanded;
            continue;
        }
        if let Some(var) = collection_binding_var(form) {
            let values = inputs
                .get(input_idx)
                .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
            input_idx += 1;
            let values = input_collection_values(values)?;
            let mut expanded = Vec::new();
            for binding in &bindings {
                for value in &values {
                    let mut next = binding.clone();
                    next.insert(var.to_string(), value.clone());
                    expanded.push(next);
                }
            }
            bindings = expanded;
            continue;
        }
        let Some(var) = variable_name(form) else {
            continue;
        };
        let value = inputs
            .get(input_idx)
            .cloned()
            .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
        input_idx += 1;
        for binding in bindings.iter_mut() {
            binding.insert(var.to_string(), value.clone());
        }
    }
    Ok(bindings)
}

fn rules_from_inputs(in_forms: &EdnValue, inputs: &[EdnValue]) -> Result<Vec<QueryRule>> {
    let forms = in_forms
        .as_vector()
        .ok_or_else(|| DatomicError::Query(":in must be a vector".into()))?;
    let mut input_idx = 0;
    for form in forms {
        if is_query_source_symbol(form) {
            if inputs.get(input_idx).is_some_and(is_query_source_symbol) {
                input_idx += 1;
            }
            continue;
        }
        if matches!(form.as_symbol(), Some(s) if s.name == "%") {
            let rules = inputs
                .get(input_idx)
                .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
            return parse_query_rules(rules);
        }
        input_idx += 1;
    }
    Ok(Vec::new())
}

fn tuple_binding_terms(form: &EdnValue) -> Option<&[EdnValue]> {
    let terms = form.as_seq()?;
    if terms.len() > 1
        && !matches!(terms.last().and_then(EdnValue::as_symbol), Some(s) if s.name == "...")
        && !terms.iter().any(|term| term.as_seq().is_some())
    {
        return Some(terms);
    }
    None
}

fn relation_binding_terms(form: &EdnValue) -> Option<&[EdnValue]> {
    let outer = form.as_seq()?;
    if outer.len() == 1 {
        let terms = outer[0].as_seq()?;
        if terms.len() > 1 {
            return Some(terms);
        }
    }
    None
}

fn collection_binding_var(form: &EdnValue) -> Option<&str> {
    let seq = form.as_seq()?;
    if seq.len() == 2 && matches!(seq[1].as_symbol(), Some(s) if s.name == "...") {
        variable_name(&seq[0])
    } else {
        None
    }
}

fn input_collection_values(value: &EdnValue) -> Result<Vec<EdnValue>> {
    match value {
        EdnValue::Vector(values) | EdnValue::List(values) => Ok(values.clone()),
        EdnValue::Set(values) => Ok(values.iter().cloned().collect()),
        other => Err(DatomicError::Query(format!(
            "collection binding input must be a vector, list, or set, got {}",
            edn_to_string(other)
        ))),
    }
}

fn input_tuple_values(value: &EdnValue, width: usize) -> Result<Vec<EdnValue>> {
    let tuple = value.as_seq().ok_or_else(|| {
        DatomicError::Query(format!(
            "tuple binding input must be a vector or list, got {}",
            edn_to_string(value)
        ))
    })?;
    if tuple.len() != width {
        return Err(DatomicError::Query(format!(
            "tuple binding width {} does not match expected {width}",
            tuple.len()
        )));
    }
    Ok(tuple.to_vec())
}

fn input_relation_tuples(value: &EdnValue, width: usize) -> Result<Vec<Vec<EdnValue>>> {
    let rows = match value {
        EdnValue::Vector(values) | EdnValue::List(values) => values.clone(),
        EdnValue::Set(values) => values.iter().cloned().collect(),
        other => {
            return Err(DatomicError::Query(format!(
                "relation binding input must be a vector, list, or set, got {}",
                edn_to_string(other)
            )));
        }
    };
    rows.into_iter()
        .map(|row| {
            let tuple = row.as_seq().ok_or_else(|| {
                DatomicError::Query(format!(
                    "relation binding row must be a tuple, got {}",
                    edn_to_string(&row)
                ))
            })?;
            if tuple.len() != width {
                return Err(DatomicError::Query(format!(
                    "relation binding row width {} does not match expected {width}",
                    tuple.len()
                )));
            }
            Ok(tuple.to_vec())
        })
        .collect()
}

#[derive(Debug, Clone)]
struct QueryRule {
    name: String,
    args: Vec<EdnValue>,
    clauses: Vec<EdnValue>,
}

fn parse_query_rules(value: &EdnValue) -> Result<Vec<QueryRule>> {
    let rules = match value {
        EdnValue::Vector(values) | EdnValue::List(values) => values,
        other => {
            return Err(DatomicError::Query(format!(
                "rules input must be a vector or list, got {}",
                edn_to_string(other)
            )));
        }
    };
    rules
        .iter()
        .map(|rule| {
            let seq = rule.as_seq().ok_or_else(|| {
                DatomicError::Query(format!(
                    "rule must be a vector/list, got {}",
                    edn_to_string(rule)
                ))
            })?;
            let Some((head, clauses)) = seq.split_first() else {
                return Err(DatomicError::Query("rule cannot be empty".into()));
            };
            let head = head
                .as_seq()
                .ok_or_else(|| DatomicError::Query("rule head must be a list/vector".into()))?;
            let (name, args) = rule_head(head)?;
            Ok(QueryRule {
                name,
                args: args.to_vec(),
                clauses: clauses.to_vec(),
            })
        })
        .collect()
}

fn rule_head(head: &[EdnValue]) -> Result<(String, &[EdnValue])> {
    let Some((name, args)) = head.split_first() else {
        return Err(DatomicError::Query("rule head cannot be empty".into()));
    };
    let name = name
        .as_symbol()
        .map(Symbol::to_qualified)
        .ok_or_else(|| DatomicError::Query("rule head name must be a symbol".into()))?;
    Ok((name, args))
}

fn parse_find_items(find: &[EdnValue]) -> Result<Vec<FindItem>> {
    if let Some((last, elems)) = find.split_last() {
        if matches!(last.as_symbol(), Some(symbol) if symbol.name == "..." || symbol.name == ".") {
            return elems.iter().map(parse_find_item).collect();
        }
    }
    if find.len() == 1 {
        if let Some(tuple) = find[0].as_seq() {
            if !is_find_expression(tuple) {
                return tuple.iter().map(parse_find_item).collect();
            }
        }
    }
    find.iter().map(parse_find_item).collect()
}

fn is_find_expression(seq: &[EdnValue]) -> bool {
    matches!(
        seq.first().and_then(EdnValue::as_symbol),
        Some(symbol)
            if matches!(
                symbol.name.as_str(),
                "pull" | "count" | "count-distinct" | "sum" | "min" | "max" | "avg"
                    | "median" | "variance" | "stddev" | "rand" | "sample"
            )
    )
}

#[derive(Debug, Clone)]
enum FindItem {
    Value(EdnValue),
    Pull { entity: EdnValue, pattern: EdnValue },
    Count(EdnValue),
    CountDistinct(EdnValue),
    Sum(EdnValue),
    Min(EdnValue),
    Max(EdnValue),
    MinN { limit: usize, value: EdnValue },
    MaxN { limit: usize, value: EdnValue },
    Avg(EdnValue),
    Median(EdnValue),
    Variance(EdnValue),
    Stddev(EdnValue),
    Rand(EdnValue),
    Sample { limit: usize, value: EdnValue },
}

impl FindItem {
    fn is_aggregate(&self) -> bool {
        matches!(
            self,
            Self::Count(_)
                | Self::CountDistinct(_)
                | Self::Sum(_)
                | Self::Min(_)
                | Self::Max(_)
                | Self::MinN { .. }
                | Self::MaxN { .. }
                | Self::Avg(_)
                | Self::Median(_)
                | Self::Variance(_)
                | Self::Stddev(_)
                | Self::Rand(_)
                | Self::Sample { .. }
        )
    }

    fn resolve(&self, binding: &BTreeMap<String, EdnValue>, db: &Db) -> Result<EdnValue> {
        match self {
            Self::Value(value)
            | Self::Count(value)
            | Self::CountDistinct(value)
            | Self::Sum(value)
            | Self::Min(value)
            | Self::Max(value)
            | Self::MinN { value, .. }
            | Self::MaxN { value, .. }
            | Self::Avg(value)
            | Self::Median(value)
            | Self::Variance(value)
            | Self::Stddev(value)
            | Self::Rand(value)
            | Self::Sample { value, .. } => Ok(match variable_name(value) {
                Some(var) => binding.get(var).cloned().unwrap_or(EdnValue::Nil),
                None => value.clone(),
            }),
            Self::Pull { entity, pattern } => {
                let entity = resolve_query_value(entity, binding)?;
                let Some(eid) = edn_entity_value_to_cid(&entity) else {
                    return Err(DatomicError::Query(format!(
                        "pull entity must resolve to a CID string or #cid, got {}",
                        edn_to_string(&entity)
                    )));
                };
                db.pull(pattern.clone(), eid)
            }
        }
    }
}

fn parse_find_item(value: &EdnValue) -> Result<FindItem> {
    let Some(seq) = value.as_seq() else {
        return Ok(FindItem::Value(value.clone()));
    };
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "count") {
        return Ok(FindItem::Count(seq[1].clone()));
    }
    if seq.len() == 2
        && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "count-distinct")
    {
        return Ok(FindItem::CountDistinct(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "sum") {
        return Ok(FindItem::Sum(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "min") {
        return Ok(FindItem::Min(seq[1].clone()));
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "min") {
        let limit = aggregate_limit("min", &seq[1])?;
        return Ok(FindItem::MinN {
            limit,
            value: seq[2].clone(),
        });
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "max") {
        return Ok(FindItem::Max(seq[1].clone()));
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "max") {
        let limit = aggregate_limit("max", &seq[1])?;
        return Ok(FindItem::MaxN {
            limit,
            value: seq[2].clone(),
        });
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "avg") {
        return Ok(FindItem::Avg(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "median") {
        return Ok(FindItem::Median(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "variance") {
        return Ok(FindItem::Variance(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "stddev") {
        return Ok(FindItem::Stddev(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "rand") {
        return Ok(FindItem::Rand(seq[1].clone()));
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "sample") {
        let limit = aggregate_limit("sample", &seq[1])?;
        return Ok(FindItem::Sample {
            limit,
            value: seq[2].clone(),
        });
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "pull") {
        return Ok(FindItem::Pull {
            entity: seq[1].clone(),
            pattern: seq[2].clone(),
        });
    }
    Err(DatomicError::UnsupportedOperation(format!(
        "unsupported find expression {}",
        edn_to_string(value)
    )))
}

#[derive(Debug, Clone)]
enum AggregateValue {
    Count(i64),
    CountDistinct(BTreeSet<EdnValue>),
    Sum(i64),
    Min(Option<EdnValue>),
    Max(Option<EdnValue>),
    MinN { limit: usize, values: Vec<EdnValue> },
    MaxN { limit: usize, values: Vec<EdnValue> },
    Avg { sum: i64, count: i64 },
    Median(Vec<i64>),
    Variance(Vec<i64>),
    Stddev(Vec<i64>),
    Rand(Option<EdnValue>),
    Sample { limit: usize, values: Vec<EdnValue> },
}

impl AggregateValue {
    fn for_find_item(item: &FindItem) -> Option<Self> {
        match item {
            FindItem::Value(_) => None,
            FindItem::Pull { .. } => None,
            FindItem::Count(_) => Some(Self::Count(0)),
            FindItem::CountDistinct(_) => Some(Self::CountDistinct(BTreeSet::new())),
            FindItem::Sum(_) => Some(Self::Sum(0)),
            FindItem::Min(_) => Some(Self::Min(None)),
            FindItem::Max(_) => Some(Self::Max(None)),
            FindItem::MinN { limit, .. } => Some(Self::MinN {
                limit: *limit,
                values: Vec::new(),
            }),
            FindItem::MaxN { limit, .. } => Some(Self::MaxN {
                limit: *limit,
                values: Vec::new(),
            }),
            FindItem::Avg(_) => Some(Self::Avg { sum: 0, count: 0 }),
            FindItem::Median(_) => Some(Self::Median(Vec::new())),
            FindItem::Variance(_) => Some(Self::Variance(Vec::new())),
            FindItem::Stddev(_) => Some(Self::Stddev(Vec::new())),
            FindItem::Rand(_) => Some(Self::Rand(None)),
            FindItem::Sample { limit, .. } => Some(Self::Sample {
                limit: *limit,
                values: Vec::new(),
            }),
        }
    }

    fn push(&mut self, value: EdnValue) -> Result<()> {
        if matches!(value, EdnValue::Nil) {
            return Ok(());
        }
        match self {
            Self::Count(count) => *count += 1,
            Self::CountDistinct(values) => {
                values.insert(value);
            }
            Self::Sum(sum) => *sum += aggregate_integer(&value)?,
            Self::Min(min) => {
                if min
                    .as_ref()
                    .is_none_or(|current| query_sort_order(&value, current).is_lt())
                {
                    *min = Some(value);
                }
            }
            Self::Max(max) => {
                if max
                    .as_ref()
                    .is_none_or(|current| query_sort_order(&value, current).is_gt())
                {
                    *max = Some(value);
                }
            }
            Self::MinN { values, .. } | Self::MaxN { values, .. } => {
                values.push(value);
            }
            Self::Avg { sum, count } => {
                *sum += aggregate_integer(&value)?;
                *count += 1;
            }
            Self::Median(values) | Self::Variance(values) | Self::Stddev(values) => {
                values.push(aggregate_integer(&value)?);
            }
            Self::Rand(current) => {
                if current.is_none() {
                    *current = Some(value);
                }
            }
            Self::Sample { limit, values } => {
                if values.len() < *limit {
                    values.push(value);
                }
            }
        }
        Ok(())
    }

    fn result(&self) -> EdnValue {
        match self {
            Self::Count(count) => EdnValue::Integer(*count),
            Self::CountDistinct(values) => EdnValue::Integer(values.len() as i64),
            Self::Sum(sum) => EdnValue::Integer(*sum),
            Self::Min(min) => min.clone().unwrap_or(EdnValue::Nil),
            Self::Max(max) => max.clone().unwrap_or(EdnValue::Nil),
            Self::MinN { limit, values } => aggregate_top_n(values, *limit, false),
            Self::MaxN { limit, values } => aggregate_top_n(values, *limit, true),
            Self::Avg { sum, count } => {
                if *count == 0 {
                    EdnValue::Nil
                } else {
                    EdnValue::float(*sum as f64 / *count as f64)
                }
            }
            Self::Median(values) => aggregate_median(values),
            Self::Variance(values) => aggregate_variance(values),
            Self::Stddev(values) => match aggregate_variance_f64(values) {
                Some(variance) => EdnValue::float(variance.sqrt()),
                None => EdnValue::Nil,
            },
            Self::Rand(value) => value.clone().unwrap_or(EdnValue::Nil),
            Self::Sample { values, .. } => EdnValue::Vector(values.clone()),
        }
    }
}

fn aggregate_limit(op: &str, value: &EdnValue) -> Result<usize> {
    match value {
        EdnValue::Integer(limit) if *limit >= 0 => Ok(*limit as usize),
        other => Err(DatomicError::Query(format!(
            "{op} expects a non-negative integer limit, got {}",
            edn_to_string(other)
        ))),
    }
}

fn aggregate_top_n(values: &[EdnValue], limit: usize, desc: bool) -> EdnValue {
    let mut values = values.to_vec();
    values.sort_by(|left, right| {
        let ordering = query_sort_order(left, right);
        if desc {
            ordering.reverse()
        } else {
            ordering
        }
    });
    values.truncate(limit);
    EdnValue::Vector(values)
}

fn aggregate_median(values: &[i64]) -> EdnValue {
    if values.is_empty() {
        return EdnValue::Nil;
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        EdnValue::Integer(values[mid])
    } else {
        EdnValue::float((values[mid - 1] as f64 + values[mid] as f64) / 2.0)
    }
}

fn aggregate_variance(values: &[i64]) -> EdnValue {
    match aggregate_variance_f64(values) {
        Some(value) => EdnValue::float(value),
        None => EdnValue::Nil,
    }
}

fn aggregate_variance_f64(values: &[i64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mean = values.iter().sum::<i64>() as f64 / values.len() as f64;
    Some(
        values
            .iter()
            .map(|value| {
                let diff = *value as f64 - mean;
                diff * diff
            })
            .sum::<f64>()
            / values.len() as f64,
    )
}

fn aggregate_integer(value: &EdnValue) -> Result<i64> {
    match value {
        EdnValue::Integer(value) => Ok(*value),
        other => Err(DatomicError::Query(format!(
            "aggregate value must be an integer, got {}",
            edn_to_string(other)
        ))),
    }
}

fn aggregate_rows(
    find_items: &[FindItem],
    with_items: &[EdnValue],
    bindings: Vec<BTreeMap<String, EdnValue>>,
    db: &Db,
) -> Result<Vec<Vec<EdnValue>>> {
    let group_positions = find_items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| (!item.is_aggregate()).then_some(idx))
        .collect::<Vec<_>>();
    let aggregate_positions = find_items
        .iter()
        .enumerate()
        .filter_map(|(idx, item)| item.is_aggregate().then_some(idx))
        .collect::<Vec<_>>();
    let aggregate_template = aggregate_positions
        .iter()
        .filter_map(|idx| AggregateValue::for_find_item(&find_items[*idx]))
        .collect::<Vec<_>>();
    let mut groups: BTreeMap<Vec<EdnValue>, Vec<AggregateValue>> = BTreeMap::new();
    let mut seen_with_rows = BTreeSet::new();

    for binding in &bindings {
        let key = group_positions
            .iter()
            .map(|idx| find_items[*idx].resolve(binding, db))
            .collect::<Result<Vec<_>>>()?;
        if !with_items.is_empty() {
            let mut with_key = key.clone();
            for item in with_items {
                with_key.push(resolve_query_value(item, binding)?);
            }
            for find_idx in &aggregate_positions {
                with_key.push(find_items[*find_idx].resolve(binding, db)?);
            }
            if !seen_with_rows.insert(with_key) {
                continue;
            }
        }
        let counts = groups
            .entry(key)
            .or_insert_with(|| aggregate_template.clone());
        for (aggregate_idx, find_idx) in aggregate_positions.iter().enumerate() {
            counts[aggregate_idx].push(find_items[*find_idx].resolve(binding, db)?)?;
        }
    }

    let mut rows = BTreeSet::new();
    for (key, aggregates) in groups {
        let mut row = Vec::with_capacity(find_items.len());
        let mut key_idx = 0;
        let mut aggregate_idx = 0;
        for item in find_items {
            if item.is_aggregate() {
                row.push(aggregates[aggregate_idx].result());
                aggregate_idx += 1;
            } else {
                row.push(key[key_idx].clone());
                key_idx += 1;
            }
        }
        rows.insert(row);
    }
    Ok(rows.into_iter().collect())
}

fn eval_clause(
    clause: &EdnValue,
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    let seq = clause
        .as_seq()
        .ok_or_else(|| DatomicError::Query("where clause must be vector/list".into()))?;
    if matches!(seq.first().and_then(EdnValue::as_symbol), Some(s) if s.name == "not") {
        return eval_not(seq, db, facts, rules, bindings);
    }
    if matches!(seq.first().and_then(EdnValue::as_symbol), Some(s) if s.name == "not-join") {
        return eval_not_join(seq, db, facts, rules, bindings);
    }
    if matches!(seq.first().and_then(EdnValue::as_symbol), Some(s) if s.name == "or") {
        return eval_or(seq, db, facts, rules, bindings);
    }
    if matches!(seq.first().and_then(EdnValue::as_symbol), Some(s) if s.name == "or-join") {
        return eval_or_join(seq, db, facts, rules, bindings);
    }
    if let Some(rule_name) = rule_invocation_name(seq, rules) {
        return eval_rule_invocation(rule_name, &seq[1..], db, facts, rules, bindings);
    }
    if seq.len() == 2 {
        if let Some(inner) = seq[0].as_seq() {
            return eval_function_binding(inner, &seq[1], db, bindings);
        }
    }
    if let Some(triple) = data_pattern_terms(seq) {
        return eval_triple(triple, db, facts, bindings);
    }
    if seq.len() == 1 {
        if let Some(inner) = seq[0].as_seq() {
            return eval_predicate(inner, db, facts, bindings);
        }
    }
    Err(DatomicError::UnsupportedOperation(edn_to_string(clause)))
}

fn eval_not(
    not_clause: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    if not_clause.len() < 2 {
        return Err(DatomicError::UnsupportedOperation(edn_to_string(
            &EdnValue::List(not_clause.to_vec()),
        )));
    }
    let inner_clauses = &not_clause[1..];
    let mut out = Vec::new();
    for binding in bindings {
        let mut probe = vec![binding.clone()];
        for inner in inner_clauses {
            probe = eval_clause(inner, db, facts, rules, probe)?;
            if probe.is_empty() {
                break;
            }
        }
        if probe.is_empty() {
            out.push(binding);
        }
    }
    Ok(out)
}

fn eval_not_join(
    not_join_clause: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    if not_join_clause.len() < 3 {
        return Err(DatomicError::UnsupportedOperation(edn_to_string(
            &EdnValue::List(not_join_clause.to_vec()),
        )));
    }
    let join_vars = join_vars(&not_join_clause[1])?;
    let inner_clauses = &not_join_clause[2..];
    let mut out = Vec::new();
    for binding in bindings {
        let seed = project_binding(&binding, &join_vars)?;
        let mut probe = vec![seed];
        for inner in inner_clauses {
            probe = eval_clause(inner, db, facts, rules, probe)?;
            if probe.is_empty() {
                break;
            }
        }
        if probe.is_empty() {
            out.push(binding);
        }
    }
    Ok(out)
}

fn eval_or(
    or_clause: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    if or_clause.len() < 2 {
        return Err(DatomicError::UnsupportedOperation(edn_to_string(
            &EdnValue::List(or_clause.to_vec()),
        )));
    }
    let mut out = BTreeSet::new();
    for binding in bindings {
        for branch in &or_clause[1..] {
            for next in eval_or_branch(branch, db, facts, rules, vec![binding.clone()])? {
                out.insert(next);
            }
        }
    }
    Ok(out.into_iter().collect())
}

fn eval_or_join(
    or_join_clause: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    if or_join_clause.len() < 3 {
        return Err(DatomicError::UnsupportedOperation(edn_to_string(
            &EdnValue::List(or_join_clause.to_vec()),
        )));
    }
    let join_vars = join_vars(&or_join_clause[1])?;
    let mut out = BTreeSet::new();
    for binding in bindings {
        let seed = project_binding(&binding, &join_vars)?;
        for branch in &or_join_clause[2..] {
            for branch_binding in eval_or_branch(branch, db, facts, rules, vec![seed.clone()])? {
                if let Some(merged) = merge_bindings(&binding, &branch_binding) {
                    out.insert(merged);
                }
            }
        }
    }
    Ok(out.into_iter().collect())
}

fn eval_or_branch(
    branch: &EdnValue,
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    let seq = branch.as_seq().ok_or_else(|| {
        DatomicError::UnsupportedOperation(format!(
            "or branch must be a clause: {}",
            edn_to_string(branch)
        ))
    })?;
    if matches!(seq.first().and_then(EdnValue::as_symbol), Some(s) if s.name == "and") {
        let mut out = bindings;
        for clause in &seq[1..] {
            out = eval_clause(clause, db, facts, rules, out)?;
        }
        Ok(out)
    } else {
        eval_clause(branch, db, facts, rules, bindings)
    }
}

fn join_vars(value: &EdnValue) -> Result<Vec<String>> {
    let vars = value
        .as_seq()
        .ok_or_else(|| DatomicError::Query("join vars must be a vector/list".into()))?;
    vars.iter()
        .map(|var| {
            variable_name(var)
                .map(str::to_string)
                .ok_or_else(|| DatomicError::Query("join var must be a variable".into()))
        })
        .collect()
}

fn project_binding(
    binding: &BTreeMap<String, EdnValue>,
    vars: &[String],
) -> Result<BTreeMap<String, EdnValue>> {
    let mut out = BTreeMap::new();
    for var in vars {
        let value = binding
            .get(var)
            .cloned()
            .ok_or_else(|| DatomicError::Query(format!("unbound join variable {var}")))?;
        out.insert(var.clone(), value);
    }
    Ok(out)
}

fn merge_bindings(
    left: &BTreeMap<String, EdnValue>,
    right: &BTreeMap<String, EdnValue>,
) -> Option<BTreeMap<String, EdnValue>> {
    let mut out = left.clone();
    for (key, value) in right {
        match out.get(key) {
            Some(existing) if existing != value => return None,
            Some(_) => {}
            None => {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    Some(out)
}

fn rule_invocation_name<'a>(seq: &[EdnValue], rules: &'a [QueryRule]) -> Option<&'a str> {
    let name = seq.first()?.as_symbol()?.to_qualified();
    rules
        .iter()
        .any(|rule| rule.name == name && rule.args.len() == seq.len().saturating_sub(1))
        .then_some(rules.iter().find(|rule| rule.name == name)?.name.as_str())
}

fn eval_rule_invocation(
    name: &str,
    call_args: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    rules: &[QueryRule],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    let matching_rules = rules
        .iter()
        .filter(|rule| rule.name == name && rule.args.len() == call_args.len())
        .collect::<Vec<_>>();
    let mut out = BTreeSet::new();
    for binding in bindings {
        for rule in &matching_rules {
            let mut seed = binding.clone();
            let mut seed_matches = true;
            for (call_arg, rule_arg) in call_args.iter().zip(&rule.args) {
                if let Ok(value) = resolve_query_value(call_arg, &binding) {
                    if !bind_term(rule_arg, value, &mut seed)? {
                        seed_matches = false;
                        break;
                    }
                }
            }
            if !seed_matches {
                continue;
            }
            let mut rule_bindings = vec![seed];
            for clause in &rule.clauses {
                rule_bindings = eval_clause(clause, db, facts, rules, rule_bindings)?;
            }
            for rule_binding in rule_bindings {
                let mut next = binding.clone();
                let mut keep = true;
                for (call_arg, rule_arg) in call_args.iter().zip(&rule.args) {
                    let value = resolve_query_value(rule_arg, &rule_binding)?;
                    if !bind_term(call_arg, value, &mut next)? {
                        keep = false;
                        break;
                    }
                }
                if keep {
                    out.insert(next);
                }
            }
        }
    }
    Ok(out.into_iter().collect())
}

fn eval_triple(
    triple: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    let mut out = Vec::new();
    for binding in bindings {
        let candidates = candidate_datoms_for_triple(triple, db, facts, &binding)?;
        for datom in &candidates {
            if !term_matches(&triple[1], &attr_value(&datom.a), &binding)? {
                continue;
            }
            let mut next = binding.clone();
            if bind_entity_term(&triple[0], &datom.e, db, &binding, &mut next)?
                && bind_term(&triple[1], attr_value(&datom.a), &mut next)?
                && bind_term(&triple[2], datom.v.clone(), &mut next)?
                && bind_datom_tx_term(triple, datom, &binding, &mut next)?
                && bind_datom_added_term(triple, datom, &binding, &mut next)?
            {
                out.push(next);
            }
        }
    }
    Ok(out)
}

fn bind_datom_tx_term(
    pattern: &[EdnValue],
    datom: &Datom,
    binding: &BTreeMap<String, EdnValue>,
    next: &mut BTreeMap<String, EdnValue>,
) -> Result<bool> {
    let Some(term) = pattern.get(3) else {
        return Ok(true);
    };
    Ok(term_matches(term, &cid_value(&datom.t), binding)?
        && bind_term(term, cid_value(&datom.t), next)?)
}

fn bind_datom_added_term(
    pattern: &[EdnValue],
    datom: &Datom,
    binding: &BTreeMap<String, EdnValue>,
    next: &mut BTreeMap<String, EdnValue>,
) -> Result<bool> {
    let Some(term) = pattern.get(4) else {
        return Ok(true);
    };
    let added = EdnValue::Bool(datom.added);
    Ok(term_matches(term, &added, binding)? && bind_term(term, added, next)?)
}

fn candidate_datoms_for_triple(
    triple: &[EdnValue],
    db: &Db,
    facts: &[Datom],
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Vec<Datom>> {
    let lookup = match lookup_ref_entity_term(&triple[0], db, binding)? {
        Some(entity) => match resolved_attr_term(&triple[1], binding)? {
            Some(attr) => distributed::DatomIndexLookup::EntityAttribute { entity, attr },
            None => distributed::DatomIndexLookup::Entity(entity),
        },
        None if is_lookup_ref_term(&triple[0], binding) => return Ok(vec![]),
        None => datom_lookup_for_triple(triple, binding)?,
    };
    Ok(match lookup {
        distributed::DatomIndexLookup::All => facts.to_vec(),
        distributed::DatomIndexLookup::Entity(entity) => facts
            .iter()
            .cloned()
            .filter(|datom| datom.e == entity)
            .collect(),
        distributed::DatomIndexLookup::EntityAttribute { entity, attr } => facts
            .iter()
            .cloned()
            .filter(|datom| datom.e == entity && attr_matches(&datom.a, &attr))
            .collect(),
        distributed::DatomIndexLookup::Attribute(attr) => facts
            .iter()
            .cloned()
            .filter(|datom| attr_matches(&datom.a, &attr))
            .collect(),
        distributed::DatomIndexLookup::AttributeValue { attr, value } => facts
            .iter()
            .cloned()
            .filter(|datom| attr_matches(&datom.a, &attr) && datom.v == value)
            .collect(),
    })
}

fn datom_lookup_for_triple(
    triple: &[EdnValue],
    binding: &BTreeMap<String, EdnValue>,
) -> Result<distributed::DatomIndexLookup> {
    let entity = resolved_entity_term(&triple[0], binding)?;
    let attr = resolved_attr_term(&triple[1], binding)?;
    let value = resolved_value_term(&triple[2], binding)?;

    Ok(match (entity, attr, value) {
        (Some(entity), Some(attr), _) => {
            distributed::DatomIndexLookup::EntityAttribute { entity, attr }
        }
        (None, Some(attr), Some(value)) => {
            distributed::DatomIndexLookup::AttributeValue { attr, value }
        }
        (Some(entity), None, _) => distributed::DatomIndexLookup::Entity(entity),
        (None, Some(attr), None) => distributed::DatomIndexLookup::Attribute(attr),
        (None, None, _) => distributed::DatomIndexLookup::All,
    })
}

fn resolved_entity_term(
    term: &EdnValue,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Option<KotobaCid>> {
    let value = match variable_name(term) {
        Some(var) => binding.get(var),
        None => Some(term),
    };
    Ok(value.and_then(edn_entity_value_to_cid))
}

fn resolved_attr_term(
    term: &EdnValue,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Option<String>> {
    let value = match variable_name(term) {
        Some(var) => binding.get(var),
        None => Some(term),
    };
    Ok(value.and_then(|value| attr_to_string(value).ok()))
}

fn resolved_value_term(
    term: &EdnValue,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Option<EdnValue>> {
    Ok(match variable_name(term) {
        Some(var) => binding.get(var).cloned(),
        None => Some(term.clone()),
    })
}

fn eval_predicate(
    pred: &[EdnValue],
    _db: &Db,
    facts: &[Datom],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    if pred.len() == 4 && matches!(pred[0].as_symbol(), Some(symbol) if symbol.name == "missing?") {
        return eval_missing_predicate(pred, facts, bindings);
    }
    if pred.len() == 2 {
        let op = pred[0]
            .as_symbol()
            .map(Symbol::to_qualified)
            .or_else(|| pred[0].as_keyword().map(keyword_to_attr))
            .ok_or_else(|| DatomicError::Query("predicate op must be symbol".into()))?;
        let mut out = Vec::new();
        for binding in bindings {
            let value = resolve_query_value(&pred[1], &binding)?;
            if query_unary_predicate(&op, &value)? {
                out.push(binding);
            }
        }
        return Ok(out);
    }
    if pred.len() < 3 {
        return Err(DatomicError::UnsupportedOperation(edn_to_string(
            &EdnValue::Vector(pred.to_vec()),
        )));
    }
    let op = pred[0]
        .as_symbol()
        .map(Symbol::to_qualified)
        .or_else(|| pred[0].as_keyword().map(keyword_to_attr))
        .ok_or_else(|| DatomicError::Query("predicate op must be symbol".into()))?;
    let mut out = Vec::new();
    for binding in bindings {
        let values = pred[1..]
            .iter()
            .map(|term| resolve_query_value(term, &binding))
            .collect::<Result<Vec<_>>>()?;
        if query_variadic_predicate(&op, &values)? {
            out.push(binding);
        }
    }
    Ok(out)
}

fn eval_missing_predicate(
    pred: &[EdnValue],
    facts: &[Datom],
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    if !is_query_source_symbol(&pred[1]) {
        return Err(DatomicError::Query(
            "missing? first argument must be $".into(),
        ));
    }
    let attr = attr_to_string(&pred[3])?;
    let mut out = Vec::new();
    for binding in bindings {
        let entity = resolve_query_value(&pred[2], &binding)?;
        let Some(eid) = edn_entity_value_to_cid(&entity) else {
            return Err(DatomicError::Query(format!(
                "missing? entity must resolve to a CID string or #cid, got {}",
                edn_to_string(&entity)
            )));
        };
        if !facts.iter().any(|datom| datom.e == eid && datom.a == attr) {
            out.push(binding);
        }
    }
    Ok(out)
}

fn eval_function_binding(
    expr: &[EdnValue],
    target: &EdnValue,
    db: &Db,
    bindings: Vec<BTreeMap<String, EdnValue>>,
) -> Result<Vec<BTreeMap<String, EdnValue>>> {
    let op = expr
        .first()
        .and_then(EdnValue::as_symbol)
        .map(Symbol::to_qualified)
        .ok_or_else(|| DatomicError::Query("function op must be a symbol".into()))?;
    let args = &expr[1..];
    let mut out = Vec::new();
    for binding in bindings {
        if op == "fulltext" {
            for value in eval_fulltext_function(args, db, &binding)? {
                let mut next = binding.clone();
                if bind_relation_or_function_target(target, value, &mut next)? {
                    out.push(next);
                }
            }
            continue;
        }
        let value = eval_query_function(&op, args, db, &binding)?;
        let mut next = binding;
        if bind_function_target(target, value, &mut next)? {
            out.push(next);
        }
    }
    Ok(out)
}

fn eval_query_function(
    op: &str,
    args: &[EdnValue],
    db: &Db,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<EdnValue> {
    let op = query_core_op(op);
    match op {
        "ground" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("ground expects one argument".into()));
            }
            Ok(args[0].clone())
        }
        "identity" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("identity expects one argument".into()));
            }
            resolve_query_value(&args[0], binding)
        }
        "name" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("name expects one argument".into()));
            }
            pull_name_value(resolve_query_value(&args[0], binding)?)
        }
        "namespace" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("namespace expects one argument".into()));
            }
            pull_namespace_value(resolve_query_value(&args[0], binding)?)
        }
        "str" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .map(query_str_value),
        "subs" | "clojure.core/subs" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_subs_value),
        "split" | "clojure.string/split" | "str/split" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_split_value),
        "join" | "clojure.string/join" | "str/join" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_join_value),
        "replace" | "clojure.string/replace" | "str/replace" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_replace_value),
        "re-find" | "clojure.core/re-find" | "re-matches" | "clojure.core/re-matches" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_regex_value(op, values)),
        "lower-case"
        | "clojure.string/lower-case"
        | "str/lower-case"
        | "upper-case"
        | "clojure.string/upper-case"
        | "str/upper-case"
        | "capitalize"
        | "clojure.string/capitalize"
        | "str/capitalize" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_string_case_value(op, values)),
        "trim"
        | "clojure.string/trim"
        | "str/trim"
        | "triml"
        | "clojure.string/triml"
        | "str/triml"
        | "trimr"
        | "clojure.string/trimr"
        | "str/trimr" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_trim_value(op, values)),
        "keyword" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_keyword_value),
        "get" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_get_value),
        "get-in" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_get_in_value),
        "assoc-in" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_assoc_in_value),
        "update" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_update_value),
        "update-in" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_update_in_value),
        "vector" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .map(EdnValue::Vector),
        "list" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .map(EdnValue::List),
        "hash-set" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .map(query_hash_set_value),
        "union"
        | "clojure.set/union"
        | "set/union"
        | "intersection"
        | "clojure.set/intersection"
        | "set/intersection"
        | "difference"
        | "clojure.set/difference"
        | "set/difference" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_set_operation_value(op, values)),
        "hash-map" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_hash_map_value),
        "keys" | "vals" | "merge" | "select-keys" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_map_operation_value(op, values)),
        "every?" | "not-every?" | "not-any?" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_collection_predicate_value(op, values))
            .map(EdnValue::Bool),
        "not" | "boolean" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_truth_function_value(op, values)),
        _ if is_query_unary_predicate_op(op) || is_query_variadic_predicate_op(op) => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_predicate_function_value(op, values)),
        "count" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("count expects one argument".into()));
            }
            query_count_value(resolve_query_value(&args[0], binding)?)
        }
        "not-empty" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("not-empty expects one argument".into()));
            }
            query_not_empty_value(resolve_query_value(&args[0], binding)?)
        }
        "map" | "filter" | "remove" | "keep" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_collection_transform_value(op, values)),
        "reduce" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_reduce_value),
        "apply" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_apply_function_value),
        "seq" | "first" | "last" | "rest" | "next" => {
            if args.len() != 1 {
                return Err(DatomicError::Query(format!("{op} expects one argument")));
            }
            query_collection_value(op, resolve_query_value(&args[0], binding)?)
        }
        "nth" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_nth_value),
        "cons" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_cons_value),
        "take" | "drop" | "take-while" | "drop-while" | "split-at" | "split-with" | "partition"
        | "partition-all" | "subvec" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_collection_slice_value(op, values)),
        "reverse" | "sort" | "flatten" | "interpose" | "interleave" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_collection_order_value(op, values)),
        "conj" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_conj_value),
        "assoc" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_assoc_value),
        "dissoc" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_dissoc_value),
        "disj" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(query_disj_value),
        "inc" | "dec" | "abs" | "+" | "-" | "*" | "quot" | "rem" | "mod" | "min" | "max" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .and_then(|values| query_arithmetic_value(&op, values)),
        "tuple" => args
            .iter()
            .map(|arg| resolve_query_value(arg, binding))
            .collect::<Result<Vec<_>>>()
            .map(EdnValue::Vector),
        "untuple" => {
            if args.len() != 1 {
                return Err(DatomicError::Query("untuple expects one argument".into()));
            }
            let tuple = resolve_query_value(&args[0], binding)?;
            match tuple {
                EdnValue::Vector(values) | EdnValue::List(values) => Ok(EdnValue::Vector(values)),
                other => Err(DatomicError::Query(format!(
                    "untuple expects a tuple value, got {}",
                    edn_to_string(&other)
                ))),
            }
        }
        "get-else" => {
            if args.len() != 4 || !is_query_source_symbol(&args[0]) {
                return Err(DatomicError::Query(
                    "get-else expects ($ entity attr default)".into(),
                ));
            }
            let entity = resolve_query_value(&args[1], binding)?;
            let Some(eid) = edn_entity_value_to_cid(&entity) else {
                return Err(DatomicError::Query(format!(
                    "get-else entity must resolve to a CID string or #cid, got {}",
                    edn_to_string(&entity)
                )));
            };
            let attr = attr_to_string(&args[2])?;
            Ok(db_value(db, &eid, &attr).unwrap_or_else(|| args[3].clone()))
        }
        "get-some" => {
            if args.len() < 3 || !is_query_source_symbol(&args[0]) {
                return Err(DatomicError::Query(
                    "get-some expects ($ entity attr+)".into(),
                ));
            }
            let entity = resolve_query_value(&args[1], binding)?;
            let Some(eid) = edn_entity_value_to_cid(&entity) else {
                return Err(DatomicError::Query(format!(
                    "get-some entity must resolve to a CID string or #cid, got {}",
                    edn_to_string(&entity)
                )));
            };
            for attr_arg in &args[2..] {
                let attr = attr_to_string(attr_arg)?;
                if let Some(value) = db_value(db, &eid, &attr) {
                    return Ok(EdnValue::Vector(vec![attr_value(&attr), value]));
                }
            }
            Ok(EdnValue::Nil)
        }
        other => Err(DatomicError::UnsupportedOperation(other.into())),
    }
}

fn eval_fulltext_function(
    args: &[EdnValue],
    db: &Db,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<Vec<EdnValue>> {
    if args.len() != 3 || !is_query_source_symbol(&args[0]) {
        return Err(DatomicError::Query(
            "fulltext expects ($ attr search-string)".into(),
        ));
    }
    let attr = attr_to_string(&args[1])?;
    let search = resolve_query_value(&args[2], binding)?;
    let needle = search.as_string().ok_or_else(|| {
        DatomicError::Query(format!(
            "fulltext search term must be a string, got {}",
            edn_to_string(&search)
        ))
    })?;
    let needle = needle.to_ascii_lowercase();
    if needle.is_empty() {
        return Ok(Vec::new());
    }
    let mut rows = BTreeSet::new();
    for datom in db.datoms() {
        if datom.a != attr {
            continue;
        }
        let Some(haystack) = datom.v.as_string() else {
            continue;
        };
        let haystack = haystack.to_ascii_lowercase();
        let score = haystack.matches(&needle).count() as i64;
        if score > 0 {
            rows.insert(EdnValue::Vector(vec![
                cid_value(&datom.e),
                datom.v,
                cid_value(&datom.t),
                EdnValue::Integer(score),
            ]));
        }
    }
    Ok(rows.into_iter().collect())
}

fn bind_function_target(
    target: &EdnValue,
    value: EdnValue,
    binding: &mut BTreeMap<String, EdnValue>,
) -> Result<bool> {
    let Some(targets) = target.as_seq() else {
        return bind_term(target, value, binding);
    };
    let values = value.as_seq().ok_or_else(|| {
        DatomicError::Query(format!(
            "tuple binding target requires tuple value, got {}",
            edn_to_string(&value)
        ))
    })?;
    if targets.len() != values.len() {
        return Err(DatomicError::Query(format!(
            "tuple binding target width {} does not match value width {}",
            targets.len(),
            values.len()
        )));
    }
    let mut next = binding.clone();
    for (target, value) in targets.iter().zip(values.iter()) {
        if !bind_term(target, value.clone(), &mut next)? {
            return Ok(false);
        }
    }
    *binding = next;
    Ok(true)
}

fn bind_relation_or_function_target(
    target: &EdnValue,
    value: EdnValue,
    binding: &mut BTreeMap<String, EdnValue>,
) -> Result<bool> {
    if let Some(targets) = relation_binding_targets(target) {
        let values = value.as_seq().ok_or_else(|| {
            DatomicError::Query(format!(
                "relation binding target requires tuple value, got {}",
                edn_to_string(&value)
            ))
        })?;
        if targets.len() != values.len() {
            return Err(DatomicError::Query(format!(
                "relation binding target width {} does not match value width {}",
                targets.len(),
                values.len()
            )));
        }
        let mut next = binding.clone();
        for (target, value) in targets.iter().zip(values.iter()) {
            if !bind_term(target, value.clone(), &mut next)? {
                return Ok(false);
            }
        }
        *binding = next;
        Ok(true)
    } else {
        bind_function_target(target, value, binding)
    }
}

fn relation_binding_targets(target: &EdnValue) -> Option<&[EdnValue]> {
    let outer = target.as_seq()?;
    if outer.len() == 1 {
        outer[0].as_seq()
    } else {
        None
    }
}

fn db_value(db: &Db, eid: &KotobaCid, attr: &str) -> Option<EdnValue> {
    db.datoms()
        .into_iter()
        .find(|datom| &datom.e == eid && datom.a == attr)
        .map(|datom| datom.v)
}

fn term_matches(
    term: &EdnValue,
    value: &EdnValue,
    binding: &BTreeMap<String, EdnValue>,
) -> Result<bool> {
    match variable_name(term) {
        Some(var) => Ok(binding.get(var).is_none_or(|bound| bound == value)),
        None => Ok(term == value),
    }
}

fn bind_term(
    term: &EdnValue,
    value: EdnValue,
    binding: &mut BTreeMap<String, EdnValue>,
) -> Result<bool> {
    match variable_name(term) {
        Some(var) => match binding.get(var) {
            Some(bound) => Ok(bound == &value),
            None => {
                binding.insert(var.to_string(), value);
                Ok(true)
            }
        },
        None => Ok(term == &value),
    }
}

fn bind_entity_term(
    term: &EdnValue,
    entity: &KotobaCid,
    db: &Db,
    binding: &BTreeMap<String, EdnValue>,
    next: &mut BTreeMap<String, EdnValue>,
) -> Result<bool> {
    if let Some(resolved) = lookup_ref_entity_term(term, db, binding)? {
        return Ok(&resolved == entity);
    }
    bind_term(term, cid_value(entity), next)
}

fn resolve_query_value(term: &EdnValue, binding: &BTreeMap<String, EdnValue>) -> Result<EdnValue> {
    match variable_name(term) {
        Some(var) => binding
            .get(var)
            .cloned()
            .ok_or_else(|| DatomicError::Query(format!("unbound variable {var}"))),
        None => Ok(term.clone()),
    }
}

fn variable_name(value: &EdnValue) -> Option<&str> {
    value
        .as_symbol()
        .and_then(|s| s.name.strip_prefix('?').map(|_| s.name.as_str()))
}

fn cid_value(cid: &KotobaCid) -> EdnValue {
    EdnValue::String(cid.to_multibase())
}

fn attr_value(a: &str) -> EdnValue {
    if a.starts_with(':') || (a.contains('/') && !a.contains("://")) {
        EdnValue::Keyword(attr_to_keyword(a))
    } else {
        EdnValue::String(a.to_string())
    }
}

fn attr_matches(stored: &str, query: &str) -> bool {
    stored == query
        || stored.strip_prefix(':') == Some(query)
        || query.strip_prefix(':') == Some(stored)
}

fn kw(name: &str) -> EdnValue {
    match name.split_once('/') {
        Some((ns, n)) => EdnValue::Keyword(Keyword::namespaced(ns, n)),
        None => EdnValue::Keyword(Keyword::bare(name)),
    }
}

fn kw_value(name: &str) -> EdnValue {
    kw(name.trim_start_matches(':'))
}

fn edn_to_kqe_value(value: &EdnValue) -> Result<kotoba_kqe::Value> {
    match value {
        EdnValue::Nil => Ok(kotoba_kqe::Value::Text("nil".into())),
        EdnValue::Bool(b) => Ok(kotoba_kqe::Value::Bool(*b)),
        EdnValue::Integer(i) => Ok(kotoba_kqe::Value::Integer(*i)),
        EdnValue::Float(f) => Ok(kotoba_kqe::Value::Float(f.0)),
        EdnValue::String(s) => Ok(kotoba_kqe::Value::Text(s.clone())),
        EdnValue::Keyword(k) => Ok(kotoba_kqe::Value::Text(keyword_to_attr(k))),
        EdnValue::Vector(values)
            if values
                .iter()
                .all(|value| matches!(value, EdnValue::Integer(_) | EdnValue::Float(_))) =>
        {
            let mut vector = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    EdnValue::Integer(i) => vector.push(*i as f32),
                    EdnValue::Float(f) => vector.push(f.0 as f32),
                    _ => unreachable!("guarded by all() above"),
                }
            }
            Ok(kotoba_kqe::Value::VectorF32(vector))
        }
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "cid" => {
            let Some(cid) = value
                .as_string()
                .and_then(kotoba_core::cid::KotobaCid::from_multibase)
            else {
                return Err(DatomicError::UnsupportedValue(edn_to_string(value)));
            };
            Ok(kotoba_kqe::Value::Cid(cid))
        }
        EdnValue::Tagged { tag, .. } if matches!(tag.to_qualified().as_str(), "inst" | "uuid") => {
            Ok(kotoba_kqe::Value::Text(edn_to_string(value)))
        }
        EdnValue::Tagged { tag, value } if tag.to_qualified() == "bytes" => {
            let Some(hex_value) = value.as_string() else {
                return Err(DatomicError::UnsupportedValue(edn_to_string(value)));
            };
            let bytes = hex::decode(hex_value)
                .map_err(|_| DatomicError::UnsupportedValue(edn_to_string(value)))?;
            Ok(kotoba_kqe::Value::Bytes(bytes))
        }
        other => Err(DatomicError::UnsupportedValue(edn_to_string(other))),
    }
}

fn kqe_value_to_edn(value: kotoba_kqe::Value) -> EdnValue {
    match value {
        kotoba_kqe::Value::Cid(cid) => EdnValue::Tagged {
            tag: Symbol::bare("cid"),
            value: Box::new(EdnValue::String(cid.to_multibase())),
        },
        kotoba_kqe::Value::Integer(i) => EdnValue::Integer(i),
        kotoba_kqe::Value::Float(f) => EdnValue::float(f),
        kotoba_kqe::Value::Text(s) => EdnValue::String(s),
        kotoba_kqe::Value::Bool(b) => EdnValue::Bool(b),
        kotoba_kqe::Value::Bytes(bytes) => EdnValue::Tagged {
            tag: Symbol::bare("bytes"),
            value: Box::new(EdnValue::String(hex::encode(bytes))),
        },
        kotoba_kqe::Value::VectorF32(v) => {
            EdnValue::Vector(v.into_iter().map(|f| EdnValue::float(f as f64)).collect())
        }
        kotoba_kqe::Value::TensorCid { cid, shape, dtype } => EdnValue::Map(BTreeMap::from([
            (
                kw_value(":tensor/cid"),
                EdnValue::Tagged {
                    tag: Symbol::bare("cid"),
                    value: Box::new(EdnValue::String(cid.to_multibase())),
                },
            ),
            (
                kw_value(":tensor/shape"),
                EdnValue::Vector(
                    shape
                        .into_iter()
                        .map(|n| EdnValue::Integer(n as i64))
                        .collect(),
                ),
            ),
            (
                kw_value(":tensor/dtype"),
                EdnValue::String(format!("{dtype:?}")),
            ),
        ])),
        kotoba_kqe::Value::Encrypted { ct_cid, policy_cid } => EdnValue::Map(BTreeMap::from([
            (
                kw_value(":encrypted/ct-cid"),
                EdnValue::Tagged {
                    tag: Symbol::bare("cid"),
                    value: Box::new(EdnValue::String(ct_cid.to_multibase())),
                },
            ),
            (
                kw_value(":encrypted/policy-cid"),
                EdnValue::Tagged {
                    tag: Symbol::bare("cid"),
                    value: Box::new(EdnValue::String(policy_cid.to_multibase())),
                },
            ),
        ])),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_edn::parse;

    fn cid(seed: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(seed)
    }

    #[test]
    fn datom_is_exact_five_tuple_atomic_fact() {
        let e = cid(b"entity");
        let a = ":person/name".to_string();
        let v = EdnValue::String("Alice".into());
        let t = cid(b"tx");

        let datom = Datom::assert(e.clone(), a.clone(), v.clone(), t.clone());
        assert_eq!(datom.as_tuple(), (&e, &a, &v, &t, true));
    }

    #[test]
    fn edn_numeric_vector_converts_to_kqe_vector_f32() {
        let value = parse("[1 2.5 -3]").unwrap();
        assert_eq!(
            edn_to_kqe_value(&value).unwrap(),
            kotoba_kqe::Value::VectorF32(vec![1.0, 2.5, -3.0])
        );
    }

    #[tokio::test]
    async fn transact_accepts_datomic_add_and_retract_forms() {
        let conn = Connection::new();
        let tx = parse(r#"[[:db/add "alice" :person/name "Alice"]]"#).unwrap();
        let report = conn.transact(tx).await.unwrap();
        assert_eq!(report.tx_data[0].a, ":person/name");
        assert!(report.tx_data[0].added);

        let retract = parse(r#"[[:db/retract "alice" :person/name "Alice"]]"#).unwrap();
        let report = conn.transact(retract).await.unwrap();
        assert!(report.tx_data.iter().any(|d| !d.added));
        assert!(conn
            .db()
            .datoms()
            .iter()
            .all(|d| d.a != ":person/name" || d.v != EdnValue::String("Alice".into())));
    }

    #[tokio::test]
    async fn log_iterates_transaction_entries_with_tombstones() {
        let conn = Connection::new();
        let first = conn
            .transact(parse(r#"[[:db/add "alice" :person/name "Alice"]]"#).unwrap())
            .await
            .unwrap();
        let second = conn
            .transact(parse(r#"[[:db/retract "alice" :person/name "Alice"]]"#).unwrap())
            .await
            .unwrap();

        let entries: Vec<LogEntry> = conn.log().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].tx, first.tx_cid);
        assert_eq!(entries[1].tx, second.tx_cid);
        assert!(entries[0].datoms.iter().all(|d| d.t == first.tx_cid));
        assert!(entries[1].datoms.iter().all(|d| d.t == second.tx_cid));
        assert!(entries[1]
            .datoms
            .iter()
            .any(|d| d.a == ":person/name" && !d.added));
        assert_eq!(conn.log().entries(), entries.as_slice());
    }

    #[tokio::test]
    async fn transact_accepts_entity_map_form_and_pull() {
        let conn = Connection::new();
        let tx = parse(r#"[{:db/id "alice" :person/name "Alice" :person/age 30}]"#).unwrap();
        let report = conn.transact(tx).await.unwrap();
        let alice = report.tempids["alice"].clone();
        let pulled = conn.db().pull(EdnValue::Vector(vec![]), alice).unwrap();
        let map = pulled.as_map().unwrap();
        assert_eq!(
            map.get(&EdnValue::Keyword(Keyword::namespaced("person", "name"))),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            map.get(&EdnValue::Keyword(Keyword::namespaced("person", "age"))),
            Some(&EdnValue::Integer(30))
        );
    }

    #[tokio::test]
    async fn entity_map_ref_attributes_accept_nested_entity_maps() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "address-attr"
                   :db/ident :person/address
                   :db/valueType :db.type/ref
                   :db/isComponent true}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice"
                       :person/name "Alice"
                       :person/address {:address/city "Tokyo"
                                        :address/postal-code "100-0001"}}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let pulled = conn
            .db()
            .pull(
                parse(r#"[:person/name {:person/address [:address/city :address/postal-code]}]"#)
                    .unwrap(),
                alice.clone(),
            )
            .unwrap();
        let address = pulled
            .as_map()
            .and_then(|m| m.get(&kw_value(":person/address")))
            .and_then(EdnValue::as_map)
            .unwrap();
        assert_eq!(
            address.get(&kw_value(":address/city")),
            Some(&EdnValue::String("Tokyo".into()))
        );
        assert_eq!(
            address.get(&kw_value(":address/postal-code")),
            Some(&EdnValue::String("100-0001".into()))
        );
        assert!(conn.db().datoms().iter().any(|d| {
            d.e == alice
                && d.a == ":person/address"
                && matches!(d.v, EdnValue::String(ref value)
                    if KotobaCid::from_multibase(value).is_some())
        }));

        conn.transact(parse(r#"[[:db.fn/retractEntity "alice"]]"#).unwrap())
            .await
            .unwrap();
        assert!(conn
            .db()
            .datoms()
            .iter()
            .all(|d| !d.a.starts_with(":person/") && !d.a.starts_with(":address/")));
    }

    #[tokio::test]
    async fn pull_supports_datomic_wildcard_pattern() {
        let conn = Connection::new();
        let report = conn
            .transact(parse(r#"[{:db/id "alice" :person/name "Alice" :person/age 30}]"#).unwrap())
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let pulled = conn.db().pull(parse(r#"[*]"#).unwrap(), alice).unwrap();
        let map = pulled.as_map().unwrap();
        assert_eq!(
            map.get(&kw_value(":person/name")),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            map.get(&kw_value(":person/age")),
            Some(&EdnValue::Integer(30))
        );
    }

    #[tokio::test]
    async fn pull_supports_attr_as_and_default_options() {
        let conn = Connection::new();
        let report = conn
            .transact(parse(r#"[{:db/id "alice" :person/name "Alice" :person/age 30}]"#).unwrap())
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let pulled = conn
            .db()
            .pull(
                parse(r#"[[:person/name :as :name] [:person/email :default "unknown"]]"#).unwrap(),
                alice,
            )
            .unwrap();
        let map = pulled.as_map().unwrap();
        assert_eq!(
            map.get(&kw_value(":name")),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            map.get(&kw_value(":person/email")),
            Some(&EdnValue::String("unknown".into()))
        );
        assert!(!map.contains_key(&kw_value(":person/name")));
    }

    #[tokio::test]
    async fn pull_supports_attr_limit_option() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "tag" :db/ident :person/tag :db/cardinality :db.cardinality/many}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/tag ["founder" "engineer" "mentor"]}
                      {:db/id "bob" :person/name "Bob"}
                      {:db/id "eve" :person/name "Eve" :person/friend "bob"}
                      {:db/id "mallory" :person/name "Mallory" :person/friend "bob"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let bob = report.tempids["bob"].clone();

        let pulled = conn
            .db()
            .pull(parse(r#"[[:person/tag :limit 2]]"#).unwrap(), alice)
            .unwrap();
        let tags = pulled
            .as_map()
            .and_then(|map| map.get(&kw_value(":person/tag")))
            .and_then(EdnValue::as_vector)
            .unwrap();
        assert_eq!(tags.len(), 2);

        let reverse = conn
            .db()
            .pull(parse(r#"[[:person/_friend :limit 1]]"#).unwrap(), bob)
            .unwrap();
        let friends = reverse
            .as_map()
            .and_then(|map| map.get(&kw_value(":person/_friend")))
            .and_then(EdnValue::as_vector)
            .unwrap();
        assert_eq!(friends.len(), 1);
    }

    #[tokio::test]
    async fn pull_supports_attr_xform_option() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[{:db/id "alice"
                         :person/role :role/admin
                         :person/status :status/active
                         :person/name "Alice"}]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let pulled = conn
            .db()
            .pull(
                parse(
                    r#"[[:person/role :xform name :as :roleName]
                        [:person/status :xform namespace :as :statusNamespace]
                        [:person/name :xform str :as :nameString]
                        [:person/missing :default :fallback/value :xform name :as :missingName]]"#,
                )
                .unwrap(),
                alice,
            )
            .unwrap();
        let map = pulled.as_map().unwrap();
        assert_eq!(
            map.get(&kw_value(":roleName")),
            Some(&EdnValue::String("admin".into()))
        );
        assert_eq!(
            map.get(&kw_value(":statusNamespace")),
            Some(&EdnValue::String("status".into()))
        );
        assert_eq!(
            map.get(&kw_value(":nameString")),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            map.get(&kw_value(":missingName")),
            Some(&EdnValue::String("value".into()))
        );
    }

    #[tokio::test]
    async fn pull_supports_nested_ref_pattern() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/friend "bob"}
                      {:db/id "bob" :person/name "Bob" :person/role :guest}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let pulled = conn
            .db()
            .pull(
                parse(r#"[:person/name {:person/friend [:person/name :person/role]}]"#).unwrap(),
                alice,
            )
            .unwrap();
        let map = pulled.as_map().unwrap();
        assert_eq!(
            map.get(&kw_value(":person/name")),
            Some(&EdnValue::String("Alice".into()))
        );
        let friend = map
            .get(&kw_value(":person/friend"))
            .and_then(EdnValue::as_map)
            .unwrap();
        assert_eq!(
            friend.get(&kw_value(":person/name")),
            Some(&EdnValue::String("Bob".into()))
        );
        assert_eq!(
            friend.get(&kw_value(":person/role")),
            Some(&kw_value(":guest"))
        );
    }

    #[tokio::test]
    async fn pull_supports_reverse_ref_pattern() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/friend "bob"}
                      {:db/id "carol" :person/name "Carol" :person/friend "bob"}
                      {:db/id "bob" :person/name "Bob" :person/role :guest}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let bob = report.tempids["bob"].clone();
        let pulled = conn
            .db()
            .pull(
                parse(r#"[:person/name {:person/_friend [:person/name]}]"#).unwrap(),
                bob,
            )
            .unwrap();
        let map = pulled.as_map().unwrap();
        assert_eq!(
            map.get(&kw_value(":person/name")),
            Some(&EdnValue::String("Bob".into()))
        );
        let referrers = map
            .get(&kw_value(":person/_friend"))
            .and_then(EdnValue::as_vector)
            .unwrap();
        assert_eq!(referrers.len(), 2);
        let names = referrers
            .iter()
            .map(|value| {
                value
                    .as_map()
                    .and_then(|map| map.get(&kw_value(":person/name")))
                    .cloned()
                    .unwrap()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([
                EdnValue::String("Alice".into()),
                EdnValue::String("Carol".into())
            ])
        );
    }

    #[tokio::test]
    async fn history_as_of_and_since_keep_retract_tombstones() {
        let conn = Connection::new();
        let first = conn
            .transact(parse(r#"[[:db/add "alice" :person/name "Alice"]]"#).unwrap())
            .await
            .unwrap();
        let second = conn
            .transact(parse(r#"[[:db/retract "alice" :person/name "Alice"]]"#).unwrap())
            .await
            .unwrap();

        assert!(conn.db().datoms().iter().all(|d| d.a != ":person/name"));
        assert!(conn.db().history().datoms().iter().any(|d| !d.added));
        assert!(conn
            .db()
            .as_of(&first.tx_cid)
            .datoms()
            .iter()
            .any(|d| d.a == ":person/name"));
        assert!(conn
            .db()
            .since(&first.tx_cid)
            .history()
            .datoms()
            .iter()
            .any(|d| d.t == second.tx_cid && !d.added));

        let history_rows = q_history(
            parse(
                r#"{:find [?name ?added]
                   :in [$history]
                   :where [[$history ?e :person/name ?name ?tx ?added]]}"#,
            )
            .unwrap(),
            &conn.db().history(),
            &[],
        )
        .unwrap();
        assert_eq!(
            history_rows,
            vec![
                vec![EdnValue::String("Alice".into()), EdnValue::Bool(false)],
                vec![EdnValue::String("Alice".into()), EdnValue::Bool(true)]
            ]
        );
    }

    #[tokio::test]
    async fn db_exposes_datomic_five_index_datoms_scans() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "friend" :db/ident :person/friend :db/valueType :db.type/ref}
                  {:db/id "tag" :db/ident :person/tag :db/cardinality :db.cardinality/many}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/friend "bob" :person/tag ["founder" "engineer"]}
                      {:db/id "bob" :person/name "Bob"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();
        let bob = report.tempids["bob"].clone();
        let db = conn.db();

        let eavt = db
            .datoms_index(DatomIndex::Eavt, &[cid_value(&alice)])
            .unwrap();
        assert!(eavt.iter().all(|datom| datom.e == alice));
        assert!(eavt.iter().any(|datom| datom.a == ":person/name"));

        let aevt = db
            .datoms_index(DatomIndex::Aevt, &[kw_value(":person/name")])
            .unwrap();
        assert_eq!(
            aevt.iter()
                .map(|datom| datom.v.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                EdnValue::String("Alice".into()),
                EdnValue::String("Bob".into())
            ])
        );

        let avet = db
            .datoms_index(
                DatomIndex::Avet,
                &[
                    kw_value(":person/name"),
                    EdnValue::String("Alice".into()),
                    cid_value(&alice),
                ],
            )
            .unwrap();
        assert_eq!(avet.len(), 1);
        assert_eq!(avet[0].e, alice);

        let vaet = db
            .datoms_index(
                DatomIndex::Vaet,
                &[cid_value(&bob), kw_value(":person/friend")],
            )
            .unwrap();
        assert_eq!(vaet.len(), 1);
        assert_eq!(vaet[0].e, alice);
        assert_eq!(vaet[0].v, cid_value(&bob));

        let tea = db
            .history()
            .datoms_index(DatomIndex::Tea, &[cid_value(&report.tx_cid)])
            .unwrap();
        assert!(tea.iter().all(|datom| datom.t == report.tx_cid));
        assert!(tea.len() >= report.tx_data.len());

        let seek = db
            .seek_datoms(DatomIndex::Avet, &[kw_value(":person/name")])
            .unwrap();
        assert!(seek
            .iter()
            .any(|datom| datom.v == EdnValue::String("Alice".into())));
        assert!(seek
            .iter()
            .any(|datom| datom.v == EdnValue::String("Bob".into())));

        let range = db
            .index_range(
                ":person/name",
                Some(&EdnValue::String("Alice".into())),
                Some(&EdnValue::String("Bob".into())),
            )
            .unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].v, EdnValue::String("Alice".into()));

        assert!(matches!(
            db.datoms_index(
                DatomIndex::Eavt,
                &[
                    cid_value(&alice),
                    kw_value(":person/name"),
                    EdnValue::String("Alice".into()),
                    cid_value(&report.tx_cid),
                    EdnValue::Bool(true)
                ],
            ),
            Err(DatomicError::Query(message)) if message.contains("at most 4 components")
        ));
    }

    #[tokio::test]
    async fn lookup_refs_and_cardinality_one_work() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "email" :db/ident :person/email :db/unique :db.unique/identity}
                  {:db/id "name" :db/ident :person/name :db/cardinality :db.cardinality/one}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(
            parse(r#"[{:db/id "alice" :person/email "a@example.com" :person/name "Alice"}]"#)
                .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(
            parse(r#"[[:db/add [:person/email "a@example.com"] :person/name "Alicia"]]"#).unwrap(),
        )
        .await
        .unwrap();

        let facts = conn.db().datoms();
        assert!(facts
            .iter()
            .any(|d| d.a == ":person/name" && d.v == EdnValue::String("Alicia".into())));
        assert!(!facts
            .iter()
            .any(|d| d.a == ":person/name" && d.v == EdnValue::String("Alice".into())));
    }

    #[tokio::test]
    async fn schema_install_attribute_without_db_id_is_recognized() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/ident :person/email
                   :db/valueType :db.type/string
                   :db/cardinality :db.cardinality/one
                   :db/unique :db.unique/identity
                   :db.install/_attribute :db.part/db}
                  {:db/ident :person/name
                   :db/valueType :db.type/string
                   :db/cardinality :db.cardinality/one
                   :db.install/_attribute :db.part/db}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let first = conn
            .transact(
                parse(r#"[{:db/id "alice" :person/email "a@example.com" :person/name "Alice"}]"#)
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = conn
            .transact(
                parse(
                    r#"[{:db/id "alice-2" :person/email "a@example.com" :person/name "Alicia"}]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let alice = first.tempids["alice"].clone();
        assert_eq!(second.tempids["alice-2"], alice);
        let rows = q(
            parse(
                r#"{:find [?name]
                   :where [[[:person/email "a@example.com"] :person/name ?name]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alicia".into())]]);
    }

    #[tokio::test]
    async fn schema_index_and_doc_are_persisted_as_metadata() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/ident :person/email
                   :db/valueType :db.type/string
                   :db/index true
                   :db/doc "Email address used for lookup and display."}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(parse(r#"[{:db/id "alice" :person/email "a@example.com"}]"#).unwrap())
            .await
            .unwrap();

        let schema = Schema::from_datoms(&conn.db().all_datoms());
        assert!(schema.indexed.contains(":person/email"));
        assert_eq!(
            schema.docs.get(":person/email").map(String::as_str),
            Some("Email address used for lookup and display.")
        );
        assert!(conn.db().history().datoms().iter().any(|d| {
            d.a == DB_DOC
                && d.v == EdnValue::String("Email address used for lookup and display.".into())
        }));

        let rows = q(
            parse(r#"{:find [?e] :where [[?e :person/email "a@example.com"]]}"#).unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn q_supports_string_iri_attribute_terms() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  [:db/add "tx" "https://w3id.org/security#allowedAction" "vc:issue"]
                  [:db/add "tx" "https://w3id.org/security#invocationTarget" "kotoba://graph/example"]
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let rows = q(
            parse(
                r#"{:find [?action ?target]
                   :where [[?tx "https://w3id.org/security#allowedAction" ?action]
                           [?tx "https://w3id.org/security#invocationTarget" ?target]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();

        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("vc:issue".into()),
                EdnValue::String("kotoba://graph/example".into())
            ]]
        );
    }

    #[test]
    fn q_matches_legacy_namespaced_attrs_without_leading_colon() {
        let e = KotobaCid::from_bytes(b"message");
        let tx = KotobaCid::from_bytes(b"tx");
        let db = Db::from_datoms(
            vec![Datom::assert(
                e,
                "didcomm/thread".to_string(),
                EdnValue::String("thread-1".into()),
                tx,
            )],
            None,
        );

        let rows = q(
            parse(r#"{:find [?thread] :where [[?e :didcomm/thread ?thread]]}"#).unwrap(),
            &db,
            &[],
        )
        .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("thread-1".into())]]);
    }

    #[tokio::test]
    async fn datomic_tx_tempid_resolves_to_transaction_entity() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                      [:db/add "datomic.tx" :tx/source "xrpc"]
                      {:db/id "datomic.tx" :tx/capability "cacao-proof"}
                      {:db/id "alice" :person/name "Alice"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(report.tempids[DATOMIC_TX_TEMPID], report.tx_cid);
        assert!(report.tx_data.iter().any(|d| {
            d.e == report.tx_cid && d.a == ":tx/source" && d.v == EdnValue::String("xrpc".into())
        }));
        assert!(report.tx_data.iter().any(|d| {
            d.e == report.tx_cid
                && d.a == ":tx/capability"
                && d.v == EdnValue::String("cacao-proof".into())
        }));
        assert!(report
            .tx_data
            .iter()
            .any(|d| d.e == report.tx_cid && d.a == DB_TX_INSTANT));
    }

    #[tokio::test]
    async fn db_part_tx_tempid_resolves_to_transaction_entity() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                      [:db/add #db/id [:db.part/tx] :tx/source "ingest-42"]
                      {:db/id #db/id [:db.part/tx] :tx/operator "alice"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        assert!(report.tx_data.iter().any(|d| {
            d.e == report.tx_cid
                && d.a == ":tx/source"
                && d.v == EdnValue::String("ingest-42".into())
        }));
        assert!(report.tx_data.iter().any(|d| {
            d.e == report.tx_cid && d.a == ":tx/operator" && d.v == EdnValue::String("alice".into())
        }));
        let tx_instant = report
            .tx_data
            .iter()
            .find(|d| d.e == report.tx_cid && d.a == DB_TX_INSTANT)
            .and_then(|d| match &d.v {
                EdnValue::Tagged { tag, value } if tag.to_qualified() == "inst" => {
                    value.as_string()
                }
                _ => None,
            })
            .unwrap();
        assert!(tx_instant.contains('T'));
        assert!(tx_instant.ends_with('Z'));
    }

    #[test]
    fn unix_seconds_format_as_datomic_inst_utc() {
        assert_eq!(unix_seconds_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            unix_seconds_to_rfc3339(1_798_502_400),
            "2026-12-29T00:00:00Z"
        );
    }

    #[test]
    fn tx_cid_is_derived_from_sorted_datom_content_and_prev_tx() {
        let placeholder = tx_placeholder_cid();
        let alice = cid(b"alice");
        let d1 = Datom::assert(
            placeholder.clone(),
            ":tx/source".into(),
            EdnValue::String("ingest-42".into()),
            placeholder.clone(),
        );
        let d2 = Datom::assert(
            alice,
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            placeholder.clone(),
        );
        let instant = "2026-05-29T00:00:00Z";
        let prev = cid(b"prev-tx");

        let forward = tx_cid_for_datoms(
            &[d1.clone(), d2.clone()],
            &placeholder,
            instant,
            Some(&prev),
        );
        let reversed = tx_cid_for_datoms(&[d2, d1], &placeholder, instant, Some(&prev));
        let different_prev = tx_cid_for_datoms(
            &[Datom::assert(
                placeholder.clone(),
                ":tx/source".into(),
                EdnValue::String("ingest-42".into()),
                placeholder.clone(),
            )],
            &placeholder,
            instant,
            Some(&cid(b"other-prev")),
        );

        assert_eq!(forward, reversed);
        assert_ne!(forward, different_prev);
    }

    #[tokio::test]
    async fn transact_rewrites_tx_placeholder_to_final_content_addressed_tx() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                      [:db/add #db/id [:db.part/tx] :tx/source "ingest-42"]
                      {:db/id "alice" :person/name "Alice"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let placeholder = tx_placeholder_cid();

        assert_ne!(report.tx_cid, placeholder);
        assert!(report
            .tx_data
            .iter()
            .all(|d| d.e != placeholder && d.t != placeholder));
        assert!(report.tx_data.iter().any(|d| {
            d.e == report.tx_cid
                && d.t == report.tx_cid
                && d.a == ":tx/source"
                && d.v == EdnValue::String("ingest-42".into())
        }));
        assert!(report.tempids.values().all(|cid| cid != &placeholder));
    }

    #[tokio::test]
    async fn cardinality_many_keeps_multiple_values() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "tag" :db/ident :person/tag :db/cardinality :db.cardinality/many}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(
            parse(
                r#"[
                  [:db/add "alice" :person/tag "founder"]
                  [:db/add "alice" :person/tag "engineer"]
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let tags = conn
            .db()
            .datoms()
            .into_iter()
            .filter(|d| d.a == ":person/tag")
            .map(|d| d.v)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            tags,
            BTreeSet::from([
                EdnValue::String("engineer".into()),
                EdnValue::String("founder".into())
            ])
        );
    }

    #[tokio::test]
    async fn entity_map_cardinality_many_collections_expand_to_multiple_datoms() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "tag" :db/ident :person/tag :db/cardinality :db.cardinality/many}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/tag ["founder" "engineer"]}
                      {:db/id "bob" :person/tag #{"builder" "mentor"}}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let tag_tx_values = report
            .tx_data
            .iter()
            .filter(|d| d.a == ":person/tag")
            .map(|d| d.v.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            tag_tx_values,
            BTreeSet::from([
                EdnValue::String("builder".into()),
                EdnValue::String("engineer".into()),
                EdnValue::String("founder".into()),
                EdnValue::String("mentor".into()),
            ])
        );
        assert!(conn.db().datoms().iter().all(|d| {
            d.a != ":person/tag" || !matches!(d.v, EdnValue::Vector(_) | EdnValue::Set(_))
        }));
        let alice = report.tempids["alice"].clone();
        let pulled = conn
            .db()
            .pull(parse(r#"[:person/tag]"#).unwrap(), alice)
            .unwrap();
        let pulled_edn = edn_to_string(&pulled);
        assert!(pulled_edn.contains(":person/tag ["));
        assert!(pulled_edn.contains("\"engineer\""));
        assert!(pulled_edn.contains("\"founder\""));
    }

    #[tokio::test]
    async fn value_type_schema_accepts_matching_values_and_rejects_mismatches() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "name" :db/ident :person/name :db/valueType :db.type/string}
                  {:db/id "age" :db/ident :person/age :db/valueType :db.type/long}
                  {:db/id "friend" :db/ident :person/friend :db/valueType :db.type/ref}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/age 30 :person/friend "bob"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let err = conn
            .transact(parse(r#"[[:db/add "alice" :person/age "old"]]"#).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, DatomicError::ConstraintViolation(message)
            if message.contains(":person/age expects :db.type/long")));
    }

    #[tokio::test]
    async fn value_type_symbol_accepts_edn_symbols_and_rejects_strings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "state" :db/ident :workflow/state :db/valueType :db.type/symbol}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        conn.transact(parse(r#"[[:db/add "job-1" :workflow/state running]]"#).unwrap())
            .await
            .unwrap();
        assert!(conn.db().datoms().iter().any(|d| {
            d.a == ":workflow/state" && d.v == EdnValue::Symbol(Symbol::bare("running"))
        }));

        let err = conn
            .transact(parse(r#"[[:db/add "job-2" :workflow/state "running"]]"#).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, DatomicError::ConstraintViolation(message)
            if message.contains(":workflow/state expects :db.type/symbol")));
    }

    #[tokio::test]
    async fn value_type_bytes_accepts_hex_tagged_bytes_and_rejects_plain_strings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "digest" :db/ident :blob/digest :db/valueType :db.type/bytes}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        conn.transact(parse(r#"[[:db/add "blob-1" :blob/digest #bytes "deadbeef"]]"#).unwrap())
            .await
            .unwrap();
        assert!(conn.db().datoms().iter().any(|d| {
            d.a == ":blob/digest"
                && matches!(&d.v, EdnValue::Tagged { tag, value }
                    if tag.to_qualified() == "bytes"
                        && value.as_string() == Some("deadbeef"))
        }));

        let string_err = conn
            .transact(parse(r#"[[:db/add "blob-2" :blob/digest "deadbeef"]]"#).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(string_err, DatomicError::ConstraintViolation(message)
            if message.contains(":blob/digest expects :db.type/bytes"))
        );

        let invalid_hex_err = conn
            .transact(parse(r#"[[:db/add "blob-3" :blob/digest #bytes "not-hex"]]"#).unwrap())
            .await
            .unwrap_err();
        assert!(
            matches!(invalid_hex_err, DatomicError::ConstraintViolation(message)
            if message.contains(":blob/digest expects :db.type/bytes"))
        );
    }

    #[tokio::test]
    async fn value_type_tuple_accepts_vectors_and_lists_and_rejects_scalars() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "coord" :db/ident :place/coord :db/valueType :db.type/tuple}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        conn.transact(parse(r#"[[:db/add "tokyo" :place/coord [35 139]]]"#).unwrap())
            .await
            .unwrap();
        conn.transact(parse(r#"[[:db/add "osaka" :place/coord (34 135)]]"#).unwrap())
            .await
            .unwrap();

        assert!(conn.db().datoms().iter().any(|d| {
            d.a == ":place/coord"
                && d.v == EdnValue::Vector(vec![EdnValue::Integer(35), EdnValue::Integer(139)])
        }));
        assert!(conn.db().datoms().iter().any(|d| {
            d.a == ":place/coord"
                && d.v == EdnValue::List(vec![EdnValue::Integer(34), EdnValue::Integer(135)])
        }));

        let err = conn
            .transact(parse(r#"[[:db/add "nagoya" :place/coord "35,136"]]"#).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, DatomicError::ConstraintViolation(message)
            if message.contains(":place/coord expects :db.type/tuple")));
    }

    #[tokio::test]
    async fn ref_value_type_normalizes_values_to_entity_cids() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "friend" :db/ident :person/friend :db/valueType :db.type/ref}
                  {:db/id "name" :db/ident :person/name :db/valueType :db.type/string}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/friend "bob"}
                      {:db/id "bob" :person/name "Bob"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let bob = report.tempids["bob"].clone();
        let friend = conn
            .db()
            .datoms()
            .into_iter()
            .find(|d| d.a == ":person/friend")
            .unwrap();
        assert_eq!(friend.v, EdnValue::String(bob.to_multibase()));

        conn.transact(parse(r#"[[:db.fn/cas "alice" :person/friend "bob" "carol"]]"#).unwrap())
            .await
            .unwrap();
        let carol = KotobaCid::from_bytes(b"carol");
        assert!(conn
            .db()
            .datoms()
            .iter()
            .any(|d| { d.a == ":person/friend" && d.v == EdnValue::String(carol.to_multibase()) }));
    }

    #[tokio::test]
    async fn no_history_omits_prior_values_from_history_projection() {
        let conn = Connection::new();
        let schema_report = conn
            .transact(
                parse(
                    r#"[
                  {:db/id "ssn" :db/ident :person/ssn :db/noHistory true}
                ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let first = conn
            .transact(parse(r#"[[:db/add "alice" :person/ssn "111"]]"#).unwrap())
            .await
            .unwrap();
        let second = conn
            .transact(parse(r#"[[:db/add "alice" :person/ssn "222"]]"#).unwrap())
            .await
            .unwrap();

        let distributed_like_db = Db::from_datoms(
            schema_report
                .tx_data
                .into_iter()
                .chain([first.tx_data[0].clone()])
                .chain([
                    second
                        .tx_data
                        .iter()
                        .find(|datom| !datom.added && datom.a == ":person/ssn")
                        .cloned()
                        .unwrap(),
                    second
                        .tx_data
                        .iter()
                        .find(|datom| datom.added && datom.a == ":person/ssn")
                        .cloned()
                        .unwrap(),
                ])
                .collect(),
            Some(second.tx_cid),
        );
        let history = distributed_like_db.history().datoms().to_vec();
        assert!(!history
            .iter()
            .any(|d| d.a == ":person/ssn" && d.v == EdnValue::String("111".into())));
        assert!(!history.iter().any(|d| d.a == ":person/ssn" && !d.added));
        assert!(history
            .iter()
            .any(|d| d.a == ":person/ssn" && d.v == EdnValue::String("222".into())));
    }

    #[tokio::test]
    async fn unique_identity_upserts_tempids_to_existing_entity() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "email" :db/ident :person/email :db/unique :db.unique/identity}
                  {:db/id "name" :db/ident :person/name :db/cardinality :db.cardinality/one}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let first = conn
            .transact(
                parse(r#"[{:db/id "alice" :person/email "a@example.com" :person/name "Alice"}]"#)
                    .unwrap(),
            )
            .await
            .unwrap();
        let second = conn
            .transact(
                parse(
                    r#"[{:db/id "alice-2" :person/email "a@example.com" :person/name "Alicia"}]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        let alice = first.tempids["alice"].clone();
        assert_eq!(second.tempids["alice-2"], alice);
        let facts = conn.db().datoms();
        assert!(facts.iter().any(|d| d.e == alice
            && d.a == ":person/name"
            && d.v == EdnValue::String("Alicia".into())));
        assert!(!facts
            .iter()
            .any(|d| d.a == ":person/name" && d.v == EdnValue::String("Alice".into())));
    }

    #[tokio::test]
    async fn unique_identity_upserts_tempids_within_same_transaction() {
        let conn = Connection::new();
        conn.transact(
            parse(r#"[{:db/id "email" :db/ident :person/email :db/unique :db.unique/identity}]"#)
                .unwrap(),
        )
        .await
        .unwrap();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/email "a@example.com" :person/name "Alice"}
                      {:db/id "same-alice" :person/email "a@example.com" :person/role :admin}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(report.tempids["same-alice"], report.tempids["alice"]);
        let alice = report.tempids["alice"].clone();
        let facts = conn.db().datoms();
        assert!(facts.iter().any(|d| d.e == alice
            && d.a == ":person/name"
            && d.v == EdnValue::String("Alice".into())));
        assert!(facts
            .iter()
            .any(|d| d.e == alice && d.a == ":person/role" && d.v == kw_value(":admin")));
    }

    #[tokio::test]
    async fn unique_value_rejects_duplicates_without_upserting_tempids() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "ssn" :db/ident :person/ssn :db/unique :db.unique/value}
                  {:db/id "name" :db/ident :person/name :db/cardinality :db.cardinality/one}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let first = conn
            .transact(
                parse(r#"[{:db/id "alice" :person/ssn "111" :person/name "Alice"}]"#).unwrap(),
            )
            .await
            .unwrap();

        let err = conn
            .transact(
                parse(r#"[{:db/id "alice-2" :person/ssn "111" :person/name "Alicia"}]"#).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DatomicError::ConstraintViolation(message)
            if message.contains("unique attr :person/ssn already has value \"111\"")));

        let alice = first.tempids["alice"].clone();
        let facts = conn.db().datoms();
        assert!(facts.iter().any(|d| d.e == alice
            && d.a == ":person/name"
            && d.v == EdnValue::String("Alice".into())));
        assert!(!facts
            .iter()
            .any(|d| d.a == ":person/name" && d.v == EdnValue::String("Alicia".into())));
    }

    #[tokio::test]
    async fn q_supports_lookup_ref_in_entity_position() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "email" :db/ident :person/email :db/unique :db.unique/identity}
                  {:db/id "alice" :person/email "a@example.com" :person/name "Alice"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let rows = q(
            parse(
                r#"{:find [?name]
                   :where [[[:person/email "a@example.com"] :person/name ?name]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);

        let rows = q(
            parse(
                r#"{:find [?name]
                   :in [$ ?email]
                   :where [[[:person/email ?email] :person/name ?name]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[EdnValue::String("a@example.com".into())],
        )
        .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[tokio::test]
    async fn lookup_ref_requires_unique_attribute() {
        let conn = Connection::new();
        conn.transact(
            parse(r#"[{:db/id "alice" :person/email "a@example.com" :person/name "Alice"}]"#)
                .unwrap(),
        )
        .await
        .unwrap();

        let err = q(
            parse(
                r#"{:find [?name]
                   :where [[[:person/email "a@example.com"] :person/name ?name]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap_err();

        assert!(matches!(err, DatomicError::ConstraintViolation(message)
            if message.contains("lookup ref attr :person/email is not unique")));
    }

    #[tokio::test]
    async fn cas_and_retract_entity_tx_functions_work() {
        let conn = Connection::new();
        conn.transact(parse(r#"[{:db/id "alice" :person/age 30 :person/name "Alice"}]"#).unwrap())
            .await
            .unwrap();
        conn.transact(parse(r#"[[:db.fn/cas "alice" :person/age 30 31]]"#).unwrap())
            .await
            .unwrap();
        assert!(conn
            .db()
            .datoms()
            .iter()
            .any(|d| d.a == ":person/age" && d.v == EdnValue::Integer(31)));

        conn.transact(parse(r#"[[:db.fn/retractEntity "alice"]]"#).unwrap())
            .await
            .unwrap();
        assert!(conn
            .db()
            .datoms()
            .iter()
            .all(|d| !d.a.starts_with(":person/")));
    }

    #[tokio::test]
    async fn retract_attribute_retracts_only_current_values() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/ident :person/age
                   :db/cardinality :db.cardinality/one}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(parse(r#"[[:db/add "alice" :person/age 30]]"#).unwrap())
            .await
            .unwrap();
        conn.transact(parse(r#"[[:db/add "alice" :person/age 31]]"#).unwrap())
            .await
            .unwrap();

        let report = conn
            .transact(parse(r#"[[:db.fn/retractAttribute "alice" :person/age]]"#).unwrap())
            .await
            .unwrap();

        assert!(conn.db().datoms().iter().all(|d| d.a != ":person/age"));
        let retracted_values: Vec<_> = report
            .tx_data
            .iter()
            .filter(|d| d.a == ":person/age" && !d.added)
            .map(|d| d.v.clone())
            .collect();
        assert_eq!(retracted_values, vec![EdnValue::Integer(31)]);
    }

    #[tokio::test]
    async fn registered_user_tx_fn_expands_to_same_transaction_datoms() {
        let conn = Connection::new();
        conn.register_tx_fn("my.fn/increment", |db, args| {
            if args.len() != 3 {
                return Err(DatomicError::InvalidOpForm);
            }
            let e = entity_ref_to_cid(&args[0], &mut BTreeMap::new(), db)?;
            let a = attr_to_string(&args[1])?;
            let EdnValue::Integer(amount) = args[2] else {
                return Err(DatomicError::InvalidOpForm);
            };
            let current = db
                .datoms()
                .into_iter()
                .find(|d| d.e == e && d.a == a)
                .and_then(|d| match d.v {
                    EdnValue::Integer(n) => Some(n),
                    _ => None,
                })
                .unwrap_or(0);

            Ok(EdnValue::Vector(vec![EdnValue::Vector(vec![
                kw_value(":db/add"),
                args[0].clone(),
                args[1].clone(),
                EdnValue::Integer(current + amount),
            ])]))
        })
        .unwrap();

        let first = conn
            .transact(parse(r#"[[:my.fn/increment "alice" :person/score 10]]"#).unwrap())
            .await
            .unwrap();
        assert!(first.tx_data.iter().any(|d| {
            d.a == ":person/score" && d.v == EdnValue::Integer(10) && d.t == first.tx_cid
        }));

        let second = conn
            .transact(parse(r#"[[:my.fn/increment "alice" :person/score 5]]"#).unwrap())
            .await
            .unwrap();
        let alice = second.tempids["alice"].clone();
        assert!(conn
            .db()
            .datoms()
            .iter()
            .any(|d| { d.e == alice && d.a == ":person/score" && d.v == EdnValue::Integer(15) }));
        assert!(second
            .tx_data
            .iter()
            .any(|d| { !d.added && d.a == ":person/score" && d.v == EdnValue::Integer(10) }));
    }

    #[tokio::test]
    async fn q_supports_basic_datomic_map_query() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/age 30 :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/age 12 :person/role :user}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :in [$ ?role]
                :where [[?e :person/role ?role]
                        [?e :person/name ?name]
                        [?e :person/age ?age]
                        [(> ?age 18)]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[kw_value(":admin")]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[test]
    fn triple_lookup_shape_tracks_bound_entity_attribute_and_value() {
        let alice = cid(b"alice");
        let mut binding = BTreeMap::new();
        binding.insert("?e".to_string(), cid_value(&alice));

        let triple = parse(r#"[?e :person/name ?name]"#).unwrap();
        assert_eq!(
            plan_datom_lookup_for_triple(&triple, &binding).unwrap(),
            distributed::DatomIndexLookup::EntityAttribute {
                entity: alice,
                attr: ":person/name".into()
            }
        );

        let triple = parse(r#"[?e :person/name "Alice"]"#).unwrap();
        assert_eq!(
            plan_datom_lookup_for_triple(&triple, &BTreeMap::new()).unwrap(),
            distributed::DatomIndexLookup::AttributeValue {
                attr: ":person/name".into(),
                value: EdnValue::String("Alice".into())
            }
        );

        let triple = parse(r#"[?e :person/name ?name]"#).unwrap();
        assert_eq!(
            plan_datom_lookup_for_triple(&triple, &BTreeMap::new()).unwrap(),
            distributed::DatomIndexLookup::Attribute(":person/name".into())
        );
    }

    #[tokio::test]
    async fn q_supports_pull_find_expression() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/friend "bob"}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [(pull ?e [:person/name {:person/friend [:person/name :person/role]}])]
                :where [[?e :person/name "Alice"]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows.len(), 1);
        let pulled = rows[0][0].as_map().unwrap();
        assert_eq!(
            pulled.get(&kw_value(":person/name")),
            Some(&EdnValue::String("Alice".into()))
        );
        let friend = pulled
            .get(&kw_value(":person/friend"))
            .and_then(EdnValue::as_map)
            .unwrap();
        assert_eq!(
            friend.get(&kw_value(":person/name")),
            Some(&EdnValue::String("Bob".into()))
        );
        assert_eq!(
            friend.get(&kw_value(":person/role")),
            Some(&kw_value(":guest"))
        );
    }

    #[tokio::test]
    async fn q_accepts_datomic_find_collection_and_tuple_specs() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let collection_query = parse(
            r#"{:find [?name ...]
                :where [[?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(collection_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Bob".into())]
            ]
        );

        let tuple_query = parse(
            r#"{:find [[?name ?role]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = q(tuple_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into()), kw_value(":admin")],
                vec![EdnValue::String("Bob".into()), kw_value(":guest")]
            ]
        );

        let scalar_query = parse(
            r#"{:find [?name .]
                :where [[?e :person/role :admin]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(scalar_query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[tokio::test]
    async fn q_supports_datomic_fulltext_relation_binding() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice"
                   :person/name "Alice"
                   :person/bio "Kotoba stores W3C credentials as Datoms."}
                  {:db/id "bob"
                   :person/name "Bob"
                   :person/bio "kotoba kotoba distributed query"}
                  {:db/id "carol"
                   :person/name "Carol"
                   :person/bio "unrelated text"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let query = parse(
            r#"{:find [?name ?score]
                :where [[(fulltext $ :person/bio "KOTOBA") [[?e ?bio ?tx ?score]]]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into()), EdnValue::Integer(1)],
                vec![EdnValue::String("Bob".into()), EdnValue::Integer(2)],
            ]
        );
    }

    #[tokio::test]
    async fn q_applies_datomic_limit_and_offset_after_projection() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice"}
                  {:db/id "bob" :person/name "Bob"}
                  {:db/id "carol" :person/name "Carol"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]]
                :offset 1
                :limit 1}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Bob".into())]]);
    }

    #[tokio::test]
    async fn q_applies_datomic_order_by_before_limit_and_offset() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/score 10}
                  {:db/id "bob" :person/name "Bob" :person/score 30}
                  {:db/id "carol" :person/name "Carol" :person/score 20}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let query = parse(
            r#"{:find [?name ?score]
                :where [[?e :person/name ?name]
                        [?e :person/score ?score]]
                :order-by [[?score :desc] [?name :asc]]
                :offset 1
                :limit 1}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Carol".into()),
                EdnValue::Integer(20)
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_keys_strs_and_syms_named_results() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/age 30}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        let keys_rows = q(
            parse(
                r#"{:find [?name ?age]
                   :keys [person/name age]
                   :where [[?e :person/name ?name]
                           [?e :person/age ?age]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();
        assert_eq!(
            keys_rows,
            vec![vec![EdnValue::map([
                (kw_value(":person/name"), EdnValue::String("Alice".into())),
                (kw_value(":age"), EdnValue::Integer(30)),
            ])]]
        );

        let strs_rows = q(
            parse(
                r#"{:find [?name ?age]
                   :strs [name age]
                   :where [[?e :person/name ?name]
                           [?e :person/age ?age]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();
        assert_eq!(
            strs_rows,
            vec![vec![EdnValue::map([
                (
                    EdnValue::String("name".into()),
                    EdnValue::String("Alice".into())
                ),
                (EdnValue::String("age".into()), EdnValue::Integer(30)),
            ])]]
        );

        let syms_rows = q(
            parse(
                r#"{:find [?name ?age]
                   :syms [name age]
                   :where [[?e :person/name ?name]
                           [?e :person/age ?age]]}"#,
            )
            .unwrap(),
            &conn.db(),
            &[],
        )
        .unwrap();
        assert_eq!(
            syms_rows,
            vec![vec![EdnValue::map([
                (EdnValue::sym("name"), EdnValue::String("Alice".into())),
                (EdnValue::sym("age"), EdnValue::Integer(30)),
            ])]]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_collection_binding_inputs() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :user}
                  {:db/id "eve" :person/name "Eve" :person/role :auditor}
                ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let query = parse(
            r#"{:find [?name]
                :in [$ [?role ...]]
                :where [[?e :person/role ?role]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(
            query.clone(),
            &conn.db(),
            &[EdnValue::Vector(vec![
                kw_value(":admin"),
                kw_value(":user"),
            ])],
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Bob".into())]
            ]
        );

        let rows = q(
            query,
            &conn.db(),
            &[
                EdnValue::Symbol(Symbol::bare("$")),
                EdnValue::Vector(vec![kw_value(":auditor")]),
            ],
        )
        .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);

        let named_source_query = parse(
            r#"{:find [?name]
                :in [$db [?role ...]]
                :where [[?e :person/role ?role]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(
            named_source_query.clone(),
            &conn.db(),
            &[EdnValue::Vector(vec![kw_value(":admin")])],
        )
        .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);

        let rows = q(
            named_source_query,
            &conn.db(),
            &[
                EdnValue::Symbol(Symbol::bare("$db")),
                EdnValue::Vector(vec![kw_value(":user")]),
            ],
        )
        .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Bob".into())]]);

        let source_pattern_query = parse(
            r#"{:find [?name]
                :in [$db]
                :where [[$db ?e :person/role :admin]
                        [$db ?e :person/name ?name]
                        [(missing? $db ?e :person/ban-reason)]]}"#,
        )
        .unwrap();
        let rows = q(source_pattern_query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);

        let vector_query = parse(
            r#"[:find ?name
                :in $db [?role ...]
                :where [$db ?e :person/role ?role]
                       [$db ?e :person/name ?name]]"#,
        )
        .unwrap();
        let rows = q(
            vector_query,
            &conn.db(),
            &[EdnValue::Vector(vec![
                kw_value(":admin"),
                kw_value(":auditor"),
            ])],
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Eve".into())]
            ]
        );

        let tx_pattern_query = parse(
            r#"{:find [?name ?tx]
                :where [[?e :person/role :admin ?tx]
                        [?e :person/name ?name ?tx]]}"#,
        )
        .unwrap();
        let rows = q(tx_pattern_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                cid_value(&report.tx_cid)
            ]]
        );

        let added_pattern_query = parse(
            r#"{:find [?name ?tx ?added]
                :where [[?e :person/role :admin ?tx ?added]
                        [?e :person/name ?name ?tx ?added]]}"#,
        )
        .unwrap();
        let rows = q(added_pattern_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                cid_value(&report.tx_cid),
                EdnValue::Bool(true)
            ]]
        );

        let source_tx_pattern_query = parse(
            r#"[:find ?name ?tx
                :in $db
                :where [$db ?e :person/role :auditor ?tx]
                       [$db ?e :person/name ?name ?tx]]"#,
        )
        .unwrap();
        let rows = q(source_tx_pattern_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Eve".into()),
                cid_value(&report.tx_cid)
            ]]
        );

        let source_added_pattern_query = parse(
            r#"[:find ?name ?tx ?added
                :in $db
                :where [$db ?e :person/role :auditor ?tx ?added]
                       [$db ?e :person/name ?name ?tx ?added]]"#,
        )
        .unwrap();
        let rows = q(source_added_pattern_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Eve".into()),
                cid_value(&report.tx_cid),
                EdnValue::Bool(true)
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_relation_binding_inputs() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                  {:db/id "eve" :person/name "Eve" :person/role :auditor}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :in [$ [[?name ?role]]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = q(
            query,
            &conn.db(),
            &[parse(r#"[["Alice" :admin] ["Eve" :guest] ["Bob" :guest]]"#).unwrap()],
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Bob".into())]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_tuple_binding_inputs() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :in [$ [?name ?role]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[parse(r#"["Alice" :admin]"#).unwrap()]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[tokio::test]
    async fn q_supports_datomic_rule_inputs() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :in [$ %]
                :where [(eligible ?e)
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rules = parse(r#"[[(eligible ?e) [?e :person/role :admin]]]"#).unwrap();
        let rows = q(query, &conn.db(), &[rules]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[tokio::test]
    async fn q_supports_datomic_not_clause() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest :person/suspended true}
                  {:db/id "eve" :person/name "Eve" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/role :guest]
                        (not [?e :person/suspended true])
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);
    }

    #[tokio::test]
    async fn q_supports_datomic_or_clause() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                  {:db/id "eve" :person/name "Eve" :person/role :auditor :person/verified true}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]
                        (or [?e :person/role :admin]
                            (and [?e :person/role :auditor]
                                 [?e :person/verified true]))]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Eve".into())]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_not_join_clause() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest :person/ban-reason "spam"}
                  {:db/id "eve" :person/name "Eve" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/role :guest]
                        (not-join [?e] [?e :person/ban-reason ?reason])
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);
    }

    #[tokio::test]
    async fn q_supports_datomic_missing_predicate_and_not_equals() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest :person/ban-reason "spam"}
                  {:db/id "eve" :person/name "Eve" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/role ?role]
                        [(!= ?role :admin)]
                        [(missing? $ ?e :person/ban-reason)]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);

        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/role ?role]
                        [(not= ?role :guest)]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[tokio::test]
    async fn q_supports_ground_and_identity_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?copy]
                :where [[(ground :guest) ?role]
                        [?e :person/role ?role]
                        [?e :person/name ?name]
                        [(identity ?name) ?copy]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Bob".into())]]);
    }

    #[tokio::test]
    async fn q_supports_name_and_namespace_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(r#"[{:db/id "alice" :person/name "Alice" :person/role :role/admin}]"#).unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?roleName ?roleNamespace]
                :where [[?e :person/role ?role]
                        [(name ?role) ?roleName]
                        [(namespace ?role) ?roleNamespace]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("admin".into()),
                EdnValue::String("role".into()),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_str_and_keyword_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(r#"[{:db/id "alice" :person/name "Alice" :person/role :role/admin}]"#).unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?resource ?rebuilt]
                :where [[?e :person/role ?role]
                        [(name ?role) ?roleName]
                        [(str "kotoba://role/" ?roleName) ?resource]
                        [(keyword "role" ?roleName) ?rebuilt]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("kotoba://role/admin".into()),
                EdnValue::Keyword(Keyword::parse("role/admin")),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_contains_and_starts_with_predicates() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice"
                   :person/name "Alice"
                   :person/role :role/admin
                   :atproto/uri "at://did:plc:alice/app.bsky.feed.post/r1"}
                  {:db/id "bob"
                   :person/name "Bob"
                   :person/role :role/guest
                   :atproto/uri "https://example.com/not-atproto"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name ?displayName ?uri ?collection ?rkey ?splitCollection ?splitRkey ?nthCollection ?lastRkey ?joinedUri ?normalizedUri ?scheme ?trimmedScheme]
                :where [[?e :person/role ?role]
                        [(contains? #{:role/admin :role/moderator} ?role)]
                        [?e :atproto/uri ?uri]
                        [(clojure.string/starts-with? ?uri "at://")]
                        [(clojure.string/includes? ?uri "/app.bsky.feed.post/")]
                        [(str/ends-with? ?uri "/r1")]
                        [(subs ?uri 19 37) ?collection]
                        [(clojure.core/subs ?uri 38) ?rkey]
                        [(clojure.string/split ?uri "/") ?uriParts]
                        [(get ?uriParts 3) ?splitCollection]
                        [(get ?uriParts 4) ?splitRkey]
                        [(nth ?uriParts 3) ?nthCollection]
                        [(last ?uriParts) ?lastRkey]
                        [(clojure.string/join "/" ?uriParts) ?joinedUri]
                        [(= ?joinedUri ?uri)]
                        [(clojure.string/replace ?uri "at://" "at-uri://") ?normalizedUri]
                        [(upper-case "at") ?upperScheme]
                        [(clojure.string/lower-case ?upperScheme) ?scheme]
                        [(str/trim "  at  ") ?trimmedScheme]
                        [(clojure.string/blank? "   ")]
                        [(clojure.string/capitalize "alice") ?displayName]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                EdnValue::String("Alice".into()),
                EdnValue::String("at://did:plc:alice/app.bsky.feed.post/r1".into()),
                EdnValue::String("app.bsky.feed.post".into()),
                EdnValue::String("r1".into()),
                EdnValue::String("app.bsky.feed.post".into()),
                EdnValue::String("r1".into()),
                EdnValue::String("app.bsky.feed.post".into()),
                EdnValue::String("r1".into()),
                EdnValue::String("at://did:plc:alice/app.bsky.feed.post/r1".into()),
                EdnValue::String("at-uri://did:plc:alice/app.bsky.feed.post/r1".into()),
                EdnValue::String("at".into()),
                EdnValue::String("at".into()),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_get_function_binding_for_ipld_map_values() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "vc1"
                   :credential/claims {:claim/type "VerifiableCredential"
                                       :claim/status "active"
                                       :claim/verified true
                                       :claim/score 42
                                       :claim/tags [:vc :ipld]
                                       :claim/subject {:subject/id "did:example:alice"
                                                       :subject/roles [:issuer :holder]}}}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?type ?status ?verified ?score ?nextScore ?adjustedScore ?doubleScore ?quotScore ?remScore ?modScore ?negativeMod ?minScore ?maxScore ?firstTag ?tagCount ?subject ?firstRole ?generatedStatus ?summaryCount ?fallback ?nonEmptyTags]
                :where [[?e :credential/claims ?claims]
                        [(map? ?claims)]
                        [(coll? ?claims)]
                        [(get ?claims :claim/type) ?type]
                        [(string? ?type)]
                        [(get ?claims :claim/status) ?status]
                        [(get ?claims :claim/verified) ?verified]
                        [(boolean? ?verified)]
                        [(true? ?verified)]
                        [(get ?claims :claim/score) ?score]
                        [(integer? ?score)]
                        [(number? ?score)]
                        [(update ?claims :claim/score + 1) ?updatedScoreClaims]
                        [(get ?updatedScoreClaims :claim/score) ?updatedScore]
                        [(= ?updatedScore 43)]
                        [(+ ?score 1) ?nextScore]
                        [(- ?nextScore 2) ?adjustedScore]
                        [(* ?score 2) ?doubleScore]
                        [(quot ?score 2) ?quotScore]
                        [(rem ?score 2) ?remScore]
                        [(zero? ?remScore)]
                        [(mod ?score 5) ?modScore]
                        [(mod -3 5) ?negativeMod]
                        [(neg? -1)]
                        [(min ?score 50) ?minScore]
                        [(max ?score 10) ?maxScore]
                        [(pos? ?score)]
                        [(< 0 ?score ?nextScore 100)]
                        [(<= 42 ?score ?score ?nextScore)]
                        [(> 100 ?doubleScore ?score 0)]
                        [(>= 84 ?doubleScore ?score 42)]
                        [(= ?score 42 42)]
                        [(not= ?score ?nextScore ?score)]
                        [(get ?claims :claim/tags) ?tags]
                        [(vector? ?tags)]
                        [(seq ?tags) ?seqTags]
                        [(some? ?seqTags)]
                        [(get ?tags 0) ?firstTag]
                        [(first ?tags) ?seqFirstTag]
                        [(= ?seqFirstTag ?firstTag)]
                        [(rest ?tags) ?restTags]
                        [(= ?restTags [:ipld])]
                        [(next ?tags) ?nextTags]
                        [(= ?nextTags [:ipld])]
                        [(next [:vc]) ?singleNext]
                        [(nil? ?singleNext)]
                        [(conj ?tags :dag-cbor) ?extendedTags]
                        [(= ?extendedTags [:vc :ipld :dag-cbor])]
                        [(cons :json-ld ?tags) ?wireTags]
                        [(= ?wireTags [:json-ld :vc :ipld])]
                        [(hash-map :claim/type ?type) ?baseSummary]
                        [(vector :claim/status ?status) ?statusPair]
                        [(conj ?baseSummary ?statusPair) ?summary2]
                        [(= ?summary2 {:claim/type "VerifiableCredential" :claim/status "active"})]
                        [(assoc ?summary2 :claim/format :dag-cbor) ?summary3]
                        [(= ?summary3 {:claim/type "VerifiableCredential" :claim/status "active" :claim/format :dag-cbor})]
                        [(dissoc ?summary3 :claim/format) ?summary4]
                        [(= ?summary4 ?summary2)]
                        [(assoc ?tags 2 :dag-cbor) ?assocTags]
                        [(= ?assocTags [:vc :ipld :dag-cbor])]
                        [(take 1 ?assocTags) ?firstAssocTag]
                        [(= ?firstAssocTag [:vc])]
                        [(drop 1 ?assocTags) ?tailAssocTags]
                        [(= ?tailAssocTags [:ipld :dag-cbor])]
                        [(subvec ?assocTags 1 3) ?middleAssocTags]
                        [(= ?middleAssocTags [:ipld :dag-cbor])]
                        [(reverse ?assocTags) ?reverseAssocTags]
                        [(= ?reverseAssocTags [:dag-cbor :ipld :vc])]
                        [(sort ?reverseAssocTags) ?sortedAssocTags]
                        [(= ?sortedAssocTags [:dag-cbor :ipld :vc])]
                        [(keyword? ?firstTag)]
                        [(count ?tags) ?tagCount]
                        [(not-empty ?tags) ?nonEmptyTags]
                        [(some? ?nonEmptyTags)]
                        [(vector) ?emptyTags]
                        [(empty? ?emptyTags)]
                        [(get-in ?claims [:claim/subject :subject/id]) ?subject]
                        [(string? ?subject)]
                        [(assoc-in ?claims [:claim/subject :subject/verified] true) ?verifiedClaims]
                        [(get-in ?verifiedClaims [:claim/subject :subject/verified]) ?subjectVerified]
                        [(true? ?subjectVerified)]
                        [(update-in ?claims [:claim/subject :subject/roles] conj :verifier) ?roleUpdatedClaims]
                        [(get-in ?roleUpdatedClaims [:claim/subject :subject/roles]) ?updatedRoles]
                        [(= ?updatedRoles [:issuer :holder :verifier])]
                        [(get-in ?claims [:claim/subject :subject/roles 0]) ?firstRole]
                        [(vector :vc :ipld) ?expectedTags]
                        [(= ?tags ?expectedTags)]
                        [(hash-set :issuer :holder) ?expectedRoles]
                        [(set? ?expectedRoles)]
                        [(contains? ?expectedRoles ?firstRole)]
                        [(disj ?expectedRoles :holder) ?issuerOnly]
                        [(= ?issuerOnly #{:issuer})]
                        [(hash-map :claim/type ?type :claim/status ?status) ?summary]
                        [(map? ?summary)]
                        [(get ?summary :claim/status) ?generatedStatus]
                        [(count ?summary) ?summaryCount]
                        [(get ?claims :claim/missing) ?missing]
                        [(nil? ?missing)]
                        [(get ?claims :claim/missing "fallback") ?fallback]
                        [(some? ?fallback)]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("VerifiableCredential".into()),
                EdnValue::String("active".into()),
                EdnValue::Bool(true),
                EdnValue::Integer(42),
                EdnValue::Integer(43),
                EdnValue::Integer(41),
                EdnValue::Integer(84),
                EdnValue::Integer(21),
                EdnValue::Integer(0),
                EdnValue::Integer(2),
                EdnValue::Integer(2),
                EdnValue::Integer(42),
                EdnValue::Integer(42),
                EdnValue::Keyword(Keyword::parse("vc")),
                EdnValue::Integer(2),
                EdnValue::String("did:example:alice".into()),
                EdnValue::Keyword(Keyword::parse("issuer")),
                EdnValue::String("active".into()),
                EdnValue::Integer(2),
                EdnValue::String("fallback".into()),
                EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("vc")),
                    EdnValue::Keyword(Keyword::parse("ipld")),
                ]),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_inc_and_dec_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice"
                   :person/score 42
                   :person/claims {:claim/score 42}}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?incScore ?decScore ?updatedScore]
                :where [[?e :person/score ?score]
                        [(clojure.core/inc ?score) ?incScore]
                        [(clojure.core/dec ?score) ?decScore]
                        [?e :person/claims ?claims]
                        [(clojure.core/update ?claims :claim/score clojure.core/inc) ?updatedClaims]
                        [(clojure.core/get ?updatedClaims :claim/score) ?updatedScore]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Integer(43),
                EdnValue::Integer(41),
                EdnValue::Integer(43),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_abs_even_and_odd_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/score -42}
                  {:db/id "bob" :person/score 7}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?score ?absolute]
                :where [[?e :person/score ?score]
                        [(abs ?score) ?absolute]
                        [(even? ?absolute)]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![EdnValue::Integer(-42), EdnValue::Integer(42)]]
        );

        let odd_query = parse(
            r#"{:find [?score]
                :where [[?e :person/score ?score]
                        [(odd? ?score)]]}"#,
        )
        .unwrap();
        let rows = q(odd_query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::Integer(7)]]);
    }

    #[tokio::test]
    async fn q_supports_numeric_comparisons_across_edn_number_types() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :metric/score 2.5M}
                  {:db/id "bob" :metric/score 4.0}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?score]
                :where [[?e :metric/score ?score]
                        [(number? ?score)]
                        [(< 2 ?score 3N)]
                        [(<= 2.5 ?score 2.5M)]
                        [(> 10.0 ?score 1)]
                        [(>= 2.5M ?score 2.5)]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::BigDec("2.5".into())]]);
    }

    #[tokio::test]
    async fn q_supports_regex_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "task1" :task/code "KOTOBA-42"}
                  {:db/id "task2" :task/code "kotoba-99"}
                  {:db/id "task3" :task/code "KOTOBA-42-extra"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?code ?project ?number ?whole]
                :where [[?e :task/code ?code]
                        [(re-find "([A-Z]+)-([0-9]+)" ?code) ?found]
                        [(some? ?found)]
                        [(get ?found 1) ?project]
                        [(get ?found 2) ?number]
                        [(clojure.core/re-matches "[A-Z]+-[0-9]+" ?code) ?whole]
                        [(some? ?whole)]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("KOTOBA-42".into()),
                EdnValue::String("KOTOBA".into()),
                EdnValue::String("42".into()),
                EdnValue::String("KOTOBA-42".into()),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_clojure_set_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/roles #{:role/admin :role/auditor}}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?expanded ?shared ?reduced]
                :where [[?e :person/roles ?roles]
                        [(clojure.set/union ?roles #{:role/operator}) ?expanded]
                        [(set/subset? #{:role/admin} ?expanded)]
                        [(set/superset? ?expanded ?roles)]
                        [(set/intersection ?expanded #{:role/admin :role/missing}) ?shared]
                        [(set/difference ?expanded #{:role/auditor}) ?reduced]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Set(BTreeSet::from([
                    kw_value(":role/admin"),
                    kw_value(":role/auditor"),
                    kw_value(":role/operator"),
                ])),
                EdnValue::Set(BTreeSet::from([kw_value(":role/admin")])),
                EdnValue::Set(BTreeSet::from([
                    kw_value(":role/admin"),
                    kw_value(":role/operator"),
                ])),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_clojure_map_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/profile {:person/name "Alice" :person/role :admin}}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?selected ?merged ?keys ?vals]
                :where [[?e :person/profile ?profile]
                        [(select-keys ?profile [:person/name]) ?selected]
                        [(merge ?selected {:person/active true}) ?merged]
                        [(keys ?selected) ?keys]
                        [(vals ?selected) ?vals]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Map(BTreeMap::from([(
                    kw_value(":person/name"),
                    EdnValue::String("Alice".into()),
                )])),
                EdnValue::Map(BTreeMap::from([
                    (kw_value(":person/active"), EdnValue::Bool(true)),
                    (kw_value(":person/name"), EdnValue::String("Alice".into())),
                ])),
                EdnValue::Vector(vec![kw_value(":person/name")]),
                EdnValue::Vector(vec![EdnValue::String("Alice".into())]),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_clojure_collection_predicates() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/scores [1 2 3] :person/names ["Alice" "" "Alicia"]}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?allScores ?notEveryScoreString ?noNilScores ?allNames ?scoresVector ?sameScore ?hasAdmin ?notFalse ?truthyScores ?namesString ?incScores ?oddScores ?nonOddScores ?nonEmptyNames ?scoreSum ?scoreProduct ?scoreMax ?applySum ?applyMax ?scoreSet ?initialOdds ?afterOdds ?splitScores ?splitOdds ?flatScores ?interposedScores ?interleavedScores ?pairs ?windows ?paddedPairs ?allPairs]
                :where [[?e :person/scores ?scores]
                        [?e :person/names ?names]
                        [(distinct? 1 2 3)]
                        [(every? integer? ?scores)]
                        [(every? integer? ?scores) ?allScores]
                        [(not-every? string? ?scores) ?notEveryScoreString]
                        [(not-any? nil? ?scores) ?noNilScores]
                        [(every? string? ?names) ?allNames]
                        [(vector? ?scores) ?scoresVector]
                        [(= 3 3) ?sameScore]
                        [(contains? #{:role/admin :role/auditor} :role/admin) ?hasAdmin]
                        [(clojure.core/not false) ?notFalse]
                        [(boolean ?scores) ?truthyScores]
                        [(string? ?names) ?namesString]
                        [(map inc ?scores) ?incScores]
                        [(filter odd? ?scores) ?oddScores]
                        [(remove odd? ?scores) ?nonOddScores]
                        [(keep not-empty ?names) ?nonEmptyNames]
                        [(reduce + 0 ?scores) ?scoreSum]
                        [(reduce * ?scores) ?scoreProduct]
                        [(reduce max ?scores) ?scoreMax]
                        [(apply + ?scores) ?applySum]
                        [(apply max ?scores) ?applyMax]
                        [(apply hash-set ?scores) ?scoreSet]
                        [(take-while odd? ?scores) ?initialOdds]
                        [(drop-while odd? ?scores) ?afterOdds]
                        [(split-at 2 ?scores) ?splitScores]
                        [(split-with odd? ?scores) ?splitOdds]
                        [(flatten [[1 2 3] [4 [5]]]) ?flatScores]
                        [(interpose 0 ?scores) ?interposedScores]
                        [(interleave ?scores [:a :b :c]) ?interleavedScores]
                        [(partition 2 ?scores) ?pairs]
                        [(partition 2 1 ?scores) ?windows]
                        [(partition 2 2 [0] ?scores) ?paddedPairs]
                        [(partition-all 2 ?scores) ?allPairs]
                        [(= ?allScores true)]
                        [(= ?notEveryScoreString true)]
                        [(= ?noNilScores true)]
                        [(= ?allNames true)]
                        [(= ?scoresVector true)]
                        [(= ?sameScore true)]
                        [(= ?hasAdmin true)]
                        [(= ?notFalse true)]
                        [(= ?truthyScores true)]
                        [(= ?namesString false)]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(true),
                EdnValue::Bool(false),
                EdnValue::Vector(vec![
                    EdnValue::Integer(2),
                    EdnValue::Integer(3),
                    EdnValue::Integer(4),
                ]),
                EdnValue::Vector(vec![EdnValue::Integer(1), EdnValue::Integer(3)]),
                EdnValue::Vector(vec![EdnValue::Integer(2)]),
                EdnValue::Vector(vec![
                    EdnValue::String("Alice".into()),
                    EdnValue::String("Alicia".into()),
                ]),
                EdnValue::Integer(6),
                EdnValue::Integer(6),
                EdnValue::Integer(3),
                EdnValue::Integer(6),
                EdnValue::Integer(3),
                EdnValue::Set(BTreeSet::from([
                    EdnValue::Integer(1),
                    EdnValue::Integer(2),
                    EdnValue::Integer(3),
                ])),
                EdnValue::Vector(vec![EdnValue::Integer(1)]),
                EdnValue::Vector(vec![EdnValue::Integer(2), EdnValue::Integer(3)]),
                EdnValue::Vector(vec![
                    EdnValue::Vector(vec![EdnValue::Integer(1), EdnValue::Integer(2)]),
                    EdnValue::Vector(vec![EdnValue::Integer(3)]),
                ]),
                EdnValue::Vector(vec![
                    EdnValue::Vector(vec![EdnValue::Integer(1)]),
                    EdnValue::Vector(vec![EdnValue::Integer(2), EdnValue::Integer(3)]),
                ]),
                EdnValue::Vector(vec![
                    EdnValue::Integer(1),
                    EdnValue::Integer(2),
                    EdnValue::Integer(3),
                    EdnValue::Integer(4),
                    EdnValue::Integer(5),
                ]),
                EdnValue::Vector(vec![
                    EdnValue::Integer(1),
                    EdnValue::Integer(0),
                    EdnValue::Integer(2),
                    EdnValue::Integer(0),
                    EdnValue::Integer(3),
                ]),
                EdnValue::Vector(vec![
                    EdnValue::Integer(1),
                    kw_value(":a"),
                    EdnValue::Integer(2),
                    kw_value(":b"),
                    EdnValue::Integer(3),
                    kw_value(":c"),
                ]),
                EdnValue::Vector(vec![EdnValue::Vector(vec![
                    EdnValue::Integer(1),
                    EdnValue::Integer(2),
                ])]),
                EdnValue::Vector(vec![
                    EdnValue::Vector(vec![EdnValue::Integer(1), EdnValue::Integer(2)]),
                    EdnValue::Vector(vec![EdnValue::Integer(2), EdnValue::Integer(3)]),
                ]),
                EdnValue::Vector(vec![
                    EdnValue::Vector(vec![EdnValue::Integer(1), EdnValue::Integer(2)]),
                    EdnValue::Vector(vec![EdnValue::Integer(3), EdnValue::Integer(0)]),
                ]),
                EdnValue::Vector(vec![
                    EdnValue::Vector(vec![EdnValue::Integer(1), EdnValue::Integer(2)]),
                    EdnValue::Vector(vec![EdnValue::Integer(3)]),
                ]),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_tuple_and_untuple_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?pair ?name2 ?role2]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]
                        [(tuple ?name ?role) ?pair]
                        [(untuple ?pair) [?name2 ?role2]]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Vector(vec![EdnValue::String("Alice".into()), kw_value(":admin")]),
                EdnValue::String("Alice".into()),
                kw_value(":admin"),
            ]]
        );
    }

    #[tokio::test]
    async fn q_supports_get_else_and_get_some_function_bindings() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name ?role ?found]
                :where [[?e :person/name ?name]
                        [(get-else $ ?e :person/role :guest) ?role]
                        [(get-some $ ?e :person/role :person/name) ?found]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    EdnValue::String("Alice".into()),
                    kw_value(":admin"),
                    EdnValue::Vector(vec![kw_value(":person/role"), kw_value(":admin")])
                ],
                vec![
                    EdnValue::String("Bob".into()),
                    kw_value(":guest"),
                    EdnValue::Vector(vec![
                        kw_value(":person/name"),
                        EdnValue::String("Bob".into())
                    ])
                ]
            ]
        );

        let named_source_query = parse(
            r#"{:find [?name ?role ?found]
                :in [$db]
                :where [[$db ?e :person/name ?name]
                        [(get-else $db ?e :person/role :guest) ?role]
                        [(get-some $db ?e :person/role :person/name) ?found]]}"#,
        )
        .unwrap();
        let rows = q(named_source_query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    EdnValue::String("Alice".into()),
                    kw_value(":admin"),
                    EdnValue::Vector(vec![kw_value(":person/role"), kw_value(":admin")])
                ],
                vec![
                    EdnValue::String("Bob".into()),
                    kw_value(":guest"),
                    EdnValue::Vector(vec![
                        kw_value(":person/name"),
                        EdnValue::String("Bob".into())
                    ])
                ]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_or_join_clause() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                  {:db/id "eve" :person/name "Eve" :person/role :auditor :person/verified true}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]
                        (or-join [?e]
                          [?e :person/role :admin]
                          (and [?e :person/role :auditor]
                               [?e :person/verified true]))]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Eve".into())]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_count_aggregate_grouping() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/role :admin}
                  {:db/id "bob" :person/name "Bob" :person/role :guest}
                  {:db/id "eve" :person/name "Eve" :person/role :guest}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?role (count ?e)]
                :where [[?e :person/role ?role]]
                :order-by [[(count ?e) :desc] [?role :asc]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![kw_value(":guest"), EdnValue::Integer(2)],
                vec![kw_value(":admin"), EdnValue::Integer(1)]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_with_for_aggregate_basis() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/role :guest :person/score 10}
                  {:db/id "bob" :person/role :guest :person/score 10}
                  {:db/id "eve" :person/role :guest :person/score 20}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let without_with = parse(
            r#"{:find [?role (count ?score)]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]}"#,
        )
        .unwrap();
        let with_entity = parse(
            r#"{:find [?role (count ?score)]
                :with [?e]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]}"#,
        )
        .unwrap();
        assert_eq!(
            q(without_with, &conn.db(), &[]).unwrap(),
            vec![vec![kw_value(":guest"), EdnValue::Integer(3)]]
        );
        assert_eq!(
            q(with_entity, &conn.db(), &[]).unwrap(),
            vec![vec![kw_value(":guest"), EdnValue::Integer(3)]]
        );
    }

    #[tokio::test]
    async fn q_supports_count_distinct_aggregate_grouping() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  [:db/add "alice" :person/role :admin]
                  [:db/add "bob" :person/role :guest]
                  [:db/add "eve" :person/role :guest]
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [(count ?role) (count-distinct ?role)]
                :where [[?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows, vec![vec![EdnValue::Integer(3), EdnValue::Integer(2)]]);
    }

    #[tokio::test]
    async fn q_supports_integer_sum_min_max_aggregates() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/role :admin :person/score 10}
                  {:db/id "bob" :person/role :guest :person/score 3}
                  {:db/id "eve" :person/role :guest :person/score 7}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?role (sum ?score) (min ?score) (max ?score) (min 2 ?score) (max 2 ?score) (min 0 ?score) (max 0 ?score)]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    kw_value(":admin"),
                    EdnValue::Integer(10),
                    EdnValue::Integer(10),
                    EdnValue::Integer(10),
                    EdnValue::Vector(vec![EdnValue::Integer(10)]),
                    EdnValue::Vector(vec![EdnValue::Integer(10)]),
                    EdnValue::Vector(vec![]),
                    EdnValue::Vector(vec![])
                ],
                vec![
                    kw_value(":guest"),
                    EdnValue::Integer(10),
                    EdnValue::Integer(3),
                    EdnValue::Integer(7),
                    EdnValue::Vector(vec![EdnValue::Integer(3), EdnValue::Integer(7)]),
                    EdnValue::Vector(vec![EdnValue::Integer(7), EdnValue::Integer(3)]),
                    EdnValue::Vector(vec![]),
                    EdnValue::Vector(vec![])
                ]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_integer_avg_aggregate() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/role :admin :person/score 10}
                  {:db/id "bob" :person/role :guest :person/score 3}
                  {:db/id "eve" :person/role :guest :person/score 8}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?role (avg ?score)]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![kw_value(":admin"), EdnValue::float(10.0)],
                vec![kw_value(":guest"), EdnValue::float(5.5)]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_statistical_aggregates() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/role :admin :person/score 10}
                  {:db/id "bob" :person/role :guest :person/score 3}
                  {:db/id "eve" :person/role :guest :person/score 8}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?role (median ?score) (variance ?score) (stddev ?score)]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    kw_value(":admin"),
                    EdnValue::Integer(10),
                    EdnValue::float(0.0),
                    EdnValue::float(0.0)
                ],
                vec![
                    kw_value(":guest"),
                    EdnValue::float(5.5),
                    EdnValue::float(6.25),
                    EdnValue::float(2.5)
                ]
            ]
        );
    }

    #[tokio::test]
    async fn q_supports_datomic_rand_and_sample_aggregates() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/role :admin :person/name "Alice"}
                  {:db/id "bob" :person/role :admin :person/name "Bob"}
                  {:db/id "eve" :person/role :admin :person/name "Eve"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        let query = parse(
            r#"{:find [?role (rand ?name) (sample 2 ?name)]
                :where [[?e :person/role ?role]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = q(query, &conn.db(), &[]).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], kw_value(":admin"));
        assert!(
            matches!(&rows[0][1], EdnValue::String(value) if ["Alice", "Bob", "Eve"].contains(&value.as_str()))
        );
        assert!(matches!(&rows[0][2], EdnValue::Vector(values)
            if values.len() == 2
                && values.iter().all(|value| matches!(value, EdnValue::String(name)
                    if ["Alice", "Bob", "Eve"].contains(&name.as_str())))));
    }

    #[tokio::test]
    async fn retract_entity_cascades_component_refs() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "address-attr"
                   :db/ident :person/address
                   :db/valueType :db.type/ref
                   :db/isComponent true}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(
            parse(
                r#"[
                  {:db/id "alice" :person/name "Alice" :person/address "addr"}
                  {:db/id "addr" :address/city "Tokyo"}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();

        conn.transact(parse(r#"[[:db.fn/retractEntity "alice"]]"#).unwrap())
            .await
            .unwrap();

        let current = conn.db().datoms();
        assert!(current.iter().all(|d| d.a != ":person/name"));
        assert!(current.iter().all(|d| d.a != ":address/city"));
        assert!(conn
            .db()
            .history()
            .datoms()
            .iter()
            .any(|d| d.a == ":address/city" && !d.added));
    }

    #[tokio::test]
    async fn no_history_attr_discards_previous_values() {
        let conn = Connection::new();
        conn.transact(
            parse(
                r#"[
                  {:db/id "secret-attr"
                   :db/ident :person/secret
                   :db/noHistory true}
                ]"#,
            )
            .unwrap(),
        )
        .await
        .unwrap();
        conn.transact(parse(r#"[[:db/add "alice" :person/secret "old"]]"#).unwrap())
            .await
            .unwrap();
        conn.transact(parse(r#"[[:db/add "alice" :person/secret "new"]]"#).unwrap())
            .await
            .unwrap();

        let db = conn.db();
        assert!(db
            .history()
            .datoms()
            .iter()
            .all(|d| d.v != EdnValue::String("old".into())));
        assert!(db
            .datoms()
            .iter()
            .any(|d| d.a == ":person/secret" && d.v == EdnValue::String("new".into())));
    }

    #[tokio::test]
    async fn excision_removes_entity_or_attribute_history() {
        let conn = Connection::new();
        let report = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/secret "s"}
                      {:db/id "bob" :person/name "Bob" :person/secret "b"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = report.tempids["alice"].clone();

        assert!(conn.excise_entity(&alice).unwrap() > 0);
        assert!(conn.db().history().datoms().iter().all(|d| d.e != alice));

        assert!(conn.excise_attribute(":person/secret").unwrap() > 0);
        assert!(conn
            .db()
            .history()
            .datoms()
            .iter()
            .all(|d| d.a != ":person/secret"));
    }

    #[tokio::test]
    async fn excision_transaction_form_removes_entity_or_attribute_history() {
        let conn = Connection::new();
        let first = conn
            .transact(
                parse(
                    r#"[
                      {:db/id "alice" :person/name "Alice" :person/secret "s"}
                      {:db/id "bob" :person/name "Bob" :person/secret "b"}
                    ]"#,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let alice = first.tempids["alice"].clone();

        conn.transact(parse(r#"[{:db/excise "alice"}]"#).unwrap())
            .await
            .unwrap();
        assert!(conn.db().history().datoms().iter().all(|d| d.e != alice));
        assert!(conn
            .db()
            .datoms()
            .iter()
            .any(|d| d.a == ":person/name" && d.v == EdnValue::String("Bob".into())));

        conn.transact(parse(r#"[{:db/excise :person/secret}]"#).unwrap())
            .await
            .unwrap();
        assert!(conn
            .db()
            .history()
            .datoms()
            .iter()
            .all(|d| d.a != ":person/secret"));
    }

    #[tokio::test]
    async fn excision_transaction_form_honors_before_tx() {
        let conn = Connection::new();
        let first = conn
            .transact(parse(r#"[[:db/add "alice" :person/secret "old"]]"#).unwrap())
            .await
            .unwrap();
        conn.transact(parse(r#"[[:db/add "alice" :person/name "Alice"]]"#).unwrap())
            .await
            .unwrap();

        let mut excise = BTreeMap::new();
        excise.insert(kw_value(DB_EXCISE), kw_value(":person/secret"));
        excise.insert(
            kw_value(DB_EXCISE_BEFORE),
            EdnValue::String(first.tx_cid.to_multibase()),
        );
        conn.transact(EdnValue::Vector(vec![EdnValue::Map(excise)]))
            .await
            .unwrap();

        let history_db = conn.db().history();
        let history = history_db.datoms();
        assert!(!history.iter().any(|d| d.a == ":person/secret"));
        assert!(history
            .iter()
            .any(|d| d.a == ":person/name" && d.v == EdnValue::String("Alice".into())));
    }

    #[test]
    fn datom_converts_to_kqe_substrate_datom() {
        let e = cid(b"alice");
        let tx = cid(b"tx");
        let datom = Datom::assert(
            e.clone(),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            tx.clone(),
        );
        let substrate = datom.to_kqe().unwrap();
        assert_eq!(substrate.as_tuple().0, &e);
        assert_eq!(substrate.as_tuple().1, ":person/name");
        assert_eq!(substrate.as_tuple().3, &tx);
        assert!(substrate.as_tuple().4);

        let roundtrip = Datom::from_kqe(substrate);
        assert_eq!(roundtrip, datom);
    }
}
