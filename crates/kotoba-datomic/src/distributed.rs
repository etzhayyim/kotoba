//! Distributed Datomic commit writer.
//!
//! This module is the write-path bridge from Datomic-compatible tx data to the
//! IPFS/IPLD/IPNS substrate.  It deliberately writes Datom indexes directly,
//! without going through the legacy Quad projection.

use crate::{
    current_datoms, edn_to_kqe_value, index_range_datoms, plan_datom_lookup_for_triple,
    seek_datoms_index, Connection, Datom, DatomIndex, DatomicError, Db, Entity, LogEntry,
    TransactReport, Value,
};
use kotoba_core::cid::KotobaCid;
use kotoba_core::prolly::ProllyTree;
use kotoba_core::store::BlockStore;
use kotoba_edn::Keyword;
use kotoba_ipfs::{IpnsName, IpnsRecord, IpnsRegistry, IpnsRegistryError};
use kotoba_kqe::Datom as KqeDatom;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Mutex;

pub const ROOT_EAVT: &str = "eavt";
pub const ROOT_AEVT: &str = "aevt";
pub const ROOT_AVET: &str = "avet";
pub const ROOT_VAET: &str = "vaet";
pub const ROOT_TEA: &str = "tea";
const DISTRIBUTED_RULE_RECURSION_LIMIT: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum DistributedCommitError {
    #[error("datom conversion: {0}")]
    Datom(#[from] DatomicError),
    #[error("cbor encode: {0}")]
    Cbor(String),
    #[error("edn decode: {0}")]
    Edn(String),
    #[error("block store: {0}")]
    Store(#[from] anyhow::Error),
    #[error("ipns: {0}")]
    Ipns(#[from] IpnsRegistryError),
    #[error("ipns signature: {0}")]
    IpnsSignature(String),
    #[error("stale parent for {name}: expected {expected:?}, current {current:?}")]
    StaleParent {
        name: String,
        expected: Option<String>,
        current: Option<String>,
    },
    #[error("commit CID is not an IPFS CID: {0}")]
    InvalidCommitCid(String),
    #[error("commit not found: {0}")]
    MissingCommit(String),
    #[error("missing index root {root} in commit {commit}")]
    MissingIndexRoot { commit: String, root: &'static str },
}

/// DAG-CBOR commit block for a Datomic database/graph head.
///
/// The CID is derived from the encoded payload and is not serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributedDatomCommit {
    #[serde(skip)]
    pub cid: KotobaCid,
    /// Stable graph/database identity.  The mutable pointer to this commit is
    /// the IPNS name, while this CID scopes Datomic facts and authorization.
    pub graph: KotobaCid,
    pub tx_cid: KotobaCid,
    pub prev: Option<KotobaCid>,
    pub author: String,
    pub seq: u64,
    pub ts: u64,
    /// Covering ProllyTree roots: eavt/aevt/avet/vaet/tea.
    pub index_roots: HashMap<String, KotobaCid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cacao_proof_cid: Option<KotobaCid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReport {
    pub commit: DistributedDatomCommit,
    pub ipns_record: IpnsRecord,
    pub datom_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedTxRangeEntry {
    pub commit: DistributedDatomCommit,
    pub datoms: Vec<Datom>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatomIndexLookup {
    All,
    Entity(KotobaCid),
    EntityAttribute { entity: KotobaCid, attr: String },
    Attribute(String),
    AttributeValue { attr: String, value: Value },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LookupRefResolution {
    NotLookupRef,
    Missing,
    Resolved(KotobaCid),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredDatom {
    e: String,
    a: String,
    v_edn: String,
    t: String,
    added: bool,
}

/// Synchronous block-store adapter for a remote `kotoba-ipfs/1` peer.
///
/// This is the bridge that lets [`DistributedDatomReader`] traverse a Datomic
/// commit chain whose commit blocks and ProllyTree index blocks live on another
/// Kotoba/IPFS node.
pub struct RemoteIpfsBlockStore {
    socket: SocketAddr,
    cache: Mutex<HashMap<KotobaCid, bytes::Bytes>>,
}

impl RemoteIpfsBlockStore {
    pub fn new(socket: SocketAddr) -> Self {
        Self {
            socket,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn cached_blocks(&self) -> Result<Vec<(KotobaCid, bytes::Bytes)>, DistributedCommitError> {
        Ok(self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("remote block cache lock poisoned"))?
            .iter()
            .map(|(cid, bytes)| (cid.clone(), bytes.clone()))
            .collect())
    }
}

impl BlockStore for RemoteIpfsBlockStore {
    fn put(&self, cid: &KotobaCid, data: &[u8]) -> anyhow::Result<()> {
        self.cache
            .lock()
            .map_err(|_| anyhow::anyhow!("remote block cache lock poisoned"))?
            .insert(cid.clone(), bytes::Bytes::copy_from_slice(data));
        Ok(())
    }

    fn get(&self, cid: &KotobaCid) -> anyhow::Result<Option<bytes::Bytes>> {
        if let Some(bytes) = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("remote block cache lock poisoned"))?
            .get(cid)
            .cloned()
        {
            return Ok(Some(bytes));
        }
        let Some(bytes) = fetch_remote_block(self.socket, cid)? else {
            return Ok(None);
        };
        self.cache
            .lock()
            .map_err(|_| anyhow::anyhow!("remote block cache lock poisoned"))?
            .insert(cid.clone(), bytes.clone());
        Ok(Some(bytes))
    }

    fn has(&self, cid: &KotobaCid) -> bool {
        self.get(cid).ok().flatten().is_some()
    }
}

/// IPNS registry adapter for resolving Datomic heads from a remote
/// `kotoba-ipfs/1` peer.
pub struct RemoteIpfsIpnsRegistry {
    socket: SocketAddr,
}

impl RemoteIpfsIpnsRegistry {
    pub fn new(socket: SocketAddr) -> Self {
        Self { socket }
    }
}

impl IpnsRegistry for RemoteIpfsIpnsRegistry {
    fn publish(&self, _record: IpnsRecord) -> Result<(), IpnsRegistryError> {
        Err(IpnsRegistryError::Kubo(
            "remote kotoba-ipfs IPNS registry is read-only".into(),
        ))
    }

    fn resolve(&self, name: &IpnsName) -> Result<IpnsRecord, IpnsRegistryError> {
        fetch_remote_ipns_record(self.socket, name)
    }
}

fn fetch_remote_block(socket: SocketAddr, cid: &KotobaCid) -> anyhow::Result<Option<bytes::Bytes>> {
    let mut stream = TcpStream::connect(socket)?;
    stream.write_all(format!("GET kotoba-ipfs/1 {}\n", cid.to_multibase()).as_bytes())?;
    stream.flush()?;
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf)?;
    let len = u64::from_be_bytes(len_buf);
    if len == u64::MAX {
        return Ok(None);
    }
    if len > usize::MAX as u64 {
        return Err(anyhow::anyhow!("remote block too large: {len}"));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf)?;
    if KotobaCid::from_bytes(&buf) != *cid {
        return Err(anyhow::anyhow!("remote block CID mismatch: {cid}"));
    }
    Ok(Some(bytes::Bytes::from(buf)))
}

fn fetch_remote_ipns_record(
    socket: SocketAddr,
    name: &IpnsName,
) -> Result<IpnsRecord, IpnsRegistryError> {
    let mut stream =
        TcpStream::connect(socket).map_err(|e| IpnsRegistryError::Kubo(e.to_string()))?;
    stream
        .write_all(format!("NAME kotoba-ipfs/1 {}\n", name.0).as_bytes())
        .map_err(|e| IpnsRegistryError::Kubo(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| IpnsRegistryError::Kubo(e.to_string()))?;
    let mut len_buf = [0u8; 8];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| IpnsRegistryError::Kubo(e.to_string()))?;
    let len = u64::from_be_bytes(len_buf);
    if len == u64::MAX {
        return Err(IpnsRegistryError::NotFound(name.0.clone()));
    }
    if len > usize::MAX as u64 {
        return Err(IpnsRegistryError::Kubo(format!(
            "remote IPNS record too large: {len}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .map_err(|e| IpnsRegistryError::Kubo(e.to_string()))?;
    ciborium::from_reader(&buf[..]).map_err(|e| IpnsRegistryError::Kubo(e.to_string()))
}

pub struct DistributedDatomReader<'a, R>
where
    R: IpnsRegistry + ?Sized,
{
    store: &'a dyn BlockStore,
    ipns: &'a R,
}

impl<'a, R> DistributedDatomReader<'a, R>
where
    R: IpnsRegistry + ?Sized,
{
    pub fn new(store: &'a dyn BlockStore, ipns: &'a R) -> Self {
        Self { store, ipns }
    }

    pub fn resolve_head(
        &self,
        ipns_name: &str,
    ) -> Result<Option<DistributedDatomCommit>, DistributedCommitError> {
        let record = match self.ipns.resolve(&IpnsName::new(ipns_name.to_string())) {
            Ok(record) => record,
            Err(IpnsRegistryError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let cid = KotobaCid::from_multibase(&record.value)
            .ok_or_else(|| DistributedCommitError::InvalidCommitCid(record.value.clone()))?;
        DistributedDatomCommit::load(&cid, self.store)
    }

    pub fn history_for_name(&self, ipns_name: &str) -> Result<Vec<Datom>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.history_from_head(&head.cid)
    }

    pub fn current_db_for_name(
        &self,
        ipns_name: &str,
    ) -> Result<Option<Db>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.current_db_from_head(&head.cid).map(Some)
    }

    pub fn tx_range_for_name(
        &self,
        ipns_name: &str,
        start: Option<&KotobaCid>,
        end: Option<&KotobaCid>,
    ) -> Result<Vec<DistributedTxRangeEntry>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.tx_range_from_head(&head.cid, start, end)
    }

    pub fn log_for_name(&self, ipns_name: &str) -> Result<Vec<LogEntry>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.log_from_head(&head.cid)
    }

    pub fn log_from_head(&self, head: &KotobaCid) -> Result<Vec<LogEntry>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        let mut entries = Vec::new();
        for commit in chain.into_iter().rev() {
            entries.push(LogEntry {
                tx: commit.tx_cid.clone(),
                datoms: datoms_from_commit(&commit, self.store)?,
            });
        }
        Ok(entries)
    }

    /// Traverse the full distributed Datomic DAG reachable from `head`.
    ///
    /// This is primarily used by remote sync adapters: when `self.store` is a
    /// caching remote block store, loading every index root causes all commit
    /// and ProllyTree blocks needed for later local q/datoms/pull reads to be
    /// cached for persistence into the caller's local block store.
    pub fn materialize_head_blocks(&self, head: &KotobaCid) -> Result<(), DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        for commit in chain {
            for root_name in [ROOT_EAVT, ROOT_AEVT, ROOT_AVET, ROOT_VAET, ROOT_TEA] {
                let root = commit.index_roots.get(root_name).ok_or_else(|| {
                    DistributedCommitError::MissingIndexRoot {
                        commit: commit.cid.to_multibase(),
                        root: root_name,
                    }
                })?;
                ProllyTree::scan_prefix(root, &[], self.store)
                    .map_err(DistributedCommitError::Store)?;
            }
        }
        Ok(())
    }

    pub fn tx_range_from_head(
        &self,
        head: &KotobaCid,
        start: Option<&KotobaCid>,
        end: Option<&KotobaCid>,
    ) -> Result<Vec<DistributedTxRangeEntry>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        if let Some(start) = start {
            if !chain.iter().any(|commit| &commit.tx_cid == start) {
                return Err(DatomicError::Query(format!(
                    "txRange start transaction not found: {}",
                    start.to_multibase()
                ))
                .into());
            }
        }
        if let Some(end) = end {
            if !chain.iter().any(|commit| &commit.tx_cid == end) {
                return Err(DatomicError::Query(format!(
                    "txRange end transaction not found: {}",
                    end.to_multibase()
                ))
                .into());
            }
        }

        let mut in_range = start.is_none();
        let mut entries = Vec::new();
        for commit in chain.into_iter().rev() {
            if let Some(end) = end {
                if &commit.tx_cid == end {
                    break;
                }
            }
            if !in_range {
                if Some(&commit.tx_cid) == start {
                    in_range = true;
                } else {
                    continue;
                }
            }
            let datoms = datoms_from_commit(&commit, self.store)?;
            entries.push(DistributedTxRangeEntry { commit, datoms });
        }
        Ok(entries)
    }

    pub fn history_from_head(
        &self,
        head: &KotobaCid,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        let mut datoms = Vec::new();
        for commit in chain.into_iter().rev() {
            datoms.extend(datoms_from_commit(&commit, self.store)?);
        }
        Ok(datoms)
    }

    pub fn history_for_entity(
        &self,
        head: &KotobaCid,
        entity: &KotobaCid,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        self.history_from_index_prefix(head, ROOT_EAVT, &entity.0)
    }

    pub fn current_for_entity(
        &self,
        head: &KotobaCid,
        entity: &KotobaCid,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        Ok(current_datoms(&self.history_for_entity(head, entity)?))
    }

    pub fn history_for_entity_attribute(
        &self,
        head: &KotobaCid,
        entity: &KotobaCid,
        attr: &str,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let mut out = Vec::new();
        for attr in attr_lookup_variants(attr) {
            extend_unique_datoms(
                &mut out,
                self.history_from_index_prefix(
                    head,
                    ROOT_EAVT,
                    &eavt_entity_attr_prefix(entity, attr),
                )?,
            );
        }
        Ok(out)
    }

    pub fn current_for_entity_attribute(
        &self,
        head: &KotobaCid,
        entity: &KotobaCid,
        attr: &str,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        Ok(current_datoms(
            &self.history_for_entity_attribute(head, entity, attr)?,
        ))
    }

    pub fn history_for_attribute(
        &self,
        head: &KotobaCid,
        attr: &str,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let mut out = Vec::new();
        for attr in attr_lookup_variants(attr) {
            extend_unique_datoms(
                &mut out,
                self.history_from_index_prefix(head, ROOT_AEVT, &attr_prefix(attr))?,
            );
        }
        Ok(out)
    }

    pub fn current_for_attribute(
        &self,
        head: &KotobaCid,
        attr: &str,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        Ok(current_datoms(&self.history_for_attribute(head, attr)?))
    }

    pub fn history_for_attribute_value(
        &self,
        head: &KotobaCid,
        attr: &str,
        value: &Value,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let mut out = Vec::new();
        for attr in attr_lookup_variants(attr) {
            extend_unique_datoms(
                &mut out,
                self.history_from_index_prefix(head, ROOT_AVET, &avet_prefix(attr, value))?,
            );
        }
        Ok(out)
    }

    pub fn current_for_attribute_value(
        &self,
        head: &KotobaCid,
        attr: &str,
        value: &Value,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        Ok(current_datoms(
            &self.history_for_attribute_value(head, attr, value)?,
        ))
    }

    pub fn history_for_lookup(
        &self,
        head: &KotobaCid,
        lookup: &DatomIndexLookup,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        match lookup {
            DatomIndexLookup::All => self.history_from_head(head),
            DatomIndexLookup::Entity(entity) => self.history_for_entity(head, entity),
            DatomIndexLookup::EntityAttribute { entity, attr } => {
                self.history_for_entity_attribute(head, entity, attr)
            }
            DatomIndexLookup::Attribute(attr) => self.history_for_attribute(head, attr),
            DatomIndexLookup::AttributeValue { attr, value } => {
                self.history_for_attribute_value(head, attr, value)
            }
        }
    }

    pub fn current_for_lookup(
        &self,
        head: &KotobaCid,
        lookup: &DatomIndexLookup,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        Ok(current_datoms(&self.history_for_lookup(head, lookup)?))
    }

    /// Datomic-compatible current datom scan over a distributed Prolly index.
    pub fn datoms_index(
        &self,
        head: &KotobaCid,
        index: DatomIndex,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        self.current_for_index_components(head, root_for_datom_index(index), components)
    }

    pub fn datoms_index_for_name(
        &self,
        ipns_name: &str,
        index: DatomIndex,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.datoms_index(&head.cid, index, components)
    }

    /// Datomic-compatible history datom scan over a distributed Prolly index.
    pub fn history_datoms_index(
        &self,
        head: &KotobaCid,
        index: DatomIndex,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        self.history_for_index_components(head, root_for_datom_index(index), components)
    }

    pub fn history_datoms_index_for_name(
        &self,
        ipns_name: &str,
        index: DatomIndex,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.history_datoms_index(&head.cid, index, components)
    }

    /// Datomic-compatible `seek-datoms` over the current distributed database.
    pub fn seek_datoms(
        &self,
        head: &KotobaCid,
        index: DatomIndex,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let datoms = current_datoms(&self.history_from_index_seek(
            head,
            root_for_datom_index(index),
            components,
        )?);
        seek_datoms_index(datoms, index, components).map_err(Into::into)
    }

    pub fn seek_datoms_for_name(
        &self,
        ipns_name: &str,
        index: DatomIndex,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.seek_datoms(&head.cid, index, components)
    }

    /// Datomic-compatible `index-range` over the current distributed database.
    pub fn index_range(
        &self,
        head: &KotobaCid,
        attr: &str,
        start: Option<&Value>,
        end: Option<&Value>,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let mut history = Vec::new();
        for attr in attr_lookup_variants(attr) {
            let start_key = start
                .map(|value| avet_prefix(attr, value))
                .unwrap_or_else(|| attr_prefix(attr));
            extend_unique_datoms(
                &mut history,
                self.history_from_index_range(head, ROOT_AVET, &start_key)?,
            );
        }
        let datoms = current_datoms(&history);
        index_range_datoms(datoms, attr, start, end).map_err(Into::into)
    }

    pub fn index_range_for_name(
        &self,
        ipns_name: &str,
        attr: &str,
        start: Option<&Value>,
        end: Option<&Value>,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.index_range(&head.cid, attr, start, end)
    }

    pub fn history_for_index_components(
        &self,
        head: &KotobaCid,
        root_name: &'static str,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let datoms = match index_components_prefix(root_name, components)? {
            Some(prefix) => self.history_from_index_prefix(head, root_name, &prefix)?,
            None => self.history_from_head(head)?,
        };
        Ok(datoms
            .into_iter()
            .filter(|datom| datom_matches_index_components(datom, root_name, components))
            .collect())
    }

    pub fn current_for_index_components(
        &self,
        head: &KotobaCid,
        root_name: &'static str,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let datoms = match index_components_prefix(root_name, components)? {
            Some(prefix) => {
                current_datoms(&self.history_from_index_prefix(head, root_name, &prefix)?)
            }
            None => self.current_db_from_head(head)?.datoms(),
        };
        Ok(datoms
            .into_iter()
            .filter(|datom| datom_matches_index_components(datom, root_name, components))
            .collect())
    }

    pub fn current_for_index_components_as_of_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        root_name: &'static str,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let Some(as_of_head) = self.head_cid_as_of_tx(head, tx_cid)? else {
            return Err(DatomicError::Query(format!(
                "as-of transaction not found: {}",
                tx_cid.to_multibase()
            ))
            .into());
        };
        self.current_for_index_components(&as_of_head, root_name, components)
    }

    pub fn current_for_index_components_since_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        root_name: &'static str,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let datoms =
            self.history_from_index_prefix_since_tx(head, tx_cid, root_name, components)?;
        Ok(current_datoms(&datoms)
            .into_iter()
            .filter(|datom| datom_matches_index_components(datom, root_name, components))
            .collect())
    }

    pub fn current_for_triple(
        &self,
        head: &KotobaCid,
        triple: &Value,
        binding: &BTreeMap<String, Value>,
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let seq = triple
            .as_seq()
            .ok_or_else(|| DatomicError::Query("triple clause must be vector/list".into()))?;
        let seq = crate::data_pattern_terms(seq).ok_or_else(|| {
            DatomicError::Query(format!(
                "triple clause must have 3 terms or source plus 3 terms, got {}",
                seq.len()
            ))
        })?;
        let lookup_ref = self.resolve_lookup_ref_entity_term(head, &seq[0], binding)?;
        let lookup = match &lookup_ref {
            LookupRefResolution::Resolved(entity) => match resolved_attr_term(&seq[1], binding) {
                Some(attr) => DatomIndexLookup::EntityAttribute {
                    entity: entity.clone(),
                    attr,
                },
                None => DatomIndexLookup::Entity(entity.clone()),
            },
            LookupRefResolution::Missing => return Ok(vec![]),
            LookupRefResolution::NotLookupRef => plan_datom_lookup_for_triple(triple, binding)?,
        };
        let candidates = self.current_for_lookup(head, &lookup)?;
        Ok(candidates
            .into_iter()
            .filter(|datom| datom_matches_triple(datom, seq, binding, &lookup_ref))
            .collect())
    }

    pub fn bindings_for_triples(
        &self,
        head: &KotobaCid,
        triples: &[Value],
        initial_bindings: Vec<BTreeMap<String, Value>>,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        let mut bindings = initial_bindings;
        for triple in triples {
            let seq = triple
                .as_seq()
                .ok_or_else(|| DatomicError::Query("triple clause must be vector/list".into()))?;
            let Some(seq) = crate::data_pattern_terms(seq) else {
                return Err(DatomicError::Query(format!(
                    "triple clause must have 3 terms or source plus 3 terms, got {}",
                    seq.len()
                ))
                .into());
            };
            let mut next_bindings = Vec::new();
            for binding in bindings {
                let lookup_ref = self.resolve_lookup_ref_entity_term(head, &seq[0], &binding)?;
                for datom in self.current_for_triple(head, triple, &binding)? {
                    let mut next = binding.clone();
                    if bind_datom_to_triple(&datom, seq, &binding, &lookup_ref, &mut next) {
                        next_bindings.push(next);
                    }
                }
            }
            bindings = next_bindings;
            if bindings.is_empty() {
                break;
            }
        }
        Ok(bindings)
    }

    pub fn q_triples(
        &self,
        head: &KotobaCid,
        query: &Value,
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        self.q_triples_with_inputs(head, query, &[])
    }

    pub fn q_triples_for_name(
        &self,
        ipns_name: &str,
        query: &Value,
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        self.q_triples_for_name_with_inputs(ipns_name, query, &[])
    }

    pub fn q_triples_for_name_with_inputs(
        &self,
        ipns_name: &str,
        query: &Value,
        inputs: &[Value],
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.q_triples_with_inputs(&head.cid, query, inputs)
    }

    pub fn db_from_head(&self, head: &KotobaCid) -> Result<Db, DistributedCommitError> {
        self.current_db_from_head(head)
    }

    pub fn pull_from_head(
        &self,
        head: &KotobaCid,
        pattern: Value,
        eid: Entity,
    ) -> Result<Value, DistributedCommitError> {
        self.current_db_from_head(head)?
            .pull(pattern, eid)
            .map_err(Into::into)
    }

    pub fn pull_for_name(
        &self,
        ipns_name: &str,
        pattern: Value,
        eid: Entity,
    ) -> Result<Option<Value>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.pull_from_head(&head.cid, pattern, eid).map(Some)
    }

    pub fn pull_many_from_head(
        &self,
        head: &KotobaCid,
        pattern: Value,
        eids: Vec<Entity>,
    ) -> Result<Vec<Value>, DistributedCommitError> {
        self.current_db_from_head(head)?
            .pull_many(pattern, eids)
            .map_err(Into::into)
    }

    pub fn pull_many_for_name(
        &self,
        ipns_name: &str,
        pattern: Value,
        eids: Vec<Entity>,
    ) -> Result<Option<Vec<Value>>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.pull_many_from_head(&head.cid, pattern, eids).map(Some)
    }

    pub fn entity_from_head(
        &self,
        head: &KotobaCid,
        eid: Entity,
    ) -> Result<Value, DistributedCommitError> {
        self.current_db_from_head(head)?
            .entity(eid)
            .map_err(Into::into)
    }

    pub fn entity_for_name(
        &self,
        ipns_name: &str,
        eid: Entity,
    ) -> Result<Option<Value>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.entity_from_head(&head.cid, eid).map(Some)
    }

    pub fn pull_as_of_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        pattern: Value,
        eid: Entity,
    ) -> Result<Value, DistributedCommitError> {
        self.db_as_of_tx(head, tx_cid)?
            .pull(pattern, eid)
            .map_err(Into::into)
    }

    pub fn pull_as_of_tx_for_name(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
        pattern: Value,
        eid: Entity,
    ) -> Result<Option<Value>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.pull_as_of_tx(&head.cid, tx_cid, pattern, eid)
            .map(Some)
    }

    pub fn pull_since_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        pattern: Value,
        eid: Entity,
    ) -> Result<Value, DistributedCommitError> {
        self.db_since_tx(head, tx_cid)?
            .pull(pattern, eid)
            .map_err(Into::into)
    }

    pub fn pull_since_tx_for_name(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
        pattern: Value,
        eid: Entity,
    ) -> Result<Option<Value>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.pull_since_tx(&head.cid, tx_cid, pattern, eid)
            .map(Some)
    }

    pub fn db_as_of_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
    ) -> Result<Db, DistributedCommitError> {
        let Some(as_of_head) = self.head_cid_as_of_tx(head, tx_cid)? else {
            return Err(DatomicError::Query(format!(
                "as-of transaction not found: {}",
                tx_cid.to_multibase()
            ))
            .into());
        };
        self.current_db_from_head(&as_of_head)
    }

    pub fn db_as_of_tx_for_name(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
    ) -> Result<Option<Db>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.db_as_of_tx(&head.cid, tx_cid).map(Some)
    }

    pub fn db_since_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
    ) -> Result<Db, DistributedCommitError> {
        self.since_db_from_head(head, tx_cid)
    }

    pub fn db_since_tx_for_name(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
    ) -> Result<Option<Db>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(None);
        };
        self.db_since_tx(&head.cid, tx_cid).map(Some)
    }

    pub fn history_db_from_head(&self, head: &KotobaCid) -> Result<Db, DistributedCommitError> {
        self.history_db_from_head_cid(head)
    }

    pub fn history_db_as_of_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
    ) -> Result<Db, DistributedCommitError> {
        let Some(as_of_head) = self.head_cid_as_of_tx(head, tx_cid)? else {
            return Err(DatomicError::Query(format!(
                "as-of transaction not found: {}",
                tx_cid.to_multibase()
            ))
            .into());
        };
        self.history_db_from_head_cid(&as_of_head)
    }

    pub fn history_db_since_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
    ) -> Result<Db, DistributedCommitError> {
        self.since_db_from_head(head, tx_cid)
    }

    pub fn q_triples_with_inputs(
        &self,
        head: &KotobaCid,
        query: &Value,
        inputs: &[Value],
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        let query = crate::query_map(query)?;
        let find = query_vec(&query, ":find")?;
        let where_clauses = query_vec(&query, ":where")?;
        let find_items = parse_distributed_find_items(find)?;
        let rules = match query.get(&query_key(":in")) {
            Some(in_forms) => distributed_rules_from_inputs(in_forms, inputs)?,
            None => Vec::new(),
        };
        let initial_bindings = match query.get(&query_key(":in")) {
            Some(in_forms) => bind_query_inputs(in_forms, inputs)?,
            None => vec![BTreeMap::new()],
        };
        let bindings = self.bindings_for_where(head, where_clauses, initial_bindings, &rules)?;
        let pull_db = find_items
            .iter()
            .any(|item| matches!(item, DistributedFindItem::Pull { .. }))
            .then(|| self.current_db_from_head(head))
            .transpose()?;
        if find_items.iter().any(DistributedFindItem::is_aggregate) {
            let with_items = query
                .get(&query_key(":with"))
                .map(query_value_vec)
                .transpose()?
                .unwrap_or_default();
            return aggregate_distributed_rows(
                &find_items,
                &with_items,
                bindings,
                pull_db.as_ref(),
            )
            .and_then(|rows| crate::query_result_window(&query, find, rows).map_err(Into::into));
        }
        let mut rows = BTreeSet::new();
        for binding in bindings {
            let mut row = Vec::new();
            for item in &find_items {
                row.push(resolve_distributed_find_item(
                    item,
                    &binding,
                    pull_db.as_ref(),
                )?);
            }
            rows.insert(row);
        }
        crate::query_result_window(&query, find, rows.into_iter().collect()).map_err(Into::into)
    }

    pub fn q_triples_as_of_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        query: &Value,
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        self.q_triples_as_of_tx_with_inputs(head, tx_cid, query, &[])
    }

    pub fn q_triples_as_of_tx_for_name(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
        query: &Value,
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        self.q_triples_as_of_tx_for_name_with_inputs(ipns_name, tx_cid, query, &[])
    }

    pub fn q_triples_as_of_tx_for_name_with_inputs(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
        query: &Value,
        inputs: &[Value],
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.q_triples_as_of_tx_with_inputs(&head.cid, tx_cid, query, inputs)
    }

    pub fn q_triples_as_of_tx_with_inputs(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        query: &Value,
        inputs: &[Value],
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        let Some(as_of_head) = self.head_cid_as_of_tx(head, tx_cid)? else {
            return Err(DatomicError::Query(format!(
                "as-of transaction not found: {}",
                tx_cid.to_multibase()
            ))
            .into());
        };
        self.q_triples_with_inputs(&as_of_head, query, inputs)
    }

    pub fn q_triples_since_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        query: &Value,
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        self.q_triples_since_tx_with_inputs(head, tx_cid, query, &[])
    }

    pub fn q_triples_since_tx_for_name(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
        query: &Value,
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        self.q_triples_since_tx_for_name_with_inputs(ipns_name, tx_cid, query, &[])
    }

    pub fn q_triples_since_tx_for_name_with_inputs(
        &self,
        ipns_name: &str,
        tx_cid: &KotobaCid,
        query: &Value,
        inputs: &[Value],
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        let Some(head) = self.resolve_head(ipns_name)? else {
            return Ok(vec![]);
        };
        self.q_triples_since_tx_with_inputs(&head.cid, tx_cid, query, inputs)
    }

    pub fn q_triples_since_tx_with_inputs(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        query: &Value,
        inputs: &[Value],
    ) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
        let db = self.since_db_from_head(head, tx_cid)?;
        crate::q(query.clone(), &db, inputs).map_err(Into::into)
    }

    fn current_db_from_head(&self, head: &KotobaCid) -> Result<Db, DistributedCommitError> {
        let history_db = self.history_db_from_head_cid(head)?;
        let history_datoms = history_db.datoms();
        let datoms = current_datoms(&history_datoms);
        Ok(Db::from_datoms(datoms, history_db.basis_t))
    }

    fn history_db_from_head_cid(&self, head: &KotobaCid) -> Result<Db, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        let basis_t = chain.first().map(|commit| commit.tx_cid.clone());
        let mut history = Vec::new();
        for commit in chain.into_iter().rev() {
            history.extend(datoms_from_commit(&commit, self.store)?);
        }
        Ok(Db::from_datoms(history, basis_t))
    }

    fn head_cid_as_of_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
    ) -> Result<Option<KotobaCid>, DistributedCommitError> {
        Ok(self
            .commit_chain_from_head(head)?
            .into_iter()
            .find(|commit| &commit.tx_cid == tx_cid)
            .map(|commit| commit.cid))
    }

    fn since_db_from_head(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
    ) -> Result<Db, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        if !chain.iter().any(|commit| &commit.tx_cid == tx_cid) {
            return Err(DatomicError::Query(format!(
                "since transaction not found: {}",
                tx_cid.to_multibase()
            ))
            .into());
        }
        let basis_t = chain.first().map(|commit| commit.tx_cid.clone());
        let mut seen = false;
        let mut datoms = Vec::new();
        for commit in chain.into_iter().rev() {
            if commit.tx_cid == *tx_cid {
                seen = true;
                continue;
            }
            if seen {
                datoms.extend(datoms_from_commit(&commit, self.store)?);
            }
        }
        Ok(Db::from_datoms(datoms, basis_t))
    }

    fn bindings_for_where(
        &self,
        head: &KotobaCid,
        clauses: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        self.bindings_for_where_at_depth(head, clauses, bindings, rules, 0)
    }

    fn bindings_for_where_at_depth(
        &self,
        head: &KotobaCid,
        clauses: &[Value],
        mut bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        for clause in clauses {
            bindings = self.eval_where_clause(head, clause, bindings, rules, rule_depth)?;
            if bindings.is_empty() {
                break;
            }
        }
        Ok(bindings)
    }

    fn eval_where_clause(
        &self,
        head: &KotobaCid,
        clause: &Value,
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        let seq = clause.as_seq().ok_or_else(|| {
            DatomicError::Query("distributed q_triples where clause must be a vector/list".into())
        })?;
        if matches!(seq.first().and_then(Value::as_symbol), Some(symbol) if symbol.name == "not") {
            return self.eval_not_clause(head, seq, bindings, rules, rule_depth);
        }
        if matches!(seq.first().and_then(Value::as_symbol), Some(symbol) if symbol.name == "not-join")
        {
            return self.eval_not_join_clause(head, seq, bindings, rules, rule_depth);
        }
        if matches!(seq.first().and_then(Value::as_symbol), Some(symbol) if symbol.name == "or") {
            return self.eval_or_clause(head, seq, bindings, rules, rule_depth);
        }
        if matches!(seq.first().and_then(Value::as_symbol), Some(symbol) if symbol.name == "or-join")
        {
            return self.eval_or_join_clause(head, seq, bindings, rules, rule_depth);
        }
        if let Some(rule_name) = distributed_rule_invocation_name(seq, rules) {
            return self.eval_rule_invocation(
                rule_name,
                &seq[1..],
                head,
                rules,
                bindings,
                rule_depth,
            );
        }
        if seq.len() == 2 {
            if let Some(expr) = seq[0].as_seq() {
                return self.eval_function_binding(head, expr, &seq[1], bindings);
            }
        }
        if crate::data_pattern_terms(seq).is_some() {
            return self.bindings_for_triples(head, std::slice::from_ref(clause), bindings);
        }
        if seq.len() == 1 {
            if let Some(pred) = seq[0].as_seq() {
                return self.eval_predicate(head, pred, bindings);
            }
        }
        Err(DatomicError::UnsupportedOperation(kotoba_edn::to_string(clause)).into())
    }

    fn eval_not_clause(
        &self,
        head: &KotobaCid,
        not_clause: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if not_clause.len() < 2 {
            return Err(
                DatomicError::UnsupportedOperation(kotoba_edn::to_string(&Value::List(
                    not_clause.to_vec(),
                )))
                .into(),
            );
        }
        let inner_clauses = &not_clause[1..];
        let mut out = Vec::new();
        for binding in bindings {
            let probe = self.bindings_for_where_at_depth(
                head,
                inner_clauses,
                vec![binding.clone()],
                rules,
                rule_depth,
            )?;
            if probe.is_empty() {
                out.push(binding);
            }
        }
        Ok(out)
    }

    fn eval_not_join_clause(
        &self,
        head: &KotobaCid,
        not_join_clause: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if not_join_clause.len() < 3 {
            return Err(
                DatomicError::UnsupportedOperation(kotoba_edn::to_string(&Value::List(
                    not_join_clause.to_vec(),
                )))
                .into(),
            );
        }
        let join_vars = query_join_vars(&not_join_clause[1])?;
        let inner_clauses = &not_join_clause[2..];
        let mut out = Vec::new();
        for binding in bindings {
            let seed = project_query_binding(&binding, &join_vars)?;
            let probe = self.bindings_for_where_at_depth(
                head,
                inner_clauses,
                vec![seed],
                rules,
                rule_depth,
            )?;
            if probe.is_empty() {
                out.push(binding);
            }
        }
        Ok(out)
    }

    fn eval_or_clause(
        &self,
        head: &KotobaCid,
        or_clause: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if or_clause.len() < 2 {
            return Err(
                DatomicError::UnsupportedOperation(kotoba_edn::to_string(&Value::List(
                    or_clause.to_vec(),
                )))
                .into(),
            );
        }
        let mut out = BTreeSet::new();
        for binding in bindings {
            for branch in &or_clause[1..] {
                for next in
                    self.eval_or_branch(head, branch, vec![binding.clone()], rules, rule_depth)?
                {
                    out.insert(next);
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    fn eval_or_join_clause(
        &self,
        head: &KotobaCid,
        or_join_clause: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if or_join_clause.len() < 3 {
            return Err(
                DatomicError::UnsupportedOperation(kotoba_edn::to_string(&Value::List(
                    or_join_clause.to_vec(),
                )))
                .into(),
            );
        }
        let join_vars = query_join_vars(&or_join_clause[1])?;
        let mut out = BTreeSet::new();
        for binding in bindings {
            let seed = project_query_binding(&binding, &join_vars)?;
            for branch in &or_join_clause[2..] {
                for branch_binding in
                    self.eval_or_branch(head, branch, vec![seed.clone()], rules, rule_depth)?
                {
                    if let Some(merged) = merge_query_bindings(&binding, &branch_binding) {
                        out.insert(merged);
                    }
                }
            }
        }
        Ok(out.into_iter().collect())
    }

    fn eval_or_branch(
        &self,
        head: &KotobaCid,
        branch: &Value,
        bindings: Vec<BTreeMap<String, Value>>,
        rules: &[DistributedQueryRule],
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        let seq = branch.as_seq().ok_or_else(|| {
            DatomicError::UnsupportedOperation(format!(
                "distributed or branch must be a clause: {}",
                kotoba_edn::to_string(branch)
            ))
        })?;
        if matches!(seq.first().and_then(Value::as_symbol), Some(symbol) if symbol.name == "and") {
            self.bindings_for_where_at_depth(head, &seq[1..], bindings, rules, rule_depth)
        } else {
            self.eval_where_clause(head, branch, bindings, rules, rule_depth)
        }
    }

    fn eval_rule_invocation(
        &self,
        name: &str,
        call_args: &[Value],
        head: &KotobaCid,
        rules: &[DistributedQueryRule],
        bindings: Vec<BTreeMap<String, Value>>,
        rule_depth: usize,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if rule_depth >= DISTRIBUTED_RULE_RECURSION_LIMIT {
            return Err(
                DatomicError::Query("distributed rule recursion limit exceeded".into()).into(),
            );
        }
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
                    if let Some(value) = resolve_query_value(call_arg, &binding) {
                        if !bind_term(rule_arg, value, &mut seed) {
                            seed_matches = false;
                            break;
                        }
                    }
                }
                if !seed_matches {
                    continue;
                }
                let rule_bindings = self.bindings_for_where_at_depth(
                    head,
                    &rule.clauses,
                    vec![seed],
                    rules,
                    rule_depth + 1,
                )?;
                for rule_binding in rule_bindings {
                    let mut next = binding.clone();
                    let mut keep = true;
                    for (call_arg, rule_arg) in call_args.iter().zip(&rule.args) {
                        let value = required_query_value(rule_arg, &rule_binding)?;
                        if !bind_term(call_arg, value, &mut next) {
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

    fn eval_predicate(
        &self,
        head: &KotobaCid,
        pred: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if pred.len() == 4
            && matches!(pred[0].as_symbol(), Some(symbol) if symbol.name == "missing?")
        {
            return self.eval_missing_predicate(head, pred, bindings);
        }
        if pred.len() == 2 {
            let op = pred[0]
                .as_symbol()
                .map(|symbol| symbol.to_qualified())
                .or_else(|| pred[0].as_keyword().map(|keyword| keyword.to_qualified()))
                .ok_or_else(|| DatomicError::Query("predicate op must be symbol".into()))?;
            let mut out = Vec::new();
            for binding in bindings {
                let value = required_query_value(&pred[1], &binding)?;
                if crate::query_unary_predicate(&op, &value)? {
                    out.push(binding);
                }
            }
            return Ok(out);
        }
        if pred.len() < 3 {
            return Err(
                DatomicError::UnsupportedOperation(kotoba_edn::to_string(&Value::Vector(
                    pred.to_vec(),
                )))
                .into(),
            );
        }
        let op = pred[0]
            .as_symbol()
            .map(|symbol| symbol.to_qualified())
            .or_else(|| pred[0].as_keyword().map(|keyword| keyword.to_qualified()))
            .ok_or_else(|| DatomicError::Query("predicate op must be symbol".into()))?;
        let mut out = Vec::new();
        for binding in bindings {
            let values = pred[1..]
                .iter()
                .map(|term| required_query_value(term, &binding))
                .collect::<Result<Vec<_>, _>>()?;
            if crate::query_variadic_predicate(&op, &values)? {
                out.push(binding);
            }
        }
        Ok(out)
    }

    fn eval_missing_predicate(
        &self,
        head: &KotobaCid,
        pred: &[Value],
        bindings: Vec<BTreeMap<String, Value>>,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        if !crate::is_query_source_symbol(&pred[1]) {
            return Err(DatomicError::Query("missing? first argument must be $".into()).into());
        }
        let attr = attr_string(&pred[3]).ok_or(DatomicError::AttributeMustBeKeyword)?;
        let mut out = Vec::new();
        for binding in bindings {
            let entity = required_query_value(&pred[2], &binding)?;
            let Some(eid) = entity_value_to_cid(&entity) else {
                return Err(DatomicError::Query(format!(
                    "missing? entity must resolve to a CID string or #cid, got {}",
                    kotoba_edn::to_string(&entity)
                ))
                .into());
            };
            if self
                .current_for_entity_attribute(head, &eid, &attr)?
                .is_empty()
            {
                out.push(binding);
            }
        }
        Ok(out)
    }

    fn eval_function_binding(
        &self,
        head: &KotobaCid,
        expr: &[Value],
        target: &Value,
        bindings: Vec<BTreeMap<String, Value>>,
    ) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
        let op = expr
            .first()
            .and_then(Value::as_symbol)
            .map(|symbol| symbol.to_qualified())
            .ok_or_else(|| DatomicError::Query("function op must be a symbol".into()))?;
        let args = &expr[1..];
        let mut out = Vec::new();
        for binding in bindings {
            if op == "fulltext" {
                for value in self.eval_fulltext_function(head, args, &binding)? {
                    let mut next = binding.clone();
                    if bind_relation_or_function_target(target, value, &mut next)? {
                        out.push(next);
                    }
                }
                continue;
            }
            let value = self.eval_query_function(head, &op, args, &binding)?;
            let mut next = binding;
            if bind_function_target(target, value, &mut next)? {
                out.push(next);
            }
        }
        Ok(out)
    }

    fn eval_query_function(
        &self,
        head: &KotobaCid,
        op: &str,
        args: &[Value],
        binding: &BTreeMap<String, Value>,
    ) -> Result<Value, DistributedCommitError> {
        let op = crate::query_core_op(op);
        match op {
            "ground" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("ground expects one argument".into()).into());
                }
                Ok(args[0].clone())
            }
            "identity" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("identity expects one argument".into()).into());
                }
                required_query_value(&args[0], binding)
            }
            "name" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("name expects one argument".into()).into());
                }
                crate::pull_name_value(required_query_value(&args[0], binding)?).map_err(Into::into)
            }
            "namespace" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("namespace expects one argument".into()).into());
                }
                crate::pull_namespace_value(required_query_value(&args[0], binding)?)
                    .map_err(Into::into)
            }
            "str" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .map(crate::query_str_value),
            "subs" | "clojure.core/subs" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_subs_value(values).map_err(Into::into)),
            "split" | "clojure.string/split" | "str/split" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_split_value(values).map_err(Into::into)),
            "join" | "clojure.string/join" | "str/join" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_join_value(values).map_err(Into::into)),
            "replace" | "clojure.string/replace" | "str/replace" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_replace_value(values).map_err(Into::into)),
            "re-find" | "clojure.core/re-find" | "re-matches" | "clojure.core/re-matches" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_regex_value(op, values).map_err(Into::into)),
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
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_string_case_value(op, values).map_err(Into::into)),
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
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_trim_value(op, values).map_err(Into::into)),
            "keyword" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_keyword_value(values).map_err(Into::into)),
            "get" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_get_value(values).map_err(Into::into)),
            "get-in" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_get_in_value(values).map_err(Into::into)),
            "assoc-in" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_assoc_in_value(values).map_err(Into::into)),
            "update" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_update_value(values).map_err(Into::into)),
            "update-in" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_update_in_value(values).map_err(Into::into)),
            "vector" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Vector),
            "list" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::List),
            "hash-set" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .map(crate::query_hash_set_value),
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
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_set_operation_value(op, values).map_err(Into::into)
                }),
            "hash-map" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_hash_map_value(values).map_err(Into::into)),
            "keys" | "vals" | "merge" | "select-keys" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_map_operation_value(op, values).map_err(Into::into)
                }),
            "every?" | "not-every?" | "not-any?" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_collection_predicate_value(op, values)
                        .map(Value::Bool)
                        .map_err(Into::into)
                }),
            "not" | "boolean" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_truth_function_value(op, values).map_err(Into::into)
                }),
            _ if crate::is_query_predicate_function_op(op) => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_predicate_function_value(op, values).map_err(Into::into)
                }),
            "count" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("count expects one argument".into()).into());
                }
                crate::query_count_value(required_query_value(&args[0], binding)?)
                    .map_err(Into::into)
            }
            "not-empty" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("not-empty expects one argument".into()).into());
                }
                crate::query_not_empty_value(required_query_value(&args[0], binding)?)
                    .map_err(Into::into)
            }
            "seq" | "first" | "last" | "rest" | "next" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query(format!("{op} expects one argument")).into());
                }
                crate::query_collection_value(op, required_query_value(&args[0], binding)?)
                    .map_err(Into::into)
            }
            "nth" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_nth_value(values).map_err(Into::into)),
            "cons" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_cons_value(values).map_err(Into::into)),
            "take" | "drop" | "subvec" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_collection_slice_value(op, values).map_err(Into::into)
                }),
            "reverse" | "sort" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| {
                    crate::query_collection_order_value(op, values).map_err(Into::into)
                }),
            "conj" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_conj_value(values).map_err(Into::into)),
            "assoc" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_assoc_value(values).map_err(Into::into)),
            "dissoc" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_dissoc_value(values).map_err(Into::into)),
            "disj" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .and_then(|values| crate::query_disj_value(values).map_err(Into::into)),
            "inc" | "dec" | "abs" | "+" | "-" | "*" | "quot" | "rem" | "mod" | "min" | "max" => {
                args.iter()
                    .map(|arg| required_query_value(arg, binding))
                    .collect::<Result<Vec<_>, _>>()
                    .and_then(|values| {
                        crate::query_arithmetic_value(op, values).map_err(Into::into)
                    })
            }
            "tuple" => args
                .iter()
                .map(|arg| required_query_value(arg, binding))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Vector),
            "untuple" => {
                if args.len() != 1 {
                    return Err(DatomicError::Query("untuple expects one argument".into()).into());
                }
                let tuple = required_query_value(&args[0], binding)?;
                match tuple {
                    Value::Vector(values) | Value::List(values) => Ok(Value::Vector(values)),
                    other => Err(DatomicError::Query(format!(
                        "untuple expects a tuple value, got {}",
                        kotoba_edn::to_string(&other)
                    ))
                    .into()),
                }
            }
            "get-else" => {
                if args.len() != 4 || !crate::is_query_source_symbol(&args[0]) {
                    return Err(DatomicError::Query(
                        "get-else expects ($ entity attr default)".into(),
                    )
                    .into());
                }
                let entity = required_query_value(&args[1], binding)?;
                let Some(eid) = entity_value_to_cid(&entity) else {
                    return Err(DatomicError::Query(format!(
                        "get-else entity must resolve to a CID string or #cid, got {}",
                        kotoba_edn::to_string(&entity)
                    ))
                    .into());
                };
                let attr = attr_string(&args[2]).ok_or(DatomicError::AttributeMustBeKeyword)?;
                Ok(self
                    .db_value_from_head(head, &eid, &attr)?
                    .unwrap_or_else(|| args[3].clone()))
            }
            "get-some" => {
                if args.len() < 3 || !crate::is_query_source_symbol(&args[0]) {
                    return Err(
                        DatomicError::Query("get-some expects ($ entity attr+)".into()).into(),
                    );
                }
                let entity = required_query_value(&args[1], binding)?;
                let Some(eid) = entity_value_to_cid(&entity) else {
                    return Err(DatomicError::Query(format!(
                        "get-some entity must resolve to a CID string or #cid, got {}",
                        kotoba_edn::to_string(&entity)
                    ))
                    .into());
                };
                for attr_arg in &args[2..] {
                    let attr = attr_string(attr_arg).ok_or(DatomicError::AttributeMustBeKeyword)?;
                    if let Some(value) = self.db_value_from_head(head, &eid, &attr)? {
                        return Ok(Value::Vector(vec![attr_value(&attr), value]));
                    }
                }
                Ok(Value::Nil)
            }
            other => Err(DatomicError::UnsupportedOperation(other.into()).into()),
        }
    }

    fn eval_fulltext_function(
        &self,
        head: &KotobaCid,
        args: &[Value],
        binding: &BTreeMap<String, Value>,
    ) -> Result<Vec<Value>, DistributedCommitError> {
        if args.len() != 3 || !crate::is_query_source_symbol(&args[0]) {
            return Err(
                DatomicError::Query("fulltext expects ($ attr search-string)".into()).into(),
            );
        }
        let attr = attr_string(&args[1]).ok_or(DatomicError::AttributeMustBeKeyword)?;
        let search = required_query_value(&args[2], binding)?;
        let needle = search.as_string().ok_or_else(|| {
            DatomicError::Query(format!(
                "fulltext search term must be a string, got {}",
                kotoba_edn::to_string(&search)
            ))
        })?;
        let needle = needle.to_ascii_lowercase();
        if needle.is_empty() {
            return Ok(Vec::new());
        }
        let mut rows = BTreeSet::new();
        for datom in self.current_for_attribute(head, &attr)? {
            let Some(haystack) = datom.v.as_string() else {
                continue;
            };
            let haystack = haystack.to_ascii_lowercase();
            let score = haystack.matches(&needle).count() as i64;
            if score > 0 {
                rows.insert(Value::Vector(vec![
                    cid_value(&datom.e),
                    datom.v,
                    cid_value(&datom.t),
                    Value::Integer(score),
                ]));
            }
        }
        Ok(rows.into_iter().collect())
    }

    fn db_value_from_head(
        &self,
        head: &KotobaCid,
        eid: &KotobaCid,
        attr: &str,
    ) -> Result<Option<Value>, DistributedCommitError> {
        Ok(self
            .current_for_entity_attribute(head, eid, attr)?
            .into_iter()
            .next()
            .map(|datom| datom.v))
    }

    fn resolve_lookup_ref_entity_term(
        &self,
        head: &KotobaCid,
        term: &Value,
        binding: &BTreeMap<String, Value>,
    ) -> Result<LookupRefResolution, DistributedCommitError> {
        let Some((attr, value)) = lookup_ref_parts(term, binding) else {
            return Ok(LookupRefResolution::NotLookupRef);
        };
        let Some(datom) = self
            .current_for_attribute_value(head, &attr, &value)?
            .into_iter()
            .next()
        else {
            return Ok(LookupRefResolution::Missing);
        };
        Ok(LookupRefResolution::Resolved(datom.e))
    }

    fn commit_chain_from_head(
        &self,
        head: &KotobaCid,
    ) -> Result<Vec<DistributedDatomCommit>, DistributedCommitError> {
        let mut chain = Vec::new();
        let mut current = Some(head.clone());
        while let Some(cid) = current {
            let Some(commit) = DistributedDatomCommit::load(&cid, self.store)? else {
                return Err(DistributedCommitError::MissingCommit(cid.to_multibase()));
            };
            current = commit.prev.clone();
            chain.push(commit);
        }
        Ok(chain)
    }

    fn history_from_index_prefix(
        &self,
        head: &KotobaCid,
        root_name: &'static str,
        prefix: &[u8],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        let mut datoms = Vec::new();
        for commit in chain.into_iter().rev() {
            datoms.extend(datoms_from_index_prefix(
                &commit, root_name, prefix, self.store,
            )?);
        }
        Ok(datoms)
    }

    fn history_from_index_seek(
        &self,
        head: &KotobaCid,
        root_name: &'static str,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        let start = index_components_prefix(root_name, components)?.unwrap_or_default();
        let mut datoms = Vec::new();
        for commit in chain.into_iter().rev() {
            datoms.extend(datoms_from_index_seek(
                &commit, root_name, &start, self.store,
            )?);
        }
        Ok(datoms)
    }

    fn history_from_index_range(
        &self,
        head: &KotobaCid,
        root_name: &'static str,
        start_key: &[u8],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        let mut datoms = Vec::new();
        for commit in chain.into_iter().rev() {
            datoms.extend(datoms_from_index_seek(
                &commit, root_name, start_key, self.store,
            )?);
        }
        Ok(datoms)
    }

    fn history_from_index_prefix_since_tx(
        &self,
        head: &KotobaCid,
        tx_cid: &KotobaCid,
        root_name: &'static str,
        components: &[Value],
    ) -> Result<Vec<Datom>, DistributedCommitError> {
        let chain = self.commit_chain_from_head(head)?;
        if !chain.iter().any(|commit| &commit.tx_cid == tx_cid) {
            return Err(DatomicError::Query(format!(
                "since transaction not found: {}",
                tx_cid.to_multibase()
            ))
            .into());
        }
        let prefix = index_components_prefix(root_name, components)?;
        let mut seen = false;
        let mut datoms = Vec::new();
        for commit in chain.into_iter().rev() {
            if commit.tx_cid == *tx_cid {
                seen = true;
                continue;
            }
            if !seen {
                continue;
            }
            match &prefix {
                Some(prefix) => datoms.extend(datoms_from_index_prefix(
                    &commit, root_name, prefix, self.store,
                )?),
                None => datoms.extend(datoms_from_commit(&commit, self.store)?),
            }
        }
        Ok(datoms)
    }
}

pub struct DistributedCommitWriter<'a, R>
where
    R: IpnsRegistry + ?Sized,
{
    store: &'a dyn BlockStore,
    ipns: &'a R,
}

impl<'a, R> DistributedCommitWriter<'a, R>
where
    R: IpnsRegistry + ?Sized,
{
    pub fn new(store: &'a dyn BlockStore, ipns: &'a R) -> Self {
        Self { store, ipns }
    }

    pub fn commit_datoms(
        &self,
        req: CommitDatomsRequest,
    ) -> Result<CommitReport, DistributedCommitError> {
        let name = IpnsName::new(req.ipns_name.clone());
        let current = match self.ipns.resolve(&name) {
            Ok(record) => Some(record),
            Err(IpnsRegistryError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let current_value = current.as_ref().map(|r| r.value.clone());
        let expected = req.expected_parent.as_ref().map(KotobaCid::to_multibase);
        if current_value != expected {
            return Err(DistributedCommitError::StaleParent {
                name: req.ipns_name,
                expected,
                current: current_value,
            });
        }

        let seed_roots = build_datom_roots(&req.datoms, self.store)?;
        let root_seed = seed_roots
            .get(ROOT_EAVT)
            .cloned()
            .unwrap_or_else(KotobaCid::default);
        let tx_cid = req.tx_cid.unwrap_or_else(|| {
            derive_tx_cid(
                &req.graph,
                &root_seed,
                req.expected_parent.as_ref(),
                req.seq,
            )
        });
        let datoms = req
            .datoms
            .into_iter()
            .map(|mut datom| {
                datom.t = tx_cid.clone();
                datom
            })
            .collect::<Vec<_>>();
        let datom_count = datoms.len();
        let roots = build_datom_roots(&datoms, self.store)?;
        let commit = DistributedDatomCommit::seal(
            req.graph,
            tx_cid.clone(),
            req.expected_parent,
            req.author,
            req.seq,
            roots,
            req.cacao_proof_cid,
        )?;
        commit.persist(self.store)?;

        let commit_ipfs_cid = kotoba_ipfs::parse_cid(&commit.cid.to_multibase())
            .map_err(|e| DistributedCommitError::InvalidCommitCid(e.to_string()))?;
        let mut ipns_record = IpnsRecord::new(
            name.0.clone(),
            &commit_ipfs_cid,
            current.map(|r| r.sequence + 1).unwrap_or(1),
            req.valid_until,
        );
        ipns_record.ttl_secs = req.ttl_secs;
        ipns_record.controller_did = req.ipns_controller_did;
        if let Some(signing_key) = &req.ipns_signing_key {
            ipns_record
                .sign_ed25519(signing_key)
                .map_err(|e| DistributedCommitError::IpnsSignature(e.to_string()))?;
        }
        self.ipns.publish(ipns_record.clone())?;

        Ok(CommitReport {
            commit,
            ipns_record,
            datom_count,
        })
    }

    pub async fn transact(
        &self,
        req: DistributedTransactRequest,
    ) -> Result<DistributedTransactReport, DistributedCommitError> {
        self.transact_with(req, |_, _, _| Ok(())).await
    }

    pub async fn transact_with<F>(
        &self,
        req: DistributedTransactRequest,
        augment_datoms: F,
    ) -> Result<DistributedTransactReport, DistributedCommitError>
    where
        F: FnOnce(
            &TransactReport,
            &DistributedTransactContext,
            &mut Vec<Datom>,
        ) -> Result<(), DistributedCommitError>,
    {
        self.transact_with_tx_fns(req, |_| Ok(()), augment_datoms)
            .await
    }

    pub async fn transact_with_tx_fns<F, G>(
        &self,
        req: DistributedTransactRequest,
        register_tx_fns: F,
        augment_datoms: G,
    ) -> Result<DistributedTransactReport, DistributedCommitError>
    where
        F: FnOnce(&Connection) -> Result<(), DistributedCommitError>,
        G: FnOnce(
            &TransactReport,
            &DistributedTransactContext,
            &mut Vec<Datom>,
        ) -> Result<(), DistributedCommitError>,
    {
        let name = IpnsName::new(req.ipns_name.clone());
        let current = match self.ipns.resolve(&name) {
            Ok(record) => Some(record),
            Err(IpnsRegistryError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        };
        let expected_parent = req.expected_parent.or_else(|| {
            current
                .as_ref()
                .and_then(|record| KotobaCid::from_multibase(&record.value))
        });
        let db_before = match &expected_parent {
            Some(parent) => {
                DistributedDatomReader::new(self.store, self.ipns).db_from_head(parent)?
            }
            None => Db::from_datoms(vec![], None),
        };
        let conn = Connection::from_datoms(db_before.all_datoms());
        register_tx_fns(&conn)?;
        let transact = conn.transact(req.tx_data).await?;
        let seq = current
            .as_ref()
            .map(|record| record.sequence + 1)
            .unwrap_or(1);
        let context = DistributedTransactContext {
            ipns_name: req.ipns_name.clone(),
            graph: req.graph.clone(),
            expected_parent: expected_parent.clone(),
            seq,
        };
        let mut datoms = transact.tx_data.clone();
        augment_datoms(&transact, &context, &mut datoms)?;
        let commit = self.commit_datoms(CommitDatomsRequest {
            ipns_name: req.ipns_name,
            graph: req.graph,
            datoms: datoms.clone(),
            expected_parent,
            tx_cid: Some(transact.tx_cid.clone()),
            author: req.author,
            seq,
            valid_until: req.valid_until,
            ttl_secs: req.ttl_secs,
            cacao_proof_cid: req.cacao_proof_cid,
            ipns_controller_did: req.ipns_controller_did,
            ipns_signing_key: req.ipns_signing_key,
        })?;
        Ok(DistributedTransactReport {
            transact,
            commit,
            datoms,
            context,
        })
    }
}

pub struct CommitDatomsRequest {
    pub ipns_name: String,
    pub graph: KotobaCid,
    pub datoms: Vec<Datom>,
    pub expected_parent: Option<KotobaCid>,
    pub tx_cid: Option<KotobaCid>,
    pub author: String,
    pub seq: u64,
    pub valid_until: String,
    pub ttl_secs: Option<u64>,
    pub cacao_proof_cid: Option<KotobaCid>,
    pub ipns_controller_did: Option<String>,
    pub ipns_signing_key: Option<ed25519_dalek::SigningKey>,
}

pub struct DistributedTransactRequest {
    pub ipns_name: String,
    pub graph: KotobaCid,
    pub tx_data: Value,
    pub expected_parent: Option<KotobaCid>,
    pub author: String,
    pub valid_until: String,
    pub ttl_secs: Option<u64>,
    pub cacao_proof_cid: Option<KotobaCid>,
    pub ipns_controller_did: Option<String>,
    pub ipns_signing_key: Option<ed25519_dalek::SigningKey>,
}

pub struct DistributedTransactReport {
    pub transact: TransactReport,
    pub commit: CommitReport,
    pub datoms: Vec<Datom>,
    pub context: DistributedTransactContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedTransactContext {
    pub ipns_name: String,
    pub graph: KotobaCid,
    pub expected_parent: Option<KotobaCid>,
    pub seq: u64,
}

impl DistributedDatomCommit {
    pub fn seal(
        graph: KotobaCid,
        tx_cid: KotobaCid,
        prev: Option<KotobaCid>,
        author: String,
        seq: u64,
        index_roots: HashMap<String, KotobaCid>,
        cacao_proof_cid: Option<KotobaCid>,
    ) -> Result<Self, DistributedCommitError> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut commit = Self {
            cid: KotobaCid::default(),
            graph,
            tx_cid,
            prev,
            author,
            seq,
            ts,
            index_roots,
            cacao_proof_cid,
        };
        commit.cid = commit.derived_cid()?;
        Ok(commit)
    }

    pub fn derived_cid(&self) -> Result<KotobaCid, DistributedCommitError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| DistributedCommitError::Cbor(e.to_string()))?;
        Ok(KotobaCid::from_bytes(&bytes))
    }

    pub fn persist(&self, store: &dyn BlockStore) -> Result<KotobaCid, DistributedCommitError> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)
            .map_err(|e| DistributedCommitError::Cbor(e.to_string()))?;
        let cid = KotobaCid::from_bytes(&bytes);
        if cid != self.cid {
            return Err(DistributedCommitError::Store(anyhow::anyhow!(
                "commit CID mismatch"
            )));
        }
        store.put(&cid, &bytes)?;
        Ok(cid)
    }

    pub fn load(
        cid: &KotobaCid,
        store: &dyn BlockStore,
    ) -> Result<Option<Self>, DistributedCommitError> {
        let Some(bytes) = store.get(cid)? else {
            return Ok(None);
        };
        let mut commit: Self = ciborium::from_reader(&bytes[..])
            .map_err(|e| DistributedCommitError::Cbor(e.to_string()))?;
        commit.cid = cid.clone();
        Ok(Some(commit))
    }
}

fn build_datom_roots(
    datoms: &[Datom],
    store: &dyn BlockStore,
) -> Result<HashMap<String, KotobaCid>, DistributedCommitError> {
    let mut eavt = Vec::with_capacity(datoms.len());
    let mut aevt = Vec::with_capacity(datoms.len());
    let mut avet = Vec::with_capacity(datoms.len());
    let mut vaet = Vec::new();
    let mut tea = Vec::with_capacity(datoms.len());

    for datom in datoms {
        let kqe = indexable_kqe_datom(datom);
        let value = encode_stored_datom(datom)?;
        eavt.push((kqe.eavt_key(), value.clone()));
        aevt.push((kqe.aevt_key(), value.clone()));
        avet.push((kqe.avet_key(), value.clone()));
        if let Some(key) = vaet_key_for_datom(datom) {
            vaet.push((key, value.clone()));
        }
        tea.push((kqe.tea_key(), value));
    }

    let roots = [
        (ROOT_EAVT, eavt),
        (ROOT_AEVT, aevt),
        (ROOT_AVET, avet),
        (ROOT_VAET, vaet),
        (ROOT_TEA, tea),
    ]
    .into_iter()
    .map(|(name, entries)| {
        ProllyTree::build_tree(entries, store)
            .map(|root| (name.to_string(), root))
            .map_err(DistributedCommitError::Store)
    })
    .collect::<Result<HashMap<_, _>, _>>()?;

    Ok(roots)
}

fn datoms_from_commit(
    commit: &DistributedDatomCommit,
    store: &dyn BlockStore,
) -> Result<Vec<Datom>, DistributedCommitError> {
    let root = commit.index_roots.get(ROOT_TEA).ok_or_else(|| {
        DistributedCommitError::MissingIndexRoot {
            commit: commit.cid.to_multibase(),
            root: ROOT_TEA,
        }
    })?;
    let entries =
        ProllyTree::scan_prefix(root, &[], store).map_err(DistributedCommitError::Store)?;
    entries
        .into_iter()
        .map(|(_, value)| decode_stored_datom(&value))
        .collect()
}

fn datoms_from_index_prefix(
    commit: &DistributedDatomCommit,
    root_name: &'static str,
    prefix: &[u8],
    store: &dyn BlockStore,
) -> Result<Vec<Datom>, DistributedCommitError> {
    let root = commit.index_roots.get(root_name).ok_or_else(|| {
        DistributedCommitError::MissingIndexRoot {
            commit: commit.cid.to_multibase(),
            root: root_name,
        }
    })?;
    let entries =
        ProllyTree::scan_prefix(root, prefix, store).map_err(DistributedCommitError::Store)?;
    entries
        .into_iter()
        .map(|(_, value)| decode_stored_datom(&value))
        .collect()
}

fn datoms_from_index_seek(
    commit: &DistributedDatomCommit,
    root_name: &'static str,
    start: &[u8],
    store: &dyn BlockStore,
) -> Result<Vec<Datom>, DistributedCommitError> {
    let root = commit.index_roots.get(root_name).ok_or_else(|| {
        DistributedCommitError::MissingIndexRoot {
            commit: commit.cid.to_multibase(),
            root: root_name,
        }
    })?;
    let entries =
        ProllyTree::scan_from(root, start, store).map_err(DistributedCommitError::Store)?;
    entries
        .into_iter()
        .map(|(_, value)| decode_stored_datom(&value))
        .collect()
}

fn indexable_kqe_datom(datom: &Datom) -> KqeDatom {
    datom.to_kqe().unwrap_or_else(|_| KqeDatom {
        e: datom.e.clone(),
        a: datom.a.clone(),
        v: kotoba_kqe::Value::Text(kotoba_edn::to_string(&datom.v)),
        tx: datom.t.clone(),
        op: datom.added,
    })
}

fn encode_stored_datom(datom: &Datom) -> Result<Vec<u8>, DistributedCommitError> {
    let stored = StoredDatom {
        e: datom.e.to_multibase(),
        a: datom.a.clone(),
        v_edn: kotoba_edn::to_string(&datom.v),
        t: datom.t.to_multibase(),
        added: datom.added,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&stored, &mut bytes)
        .map_err(|e| DistributedCommitError::Cbor(e.to_string()))?;
    Ok(bytes)
}

fn decode_stored_datom(bytes: &[u8]) -> Result<Datom, DistributedCommitError> {
    let stored: StoredDatom =
        ciborium::from_reader(bytes).map_err(|e| DistributedCommitError::Cbor(e.to_string()))?;
    let e = KotobaCid::from_multibase(&stored.e)
        .ok_or_else(|| DistributedCommitError::InvalidCommitCid(stored.e.clone()))?;
    let t = KotobaCid::from_multibase(&stored.t)
        .ok_or_else(|| DistributedCommitError::InvalidCommitCid(stored.t.clone()))?;
    let v =
        kotoba_edn::parse(&stored.v_edn).map_err(|e| DistributedCommitError::Edn(e.to_string()))?;
    Ok(if stored.added {
        Datom::assert(e, stored.a, v, t)
    } else {
        Datom::retract(e, stored.a, v, t)
    })
}

fn derive_tx_cid(
    graph: &KotobaCid,
    eavt_root: &KotobaCid,
    prev: Option<&KotobaCid>,
    seq: u64,
) -> KotobaCid {
    let mut seed = b"kotoba-datomic-tx:v1\n".to_vec();
    seed.extend_from_slice(&graph.0);
    seed.extend_from_slice(&eavt_root.0);
    if let Some(prev) = prev {
        seed.extend_from_slice(&prev.0);
    }
    seed.extend_from_slice(&seq.to_be_bytes());
    KotobaCid::from_bytes(&seed)
}

fn attr_prefix(attr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(attr.len() + 1);
    out.extend_from_slice(attr.as_bytes());
    out.push(0);
    out
}

fn attr_lookup_variants(attr: &str) -> Vec<&str> {
    match attr.strip_prefix(':') {
        Some(stripped) if !stripped.is_empty() => vec![attr, stripped],
        _ => vec![attr],
    }
}

fn root_for_datom_index(index: DatomIndex) -> &'static str {
    match index {
        DatomIndex::Eavt => ROOT_EAVT,
        DatomIndex::Aevt => ROOT_AEVT,
        DatomIndex::Avet => ROOT_AVET,
        DatomIndex::Vaet => ROOT_VAET,
        DatomIndex::Tea => ROOT_TEA,
    }
}

fn extend_unique_datoms(out: &mut Vec<Datom>, datoms: Vec<Datom>) {
    for datom in datoms {
        if !out.contains(&datom) {
            out.push(datom);
        }
    }
}

fn eavt_entity_attr_prefix(entity: &KotobaCid, attr: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(entity.0.len() + attr.len() + 1);
    out.extend_from_slice(&entity.0);
    out.extend_from_slice(&attr_prefix(attr));
    out
}

fn kqe_value(value: &Value) -> kotoba_kqe::Value {
    edn_to_kqe_value(value)
        .unwrap_or_else(|_| kotoba_kqe::Value::Text(kotoba_edn::to_string(value)))
}

fn prefix_datoms_entity(value: &Value) -> KotobaCid {
    match value {
        Value::String(s) => {
            KotobaCid::from_multibase(s).unwrap_or_else(|| KotobaCid::from_bytes(s.as_bytes()))
        }
        Value::Integer(i) => KotobaCid::from_bytes(i.to_string().as_bytes()),
        Value::Keyword(keyword) => {
            KotobaCid::from_bytes(format!(":{}", keyword.to_qualified()).as_bytes())
        }
        Value::Tagged { tag, value } if tag.to_qualified() == "cid" => value
            .as_string()
            .and_then(KotobaCid::from_multibase)
            .unwrap_or_else(|| KotobaCid::from_bytes(kotoba_edn::to_string(value).as_bytes())),
        _ => KotobaCid::from_bytes(kotoba_edn::to_string(value).as_bytes()),
    }
}

fn prefix_datoms_attr(value: &Value) -> Result<String, DistributedCommitError> {
    attr_string(value)
        .ok_or(DatomicError::AttributeMustBeKeyword)
        .map_err(DistributedCommitError::Datom)
}

fn truncate_tx_op(mut key: Vec<u8>) -> Vec<u8> {
    key.truncate(key.len().saturating_sub(36 + 1));
    key
}

fn truncate_op(mut key: Vec<u8>) -> Vec<u8> {
    key.truncate(key.len().saturating_sub(1));
    key
}

fn index_components_prefix(
    root_name: &'static str,
    components: &[Value],
) -> Result<Option<Vec<u8>>, DistributedCommitError> {
    if components.len() > 4 {
        return Err(DatomicError::Query(format!(
            "{root_name} index supports at most 4 components"
        ))
        .into());
    }
    if components.is_empty() {
        return Ok(Some(Vec::new()));
    }
    let zero = KotobaCid::default();
    Ok(Some(match root_name {
        ROOT_EAVT => {
            let e = prefix_datoms_entity(&components[0]);
            match components.len() {
                1 => e.0.to_vec(),
                2 => eavt_entity_attr_prefix(&e, &prefix_datoms_attr(&components[1])?),
                3 => truncate_tx_op(
                    KqeDatom {
                        e,
                        a: prefix_datoms_attr(&components[1])?,
                        v: kqe_value(&components[2]),
                        tx: zero,
                        op: true,
                    }
                    .eavt_key(),
                ),
                4 => truncate_op(
                    KqeDatom {
                        e,
                        a: prefix_datoms_attr(&components[1])?,
                        v: kqe_value(&components[2]),
                        tx: prefix_datoms_entity(&components[3]),
                        op: true,
                    }
                    .eavt_key(),
                ),
                _ => unreachable!(),
            }
        }
        ROOT_AEVT => {
            let a = prefix_datoms_attr(&components[0])?;
            match components.len() {
                1 => attr_prefix(&a),
                2 => {
                    let mut prefix = attr_prefix(&a);
                    prefix.extend_from_slice(&prefix_datoms_entity(&components[1]).0);
                    prefix
                }
                3 => truncate_tx_op(
                    KqeDatom {
                        e: prefix_datoms_entity(&components[1]),
                        a,
                        v: kqe_value(&components[2]),
                        tx: zero,
                        op: true,
                    }
                    .aevt_key(),
                ),
                4 => truncate_op(
                    KqeDatom {
                        e: prefix_datoms_entity(&components[1]),
                        a,
                        v: kqe_value(&components[2]),
                        tx: prefix_datoms_entity(&components[3]),
                        op: true,
                    }
                    .aevt_key(),
                ),
                _ => unreachable!(),
            }
        }
        ROOT_AVET => {
            let a = prefix_datoms_attr(&components[0])?;
            match components.len() {
                1 => attr_prefix(&a),
                2 => avet_prefix(&a, &components[1]),
                3 => {
                    let mut prefix = avet_prefix(&a, &components[1]);
                    prefix.extend_from_slice(&prefix_datoms_entity(&components[2]).0);
                    prefix
                }
                4 => truncate_op(
                    KqeDatom {
                        e: prefix_datoms_entity(&components[2]),
                        a,
                        v: kqe_value(&components[1]),
                        tx: prefix_datoms_entity(&components[3]),
                        op: true,
                    }
                    .avet_key(),
                ),
                _ => unreachable!(),
            }
        }
        ROOT_VAET => {
            let Some(v) = vaet_ref_value(&components[0]) else {
                return Ok(Some(vec![0]));
            };
            match components.len() {
                1 => vaet_prefix_for_parts(v, None, None, None),
                2 => {
                    vaet_prefix_for_parts(v, Some(prefix_datoms_attr(&components[1])?), None, None)
                }
                3 => vaet_prefix_for_parts(
                    v,
                    Some(prefix_datoms_attr(&components[1])?),
                    Some(prefix_datoms_entity(&components[2])),
                    None,
                ),
                4 => vaet_prefix_for_parts(
                    v,
                    Some(prefix_datoms_attr(&components[1])?),
                    Some(prefix_datoms_entity(&components[2])),
                    Some(prefix_datoms_entity(&components[3])),
                ),
                _ => unreachable!(),
            }
        }
        ROOT_TEA => {
            let t = prefix_datoms_entity(&components[0]);
            match components.len() {
                1 => t.0.to_vec(),
                2 => {
                    let mut prefix = t.0.to_vec();
                    prefix.extend_from_slice(&prefix_datoms_entity(&components[1]).0);
                    prefix
                }
                3 => {
                    let mut prefix = t.0.to_vec();
                    prefix.extend_from_slice(&prefix_datoms_entity(&components[1]).0);
                    prefix.extend_from_slice(&attr_prefix(&prefix_datoms_attr(&components[2])?));
                    prefix
                }
                4 => truncate_op(
                    KqeDatom {
                        e: prefix_datoms_entity(&components[1]),
                        a: prefix_datoms_attr(&components[2])?,
                        v: kqe_value(&components[3]),
                        tx: t,
                        op: true,
                    }
                    .tea_key(),
                ),
                _ => unreachable!(),
            }
        }
        _ => {
            return Err(DatomicError::Query(format!("unsupported datom index {root_name}")).into())
        }
    }))
}

fn datom_matches_index_components(
    datom: &Datom,
    root_name: &'static str,
    components: &[Value],
) -> bool {
    components
        .iter()
        .enumerate()
        .all(|(position, component)| match (root_name, position) {
            (ROOT_EAVT, 0) => datom.e == prefix_datoms_entity(component),
            (ROOT_EAVT, 1) => {
                prefix_datoms_attr(component).is_ok_and(|a| attr_matches(&datom.a, &a))
            }
            (ROOT_EAVT, 2) => datom.v == *component,
            (ROOT_EAVT, 3) => datom.t == prefix_datoms_entity(component),
            (ROOT_AEVT, 0) => {
                prefix_datoms_attr(component).is_ok_and(|a| attr_matches(&datom.a, &a))
            }
            (ROOT_AEVT, 1) => datom.e == prefix_datoms_entity(component),
            (ROOT_AEVT, 2) => datom.v == *component,
            (ROOT_AEVT, 3) => datom.t == prefix_datoms_entity(component),
            (ROOT_AVET, 0) => {
                prefix_datoms_attr(component).is_ok_and(|a| attr_matches(&datom.a, &a))
            }
            (ROOT_AVET, 1) => datom.v == *component,
            (ROOT_AVET, 2) => datom.e == prefix_datoms_entity(component),
            (ROOT_AVET, 3) => datom.t == prefix_datoms_entity(component),
            (ROOT_VAET, 0) => datom.v == *component,
            (ROOT_VAET, 1) => {
                prefix_datoms_attr(component).is_ok_and(|a| attr_matches(&datom.a, &a))
            }
            (ROOT_VAET, 2) => datom.e == prefix_datoms_entity(component),
            (ROOT_VAET, 3) => datom.t == prefix_datoms_entity(component),
            (ROOT_TEA, 0) => datom.t == prefix_datoms_entity(component),
            (ROOT_TEA, 1) => datom.e == prefix_datoms_entity(component),
            (ROOT_TEA, 2) => {
                prefix_datoms_attr(component).is_ok_and(|a| attr_matches(&datom.a, &a))
            }
            (ROOT_TEA, 3) => datom.v == *component,
            _ => false,
        })
}

fn avet_prefix(attr: &str, value: &Value) -> Vec<u8> {
    let v = kqe_value(value);
    let datom = KqeDatom {
        e: KotobaCid::default(),
        a: attr.to_string(),
        v,
        tx: KotobaCid::default(),
        op: true,
    };
    let mut key = datom.avet_key();
    key.truncate(key.len().saturating_sub(36 + 36 + 1));
    key
}

fn vaet_key_for_datom(datom: &Datom) -> Option<Vec<u8>> {
    let value = vaet_ref_value(&datom.v)?;
    KqeDatom {
        e: datom.e.clone(),
        a: datom.a.clone(),
        v: value,
        tx: datom.t.clone(),
        op: datom.added,
    }
    .vaet_key()
}

fn vaet_ref_value(value: &Value) -> Option<kotoba_kqe::Value> {
    match value {
        Value::String(s) => KotobaCid::from_multibase(s).map(kotoba_kqe::Value::Cid),
        Value::Tagged { tag, value } if tag.to_qualified() == "cid" => value
            .as_string()
            .and_then(KotobaCid::from_multibase)
            .map(kotoba_kqe::Value::Cid),
        _ => None,
    }
}

fn vaet_prefix_for_parts(
    v: kotoba_kqe::Value,
    attr: Option<String>,
    entity: Option<KotobaCid>,
    tx: Option<KotobaCid>,
) -> Vec<u8> {
    let has_attr = attr.is_some();
    let has_entity = entity.is_some();
    let has_tx = tx.is_some();
    let datom = KqeDatom {
        e: entity.unwrap_or_default(),
        a: attr.unwrap_or_default(),
        v,
        tx: tx.unwrap_or_default(),
        op: true,
    };
    let mut key = datom.vaet_key().unwrap_or_default();
    if has_tx {
        truncate_op(key)
    } else if has_entity {
        truncate_tx_op(key)
    } else if has_attr {
        key.truncate(key.len().saturating_sub(36 + 36 + 1));
        key
    } else {
        key.truncate(key.len().saturating_sub(1 + 36 + 36 + 1));
        key
    }
}

fn datom_matches_triple(
    datom: &Datom,
    triple: &[Value],
    binding: &BTreeMap<String, Value>,
    lookup_ref: &LookupRefResolution,
) -> bool {
    if !(3..=5).contains(&triple.len()) {
        return false;
    }
    entity_term_matches(&triple[0], &datom.e, binding, lookup_ref)
        && term_matches(&triple[1], &attr_value(&datom.a), binding)
        && term_matches(&triple[2], &datom.v, binding)
        && triple
            .get(3)
            .is_none_or(|term| term_matches(term, &cid_value(&datom.t), binding))
        && triple
            .get(4)
            .is_none_or(|term| term_matches(term, &Value::Bool(datom.added), binding))
}

fn entity_term_matches(
    term: &Value,
    entity: &KotobaCid,
    binding: &BTreeMap<String, Value>,
    lookup_ref: &LookupRefResolution,
) -> bool {
    match lookup_ref {
        LookupRefResolution::Resolved(resolved) => resolved == entity,
        LookupRefResolution::Missing => false,
        LookupRefResolution::NotLookupRef => term_matches(term, &cid_value(entity), binding),
    }
}

fn term_matches(term: &Value, value: &Value, binding: &BTreeMap<String, Value>) -> bool {
    match variable_name(term) {
        Some(var) => binding.get(var).is_none_or(|bound| bound == value),
        None => term == value,
    }
}

fn bind_datom_to_triple(
    datom: &Datom,
    triple: &[Value],
    binding: &BTreeMap<String, Value>,
    lookup_ref: &LookupRefResolution,
    next: &mut BTreeMap<String, Value>,
) -> bool {
    bind_entity_term(&triple[0], &datom.e, binding, lookup_ref, next)
        && bind_term(&triple[1], attr_value(&datom.a), next)
        && bind_term(&triple[2], datom.v.clone(), next)
        && triple
            .get(3)
            .is_none_or(|term| bind_term(term, cid_value(&datom.t), next))
        && triple
            .get(4)
            .is_none_or(|term| bind_term(term, Value::Bool(datom.added), next))
}

fn bind_entity_term(
    term: &Value,
    entity: &KotobaCid,
    binding: &BTreeMap<String, Value>,
    lookup_ref: &LookupRefResolution,
    next: &mut BTreeMap<String, Value>,
) -> bool {
    if !entity_term_matches(term, entity, binding, lookup_ref) {
        return false;
    }
    if matches!(lookup_ref, LookupRefResolution::Resolved(_)) {
        return true;
    }
    bind_term(term, cid_value(entity), next)
}

fn bind_term(term: &Value, value: Value, binding: &mut BTreeMap<String, Value>) -> bool {
    match variable_name(term) {
        Some(var) => match binding.get(var) {
            Some(bound) => bound == &value,
            None => {
                binding.insert(var.to_string(), value);
                true
            }
        },
        None => term == &value,
    }
}

fn bind_function_target(
    target: &Value,
    value: Value,
    binding: &mut BTreeMap<String, Value>,
) -> Result<bool, DistributedCommitError> {
    let Some(targets) = target.as_seq() else {
        return Ok(bind_term(target, value, binding));
    };
    let values = value.as_seq().ok_or_else(|| {
        DatomicError::Query(format!(
            "tuple binding target requires tuple value, got {}",
            kotoba_edn::to_string(&value)
        ))
    })?;
    if targets.len() != values.len() {
        return Err(DatomicError::Query(format!(
            "tuple binding target width {} does not match value width {}",
            targets.len(),
            values.len()
        ))
        .into());
    }
    let mut next = binding.clone();
    for (target, value) in targets.iter().zip(values.iter()) {
        if !bind_term(target, value.clone(), &mut next) {
            return Ok(false);
        }
    }
    *binding = next;
    Ok(true)
}

fn bind_relation_or_function_target(
    target: &Value,
    value: Value,
    binding: &mut BTreeMap<String, Value>,
) -> Result<bool, DistributedCommitError> {
    if let Some(targets) = relation_binding_targets(target) {
        let values = value.as_seq().ok_or_else(|| {
            DatomicError::Query(format!(
                "relation binding target requires tuple value, got {}",
                kotoba_edn::to_string(&value)
            ))
        })?;
        if targets.len() != values.len() {
            return Err(DatomicError::Query(format!(
                "relation binding target width {} does not match value width {}",
                targets.len(),
                values.len()
            ))
            .into());
        }
        let mut next = binding.clone();
        for (target, value) in targets.iter().zip(values.iter()) {
            if !bind_term(target, value.clone(), &mut next) {
                return Ok(false);
            }
        }
        *binding = next;
        Ok(true)
    } else {
        bind_function_target(target, value, binding)
    }
}

fn relation_binding_targets(target: &Value) -> Option<&[Value]> {
    let outer = target.as_seq()?;
    if outer.len() == 1 {
        outer[0].as_seq()
    } else {
        None
    }
}

fn lookup_ref_parts(term: &Value, binding: &BTreeMap<String, Value>) -> Option<(String, Value)> {
    let value = match variable_name(term) {
        Some(var) => binding.get(var).unwrap_or(term),
        None => term,
    };
    let items = value.as_seq()?;
    if items.len() != 2 {
        return None;
    }
    let attr = attr_string(&items[0])?;
    let value = resolve_query_value(&items[1], binding)?;
    Some((attr, value))
}

fn attr_string(value: &Value) -> Option<String> {
    value
        .as_keyword()
        .map(|k| format!(":{}", k.to_qualified()))
        .or_else(|| value.as_string().map(str::to_string))
}

fn resolved_attr_term(term: &Value, binding: &BTreeMap<String, Value>) -> Option<String> {
    let value = match variable_name(term) {
        Some(var) => binding.get(var),
        None => Some(term),
    };
    value.and_then(attr_string)
}

fn resolve_query_value(term: &Value, binding: &BTreeMap<String, Value>) -> Option<Value> {
    match variable_name(term) {
        Some(var) => binding.get(var).cloned(),
        None => Some(term.clone()),
    }
}

fn resolve_find_value(
    term: &Value,
    binding: &BTreeMap<String, Value>,
) -> Result<Value, DistributedCommitError> {
    match variable_name(term) {
        Some(var) => binding
            .get(var)
            .cloned()
            .ok_or_else(|| DatomicError::Query(format!("unbound variable {var}")).into()),
        None => Ok(term.clone()),
    }
}

fn required_query_value(
    term: &Value,
    binding: &BTreeMap<String, Value>,
) -> Result<Value, DistributedCommitError> {
    resolve_query_value(term, binding).ok_or_else(|| {
        DatomicError::Query(format!("unbound variable {}", kotoba_edn::to_string(term))).into()
    })
}

#[derive(Debug, Clone)]
enum DistributedFindItem {
    Value(Value),
    Pull { entity: Value, pattern: Value },
    Count(Value),
    CountDistinct(Value),
    Sum(Value),
    Min(Value),
    Max(Value),
    MinN { limit: usize, value: Value },
    MaxN { limit: usize, value: Value },
    Avg(Value),
    Median(Value),
    Variance(Value),
    Stddev(Value),
    Rand(Value),
    Sample { limit: usize, value: Value },
}

impl DistributedFindItem {
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
}

fn parse_distributed_find_item(
    value: &Value,
) -> Result<DistributedFindItem, DistributedCommitError> {
    let Some(seq) = value.as_seq() else {
        return Ok(DistributedFindItem::Value(value.clone()));
    };
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "count") {
        return Ok(DistributedFindItem::Count(seq[1].clone()));
    }
    if seq.len() == 2
        && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "count-distinct")
    {
        return Ok(DistributedFindItem::CountDistinct(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "sum") {
        return Ok(DistributedFindItem::Sum(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "min") {
        return Ok(DistributedFindItem::Min(seq[1].clone()));
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "min") {
        let limit = aggregate_query_limit("min", &seq[1])?;
        return Ok(DistributedFindItem::MinN {
            limit,
            value: seq[2].clone(),
        });
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "max") {
        return Ok(DistributedFindItem::Max(seq[1].clone()));
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "max") {
        let limit = aggregate_query_limit("max", &seq[1])?;
        return Ok(DistributedFindItem::MaxN {
            limit,
            value: seq[2].clone(),
        });
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "avg") {
        return Ok(DistributedFindItem::Avg(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "median") {
        return Ok(DistributedFindItem::Median(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "variance") {
        return Ok(DistributedFindItem::Variance(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "stddev") {
        return Ok(DistributedFindItem::Stddev(seq[1].clone()));
    }
    if seq.len() == 2 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "rand") {
        return Ok(DistributedFindItem::Rand(seq[1].clone()));
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "sample") {
        let limit = aggregate_query_limit("sample", &seq[1])?;
        return Ok(DistributedFindItem::Sample {
            limit,
            value: seq[2].clone(),
        });
    }
    if seq.len() == 3 && matches!(seq[0].as_symbol(), Some(symbol) if symbol.name == "pull") {
        return Ok(DistributedFindItem::Pull {
            entity: seq[1].clone(),
            pattern: seq[2].clone(),
        });
    }
    Err(DatomicError::UnsupportedOperation(format!(
        "distributed q_triples only supports plain find values and pull expressions, got {}",
        kotoba_edn::to_string(value)
    ))
    .into())
}

fn parse_distributed_find_items(
    find: &[Value],
) -> Result<Vec<DistributedFindItem>, DistributedCommitError> {
    if let Some((last, elems)) = find.split_last() {
        if matches!(last.as_symbol(), Some(symbol) if symbol.name == "..." || symbol.name == ".") {
            return elems.iter().map(parse_distributed_find_item).collect();
        }
    }
    if find.len() == 1 {
        if let Some(tuple) = find[0].as_seq() {
            if !is_distributed_find_expression(tuple) {
                return tuple.iter().map(parse_distributed_find_item).collect();
            }
        }
    }
    find.iter().map(parse_distributed_find_item).collect()
}

fn is_distributed_find_expression(seq: &[Value]) -> bool {
    matches!(
        seq.first().and_then(Value::as_symbol),
        Some(symbol)
            if matches!(
                symbol.name.as_str(),
                "pull" | "count" | "count-distinct" | "sum" | "min" | "max" | "avg"
                    | "median" | "variance" | "stddev" | "rand" | "sample"
            )
    )
}

fn resolve_distributed_find_item(
    item: &DistributedFindItem,
    binding: &BTreeMap<String, Value>,
    pull_db: Option<&Db>,
) -> Result<Value, DistributedCommitError> {
    match item {
        DistributedFindItem::Value(value)
        | DistributedFindItem::Count(value)
        | DistributedFindItem::CountDistinct(value)
        | DistributedFindItem::Sum(value)
        | DistributedFindItem::Min(value)
        | DistributedFindItem::Max(value)
        | DistributedFindItem::MinN { value, .. }
        | DistributedFindItem::MaxN { value, .. }
        | DistributedFindItem::Avg(value)
        | DistributedFindItem::Median(value)
        | DistributedFindItem::Variance(value)
        | DistributedFindItem::Stddev(value)
        | DistributedFindItem::Rand(value)
        | DistributedFindItem::Sample { value, .. } => Ok(match variable_name(value) {
            Some(var) => binding.get(var).cloned().unwrap_or(Value::Nil),
            None => value.clone(),
        }),
        DistributedFindItem::Pull { entity, pattern } => {
            let entity = resolve_find_value(entity, binding)?;
            let Some(eid) = entity_value_to_cid(&entity) else {
                return Err(DatomicError::Query(format!(
                    "pull entity must resolve to a CID string or #cid, got {}",
                    kotoba_edn::to_string(&entity)
                ))
                .into());
            };
            let db = pull_db
                .ok_or_else(|| DatomicError::Query("missing distributed pull database".into()))?;
            db.pull(pattern.clone(), eid).map_err(Into::into)
        }
    }
}

#[derive(Debug, Clone)]
enum DistributedAggregateValue {
    Count(i64),
    CountDistinct(BTreeSet<Value>),
    Sum(i64),
    Min(Option<Value>),
    Max(Option<Value>),
    MinN { limit: usize, values: Vec<Value> },
    MaxN { limit: usize, values: Vec<Value> },
    Avg { sum: i64, count: i64 },
    Median(Vec<i64>),
    Variance(Vec<i64>),
    Stddev(Vec<i64>),
    Rand(Option<Value>),
    Sample { limit: usize, values: Vec<Value> },
}

impl DistributedAggregateValue {
    fn for_find_item(item: &DistributedFindItem) -> Option<Self> {
        match item {
            DistributedFindItem::Value(_) | DistributedFindItem::Pull { .. } => None,
            DistributedFindItem::Count(_) => Some(Self::Count(0)),
            DistributedFindItem::CountDistinct(_) => Some(Self::CountDistinct(BTreeSet::new())),
            DistributedFindItem::Sum(_) => Some(Self::Sum(0)),
            DistributedFindItem::Min(_) => Some(Self::Min(None)),
            DistributedFindItem::Max(_) => Some(Self::Max(None)),
            DistributedFindItem::MinN { limit, .. } => Some(Self::MinN {
                limit: *limit,
                values: Vec::new(),
            }),
            DistributedFindItem::MaxN { limit, .. } => Some(Self::MaxN {
                limit: *limit,
                values: Vec::new(),
            }),
            DistributedFindItem::Avg(_) => Some(Self::Avg { sum: 0, count: 0 }),
            DistributedFindItem::Median(_) => Some(Self::Median(Vec::new())),
            DistributedFindItem::Variance(_) => Some(Self::Variance(Vec::new())),
            DistributedFindItem::Stddev(_) => Some(Self::Stddev(Vec::new())),
            DistributedFindItem::Rand(_) => Some(Self::Rand(None)),
            DistributedFindItem::Sample { limit, .. } => Some(Self::Sample {
                limit: *limit,
                values: Vec::new(),
            }),
        }
    }

    fn push(&mut self, value: Value) -> Result<(), DistributedCommitError> {
        if matches!(value, Value::Nil) {
            return Ok(());
        }
        match self {
            Self::Count(count) => *count += 1,
            Self::CountDistinct(values) => {
                values.insert(value);
            }
            Self::Sum(sum) => *sum += aggregate_query_integer(&value)?,
            Self::Min(min) => {
                if min
                    .as_ref()
                    .is_none_or(|current| crate::query_sort_order(&value, current).is_lt())
                {
                    *min = Some(value);
                }
            }
            Self::Max(max) => {
                if max
                    .as_ref()
                    .is_none_or(|current| crate::query_sort_order(&value, current).is_gt())
                {
                    *max = Some(value);
                }
            }
            Self::MinN { values, .. } | Self::MaxN { values, .. } => {
                values.push(value);
            }
            Self::Avg { sum, count } => {
                *sum += aggregate_query_integer(&value)?;
                *count += 1;
            }
            Self::Median(values) | Self::Variance(values) | Self::Stddev(values) => {
                values.push(aggregate_query_integer(&value)?);
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

    fn result(&self) -> Value {
        match self {
            Self::Count(count) => Value::Integer(*count),
            Self::CountDistinct(values) => Value::Integer(values.len() as i64),
            Self::Sum(sum) => Value::Integer(*sum),
            Self::Min(min) => min.clone().unwrap_or(Value::Nil),
            Self::Max(max) => max.clone().unwrap_or(Value::Nil),
            Self::MinN { limit, values } => aggregate_query_top_n(values, *limit, false),
            Self::MaxN { limit, values } => aggregate_query_top_n(values, *limit, true),
            Self::Avg { sum, count } => {
                if *count == 0 {
                    Value::Nil
                } else {
                    Value::float(*sum as f64 / *count as f64)
                }
            }
            Self::Median(values) => aggregate_query_median(values),
            Self::Variance(values) => aggregate_query_variance(values),
            Self::Stddev(values) => match aggregate_query_variance_f64(values) {
                Some(variance) => Value::float(variance.sqrt()),
                None => Value::Nil,
            },
            Self::Rand(value) => value.clone().unwrap_or(Value::Nil),
            Self::Sample { values, .. } => Value::Vector(values.clone()),
        }
    }
}

fn aggregate_query_limit(op: &str, value: &Value) -> Result<usize, DistributedCommitError> {
    match value {
        Value::Integer(limit) if *limit >= 0 => Ok(*limit as usize),
        other => Err(DatomicError::Query(format!(
            "{op} expects a non-negative integer limit, got {}",
            kotoba_edn::to_string(other)
        ))
        .into()),
    }
}

fn aggregate_query_top_n(values: &[Value], limit: usize, desc: bool) -> Value {
    let mut values = values.to_vec();
    values.sort_by(|left, right| {
        let ordering = crate::query_sort_order(left, right);
        if desc {
            ordering.reverse()
        } else {
            ordering
        }
    });
    values.truncate(limit);
    Value::Vector(values)
}

fn aggregate_query_median(values: &[i64]) -> Value {
    if values.is_empty() {
        return Value::Nil;
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        Value::Integer(values[mid])
    } else {
        Value::float((values[mid - 1] as f64 + values[mid] as f64) / 2.0)
    }
}

fn aggregate_query_variance(values: &[i64]) -> Value {
    match aggregate_query_variance_f64(values) {
        Some(value) => Value::float(value),
        None => Value::Nil,
    }
}

fn aggregate_query_variance_f64(values: &[i64]) -> Option<f64> {
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

fn aggregate_query_integer(value: &Value) -> Result<i64, DistributedCommitError> {
    match value {
        Value::Integer(value) => Ok(*value),
        other => Err(DatomicError::Query(format!(
            "aggregate value must be an integer, got {}",
            kotoba_edn::to_string(other)
        ))
        .into()),
    }
}

fn aggregate_distributed_rows(
    find_items: &[DistributedFindItem],
    with_items: &[Value],
    bindings: Vec<BTreeMap<String, Value>>,
    pull_db: Option<&Db>,
) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
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
        .filter_map(|idx| DistributedAggregateValue::for_find_item(&find_items[*idx]))
        .collect::<Vec<_>>();
    let mut groups: BTreeMap<Vec<Value>, Vec<DistributedAggregateValue>> = BTreeMap::new();
    let mut seen_with_rows = BTreeSet::new();

    for binding in &bindings {
        let key = group_positions
            .iter()
            .map(|idx| resolve_distributed_find_item(&find_items[*idx], binding, pull_db))
            .collect::<Result<Vec<_>, _>>()?;
        if !with_items.is_empty() {
            let mut with_key = key.clone();
            for item in with_items {
                with_key.push(required_query_value(item, binding)?);
            }
            for find_idx in &aggregate_positions {
                with_key.push(resolve_distributed_find_item(
                    &find_items[*find_idx],
                    binding,
                    pull_db,
                )?);
            }
            if !seen_with_rows.insert(with_key) {
                continue;
            }
        }
        let aggregates = groups
            .entry(key)
            .or_insert_with(|| aggregate_template.clone());
        for (aggregate_idx, find_idx) in aggregate_positions.iter().enumerate() {
            aggregates[aggregate_idx].push(resolve_distributed_find_item(
                &find_items[*find_idx],
                binding,
                pull_db,
            )?)?;
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

fn entity_value_to_cid(value: &Value) -> Option<KotobaCid> {
    match value {
        Value::String(value) => KotobaCid::from_multibase(value)
            .or_else(|| Some(KotobaCid::from_bytes(value.as_bytes()))),
        Value::Tagged { tag, value } if tag.to_qualified() == "cid" => {
            value.as_string().and_then(KotobaCid::from_multibase)
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct DistributedQueryRule {
    name: String,
    args: Vec<Value>,
    clauses: Vec<Value>,
}

fn distributed_rules_from_inputs(
    in_forms: &Value,
    inputs: &[Value],
) -> Result<Vec<DistributedQueryRule>, DistributedCommitError> {
    let forms = in_forms
        .as_vector()
        .ok_or_else(|| DatomicError::Query(":in must be a vector".into()))?;
    let mut input_idx = 0;
    for form in forms {
        if crate::is_query_source_symbol(form) {
            if inputs
                .get(input_idx)
                .is_some_and(crate::is_query_source_symbol)
            {
                input_idx += 1;
            }
            continue;
        }
        if matches!(form.as_symbol(), Some(symbol) if symbol.name == "%") {
            let rules = inputs
                .get(input_idx)
                .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
            return parse_distributed_query_rules(rules);
        }
        input_idx += 1;
    }
    Ok(Vec::new())
}

fn parse_distributed_query_rules(
    value: &Value,
) -> Result<Vec<DistributedQueryRule>, DistributedCommitError> {
    let rules = match value {
        Value::Vector(values) | Value::List(values) => values,
        other => {
            return Err(DatomicError::Query(format!(
                "rules input must be a vector or list, got {}",
                kotoba_edn::to_string(other)
            ))
            .into());
        }
    };
    rules
        .iter()
        .map(|rule| {
            let seq = rule.as_seq().ok_or_else(|| {
                DatomicError::Query(format!(
                    "rule must be a vector/list, got {}",
                    kotoba_edn::to_string(rule)
                ))
            })?;
            let Some((head, clauses)) = seq.split_first() else {
                return Err(DatomicError::Query("rule cannot be empty".into()).into());
            };
            let head = head
                .as_seq()
                .ok_or_else(|| DatomicError::Query("rule head must be a list/vector".into()))?;
            let (name, args) = distributed_rule_head(head)?;
            Ok(DistributedQueryRule {
                name,
                args: args.to_vec(),
                clauses: clauses.to_vec(),
            })
        })
        .collect()
}

fn distributed_rule_head(head: &[Value]) -> Result<(String, &[Value]), DistributedCommitError> {
    let Some((name, args)) = head.split_first() else {
        return Err(DatomicError::Query("rule head cannot be empty".into()).into());
    };
    let name = name
        .as_symbol()
        .map(|symbol| symbol.to_qualified())
        .ok_or_else(|| DatomicError::Query("rule head name must be a symbol".into()))?;
    Ok((name, args))
}

fn distributed_rule_invocation_name<'a>(
    seq: &[Value],
    rules: &'a [DistributedQueryRule],
) -> Option<&'a str> {
    let name = seq.first()?.as_symbol()?.to_qualified();
    rules
        .iter()
        .find(|rule| rule.name == name && rule.args.len() == seq.len().saturating_sub(1))
        .map(|rule| rule.name.as_str())
}

fn query_join_vars(value: &Value) -> Result<Vec<String>, DistributedCommitError> {
    let vars = value
        .as_vector()
        .ok_or_else(|| DatomicError::Query("not-join variables must be a vector".into()))?;
    vars.iter()
        .map(|value| {
            variable_name(value).map(str::to_string).ok_or_else(|| {
                DatomicError::Query(format!(
                    "not-join variable must be a query variable, got {}",
                    kotoba_edn::to_string(value)
                ))
                .into()
            })
        })
        .collect()
}

fn project_query_binding(
    binding: &BTreeMap<String, Value>,
    vars: &[String],
) -> Result<BTreeMap<String, Value>, DistributedCommitError> {
    let mut out = BTreeMap::new();
    for var in vars {
        let Some(value) = binding.get(var) else {
            return Err(DatomicError::Query(format!("unbound not-join variable {var}")).into());
        };
        out.insert(var.clone(), value.clone());
    }
    Ok(out)
}

fn merge_query_bindings(
    left: &BTreeMap<String, Value>,
    right: &BTreeMap<String, Value>,
) -> Option<BTreeMap<String, Value>> {
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

fn query_vec<'a>(
    query: &'a BTreeMap<Value, Value>,
    key: &str,
) -> Result<&'a [Value], DistributedCommitError> {
    query
        .get(&query_key(key))
        .map(query_value_vec)
        .transpose()?
        .ok_or_else(|| DatomicError::Query(format!("missing {key} vector")).into())
}

fn query_value_vec(value: &Value) -> Result<&[Value], DistributedCommitError> {
    value
        .as_vector()
        .ok_or_else(|| DatomicError::Query("query value must be a vector".into()).into())
}

fn bind_query_inputs(
    in_forms: &Value,
    inputs: &[Value],
) -> Result<Vec<BTreeMap<String, Value>>, DistributedCommitError> {
    let forms = in_forms
        .as_vector()
        .ok_or_else(|| DatomicError::Query(":in must be a vector".into()))?;
    let mut bindings = vec![BTreeMap::new()];
    let mut input_idx = 0;
    for form in forms {
        if crate::is_query_source_symbol(form) {
            if inputs
                .get(input_idx)
                .is_some_and(crate::is_query_source_symbol)
            {
                input_idx += 1;
            }
            continue;
        }
        if matches!(form.as_symbol(), Some(symbol) if symbol.name == "%") {
            input_idx += 1;
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
                        if !bind_term(term, value.clone(), &mut next) {
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
        if let Some(terms) = tuple_binding_terms(form) {
            let value = inputs
                .get(input_idx)
                .ok_or_else(|| DatomicError::Query("not enough query inputs".into()))?;
            input_idx += 1;
            let tuple = input_tuple_values(value, terms.len())?;
            for binding in bindings.iter_mut() {
                for (term, value) in terms.iter().zip(&tuple) {
                    if !bind_term(term, value.clone(), binding) {
                        return Err(DatomicError::Query(format!(
                            "tuple binding value conflicts with existing binding for {}",
                            kotoba_edn::to_string(term)
                        ))
                        .into());
                    }
                }
            }
            continue;
        }
        let Some(var) = variable_name(form) else {
            return Err(DatomicError::UnsupportedOperation(format!(
                "distributed q_triples only supports scalar, tuple, relation, and collection :in variables, got {}",
                kotoba_edn::to_string(form)
            ))
            .into());
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

fn relation_binding_terms(form: &Value) -> Option<&[Value]> {
    let outer = form.as_seq()?;
    if outer.len() == 1 {
        let terms = outer[0].as_seq()?;
        if terms.len() > 1 {
            return Some(terms);
        }
    }
    None
}

fn input_relation_tuples(
    value: &Value,
    width: usize,
) -> Result<Vec<Vec<Value>>, DistributedCommitError> {
    let rows = match value {
        Value::Vector(values) | Value::List(values) => values.clone(),
        Value::Set(values) => values.iter().cloned().collect(),
        other => {
            return Err(DatomicError::Query(format!(
                "relation binding input must be a vector, list, or set, got {}",
                kotoba_edn::to_string(other)
            ))
            .into());
        }
    };
    rows.into_iter()
        .map(|row| input_tuple_values(&row, width))
        .collect()
}

fn tuple_binding_terms(form: &Value) -> Option<&[Value]> {
    let terms = form.as_seq()?;
    if terms.len() > 1
        && !matches!(terms.last().and_then(Value::as_symbol), Some(symbol) if symbol.name == "...")
        && !terms.iter().any(|term| term.as_seq().is_some())
    {
        return Some(terms);
    }
    None
}

fn input_tuple_values(value: &Value, width: usize) -> Result<Vec<Value>, DistributedCommitError> {
    let tuple = value.as_seq().ok_or_else(|| {
        DatomicError::Query(format!(
            "tuple binding input must be a vector or list, got {}",
            kotoba_edn::to_string(value)
        ))
    })?;
    if tuple.len() != width {
        return Err(DatomicError::Query(format!(
            "tuple binding width {} does not match expected {width}",
            tuple.len()
        ))
        .into());
    }
    Ok(tuple.to_vec())
}

fn collection_binding_var(form: &Value) -> Option<&str> {
    let seq = form.as_seq()?;
    if seq.len() == 2 && matches!(seq[1].as_symbol(), Some(symbol) if symbol.name == "...") {
        variable_name(&seq[0])
    } else {
        None
    }
}

fn input_collection_values(value: &Value) -> Result<Vec<Value>, DistributedCommitError> {
    match value {
        Value::Vector(values) | Value::List(values) => Ok(values.clone()),
        Value::Set(values) => Ok(values.iter().cloned().collect()),
        other => Err(DatomicError::Query(format!(
            "collection binding input must be a vector, list, or set, got {}",
            kotoba_edn::to_string(other)
        ))
        .into()),
    }
}

fn query_key(key: &str) -> Value {
    let key = key.trim_start_matches(':');
    match key.split_once('/') {
        Some((ns, name)) => Value::Keyword(Keyword::namespaced(ns, name)),
        None => Value::Keyword(Keyword::bare(key)),
    }
}

fn variable_name(value: &Value) -> Option<&str> {
    value
        .as_symbol()
        .and_then(|s| s.name.strip_prefix('?').map(|_| s.name.as_str()))
}

fn cid_value(cid: &KotobaCid) -> Value {
    Value::String(cid.to_multibase())
}

fn attr_value(attr: &str) -> Value {
    if attr.starts_with(':') || (attr.contains('/') && !attr.contains("://")) {
        Value::Keyword(Keyword::parse(attr.strip_prefix(':').unwrap_or(attr)))
    } else {
        Value::String(attr.to_string())
    }
}

fn attr_matches(stored: &str, query: &str) -> bool {
    stored == query
        || stored.strip_prefix(':') == Some(query)
        || query.strip_prefix(':') == Some(stored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EdnValue;
    use ed25519_dalek::SigningKey;
    use kotoba_ipfs::{InMemoryIpnsRegistry, KuboIpnsRegistry, SignedIpnsRegistry};
    use kotoba_store::MemoryBlockStore;
    use std::sync::Arc;

    fn datom(e: &[u8], a: &str, v: &str, tx: &[u8]) -> Datom {
        Datom::assert(
            KotobaCid::from_bytes(e),
            a.to_string(),
            EdnValue::string(v),
            KotobaCid::from_bytes(tx),
        )
    }

    fn with_tx(mut datom: Datom, tx: &KotobaCid) -> Datom {
        datom.t = tx.clone();
        datom
    }

    fn request(ipns_name: &str, graph: KotobaCid, datoms: Vec<Datom>) -> CommitDatomsRequest {
        CommitDatomsRequest {
            ipns_name: ipns_name.to_string(),
            graph,
            datoms,
            expected_parent: None,
            tx_cid: None,
            author: "did:key:zWriter".to_string(),
            seq: 1,
            valid_until: "2030-01-01T00:00:00Z".to_string(),
            ttl_secs: Some(60),
            cacao_proof_cid: None,
            ipns_controller_did: None,
            ipns_signing_key: None,
        }
    }

    fn register_increment_tx_fn(conn: &Connection) -> Result<(), DistributedCommitError> {
        conn.register_tx_fn("my.fn/increment", |db, args| {
            if args.len() != 3 {
                return Err(DatomicError::InvalidOpForm);
            }
            let entity = args[0]
                .as_string()
                .map(|value| {
                    KotobaCid::from_multibase(value)
                        .unwrap_or_else(|| KotobaCid::from_bytes(value.as_bytes()))
                })
                .ok_or(DatomicError::InvalidOpForm)?;
            let attr = args[1]
                .as_keyword()
                .map(|keyword| format!(":{}", keyword.to_qualified()))
                .or_else(|| args[1].as_string().map(str::to_string))
                .ok_or(DatomicError::AttributeMustBeKeyword)?;
            let EdnValue::Integer(amount) = args[2] else {
                return Err(DatomicError::InvalidOpForm);
            };
            let current = db
                .datoms()
                .into_iter()
                .find(|datom| datom.e == entity && datom.a == attr)
                .and_then(|datom| match datom.v {
                    EdnValue::Integer(value) => Some(value),
                    _ => None,
                })
                .unwrap_or(0);

            Ok(EdnValue::Vector(vec![EdnValue::Vector(vec![
                EdnValue::Keyword(Keyword::parse("db/add")),
                args[0].clone(),
                args[1].clone(),
                EdnValue::Integer(current + amount),
            ])]))
        })
        .map_err(Into::into)
    }

    fn socket_from_listen_addr(addr: &kotoba_ipfs::Multiaddr) -> std::net::SocketAddr {
        let parts = addr.to_string();
        let segments = parts.split('/').collect::<Vec<_>>();
        let ip = segments
            .windows(2)
            .find_map(|window| (window[0] == "ip4").then_some(window[1]))
            .expect("ip4 segment");
        let port = segments
            .windows(2)
            .find_map(|window| (window[0] == "tcp").then_some(window[1]))
            .expect("tcp segment")
            .parse::<u16>()
            .expect("tcp port");
        format!("{ip}:{port}").parse().expect("socket addr")
    }

    #[test]
    fn commit_datoms_writes_five_roots_and_ipns_head() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let req = request(
            "k51-kotoba-db",
            graph.clone(),
            vec![datom(b"alice", "person/name", "Alice", b"tx1")],
        );

        let report = writer.commit_datoms(req).unwrap();
        assert_eq!(report.datom_count, 1);
        for name in [ROOT_EAVT, ROOT_AEVT, ROOT_AVET, ROOT_VAET, ROOT_TEA] {
            let root = report.commit.index_roots.get(name).expect("root present");
            assert!(store.has(root), "{name} root must be persisted");
            assert!(
                root.is_ipfs_compatible(),
                "{name} root must be CIDv1 dag-cbor sha2-256"
            );
            let node = ProllyTree::load_node(root, &store)
                .unwrap()
                .expect("root must decode as DAG-CBOR ProllyNode");
            assert_eq!(node.cid(), root);
        }
        assert!(store.has(&report.commit.cid));
        assert!(report.commit.cid.is_ipfs_compatible());
        assert_eq!(
            kotoba_ipfs::parse_cid(&report.commit.cid.to_multibase())
                .unwrap()
                .codec(),
            u64::from(KotobaCid::CODEC_DAG_CBOR)
        );
        let loaded = DistributedDatomCommit::load(&report.commit.cid, &store)
            .unwrap()
            .expect("commit must decode as DAG-CBOR");
        assert_eq!(loaded, report.commit);
        let stored = datoms_from_commit(&report.commit, &store).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].e, KotobaCid::from_bytes(b"alice"));
        assert_eq!(stored[0].a, "person/name");
        assert_eq!(stored[0].v, EdnValue::string("Alice"));
        assert_eq!(stored[0].t, report.commit.tx_cid);
        assert!(stored[0].added);
        let resolved = ipns.resolve(&IpnsName::new("k51-kotoba-db")).unwrap();
        assert_eq!(resolved.value, report.commit.cid.to_multibase());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reader_queries_remote_ipfs_ipns_dag_cbor_prolly_head() {
        let source_node = kotoba_ipfs::IpfsConfig::new()
            .with_listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .start()
            .await
            .expect("source ipfs node");
        let source_addr = source_node
            .listen_addrs()
            .await
            .expect("source listen addrs")
            .into_iter()
            .next()
            .expect("source listen addr");
        let source_socket = socket_from_listen_addr(&source_addr);

        let local_store = MemoryBlockStore::new();
        let local_ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&local_store, &local_ipns);
        let graph = KotobaCid::from_bytes(b"remote-datomic-graph");
        let ipns_name = "k51-kotoba-remote-datomic";
        let report = writer
            .commit_datoms(request(
                ipns_name,
                graph,
                vec![
                    datom(b"alice", "person/name", "Alice", b"tx-remote"),
                    datom(b"alice", "person/role", "admin", b"tx-remote"),
                ],
            ))
            .expect("commit distributed datoms");

        for cid in local_store.all_cids() {
            let bytes = local_store.get(&cid).unwrap().expect("stored block");
            let ipfs_cid = cid.to_standard_cid().expect("ipfs-compatible cid");
            source_node
                .put_block(&ipfs_cid, &bytes)
                .await
                .expect("seed remote ipfs block");
        }
        let commit_ipfs_cid = report
            .commit
            .cid
            .to_standard_cid()
            .expect("commit cid is ipfs-compatible");
        source_node
            .name_publish(
                ipns_name,
                &commit_ipfs_cid,
                report.ipns_record.valid_until.clone(),
            )
            .await
            .expect("publish remote ipns head");

        let remote_store = RemoteIpfsBlockStore::new(source_socket);
        let remote_ipns = RemoteIpfsIpnsRegistry::new(source_socket);
        let reader = DistributedDatomReader::new(&remote_store, &remote_ipns);
        let query = kotoba_edn::parse(
            r#"{:find [?name ?role]
               :where [[?e :person/name ?name]
                       [?e :person/role ?role]]}"#,
        )
        .expect("query parse");
        let rows = reader
            .q_triples_for_name(ipns_name, &query)
            .expect("remote distributed query");

        assert_eq!(
            rows,
            vec![vec![EdnValue::string("Alice"), EdnValue::string("admin")]]
        );
        assert!(remote_store.has(&report.commit.cid));
        for root in report.commit.index_roots.values() {
            assert!(
                remote_store.has(root),
                "remote store should fetch Prolly root {root}"
            );
        }
    }

    #[test]
    fn stale_parent_is_rejected_before_new_head_publish() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![datom(b"alice", "person/name", "Alice", b"tx1")],
            ))
            .unwrap();

        let stale = writer.commit_datoms(request(
            "k51-kotoba-db",
            graph,
            vec![datom(b"bob", "person/name", "Bob", b"tx2")],
        ));
        assert!(matches!(
            stale.unwrap_err(),
            DistributedCommitError::StaleParent { .. }
        ));
        let resolved = ipns.resolve(&IpnsName::new("k51-kotoba-db")).unwrap();
        assert_eq!(resolved.value, first.commit.cid.to_multibase());
    }

    #[test]
    fn matching_parent_advances_ipns_sequence() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![datom(b"alice", "person/name", "Alice", b"tx1")],
            ))
            .unwrap();

        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![datom(b"bob", "person/name", "Bob", b"tx2")],
        );
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();

        assert_eq!(second.commit.prev, Some(first.commit.cid));
        assert_eq!(second.ipns_record.sequence, 2);
    }

    #[test]
    fn signed_ipns_registry_requires_signed_distributed_head_publish() {
        let store = MemoryBlockStore::new();
        let ipns = SignedIpnsRegistry::new(Arc::new(InMemoryIpnsRegistry::new()));
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");

        let err = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![datom(b"alice", "person/name", "Alice", b"tx1")],
            ))
            .unwrap_err();

        assert!(matches!(
            err,
            DistributedCommitError::Ipns(IpnsRegistryError::MissingPublicKey)
        ));
    }

    #[test]
    fn signed_distributed_head_roundtrips_through_ipns_reader() {
        let store = MemoryBlockStore::new();
        let ipns = SignedIpnsRegistry::new(Arc::new(InMemoryIpnsRegistry::new()));
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let mut req = request(
            "k51-kotoba-db",
            graph.clone(),
            vec![datom(b"alice", "person/name", "Alice", b"tx1")],
        );
        req.ipns_controller_did = Some("did:key:zWriter".to_string());
        req.ipns_signing_key = Some(SigningKey::from_bytes(&[9; 32]));

        let report = writer.commit_datoms(req).unwrap();

        assert!(report.ipns_record.signature_verified());
        assert_eq!(
            report.ipns_record.controller_did.as_deref(),
            Some("did:key:zWriter")
        );
        let reader = DistributedDatomReader::new(&store, &ipns);
        let head = reader.resolve_head("k51-kotoba-db").unwrap().unwrap();
        assert_eq!(head.cid, report.commit.cid);
        assert_eq!(head.graph, graph);
        let db = reader
            .current_db_for_name("k51-kotoba-db")
            .unwrap()
            .unwrap();
        assert_eq!(db.basis_t, Some(report.commit.tx_cid));
        assert_eq!(
            db.datoms()
                .iter()
                .find(|datom| datom.a == "person/name")
                .map(|datom| &datom.v),
            Some(&EdnValue::string("Alice"))
        );
    }

    #[test]
    fn reader_queries_distributed_head_as_of_transaction() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![datom(b"alice", ":person/name", "Alice", b"tx1")],
            ))
            .unwrap();
        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![datom(b"bob", ":person/name", "Bob", b"tx2")],
        );
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();
        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]]}"#,
        )
        .unwrap();
        let reader = DistributedDatomReader::new(&store, &ipns);

        let current_rows = reader.q_triples(&second.commit.cid, &query).unwrap();
        assert_eq!(
            current_rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Bob".into())],
            ]
        );

        let as_of_rows = reader
            .q_triples_as_of_tx(&second.commit.cid, &first.commit.tx_cid, &query)
            .unwrap();
        assert_eq!(as_of_rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[test]
    fn reader_q_triples_supports_string_iri_attribute_terms() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    datom(
                        b"tx",
                        "https://w3id.org/security#allowedAction",
                        "vc:issue",
                        b"tx1",
                    ),
                    datom(
                        b"tx",
                        "https://w3id.org/security#invocationTarget",
                        "kotoba://graph/example",
                        b"tx1",
                    ),
                ],
            ))
            .unwrap();
        let query = kotoba_edn::parse(
            r#"{:find [?action ?target]
               :where [[?tx "https://w3id.org/security#allowedAction" ?action]
                       [?tx "https://w3id.org/security#invocationTarget" ?target]]}"#,
        )
        .unwrap();

        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &query)
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
    fn reader_q_triples_matches_legacy_namespaced_attrs_without_leading_colon() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![datom(b"message", "didcomm/thread", "thread-1", b"tx1")],
            ))
            .unwrap();
        let query = kotoba_edn::parse(r#"{:find [?thread] :where [[?e :didcomm/thread ?thread]]}"#)
            .unwrap();

        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &query)
            .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("thread-1".into())]]);
    }

    #[test]
    fn reader_scans_current_datoms_by_distributed_index_components() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![datom(b"alice", ":person/name", "Alice", b"tx1")],
            ))
            .unwrap();
        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![datom(b"bob", ":person/name", "Bob", b"tx2")],
        );
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();
        let reader = DistributedDatomReader::new(&store, &ipns);

        let by_attr_value = reader
            .current_for_index_components(
                &second.commit.cid,
                ROOT_AVET,
                &[
                    kotoba_edn::parse(":person/name").unwrap(),
                    EdnValue::String("Bob".into()),
                ],
            )
            .unwrap();
        assert_eq!(by_attr_value.len(), 1);
        assert_eq!(by_attr_value[0].e, KotobaCid::from_bytes(b"bob"));

        let by_entity_attr = reader
            .current_for_index_components(
                &second.commit.cid,
                ROOT_EAVT,
                &[
                    EdnValue::String(KotobaCid::from_bytes(b"alice").to_multibase()),
                    kotoba_edn::parse(":person/name").unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(by_entity_attr.len(), 1);
        assert_eq!(by_entity_attr[0].v, EdnValue::String("Alice".into()));

        let datomic_avet = reader
            .datoms_index(
                &second.commit.cid,
                DatomIndex::Avet,
                &[
                    kotoba_edn::parse(":person/name").unwrap(),
                    EdnValue::String("Bob".into()),
                ],
            )
            .unwrap();
        assert_eq!(datomic_avet.len(), 1);
        assert_eq!(datomic_avet[0].e, KotobaCid::from_bytes(b"bob"));

        let datomic_tea = reader
            .history_datoms_index(
                &second.commit.cid,
                DatomIndex::Tea,
                &[EdnValue::String(second.commit.tx_cid.to_multibase())],
            )
            .unwrap();
        assert!(datomic_tea
            .iter()
            .all(|datom| datom.t == second.commit.tx_cid));
        assert_eq!(datomic_tea.len(), 1);

        let seek = reader
            .seek_datoms(
                &second.commit.cid,
                DatomIndex::Avet,
                &[kotoba_edn::parse(":person/name").unwrap()],
            )
            .unwrap();
        assert!(seek
            .iter()
            .any(|datom| datom.v == EdnValue::String("Alice".into())));
        assert!(seek
            .iter()
            .any(|datom| datom.v == EdnValue::String("Bob".into())));

        let range = reader
            .index_range(
                &second.commit.cid,
                ":person/name",
                Some(&EdnValue::String("Alice".into())),
                Some(&EdnValue::String("Bob".into())),
            )
            .unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].v, EdnValue::String("Alice".into()));
    }

    #[test]
    fn reader_index_range_uses_current_distributed_avet_history() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice = KotobaCid::from_bytes(b"alice");
        let bob = KotobaCid::from_bytes(b"bob");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![
                    Datom::assert(
                        alice.clone(),
                        ":person/score".into(),
                        EdnValue::Integer(10),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        bob.clone(),
                        ":person/score".into(),
                        EdnValue::Integer(20),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();
        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![Datom::retract(
                alice,
                ":person/score".into(),
                EdnValue::Integer(10),
                KotobaCid::from_bytes(b"tx2"),
            )],
        );
        second_req.expected_parent = Some(first.commit.cid);
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();
        let reader = DistributedDatomReader::new(&store, &ipns);

        let range = reader
            .index_range(
                &second.commit.cid,
                ":person/score",
                Some(&EdnValue::Integer(0)),
                Some(&EdnValue::Integer(30)),
            )
            .unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].e, bob);
        assert_eq!(range[0].v, EdnValue::Integer(20));

        let range_from_value_bound = reader
            .index_range(
                &second.commit.cid,
                ":person/score",
                Some(&EdnValue::Integer(15)),
                Some(&EdnValue::Integer(30)),
            )
            .unwrap();
        assert_eq!(range_from_value_bound.len(), 1);
        assert_eq!(range_from_value_bound[0].e, bob);
        assert_eq!(range_from_value_bound[0].v, EdnValue::Integer(20));

        let seek = reader
            .seek_datoms(
                &second.commit.cid,
                DatomIndex::Avet,
                &[
                    kotoba_edn::parse(":person/score").unwrap(),
                    EdnValue::Integer(0),
                ],
            )
            .unwrap();
        assert_eq!(seek.len(), 1);
        assert_eq!(seek[0].e, bob);
        assert_eq!(seek[0].v, EdnValue::Integer(20));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires a running Kubo HTTP API; optionally set KOTOBA_IPNS_NAME and KOTOBA_IPFS_ENDPOINT, then run with --ignored"]
    async fn kubo_backed_commit_ipns_head_and_query_roundtrip() {
        let store = kotoba_store::KuboBlockStore::from_env();
        store.probe_version().await.expect("Kubo HTTP API is ready");
        let ipns = KuboIpnsRegistry::from_env();
        let ipns_name = std::env::var("KOTOBA_IPNS_NAME").unwrap_or_else(|_| {
            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos();
            ipns.generate_ed25519_key(&format!("kotoba-datomic-test-{suffix}"))
                .expect("generate isolated Kubo IPNS key")
                .id
        });
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"kubo-backed-graph");
        let alice = KotobaCid::from_bytes(b"kubo-alice");

        let report = writer
            .commit_datoms(request(
                &ipns_name,
                graph,
                vec![Datom::assert(
                    alice.clone(),
                    ":person/name".into(),
                    EdnValue::String("Alice via Kubo".into()),
                    KotobaCid::from_bytes(b"ignored-client-tx"),
                )],
            ))
            .expect("commit datoms to Kubo-backed IPLD blocks and IPNS head");
        assert!(
            store.has(&report.commit.cid),
            "Kubo must persist commit block"
        );
        for root in report.commit.index_roots.values() {
            assert!(store.has(root), "Kubo must persist every Prolly index root");
        }

        let fresh_ipns = KuboIpnsRegistry::from_env();
        let reader = DistributedDatomReader::new(&store, &fresh_ipns);
        let head = reader
            .resolve_head(&ipns_name)
            .expect("resolve Kubo-published IPNS head")
            .expect("IPNS head exists");
        assert_eq!(head.cid, report.commit.cid);
        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = reader
            .q_triples(&head.cid, &query)
            .expect("query Kubo-backed distributed Datomic head");
        assert_eq!(rows, vec![vec![EdnValue::String("Alice via Kubo".into())]]);
    }

    #[test]
    fn reader_scans_vaet_only_for_ref_cid_values() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice = KotobaCid::from_bytes(b"alice");
        let bob = KotobaCid::from_bytes(b"bob");
        let tx = KotobaCid::from_bytes(b"tx1");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        alice.clone(),
                        ":person/friend".into(),
                        EdnValue::String(bob.to_multibase()),
                        tx.clone(),
                    ),
                    Datom::assert(
                        alice.clone(),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        tx.clone(),
                    ),
                ],
            ))
            .unwrap();
        let reader = DistributedDatomReader::new(&store, &ipns);

        let all_vaet = reader
            .current_for_index_components(&report.commit.cid, ROOT_VAET, &[])
            .unwrap();
        assert_eq!(all_vaet.len(), 1);
        assert_eq!(all_vaet[0].a, ":person/friend");

        let by_ref_attr_entity_tx = reader
            .current_for_index_components(
                &report.commit.cid,
                ROOT_VAET,
                &[
                    EdnValue::String(bob.to_multibase()),
                    kotoba_edn::parse(":person/friend").unwrap(),
                    EdnValue::String(alice.to_multibase()),
                    EdnValue::String(report.commit.tx_cid.to_multibase()),
                ],
            )
            .unwrap();
        assert_eq!(by_ref_attr_entity_tx, all_vaet);

        let non_ref_value = reader
            .current_for_index_components(
                &report.commit.cid,
                ROOT_VAET,
                &[EdnValue::String("Alice".into())],
            )
            .unwrap();
        assert!(non_ref_value.is_empty());
    }

    #[test]
    fn reader_queries_distributed_history_since_transaction() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![datom(b"alice", ":person/name", "Alice", b"tx1")],
            ))
            .unwrap();
        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![datom(b"bob", ":person/name", "Bob", b"tx2")],
        );
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();
        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]]}"#,
        )
        .unwrap();

        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_since_tx(&second.commit.cid, &first.commit.tx_cid, &query)
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Bob".into())]]);
    }

    #[test]
    fn reader_rebuilds_history_from_ipns_head_chain() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let first_datom = datom(b"alice", "person/name", "Alice", b"tx1");
        let second_datom = datom(b"bob", "person/name", "Bob", b"tx2");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![first_datom.clone()],
            ))
            .unwrap();

        let mut second_req = request("k51-kotoba-db", graph, vec![second_datom.clone()]);
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let history = reader.history_for_name("k51-kotoba-db").unwrap();
        assert_eq!(
            history,
            vec![
                with_tx(first_datom, &first.commit.tx_cid),
                with_tx(second_datom, &second.commit.tx_cid)
            ]
        );
    }

    #[test]
    fn reader_queries_latest_distributed_head_by_ipns_name() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice = KotobaCid::from_bytes(b"alice");
        let bob = KotobaCid::from_bytes(b"bob");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![
                    Datom::assert(
                        alice.clone(),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        alice.clone(),
                        ":person/score".into(),
                        EdnValue::Integer(10),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![
                Datom::assert(
                    bob.clone(),
                    ":person/name".into(),
                    EdnValue::String("Bob".into()),
                    KotobaCid::from_bytes(b"tx2"),
                ),
                Datom::assert(
                    bob.clone(),
                    ":person/score".into(),
                    EdnValue::Integer(20),
                    KotobaCid::from_bytes(b"tx2"),
                ),
            ],
        );
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [?wanted]
                :where [[?e :person/name ?name]
                        [(= ?name ?wanted)]]}"#,
        )
        .unwrap();
        let reader = DistributedDatomReader::new(&store, &ipns);
        let rows = reader
            .q_triples_for_name_with_inputs(
                "k51-kotoba-db",
                &query,
                &[EdnValue::String("Bob".into())],
            )
            .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("Bob".into())]]);

        let bob_datoms = reader
            .datoms_index_for_name(
                "k51-kotoba-db",
                DatomIndex::Eavt,
                &[EdnValue::String(bob.to_multibase())],
            )
            .unwrap();
        assert!(bob_datoms
            .iter()
            .any(|datom| datom.a == ":person/name" && datom.v == EdnValue::String("Bob".into())));

        let second_history = reader
            .history_datoms_index_for_name(
                "k51-kotoba-db",
                DatomIndex::Tea,
                &[EdnValue::String(second.commit.tx_cid.to_multibase())],
            )
            .unwrap();
        assert_eq!(second_history.len(), 2);
        assert!(second_history
            .iter()
            .all(|datom| datom.t == second.commit.tx_cid));

        let score_attr = kotoba_edn::parse(":person/score").unwrap();
        let score_floor = EdnValue::Integer(15);
        let score_seek = reader
            .seek_datoms_for_name(
                "k51-kotoba-db",
                DatomIndex::Avet,
                &[score_attr.clone(), score_floor.clone()],
            )
            .unwrap();
        assert_eq!(score_seek.len(), 1);
        assert_eq!(score_seek[0].e, bob);
        assert_eq!(score_seek[0].v, EdnValue::Integer(20));

        let score_range = reader
            .index_range_for_name(
                "k51-kotoba-db",
                ":person/score",
                Some(&score_floor),
                Some(&EdnValue::Integer(30)),
            )
            .unwrap();
        assert_eq!(score_range, score_seek);

        let names_query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]]}"#,
        )
        .unwrap();
        assert_eq!(
            reader
                .q_triples_as_of_tx_for_name("k51-kotoba-db", &first.commit.tx_cid, &names_query)
                .unwrap(),
            vec![vec![EdnValue::String("Alice".into())]]
        );
        assert_eq!(
            reader
                .q_triples_since_tx_for_name("k51-kotoba-db", &first.commit.tx_cid, &names_query)
                .unwrap(),
            vec![vec![EdnValue::String("Bob".into())]]
        );
    }

    #[tokio::test]
    async fn writer_transacts_edn_to_distributed_ipns_head() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"distributed-transact-graph");
        let first = writer
            .transact(DistributedTransactRequest {
                ipns_name: "k51-kotoba-db".into(),
                graph: graph.clone(),
                tx_data: kotoba_edn::parse(
                    r#"[[:db/add "alice" :person/name "Alice"]
                        [:db/add "alice" :person/score 10]]"#,
                )
                .unwrap(),
                expected_parent: None,
                author: "did:key:zWriter".into(),
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .await
            .unwrap();
        assert_eq!(first.commit.commit.tx_cid, first.transact.tx_cid);
        assert_eq!(first.commit.ipns_record.sequence, 1);
        assert_eq!(first.commit.datom_count, first.transact.tx_data.len());
        assert_eq!(first.datoms, first.transact.tx_data);
        assert_eq!(first.context.seq, 1);

        let second = writer
            .transact(DistributedTransactRequest {
                ipns_name: "k51-kotoba-db".into(),
                graph,
                tx_data: kotoba_edn::parse(
                    r#"[[:db/add "bob" :person/name "Bob"]
                        [:db/add "bob" :person/score 20]]"#,
                )
                .unwrap(),
                expected_parent: None,
                author: "did:key:zWriter".into(),
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .await
            .unwrap();
        assert_eq!(second.commit.commit.prev, Some(first.commit.commit.cid));
        assert_eq!(second.commit.ipns_record.sequence, 2);

        let reader = DistributedDatomReader::new(&store, &ipns);
        let rows = reader
            .q_triples_for_name(
                "k51-kotoba-db",
                &kotoba_edn::parse(
                    r#"{:find [?name]
                        :where [[?e :person/name ?name]]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Bob".into())],
            ]
        );
        assert_eq!(
            reader
                .q_triples_as_of_tx_for_name(
                    "k51-kotoba-db",
                    &first.transact.tx_cid,
                    &kotoba_edn::parse(
                        r#"{:find [?name]
                            :where [[?e :person/name ?name]]}"#,
                    )
                    .unwrap(),
                )
                .unwrap(),
            vec![vec![EdnValue::String("Alice".into())]]
        );
    }

    #[tokio::test]
    async fn writer_transact_preserves_datomic_schema_unique_identity_and_cardinality_one() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"distributed-schema-graph");

        let schema = writer
            .transact(DistributedTransactRequest {
                ipns_name: "k51-kotoba-schema-db".into(),
                graph: graph.clone(),
                tx_data: kotoba_edn::parse(
                    r#"[
                      {:db/id "email" :db/ident :person/email :db/unique :db.unique/identity}
                      {:db/id "name" :db/ident :person/name :db/cardinality :db.cardinality/one}
                    ]"#,
                )
                .unwrap(),
                expected_parent: None,
                author: "did:key:zWriter".into(),
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .await
            .unwrap();
        let inserted = writer
            .transact(DistributedTransactRequest {
                ipns_name: "k51-kotoba-schema-db".into(),
                graph: graph.clone(),
                tx_data: kotoba_edn::parse(
                    r#"[{:db/id "alice" :person/email "a@example.com" :person/name "Alice"}]"#,
                )
                .unwrap(),
                expected_parent: Some(schema.commit.commit.cid.clone()),
                author: "did:key:zWriter".into(),
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .await
            .unwrap();
        let upserted = writer
            .transact(DistributedTransactRequest {
                ipns_name: "k51-kotoba-schema-db".into(),
                graph,
                tx_data: kotoba_edn::parse(
                    r#"[{:db/id "alice-2" :person/email "a@example.com" :person/name "Alicia"}]"#,
                )
                .unwrap(),
                expected_parent: Some(inserted.commit.commit.cid.clone()),
                author: "did:key:zWriter".into(),
                valid_until: "2030-01-01T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .await
            .unwrap();

        let alice = inserted.transact.tempids["alice"].clone();
        assert_eq!(upserted.transact.tempids["alice-2"], alice);
        assert!(upserted.datoms.iter().any(|datom| !datom.added
            && datom.e == alice
            && datom.a == ":person/name"
            && datom.v == EdnValue::String("Alice".into())));

        let reader = DistributedDatomReader::new(&store, &ipns);
        let head = reader
            .resolve_head("k51-kotoba-schema-db")
            .unwrap()
            .expect("ipns head");
        assert_eq!(head.cid, upserted.commit.commit.cid);
        let current_name = reader
            .current_for_entity_attribute(&head.cid, &alice, ":person/name")
            .unwrap();
        assert_eq!(current_name.len(), 1);
        assert_eq!(current_name[0].v, EdnValue::String("Alicia".into()));

        let rows = reader
            .q_triples_for_name(
                "k51-kotoba-schema-db",
                &kotoba_edn::parse(
                    r#"{:find [?name]
                        :where [[[:person/email "a@example.com"] :person/name ?name]]}"#,
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alicia".into())]]);
        assert_eq!(upserted.commit.ipns_record.sequence, 3);
    }

    #[test]
    fn reader_pulls_entities_from_distributed_ipns_head_and_time_views() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice = KotobaCid::from_bytes(b"alice");
        let bob = KotobaCid::from_bytes(b"bob");
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![
                    Datom::assert(
                        alice.clone(),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        alice.clone(),
                        ":person/role".into(),
                        EdnValue::String("admin".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();
        let mut second_req = request(
            "k51-kotoba-db",
            graph,
            vec![
                Datom::assert(
                    bob.clone(),
                    ":person/name".into(),
                    EdnValue::String("Bob".into()),
                    KotobaCid::from_bytes(b"tx2"),
                ),
                Datom::assert(
                    bob.clone(),
                    ":person/role".into(),
                    EdnValue::String("operator".into()),
                    KotobaCid::from_bytes(b"tx2"),
                ),
            ],
        );
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let pattern = kotoba_edn::parse(r#"[:person/name :person/role]"#).unwrap();
        let name_key = kotoba_edn::parse(":person/name").unwrap();
        let role_key = kotoba_edn::parse(":person/role").unwrap();

        let pulled = reader
            .pull_for_name("k51-kotoba-db", pattern.clone(), alice.clone())
            .unwrap()
            .expect("ipns head");
        let pulled_map = pulled.as_map().unwrap();
        assert_eq!(
            pulled_map.get(&name_key),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            pulled_map.get(&role_key),
            Some(&EdnValue::String("admin".into()))
        );

        let pulled_many = reader
            .pull_many_for_name(
                "k51-kotoba-db",
                pattern.clone(),
                vec![alice.clone(), bob.clone()],
            )
            .unwrap()
            .expect("ipns head");
        assert_eq!(pulled_many.len(), 2);
        assert_eq!(
            pulled_many[1].as_map().unwrap().get(&name_key),
            Some(&EdnValue::String("Bob".into()))
        );

        let as_of = reader
            .pull_as_of_tx_for_name(
                "k51-kotoba-db",
                &first.commit.tx_cid,
                pattern.clone(),
                alice,
            )
            .unwrap()
            .expect("ipns head");
        assert_eq!(
            as_of.as_map().unwrap().get(&name_key),
            Some(&EdnValue::String("Alice".into()))
        );

        let since = reader
            .pull_since_tx_for_name("k51-kotoba-db", &first.commit.tx_cid, pattern, bob)
            .unwrap()
            .expect("ipns head");
        assert_eq!(
            since.as_map().unwrap().get(&name_key),
            Some(&EdnValue::String("Bob".into()))
        );
        assert_eq!(
            reader
                .entity_for_name("k51-missing-db", KotobaCid::from_bytes(b"alice"))
                .unwrap(),
            None
        );
        assert_eq!(second.commit.prev, Some(first.commit.cid));
    }

    #[tokio::test]
    async fn writer_transact_with_augments_datoms_before_distributed_commit() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"distributed-transact-hook-graph");
        let report = writer
            .transact_with(
                DistributedTransactRequest {
                    ipns_name: "k51-kotoba-db".into(),
                    graph: graph.clone(),
                    tx_data: kotoba_edn::parse(r#"[[:db/add "alice" :person/name "Alice"]]"#)
                        .unwrap(),
                    expected_parent: None,
                    author: "did:key:zWriter".into(),
                    valid_until: "2030-01-01T00:00:00Z".into(),
                    ttl_secs: Some(60),
                    cacao_proof_cid: None,
                    ipns_controller_did: None,
                    ipns_signing_key: None,
                },
                |transact, context, datoms| {
                    datoms.push(Datom::assert(
                        transact.tx_cid.clone(),
                        ":tx/ipnsName".into(),
                        EdnValue::String(context.ipns_name.clone()),
                        transact.tx_cid.clone(),
                    ));
                    datoms.push(Datom::assert(
                        transact.tx_cid.clone(),
                        ":tx/seq".into(),
                        EdnValue::Integer(context.seq as i64),
                        transact.tx_cid.clone(),
                    ));
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(report.commit.datom_count, report.datoms.len());
        assert!(report.datoms.len() > report.transact.tx_data.len());

        let reader = DistributedDatomReader::new(&store, &ipns);
        let tx_datoms = reader
            .history_datoms_index_for_name(
                "k51-kotoba-db",
                DatomIndex::Tea,
                &[EdnValue::String(report.transact.tx_cid.to_multibase())],
            )
            .unwrap();
        assert!(tx_datoms.iter().any(|datom| datom.a == ":tx/ipnsName"
            && datom.v == EdnValue::String("k51-kotoba-db".into())));
        assert!(tx_datoms
            .iter()
            .any(|datom| datom.a == ":tx/seq" && datom.v == EdnValue::Integer(1)));
    }

    #[tokio::test]
    async fn writer_transact_with_tx_fns_expands_custom_functions_before_distributed_commit() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"distributed-custom-tx-fn-graph");

        let first = writer
            .transact_with_tx_fns(
                DistributedTransactRequest {
                    ipns_name: "k51-kotoba-tx-fn-db".into(),
                    graph: graph.clone(),
                    tx_data: kotoba_edn::parse(r#"[[:my.fn/increment "alice" :person/score 10]]"#)
                        .unwrap(),
                    expected_parent: None,
                    author: "did:key:zWriter".into(),
                    valid_until: "2030-01-01T00:00:00Z".into(),
                    ttl_secs: Some(60),
                    cacao_proof_cid: None,
                    ipns_controller_did: None,
                    ipns_signing_key: None,
                },
                register_increment_tx_fn,
                |_, _, _| Ok(()),
            )
            .await
            .unwrap();
        let second = writer
            .transact_with_tx_fns(
                DistributedTransactRequest {
                    ipns_name: "k51-kotoba-tx-fn-db".into(),
                    graph,
                    tx_data: kotoba_edn::parse(r#"[[:my.fn/increment "alice" :person/score 5]]"#)
                        .unwrap(),
                    expected_parent: Some(first.commit.commit.cid.clone()),
                    author: "did:key:zWriter".into(),
                    valid_until: "2030-01-01T00:00:00Z".into(),
                    ttl_secs: Some(60),
                    cacao_proof_cid: None,
                    ipns_controller_did: None,
                    ipns_signing_key: None,
                },
                register_increment_tx_fn,
                |transact, context, datoms| {
                    datoms.push(Datom::assert(
                        transact.tx_cid.clone(),
                        ":tx/customFn".into(),
                        EdnValue::String(context.ipns_name.clone()),
                        transact.tx_cid.clone(),
                    ));
                    Ok(())
                },
            )
            .await
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let alice = KotobaCid::from_bytes(b"alice");
        let scores = reader
            .current_for_entity_attribute(&second.commit.commit.cid, &alice, ":person/score")
            .unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].v, EdnValue::Integer(15));
        let tx_datoms = reader
            .history_datoms_index(
                &second.commit.commit.cid,
                DatomIndex::Tea,
                &[EdnValue::String(second.transact.tx_cid.to_multibase())],
            )
            .unwrap();
        assert!(tx_datoms.iter().any(|datom| datom.a == ":tx/customFn"
            && datom.v == EdnValue::String("k51-kotoba-tx-fn-db".into())));
        assert_eq!(second.commit.ipns_record.sequence, 2);
    }

    #[test]
    fn reader_logs_distributed_commits_as_transaction_entries() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let entity = KotobaCid::from_bytes(b"alice");
        let tx1 = KotobaCid::from_bytes(b"tx1");
        let tx2 = KotobaCid::from_bytes(b"tx2");
        let asserted = Datom::assert(
            entity.clone(),
            "person/name".into(),
            EdnValue::String("Alice".into()),
            tx1.clone(),
        );
        let mut first_req = request("k51-kotoba-db", graph.clone(), vec![asserted.clone()]);
        first_req.tx_cid = Some(tx1.clone());
        let first = writer.commit_datoms(first_req).unwrap();

        let retracted = Datom::retract(
            entity,
            "person/name".into(),
            EdnValue::String("Alice".into()),
            tx2.clone(),
        );
        let mut second_req = request("k51-kotoba-db", graph, vec![retracted.clone()]);
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.tx_cid = Some(tx2.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let entries = reader.log_from_head(&second.commit.cid).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].tx, first.commit.tx_cid);
        assert_eq!(entries[0].datoms, vec![asserted]);
        assert_eq!(entries[1].tx, second.commit.tx_cid);
        assert_eq!(entries[1].datoms, vec![retracted.clone()]);
        assert!(entries[1].datoms.iter().any(|datom| !datom.added));

        assert_eq!(reader.log_for_name("k51-kotoba-db").unwrap(), entries);
        assert!(reader.log_for_name("k51-missing-db").unwrap().is_empty());
    }

    #[test]
    fn reader_projects_distributed_history_db_with_retract_tombstones() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let entity = KotobaCid::from_bytes(b"alice");
        let asserted = Datom::assert(
            entity.clone(),
            "person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let first = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph.clone(),
                vec![asserted.clone()],
            ))
            .unwrap();
        let retracted = Datom::retract(
            entity,
            "person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx2"),
        );
        let mut second_req = request("k51-kotoba-db", graph, vec![retracted.clone()]);
        second_req.expected_parent = Some(first.commit.cid.clone());
        second_req.seq = 2;
        let second = writer.commit_datoms(second_req).unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let history_db = reader.history_db_from_head(&second.commit.cid).unwrap();
        assert_eq!(history_db.basis_t, Some(second.commit.tx_cid.clone()));
        assert_eq!(
            history_db.history().datoms(),
            &[
                with_tx(asserted.clone(), &first.commit.tx_cid),
                with_tx(retracted, &second.commit.tx_cid)
            ]
        );
        let history_rows = crate::q_history(
            kotoba_edn::parse(
                r#"{:find [?name ?added]
                   :in [$history]
                   :where [[$history ?e :person/name ?name ?tx ?added]]}"#,
            )
            .unwrap(),
            &history_db.history(),
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

        let current_db = reader.db_from_head(&second.commit.cid).unwrap();
        assert_eq!(current_db.datoms(), &[] as &[Datom]);

        let as_of_db = reader
            .history_db_as_of_tx(&second.commit.cid, &first.commit.tx_cid)
            .unwrap();
        assert_eq!(
            as_of_db.history().datoms(),
            &[with_tx(asserted, &first.commit.tx_cid)]
        );
    }

    #[test]
    fn reader_scans_distributed_indexes_by_entity_attribute_and_value() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = datom(b"alice", "person/name", "Alice", b"tx1");
        let alice_role = datom(b"alice", "person/role", "admin", b"tx1");
        let bob_name = datom(b"bob", "person/name", "Bob", b"tx1");

        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_name.clone(), alice_role.clone(), bob_name.clone()],
            ))
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let alice = KotobaCid::from_bytes(b"alice");
        assert_eq!(
            reader
                .current_for_entity(&report.commit.cid, &alice)
                .unwrap(),
            vec![
                with_tx(alice_name.clone(), &report.commit.tx_cid),
                with_tx(alice_role.clone(), &report.commit.tx_cid)
            ]
        );
        assert_eq!(
            reader
                .current_for_entity_attribute(&report.commit.cid, &alice, "person/role")
                .unwrap(),
            vec![with_tx(alice_role.clone(), &report.commit.tx_cid)]
        );
        assert_eq!(
            reader
                .current_for_attribute(&report.commit.cid, "person/name")
                .unwrap(),
            vec![
                with_tx(alice_name.clone(), &report.commit.tx_cid),
                with_tx(bob_name.clone(), &report.commit.tx_cid)
            ]
        );
        assert_eq!(
            reader
                .current_for_attribute_value(
                    &report.commit.cid,
                    "person/role",
                    &EdnValue::String("admin".into())
                )
                .unwrap(),
            vec![with_tx(alice_role.clone(), &report.commit.tx_cid)]
        );
        assert_eq!(
            reader
                .current_for_lookup(
                    &report.commit.cid,
                    &DatomIndexLookup::EntityAttribute {
                        entity: alice,
                        attr: "person/name".into(),
                    },
                )
                .unwrap(),
            vec![with_tx(alice_name, &report.commit.tx_cid)]
        );
        assert_eq!(
            reader
                .current_for_lookup(
                    &report.commit.cid,
                    &DatomIndexLookup::AttributeValue {
                        attr: "person/name".into(),
                        value: EdnValue::String("Bob".into()),
                    },
                )
                .unwrap(),
            vec![with_tx(bob_name, &report.commit.tx_cid)]
        );
    }

    #[test]
    fn reader_evaluates_single_triple_via_planned_index() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );

        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_name.clone(), bob_name.clone()],
            ))
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let triple = kotoba_edn::parse(r#"[?e :person/name "Bob"]"#).unwrap();
        assert_eq!(
            reader
                .current_for_triple(&report.commit.cid, &triple, &BTreeMap::new())
                .unwrap(),
            vec![with_tx(bob_name.clone(), &report.commit.tx_cid)]
        );

        let mut binding = BTreeMap::new();
        binding.insert("?e".into(), EdnValue::String(bob_name.e.to_multibase()));
        let triple = kotoba_edn::parse(r#"[?e :person/name ?name]"#).unwrap();
        assert_eq!(
            reader
                .current_for_triple(&report.commit.cid, &triple, &binding)
                .unwrap(),
            vec![with_tx(bob_name, &report.commit.tx_cid)]
        );
    }

    #[test]
    fn reader_resolves_lookup_ref_entity_position_via_distributed_index() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_email = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/email".into(),
            EdnValue::String("a@example.com".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );

        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_email, alice_name.clone(), bob_name],
            ))
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let triple =
            kotoba_edn::parse(r#"[[:person/email "a@example.com"] :person/name ?name]"#).unwrap();
        assert_eq!(
            reader
                .current_for_triple(&report.commit.cid, &triple, &BTreeMap::new())
                .unwrap(),
            vec![with_tx(alice_name.clone(), &report.commit.tx_cid)]
        );

        let mut binding = BTreeMap::new();
        binding.insert("?email".into(), EdnValue::String("a@example.com".into()));
        let triple = kotoba_edn::parse(r#"[[:person/email ?email] :person/name ?name]"#).unwrap();
        assert_eq!(
            reader
                .current_for_triple(&report.commit.cid, &triple, &binding)
                .unwrap(),
            vec![with_tx(alice_name, &report.commit.tx_cid)]
        );
    }

    #[test]
    fn reader_joins_multiple_triples_with_planned_distributed_indexes() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_role = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("guest")),
            KotobaCid::from_bytes(b"tx1"),
        );

        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_name, alice_role, bob_name, bob_role],
            ))
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let triples = vec![
            kotoba_edn::parse(r#"[?e :person/name ?name]"#).unwrap(),
            kotoba_edn::parse(r#"[?e :person/role :admin]"#).unwrap(),
        ];
        let bindings = reader
            .bindings_for_triples(&report.commit.cid, &triples, vec![BTreeMap::new()])
            .unwrap();

        assert_eq!(bindings.len(), 1);
        assert_eq!(
            bindings[0].get("?name"),
            Some(&EdnValue::String("Alice".into()))
        );
        assert_eq!(
            bindings[0].get("?e"),
            Some(&EdnValue::String(
                KotobaCid::from_bytes(b"alice").to_multibase()
            ))
        );
    }

    #[test]
    fn reader_projects_triple_only_query_rows_from_distributed_indexes() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_role = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("guest")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_name, alice_role, bob_name, bob_role],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]
                        [?e :person/role :admin]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &query)
            .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[test]
    fn reader_projects_triple_only_query_with_scalar_inputs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_role = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("guest")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_name, alice_role, bob_name, bob_role],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$ ?role]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &query,
                &[EdnValue::Keyword(Keyword::parse("guest"))],
            )
            .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("Bob".into())]]);
    }

    #[test]
    fn reader_projects_triple_only_query_with_collection_inputs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_role = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("guest")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let eve_name = Datom::assert(
            KotobaCid::from_bytes(b"eve"),
            ":person/name".into(),
            EdnValue::String("Eve".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let eve_role = Datom::assert(
            KotobaCid::from_bytes(b"eve"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("auditor")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    alice_name, alice_role, bob_name, bob_role, eve_name, eve_role,
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$ [?role ...]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &query,
                &[EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("admin")),
                    EdnValue::Keyword(Keyword::parse("auditor")),
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

        let named_source_query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$db [?role ...]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &named_source_query,
                &[EdnValue::Vector(vec![EdnValue::Keyword(Keyword::parse(
                    "admin",
                ))])],
            )
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);

        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &named_source_query,
                &[
                    EdnValue::Symbol(kotoba_edn::Symbol::bare("$db")),
                    EdnValue::Vector(vec![EdnValue::Keyword(Keyword::parse("auditor"))]),
                ],
            )
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);

        let source_pattern_query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$db]
                :where [[$db ?e :person/role :admin]
                        [$db ?e :person/name ?name]
                        [(missing? $db ?e :person/ban-reason)]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &source_pattern_query, &[])
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);

        let source_added_pattern_query = kotoba_edn::parse(
            r#"{:find [?name ?tx ?added]
                :in [$db]
                :where [[$db ?e :person/role :admin ?tx ?added]
                        [$db ?e :person/name ?name ?tx ?added]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &source_added_pattern_query, &[])
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                cid_value(&report.commit.tx_cid),
                EdnValue::Bool(true)
            ]]
        );

        let vector_query = kotoba_edn::parse(
            r#"[:find ?name
                :in $db [?role ...]
                :where [$db ?e :person/name ?name]
                       [$db ?e :person/role ?role]]"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &vector_query,
                &[EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("admin")),
                    EdnValue::Keyword(Keyword::parse("auditor")),
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

        let tx_pattern_query = kotoba_edn::parse(
            r#"{:find [?name ?tx]
                :where [[?e :person/role :admin ?tx]
                        [?e :person/name ?name ?tx]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &tx_pattern_query, &[])
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                cid_value(&report.commit.tx_cid)
            ]]
        );

        let source_tx_pattern_query = kotoba_edn::parse(
            r#"[:find ?name ?tx
                :in $db
                :where [$db ?e :person/name ?name ?tx]
                       [$db ?e :person/role :auditor ?tx]]"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &source_tx_pattern_query, &[])
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Eve".into()),
                cid_value(&report.commit.tx_cid)
            ]]
        );

        let named_source_function_query = kotoba_edn::parse(
            r#"{:find [?name ?role ?found]
                :in [$db]
                :where [[$db ?e :person/name ?name]
                        [(get-else $db ?e :person/role :guest) ?role]
                        [(= ?role :admin)]
                        [(get-some $db ?e :person/email :person/role) ?found]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &named_source_function_query, &[])
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                EdnValue::Keyword(Keyword::parse("admin")),
                EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("person/role")),
                    EdnValue::Keyword(Keyword::parse("admin"))
                ])
            ]]
        );
    }

    #[test]
    fn reader_projects_triple_only_query_with_tuple_inputs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_role = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_status = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/status".into(),
            EdnValue::Keyword(Keyword::parse("active")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_status = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/status".into(),
            EdnValue::Keyword(Keyword::parse("suspended")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    alice_name,
                    alice_role,
                    alice_status,
                    bob_name,
                    bob_role,
                    bob_status,
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$ [?role ?status]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]
                        [?e :person/status ?status]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &query,
                &[EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("admin")),
                    EdnValue::Keyword(Keyword::parse("active")),
                ])],
            )
            .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[test]
    fn reader_projects_triple_only_query_with_relation_inputs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_role = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("admin")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_status = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/status".into(),
            EdnValue::Keyword(Keyword::parse("active")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("guest")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_status = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/status".into(),
            EdnValue::Keyword(Keyword::parse("active")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let eve_name = Datom::assert(
            KotobaCid::from_bytes(b"eve"),
            ":person/name".into(),
            EdnValue::String("Eve".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let eve_role = Datom::assert(
            KotobaCid::from_bytes(b"eve"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("auditor")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let eve_status = Datom::assert(
            KotobaCid::from_bytes(b"eve"),
            ":person/status".into(),
            EdnValue::Keyword(Keyword::parse("active")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    alice_name,
                    alice_role,
                    alice_status,
                    bob_name,
                    bob_role,
                    bob_status,
                    eve_name,
                    eve_role,
                    eve_status,
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$ [[?role ?status]]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]
                        [?e :person/status ?status]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(
                &report.commit.cid,
                &query,
                &[EdnValue::Vector(vec![
                    EdnValue::Vector(vec![
                        EdnValue::Keyword(Keyword::parse("admin")),
                        EdnValue::Keyword(Keyword::parse("active")),
                    ]),
                    EdnValue::Vector(vec![
                        EdnValue::Keyword(Keyword::parse("auditor")),
                        EdnValue::Keyword(Keyword::parse("active")),
                    ]),
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
    }

    #[test]
    fn reader_projects_pull_find_expression_from_distributed_head() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let alice_name = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/name".into(),
            EdnValue::String("Alice".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let alice_friend = Datom::assert(
            KotobaCid::from_bytes(b"alice"),
            ":person/friend".into(),
            EdnValue::String("bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_name = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/name".into(),
            EdnValue::String("Bob".into()),
            KotobaCid::from_bytes(b"tx1"),
        );
        let bob_role = Datom::assert(
            KotobaCid::from_bytes(b"bob"),
            ":person/role".into(),
            EdnValue::Keyword(Keyword::parse("guest")),
            KotobaCid::from_bytes(b"tx1"),
        );
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![alice_name, alice_friend, bob_name, bob_role],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [(pull ?e [:person/name {:person/friend [:person/name :person/role]}])]
                :where [[?e :person/name "Alice"]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &query)
            .unwrap();

        assert_eq!(rows.len(), 1);
        let pulled = rows[0][0].as_map().unwrap();
        assert_eq!(
            pulled.get(&EdnValue::Keyword(Keyword::namespaced("person", "name"))),
            Some(&EdnValue::String("Alice".into()))
        );
        let friend = pulled
            .get(&EdnValue::Keyword(Keyword::namespaced("person", "friend")))
            .and_then(EdnValue::as_map)
            .unwrap();
        assert_eq!(
            friend.get(&EdnValue::Keyword(Keyword::namespaced("person", "name"))),
            Some(&EdnValue::String("Bob".into()))
        );
        assert_eq!(
            friend.get(&EdnValue::Keyword(Keyword::namespaced("person", "role"))),
            Some(&EdnValue::Keyword(Keyword::parse("guest")))
        );
    }

    #[test]
    fn reader_filters_distributed_query_with_not_and_not_join() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("role/admin")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/name".into(),
                        EdnValue::String("Bob".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/ban-reason".into(),
                        EdnValue::String("spam".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/name".into(),
                        EdnValue::String("Eve".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let not_query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/role :guest]
                        (not [?e :person/ban-reason ?reason])
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &not_query)
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);

        let not_join_query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/role :guest]
                        (not-join [?e] [?e :person/ban-reason ?reason])
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &not_join_query)
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Eve".into())]]);
    }

    #[test]
    fn reader_branches_distributed_query_with_or_and_or_join() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("admin")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/name".into(),
                        EdnValue::String("Bob".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/name".into(),
                        EdnValue::String("Eve".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("auditor")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/verified".into(),
                        EdnValue::Bool(true),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let or_query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]
                        (or [?e :person/role :admin]
                            (and [?e :person/role :auditor]
                                 [?e :person/verified true]))]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &or_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Eve".into())],
            ]
        );

        let or_join_query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]
                        (or-join [?e]
                          [?e :person/role :admin]
                          (and [?e :person/role :auditor]
                               [?e :person/verified true]))]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &or_join_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Eve".into())],
            ]
        );
    }

    #[test]
    fn reader_evaluates_distributed_predicates_and_function_bindings() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("role/admin")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/age".into(),
                        EdnValue::Integer(36),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":atproto/uri".into(),
                        EdnValue::String("at://did:plc:alice/app.bsky.feed.post/r1".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"vc1"),
                        ":credential/claims".into(),
                        EdnValue::Map(BTreeMap::from([
                            (
                                EdnValue::Keyword(Keyword::parse("claim/type")),
                                EdnValue::String("VerifiableCredential".into()),
                            ),
                            (
                                EdnValue::Keyword(Keyword::parse("claim/status")),
                                EdnValue::String("active".into()),
                            ),
                            (
                                EdnValue::Keyword(Keyword::parse("claim/verified")),
                                EdnValue::Bool(true),
                            ),
                            (
                                EdnValue::Keyword(Keyword::parse("claim/score")),
                                EdnValue::Integer(42),
                            ),
                            (
                                EdnValue::Keyword(Keyword::parse("claim/tags")),
                                EdnValue::Vector(vec![
                                    EdnValue::Keyword(Keyword::parse("vc")),
                                    EdnValue::Keyword(Keyword::parse("ipld")),
                                ]),
                            ),
                            (
                                EdnValue::Keyword(Keyword::parse("claim/subject")),
                                EdnValue::Map(BTreeMap::from([
                                    (
                                        EdnValue::Keyword(Keyword::parse("subject/id")),
                                        EdnValue::String("did:example:alice".into()),
                                    ),
                                    (
                                        EdnValue::Keyword(Keyword::parse("subject/roles")),
                                        EdnValue::Vector(vec![
                                            EdnValue::Keyword(Keyword::parse("issuer")),
                                            EdnValue::Keyword(Keyword::parse("holder")),
                                        ]),
                                    ),
                                ])),
                            ),
                        ])),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/name".into(),
                        EdnValue::String("Bob".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/age".into(),
                        EdnValue::Integer(21),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/ban-reason".into(),
                        EdnValue::String("spam".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name ?displayName ?copy ?role ?found ?roleName ?roleNamespace ?resource ?rebuilt ?uri ?collection ?rkey ?splitCollection ?splitRkey ?nthCollection ?lastRkey ?joinedUri ?normalizedUri ?scheme ?trimmedScheme]
                :where [[(ground :guest) ?guest]
                        [?e :person/name ?name]
                        [(clojure.string/capitalize "alice") ?displayName]
                        [?e :person/age ?age]
                        [(clojure.core/>= ?age 30)]
                        [(clojure.core/not= ?name "Bob")]
                        [(missing? $ ?e :person/ban-reason)]
                        [(identity ?name) ?copy]
                        [(get-else $ ?e :person/role ?guest) ?role]
                        [(clojure.core/contains? #{:role/admin :role/moderator} ?role)]
                        [(get-some $ ?e :person/email :person/role) ?found]
                        [(name ?role) ?roleName]
                        [(namespace ?role) ?roleNamespace]
                        [(str "kotoba://role/" ?roleName) ?resource]
                        [(keyword "role" ?roleName) ?rebuilt]
                        [?e :atproto/uri ?uri]
                        [(clojure.string/starts-with? ?uri "at://")]
                        [(clojure.string/includes? ?uri "/app.bsky.feed.post/")]
                        [(str/ends-with? ?uri "/r1")]
                        [(subs ?uri 19 37) ?collection]
                        [(clojure.core/subs ?uri 38) ?rkey]
                        [(clojure.string/split ?uri "/") ?uriParts]
                        [(clojure.core/get ?uriParts 3) ?splitCollection]
                        [(clojure.core/get ?uriParts 4) ?splitRkey]
                        [(clojure.core/nth ?uriParts 3) ?nthCollection]
                        [(clojure.core/last ?uriParts) ?lastRkey]
                        [(clojure.string/join "/" ?uriParts) ?joinedUri]
                        [(= ?joinedUri ?uri)]
                        [(clojure.string/replace ?uri "at://" "at-uri://") ?normalizedUri]
                        [(upper-case "at") ?upperScheme]
                        [(clojure.string/lower-case ?upperScheme) ?scheme]
                        [(clojure.string/blank? "   ")]
                        [(str/trim "  at  ") ?trimmedScheme]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &query)
            .unwrap();

        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("Alice".into()),
                EdnValue::String("Alice".into()),
                EdnValue::String("Alice".into()),
                EdnValue::Keyword(Keyword::parse("role/admin")),
                EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("person/role")),
                    EdnValue::Keyword(Keyword::parse("role/admin")),
                ]),
                EdnValue::String("admin".into()),
                EdnValue::String("role".into()),
                EdnValue::String("kotoba://role/admin".into()),
                EdnValue::Keyword(Keyword::parse("role/admin")),
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

        let window_query = kotoba_edn::parse(
            r#"{:find [?name]
                :where [[?e :person/name ?name]]
                :order-by [[?name :desc]]
                :offset 1
                :limit 1}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &window_query)
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);

        let set_query = kotoba_edn::parse(
            r#"{:find [?expanded ?shared ?reduced]
                :where [[?e :person/role ?role]
                        [(= ?role :role/admin)]
                        [(hash-set ?role :role/auditor) ?roles]
                        [(clojure.set/union ?roles #{:role/operator}) ?expanded]
                        [(set/subset? #{:role/admin} ?expanded)]
                        [(set/superset? ?expanded ?roles)]
                        [(set/intersection ?expanded #{:role/admin :role/missing}) ?shared]
                        [(set/difference ?expanded #{:role/auditor}) ?reduced]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &set_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Set(BTreeSet::from([
                    EdnValue::Keyword(Keyword::parse("role/admin")),
                    EdnValue::Keyword(Keyword::parse("role/auditor")),
                    EdnValue::Keyword(Keyword::parse("role/operator")),
                ])),
                EdnValue::Set(BTreeSet::from([EdnValue::Keyword(Keyword::parse(
                    "role/admin"
                ))])),
                EdnValue::Set(BTreeSet::from([
                    EdnValue::Keyword(Keyword::parse("role/admin")),
                    EdnValue::Keyword(Keyword::parse("role/operator")),
                ])),
            ]]
        );

        let map_query = kotoba_edn::parse(
            r#"{:find [?selected ?merged ?keys ?vals]
                :where [[?e :credential/claims ?claims]
                        [(select-keys ?claims [:claim/type]) ?selected]
                        [(merge ?selected {:claim/source :distributed}) ?merged]
                        [(keys ?selected) ?keys]
                        [(vals ?selected) ?vals]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &map_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Map(BTreeMap::from([(
                    EdnValue::Keyword(Keyword::parse("claim/type")),
                    EdnValue::String("VerifiableCredential".into()),
                )])),
                EdnValue::Map(BTreeMap::from([
                    (
                        EdnValue::Keyword(Keyword::parse("claim/source")),
                        EdnValue::Keyword(Keyword::parse("distributed")),
                    ),
                    (
                        EdnValue::Keyword(Keyword::parse("claim/type")),
                        EdnValue::String("VerifiableCredential".into()),
                    ),
                ])),
                EdnValue::Vector(vec![EdnValue::Keyword(Keyword::parse("claim/type"))]),
                EdnValue::Vector(vec![EdnValue::String("VerifiableCredential".into())]),
            ]]
        );

        let collection_predicate_query = kotoba_edn::parse(
            r#"{:find [?allTags ?noNilTags ?notEveryTagString ?tagsVector ?sameTag ?hasTag ?notFalse ?truthyTags ?tagsString]
                :where [[?e :credential/claims ?claims]
                        [(get ?claims :claim/tags) ?tags]
                        [(distinct? :role/admin :role/auditor :role/operator)]
                        [(every? keyword? ?tags)]
                        [(every? keyword? ?tags) ?allTags]
                        [(not-any? nil? ?tags) ?noNilTags]
                        [(not-every? string? ?tags) ?notEveryTagString]
                        [(vector? ?tags) ?tagsVector]
                        [(= :vc :vc) ?sameTag]
                        [(contains? #{:vc :ipld} :vc) ?hasTag]
                        [(clojure.core/not false) ?notFalse]
                        [(boolean ?tags) ?truthyTags]
                        [(string? ?tags) ?tagsString]
                        [(= ?allTags true)]
                        [(= ?noNilTags true)]
                        [(= ?notEveryTagString true)]
                        [(= ?tagsVector true)]
                        [(= ?sameTag true)]
                        [(= ?hasTag true)]
                        [(= ?notFalse true)]
                        [(= ?truthyTags true)]
                        [(= ?tagsString false)]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &collection_predicate_query)
            .unwrap();
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
                EdnValue::Bool(false),
            ]]
        );

        let regex_query = kotoba_edn::parse(
            r#"{:find [?did ?collection ?rkey ?whole]
                :where [[?e :atproto/uri ?uri]
                        [(re-find "at://([^/]+)/([^/]+)/([^/]+)" ?uri) ?found]
                        [(get ?found 1) ?did]
                        [(get ?found 2) ?collection]
                        [(get ?found 3) ?rkey]
                        [(clojure.core/re-matches "at://[^/]+/[^/]+/[^/]+" ?uri) ?whole]
                        [(some? ?whole)]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &regex_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::String("did:plc:alice".into()),
                EdnValue::String("app.bsky.feed.post".into()),
                EdnValue::String("r1".into()),
                EdnValue::String("at://did:plc:alice/app.bsky.feed.post/r1".into()),
            ]]
        );

        let get_query = kotoba_edn::parse(
            r#"{:find [?type ?status ?verified ?score ?nextScore ?adjustedScore ?doubleScore ?quotScore ?remScore ?modScore ?negativeMod ?minScore ?maxScore ?tagCount ?subject ?generatedStatus ?summaryCount ?fallback ?nonEmptyTags]
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
                        [(first ?tags) ?seqFirstTag]
                        [(= ?seqFirstTag :vc)]
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
                        [(count ?tags) ?tagCount]
                        [(not-empty ?tags) ?nonEmptyTags]
                        [(some? ?nonEmptyTags)]
                        [(vector) ?emptyTags]
                        [(empty? ?emptyTags)]
                        [(vector :vc :ipld) ?expectedTags]
                        [(= ?tags ?expectedTags)]
                        [(get-in ?claims [:claim/subject :subject/id]) ?subject]
                        [(string? ?subject)]
                        [(assoc-in ?claims [:claim/subject :subject/verified] true) ?verifiedClaims]
                        [(get-in ?verifiedClaims [:claim/subject :subject/verified]) ?subjectVerified]
                        [(true? ?subjectVerified)]
                        [(update-in ?claims [:claim/subject :subject/roles] conj :verifier) ?roleUpdatedClaims]
                        [(get-in ?roleUpdatedClaims [:claim/subject :subject/roles]) ?updatedRoles]
                        [(= ?updatedRoles [:issuer :holder :verifier])]
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
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &get_query)
            .unwrap();
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
                EdnValue::Integer(2),
                EdnValue::String("did:example:alice".into()),
                EdnValue::String("active".into()),
                EdnValue::Integer(2),
                EdnValue::String("fallback".into()),
                EdnValue::Vector(vec![
                    EdnValue::Keyword(Keyword::parse("vc")),
                    EdnValue::Keyword(Keyword::parse("ipld")),
                ]),
            ]]
        );

        let tuple_query = kotoba_edn::parse(
            r#"{:find [?pair ?name2 ?role2]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]
                        [(tuple ?name ?role) ?pair]
                        [(untuple ?pair) [?name2 ?role2]]
                        [(= ?name2 "Alice")]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &tuple_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![
                EdnValue::Vector(vec![
                    EdnValue::String("Alice".into()),
                    EdnValue::Keyword(Keyword::parse("role/admin")),
                ]),
                EdnValue::String("Alice".into()),
                EdnValue::Keyword(Keyword::parse("role/admin")),
            ]]
        );
    }

    #[test]
    fn reader_aggregates_distributed_query_rows() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("admin")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/score".into(),
                        EdnValue::Integer(10),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/score".into(),
                        EdnValue::Integer(3),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/score".into(),
                        EdnValue::Integer(8),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let grouped = kotoba_edn::parse(
            r#"{:find [?role (count ?e) (sum ?score) (min ?score) (max ?score) (min 2 ?score) (max 2 ?score) (min 0 ?score) (max 0 ?score) (rand ?score) (sample 2 ?score) (avg ?score) (median ?score) (variance ?score) (stddev ?score)]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]
                :order-by [[(count ?e) :desc] [?role :asc]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &grouped)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    EdnValue::Keyword(Keyword::parse("guest")),
                    EdnValue::Integer(2),
                    EdnValue::Integer(11),
                    EdnValue::Integer(3),
                    EdnValue::Integer(8),
                    EdnValue::Vector(vec![EdnValue::Integer(3), EdnValue::Integer(8)]),
                    EdnValue::Vector(vec![EdnValue::Integer(8), EdnValue::Integer(3)]),
                    EdnValue::Vector(vec![]),
                    EdnValue::Vector(vec![]),
                    EdnValue::Integer(3),
                    EdnValue::Vector(vec![EdnValue::Integer(3), EdnValue::Integer(8)]),
                    EdnValue::float(5.5),
                    EdnValue::float(5.5),
                    EdnValue::float(6.25),
                    EdnValue::float(2.5),
                ],
                vec![
                    EdnValue::Keyword(Keyword::parse("admin")),
                    EdnValue::Integer(1),
                    EdnValue::Integer(10),
                    EdnValue::Integer(10),
                    EdnValue::Integer(10),
                    EdnValue::Vector(vec![EdnValue::Integer(10)]),
                    EdnValue::Vector(vec![EdnValue::Integer(10)]),
                    EdnValue::Vector(vec![]),
                    EdnValue::Vector(vec![]),
                    EdnValue::Integer(10),
                    EdnValue::Vector(vec![EdnValue::Integer(10)]),
                    EdnValue::float(10.0),
                    EdnValue::Integer(10),
                    EdnValue::float(0.0),
                    EdnValue::float(0.0),
                ],
            ]
        );

        let distinct = kotoba_edn::parse(
            r#"{:find [(count ?role) (count-distinct ?role)]
                :where [[?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &distinct)
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::Integer(3), EdnValue::Integer(2)]]);

        let named = kotoba_edn::parse(
            r#"{:find [(count ?role) (count-distinct ?role)]
                :keys [total distinctRoles]
                :where [[?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &named)
            .unwrap();
        assert_eq!(
            rows,
            vec![vec![EdnValue::map([
                (EdnValue::kw_bare("total"), EdnValue::Integer(3)),
                (EdnValue::kw_bare("distinctRoles"), EdnValue::Integer(2)),
            ])]]
        );

        let with_entity = kotoba_edn::parse(
            r#"{:find [?role (count ?score)]
                :with [?e]
                :where [[?e :person/role ?role]
                        [?e :person/score ?score]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &with_entity)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    EdnValue::Keyword(Keyword::parse("admin")),
                    EdnValue::Integer(1),
                ],
                vec![
                    EdnValue::Keyword(Keyword::parse("guest")),
                    EdnValue::Integer(2),
                ],
            ]
        );
    }

    #[test]
    fn reader_evaluates_distributed_rule_inputs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("admin")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/name".into(),
                        EdnValue::String("Bob".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/name".into(),
                        EdnValue::String("Eve".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("auditor")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"eve"),
                        ":person/verified".into(),
                        EdnValue::Bool(true),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$ %]
                :where [(eligible ?e)
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rules = kotoba_edn::parse(
            r#"[
              [(eligible ?e) [?e :person/role :admin]]
              [(eligible ?e) [?e :person/role :auditor] [?e :person/verified true]]
            ]"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &query, &[rules])
            .unwrap();

        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Eve".into())],
            ]
        );
    }

    #[test]
    fn reader_evaluates_recursive_distributed_rule_inputs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/parent".into(),
                        EdnValue::String(KotobaCid::from_bytes(b"bob").to_multibase()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/parent".into(),
                        EdnValue::String(KotobaCid::from_bytes(b"carol").to_multibase()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"carol"),
                        ":person/parent".into(),
                        EdnValue::String(KotobaCid::from_bytes(b"dana").to_multibase()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"dana"),
                        ":person/name".into(),
                        EdnValue::String("Dana".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name]
                :in [$ %]
                :where [(ancestor ?e ?ancestor)
                        [?ancestor :person/name ?name]]}"#,
        )
        .unwrap();
        let rules = kotoba_edn::parse(
            r#"[
              [(ancestor ?e ?ancestor) [?e :person/parent ?ancestor]]
              [(ancestor ?e ?ancestor)
               [?e :person/parent ?parent]
               (ancestor ?parent ?ancestor)]
            ]"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples_with_inputs(&report.commit.cid, &query, &[rules])
            .unwrap();

        assert_eq!(rows, vec![vec![EdnValue::String("Dana".into())]]);
    }

    #[test]
    fn reader_accepts_distributed_find_collection_scalar_and_tuple_specs() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("admin")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/name".into(),
                        EdnValue::String("Bob".into()),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/role".into(),
                        EdnValue::Keyword(Keyword::parse("guest")),
                        KotobaCid::from_bytes(b"tx1"),
                    ),
                ],
            ))
            .unwrap();

        let collection_query = kotoba_edn::parse(
            r#"{:find [?name ...]
                :where [[?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &collection_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into())],
                vec![EdnValue::String("Bob".into())],
            ]
        );

        let tuple_query = kotoba_edn::parse(
            r#"{:find [[?name ?role]]
                :where [[?e :person/name ?name]
                        [?e :person/role ?role]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &tuple_query)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![
                    EdnValue::String("Alice".into()),
                    EdnValue::Keyword(Keyword::parse("admin")),
                ],
                vec![
                    EdnValue::String("Bob".into()),
                    EdnValue::Keyword(Keyword::parse("guest")),
                ],
            ]
        );

        let scalar_query = kotoba_edn::parse(
            r#"{:find [?name .]
                :where [[?e :person/role :admin]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &scalar_query)
            .unwrap();
        assert_eq!(rows, vec![vec![EdnValue::String("Alice".into())]]);
    }

    #[test]
    fn reader_supports_datomic_fulltext_relation_binding_from_distributed_head() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"graph");
        let tx = KotobaCid::from_bytes(b"tx1");
        let report = writer
            .commit_datoms(request(
                "k51-kotoba-db",
                graph,
                vec![
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/name".into(),
                        EdnValue::String("Alice".into()),
                        tx.clone(),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"alice"),
                        ":person/bio".into(),
                        EdnValue::String("Kotoba stores W3C credentials as Datoms.".into()),
                        tx.clone(),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/name".into(),
                        EdnValue::String("Bob".into()),
                        tx.clone(),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"bob"),
                        ":person/bio".into(),
                        EdnValue::String("kotoba kotoba distributed query".into()),
                        tx.clone(),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"carol"),
                        ":person/name".into(),
                        EdnValue::String("Carol".into()),
                        tx.clone(),
                    ),
                    Datom::assert(
                        KotobaCid::from_bytes(b"carol"),
                        ":person/bio".into(),
                        EdnValue::String("unrelated text".into()),
                        tx,
                    ),
                ],
            ))
            .unwrap();

        let query = kotoba_edn::parse(
            r#"{:find [?name ?score]
                :where [[(fulltext $ :person/bio "KOTOBA") [[?e ?bio ?tx ?score]]]
                        [?e :person/name ?name]]}"#,
        )
        .unwrap();
        let rows = DistributedDatomReader::new(&store, &ipns)
            .q_triples(&report.commit.cid, &query)
            .unwrap();
        assert_eq!(
            rows,
            vec![
                vec![EdnValue::String("Alice".into()), EdnValue::Integer(1)],
                vec![EdnValue::String("Bob".into()), EdnValue::Integer(2)],
            ]
        );
    }
}
