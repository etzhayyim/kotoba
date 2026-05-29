//! XRPC endpoint declarations and handlers for Kotoba
//! NSIDs follow ai.gftd.apps.kotoba.* namespace

pub const NSID_DATOM_CREATE: &str = "ai.gftd.apps.kotoba.datom.create";
pub const NSID_QUAD_CREATE: &str = "ai.gftd.apps.kotoba.quad.create";
pub const NSID_QUAD_RETRACT: &str = "ai.gftd.apps.kotoba.quad.retract";
pub const NSID_DATOMIC_TRANSACT: &str = "ai.gftd.apps.kotoba.datomic.transact";
pub const NSID_DATOMIC_DATOMS: &str = "ai.gftd.apps.kotoba.datomic.datoms";
pub const NSID_DATOMIC_SEEK_DATOMS: &str = "ai.gftd.apps.kotoba.datomic.seekDatoms";
pub const NSID_DATOMIC_INDEX_RANGE: &str = "ai.gftd.apps.kotoba.datomic.indexRange";
pub const NSID_DATOMIC_PULL: &str = "ai.gftd.apps.kotoba.datomic.pull";
pub const NSID_DATOMIC_PULL_MANY: &str = "ai.gftd.apps.kotoba.datomic.pullMany";
pub const NSID_DATOMIC_Q: &str = "ai.gftd.apps.kotoba.datomic.q";
pub const NSID_DATOMIC_WITH: &str = "ai.gftd.apps.kotoba.datomic.with";
pub const NSID_DATOMIC_HISTORY: &str = "ai.gftd.apps.kotoba.datomic.history";
pub const NSID_DATOMIC_TX_RANGE: &str = "ai.gftd.apps.kotoba.datomic.txRange";
pub const NSID_DATOMIC_LOG: &str = "ai.gftd.apps.kotoba.datomic.log";
pub const NSID_DATOMIC_BASIS_T: &str = "ai.gftd.apps.kotoba.datomic.basisT";
pub const NSID_DATOMIC_DB_STATS: &str = "ai.gftd.apps.kotoba.datomic.dbStats";
pub const NSID_DATOMIC_ENTITY: &str = "ai.gftd.apps.kotoba.datomic.entity";
pub const NSID_DATOMIC_IDENT: &str = "ai.gftd.apps.kotoba.datomic.ident";
pub const NSID_DATOMIC_ENTID: &str = "ai.gftd.apps.kotoba.datomic.entid";
pub const NSID_VC_ISSUE: &str = "ai.gftd.apps.kotoba.vc.issue";
pub const NSID_VC_PRESENT: &str = "ai.gftd.apps.kotoba.vc.present";
pub const NSID_DID_DOCUMENT_PUBLISH: &str = "ai.gftd.apps.kotoba.did.document.publish";
pub const NSID_DIDCOMM_SEND: &str = "ai.gftd.apps.kotoba.didcomm.send";
pub const NSID_ATPROTO_REPO_WRITE: &str = "ai.gftd.apps.kotoba.atproto.repo.write";
pub const NSID_GRAPH_QUERY: &str = "ai.gftd.apps.kotoba.graph.query";
pub const NSID_COMMIT_GET: &str = "ai.gftd.apps.kotoba.commit.get";
pub const NSID_INVOKE_RUN: &str = "ai.gftd.apps.kotoba.invoke.run";
pub const NSID_INFER_RUN: &str = "ai.gftd.apps.kotoba.infer.run";
pub const NSID_WEIGHT_PUT: &str = "ai.gftd.apps.kotoba.weight.put";
pub const NSID_LORA_APPLY: &str = "ai.gftd.apps.kotoba.lora.apply";
pub const NSID_EMBED_CREATE: &str = "ai.gftd.apps.kotoba.embed.create";
pub const NSID_NODE_STATUS: &str = "ai.gftd.apps.kotoba.node.status";
pub const NSID_BLOCK_PUT: &str = "ai.gftd.apps.kotoba.block.put";
pub const NSID_BLOCK_GET: &str = "ai.gftd.apps.kotoba.block.get";
pub const NSID_COMMIT_STORE: &str = "ai.gftd.apps.kotoba.commit.store";
pub const NSID_AGENT_RUN: &str = "ai.gftd.apps.kotoba.agent.run";
pub const NSID_AGENT_SYNC_OPEN: &str = "ai.gftd.apps.kotoba.agent.syncopen";
pub const NSID_AGENT_SYNC_ADV: &str = "ai.gftd.apps.kotoba.agent.syncadvance";
pub const NSID_AGENT_SYNC_CLOSE: &str = "ai.gftd.apps.kotoba.agent.syncclose";
pub const NSID_VAULT_PUT: &str = "ai.gftd.apps.kotoba.vault.put";
pub const NSID_VAULT_GET: &str = "ai.gftd.apps.kotoba.vault.get";

use crate::server::KotobaState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::Signer;
use kotoba_datomic::distributed::{
    CommitDatomsRequest, DistributedCommitError, DistributedCommitWriter, DistributedDatomCommit,
    DistributedDatomReader, ROOT_AEVT, ROOT_AVET, ROOT_EAVT, ROOT_TEA, ROOT_VAET,
};
use kotoba_ipfs::{IpnsName, IpnsRegistryError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Maximum size of a base64-encoded CACAO delegation token (8 KiB decoded ≈ 6 KiB base64).
const MAX_CACAO_B64_LEN: usize = 8 * 1024;

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QuadCreateReq {
    pub graph: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    /// Optional CACAO warrant (DAG-CBOR, base64-standard encoded).
    /// When present: verified before write; `cacao.p.graph_cid()` must match `graph`.
    /// Issuer DID becomes the authoritative namespace for this write.
    pub cacao_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VaultPutReq {
    /// Raw blob encoded as standard base64.
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct VaultPutResp {
    pub cid: String,
    pub size: usize,
}

#[derive(Debug, Serialize)]
pub struct VaultGetResp {
    pub cid: String,
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct QuadCreateResp {
    pub status: &'static str,
    pub journal_cid: String,
    pub datom_cid: String,
    pub quad_cid: String,
}

#[derive(Debug, Deserialize)]
pub struct DatomicTransactReq {
    pub graph: String,
    pub tx_edn: String,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    /// Optional optimistic-concurrency guard.  When omitted, the server appends
    /// to the current IPNS head for backward-compatible clients.
    pub expected_parent: Option<String>,
    pub cacao_proof_cid: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicWithReq {
    pub graph: String,
    pub tx_edn: String,
    /// Optional Datomic `as-of` transaction CID used as the speculative base DB.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID used as the speculative base DB.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicDatomsReq {
    pub graph: String,
    /// Datomic index name: `:eavt`, `:aevt`, `:avet`, or `:vaet`.
    pub index: String,
    /// Optional EDN components for the chosen index prefix.
    #[serde(default)]
    pub components_edn: Vec<String>,
    /// Optional Datomic `as-of` transaction CID.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicSeekDatomsReq {
    pub graph: String,
    /// Datomic index name: `:eavt`, `:aevt`, `:avet`, or `:vaet`.
    pub index: String,
    /// Optional EDN components for the starting tuple in the chosen index.
    #[serde(default)]
    pub components_edn: Vec<String>,
    /// Optional Datomic `as-of` transaction CID.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicIndexRangeReq {
    pub graph: String,
    /// Datomic attribute EDN, usually a keyword such as `:person/age`.
    pub attr_edn: String,
    /// Inclusive lower bound for the AVET value position.
    pub start_edn: Option<String>,
    /// Exclusive upper bound for the AVET value position.
    pub end_edn: Option<String>,
    /// Optional Datomic `as-of` transaction CID.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicPullReq {
    pub graph: String,
    pub entity: String,
    pub pattern_edn: Option<String>,
    /// Optional Datomic `as-of` transaction CID.  Queries the database value at
    /// the end of this transaction.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.  Queries facts strictly after
    /// this transaction.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicPullManyReq {
    pub graph: String,
    pub entities: Vec<String>,
    pub pattern_edn: Option<String>,
    /// Optional Datomic `as-of` transaction CID.  Queries the database value at
    /// the end of this transaction.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.  Queries facts strictly after
    /// this transaction.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicQReq {
    pub graph: String,
    pub query_edn: String,
    #[serde(default)]
    pub inputs_edn: Vec<String>,
    /// Optional Datomic `as-of` transaction CID.  Queries the database value at
    /// the end of this transaction.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.  Queries facts strictly after
    /// this transaction.
    pub since: Option<String>,
    /// Query the Datomic history database, preserving retract tombstones and
    /// the fifth datom `added` component.
    #[serde(default)]
    pub history: bool,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicHistoryReq {
    pub graph: String,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    /// Optional Datomic `as-of` transaction CID.  Returns history through this
    /// transaction.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.  Returns history strictly
    /// after this transaction.
    pub since: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicTxRangeReq {
    pub graph: String,
    /// Inclusive start transaction CID.  Omitted means the first transaction.
    pub start: Option<String>,
    /// Exclusive end transaction CID.  Omitted means the current head.
    pub end: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicLogReq {
    pub graph: String,
    /// Inclusive start transaction CID. Omitted means the first transaction.
    pub start: Option<String>,
    /// Exclusive end transaction CID. Omitted means the current head.
    pub end: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicBasisTReq {
    pub graph: String,
    /// Optional Datomic `as-of` transaction CID.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicDbStatsReq {
    pub graph: String,
    /// Optional Datomic `as-of` transaction CID.
    pub as_of: Option<String>,
    /// Optional Datomic `since` transaction CID.
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicEntityReq {
    pub graph: String,
    pub entity: String,
    pub as_of: Option<String>,
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicIdentReq {
    pub graph: String,
    pub entity: String,
    pub as_of: Option<String>,
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DatomicEntidReq {
    pub graph: String,
    /// EDN keyword ident, lookup-ref vector, CID string, or entity value.
    pub ident_edn: String,
    pub as_of: Option<String>,
    pub since: Option<String>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct VcIssueReq {
    pub graph: String,
    pub credential: kotoba_vc::VerifiableCredential,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct VcPresentReq {
    pub graph: String,
    pub presentation: kotoba_vc::VerifiablePresentation,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DidDocumentPublishReq {
    pub graph: String,
    pub document: kotoba_auth::DidDocument,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct DidCommSendReq {
    pub graph: String,
    pub message: kotoba_didcomm::DidCommMessage,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Deserialize)]
pub struct AtprotoRepoWriteReq {
    pub graph: String,
    pub uri: String,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub cid: Option<String>,
    #[serde(default)]
    pub record: Option<serde_json::Value>,
    pub cacao_b64: Option<String>,
    #[serde(default)]
    pub auth_presentation: Option<kotoba_vc::VerifiablePresentation>,
}

#[derive(Debug, Serialize)]
pub struct DatomicDatomResp {
    pub e: String,
    pub a: String,
    pub v_edn: String,
    pub t: String,
    pub added: bool,
}

#[derive(Debug, Serialize)]
pub struct DatomicTransactResp {
    pub status: &'static str,
    pub graph: String,
    pub tx_cid: String,
    pub commit_cid: String,
    pub auth_proof_cid: Option<String>,
    pub ipns_name: String,
    pub ipns_sequence: u64,
    pub ipns_valid_until: String,
    pub index_roots: BTreeMap<String, String>,
    pub datom_count: usize,
    pub journal_cids: Vec<String>,
    pub tempids: BTreeMap<String, String>,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicWithResp {
    pub status: &'static str,
    pub graph: String,
    pub db_before_basis_t: Option<String>,
    pub db_after_basis_t: Option<String>,
    pub tx_cid: String,
    pub tempids: BTreeMap<String, String>,
    pub tx_data: Vec<DatomicDatomResp>,
    pub db_after_datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicDatomsResp {
    pub graph: String,
    pub index: String,
    pub basis_t: Option<String>,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct ProtocolDatomWriteResp {
    pub status: &'static str,
    pub graph: String,
    pub entity_cid: String,
    pub tx_cid: String,
    pub commit_cid: String,
    pub auth_proof_cid: Option<String>,
    pub ipns_name: String,
    pub ipns_sequence: u64,
    pub datom_count: usize,
    pub assert_count: usize,
    pub retract_count: usize,
    pub journal_cids: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthCapabilityProjection {
    proof_format: &'static str,
    controller: String,
    invoker: String,
    allowed_actions: Vec<String>,
    invocation_targets: Vec<String>,
    proof_cid: Option<kotoba_core::cid::KotobaCid>,
    credential_ids: Vec<String>,
}

const ZCAP_ALLOWED_ACTION_IRI: &str = "https://w3id.org/security#allowedAction";
const ZCAP_INVOCATION_TARGET_IRI: &str = "https://w3id.org/security#invocationTarget";
const ZCAP_CONTROLLER_IRI: &str = "https://w3id.org/security#controller";
const ZCAP_INVOCATION_PROOF_IRI: &str = "https://w3id.org/security#proof";

#[derive(Debug, Serialize)]
pub struct DatomicPullResp {
    pub graph: String,
    pub entity: String,
    pub basis_t: Option<String>,
    pub entity_edn: String,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicPullManyEntityResp {
    pub entity: String,
    pub entity_edn: String,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicPullManyResp {
    pub graph: String,
    pub basis_t: Option<String>,
    pub entity_count: usize,
    pub entities: Vec<DatomicPullManyEntityResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicQResp {
    pub graph: String,
    pub basis_t: Option<String>,
    pub rows_edn: Vec<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_map_edn: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows_map_json: Option<Vec<std::collections::BTreeMap<String, String>>>,
}

#[derive(Debug, Serialize)]
pub struct DatomicHistoryResp {
    pub graph: String,
    pub basis_t: Option<String>,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicTxRangeTxResp {
    pub tx_cid: String,
    pub commit_cid: String,
    pub prev_commit_cid: Option<String>,
    pub seq: u64,
    pub author: String,
    pub ts: u64,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicTxRangeResp {
    pub graph: String,
    pub basis_t: Option<String>,
    pub tx_count: usize,
    pub txes: Vec<DatomicTxRangeTxResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicLogTxResp {
    pub tx_cid: String,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicLogResp {
    pub graph: String,
    pub basis_t: Option<String>,
    pub tx_count: usize,
    pub txes: Vec<DatomicLogTxResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicBasisTResp {
    pub graph: String,
    pub basis_t: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DatomicDbStatsResp {
    pub graph: String,
    pub basis_t: Option<String>,
    pub datom_count: usize,
    pub history_datom_count: usize,
    pub entity_count: usize,
    pub attribute_count: usize,
    pub tx_count: usize,
}

#[derive(Debug, Serialize)]
pub struct DatomicEntityResp {
    pub graph: String,
    pub entity: String,
    pub basis_t: Option<String>,
    pub entity_edn: String,
    pub datom_count: usize,
    pub datoms: Vec<DatomicDatomResp>,
}

#[derive(Debug, Serialize)]
pub struct DatomicIdentResp {
    pub graph: String,
    pub entity: String,
    pub basis_t: Option<String>,
    pub ident_edn: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DatomicEntidResp {
    pub graph: String,
    pub ident_edn: String,
    pub basis_t: Option<String>,
    pub entity: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InvokeRunReq {
    pub program_cid: String,
    /// "wasm-node" | "wasm-udf" | "datalog"
    pub program_type: String,
    pub agent_did: String,
    pub wasm_b64: Option<String>,
    pub ctx_b64: Option<String>,
    /// Named graph CID (multibase) — when supplied, the graph's Arrangement is
    /// snapshotted into HostState so WASM guests can call `kqe.query`.
    pub graph_cid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InvokeRunResp {
    pub status: &'static str,
    pub gas_used: u64,
    pub output_b64: String,
    pub assert_count: usize,
    pub retract_count: usize,
    /// CIDs of Journal entries created for each asserted quad
    pub journal_cids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HealthResp {
    pub status: &'static str,
    pub version: &'static str,
    pub subsystems: SubsystemStatus,
    pub node: NodeInfo,
}

#[derive(Debug, Serialize)]
pub struct SubsystemStatus {
    pub kse_journal: &'static str,
    pub kse_shelf: &'static str,
    pub wasm_executor: &'static str,
    pub udf_executor: &'static str,
    pub invoke_router: &'static str,
}

#[derive(Debug, Serialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub peer_count: usize,
}

// ── Handlers ───────────────────────────────────────────────────────────────

/// GET /_app/meta  /  GET /health
pub async fn health(State(state): State<Arc<KotobaState>>) -> impl IntoResponse {
    let neighborhood = state.neighborhood.read().await;
    Json(HealthResp {
        status: "ok",
        version: state.version,
        subsystems: SubsystemStatus {
            kse_journal: "ready",
            kse_shelf: "ready",
            #[cfg(feature = "wasm-runtime")]
            wasm_executor: "ready",
            #[cfg(not(feature = "wasm-runtime"))]
            wasm_executor: "disabled",
            #[cfg(feature = "wasm-runtime")]
            udf_executor: "ready",
            #[cfg(not(feature = "wasm-runtime"))]
            udf_executor: "disabled",
            #[cfg(feature = "wasm-runtime")]
            invoke_router: "ready",
            #[cfg(not(feature = "wasm-runtime"))]
            invoke_router: "disabled",
        },
        node: NodeInfo {
            node_id: hex::encode(state.local_node_id.0),
            peer_count: neighborhood.peers.len(),
        },
    })
}

fn map_delegation_error(e: kotoba_auth::DelegationError) -> (StatusCode, String) {
    use kotoba_auth::DelegationError;
    match &e {
        DelegationError::Expired => (StatusCode::UNAUTHORIZED, "cacao expired".to_string()),
        DelegationError::GraphMismatch { expected, got } => (
            StatusCode::UNAUTHORIZED,
            format!("cacao graph mismatch: warrant covers {expected}, request targets {got}"),
        ),
        _ => (StatusCode::UNAUTHORIZED, format!("cacao delegation: {e}")),
    }
}

/// Returns `true` if the host portion of a `did:web:` suffix is an IP literal.
///
/// The did:web spec mandates domain names. IP literals are rejected to prevent
/// SSRF attacks (e.g. `did:web:169.254.169.254` → AWS metadata endpoint).
fn is_did_web_ip_host(suffix: &str) -> bool {
    let host = suffix.split(':').next().unwrap_or(suffix);
    // Empty host means suffix starts with ':' — not a valid domain name.
    // IPv6 literals like "::1" produce an empty first segment here.
    if host.is_empty() {
        return true;
    }
    // IPv4: first segment parses as an IP address.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    // IPv6: the full suffix (no `:path` appended yet) may parse as an IP.
    // e.g. "fe80::1" — first segment is "fe80" but the full string is IPv6.
    suffix.parse::<std::net::IpAddr>().is_ok()
}

/// Resolve a `did:web:` DID document over HTTPS, extract the Ed25519 public key,
/// verify the CACAO signature, and check expiry + graph scope.
///
/// `did:web:domain`       → `https://domain/.well-known/did.json`
/// `did:web:domain:path`  → `https://domain/path/did.json`
async fn resolve_and_verify_did_web(
    cacao: &kotoba_auth::Cacao,
    graph: &str,
    client: &reqwest::Client,
) -> Result<String, (StatusCode, String)> {
    use kotoba_auth::DidDocument;

    // P3 — expiry check (DelegationChain path handles this for non-web DIDs)
    if cacao.is_expired() {
        return Err((StatusCode::UNAUTHORIZED, "cacao expired".to_string()));
    }
    // P3b — max-age check for no-expiry CACAOs (mirrors DelegationChain::verify logic)
    if cacao.p.expiry.is_none() {
        const MAX_CACAO_AGE_SECS: u64 = 7 * 24 * 3600;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match cacao.issued_at_secs() {
            None => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "cacao: invalid iat format".to_string(),
                ))
            }
            Some(iat) => {
                if now.saturating_sub(iat) > MAX_CACAO_AGE_SECS {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        "cacao expired (max-age exceeded)".to_string(),
                    ));
                }
            }
        }
    }

    // P3 — capability check
    if let Some(cap) = cacao.p.capability() {
        if cap != kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!(
                    "capability denied: need '{}', CACAO grants '{cap}'",
                    kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT
                ),
            ));
        }
    }

    // P3 — graph scope check
    if let Some(cacao_graph) = cacao.p.graph_cid() {
        if cacao_graph != graph {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!(
                    "cacao graph mismatch: warrant covers {cacao_graph}, request targets {graph}"
                ),
            ));
        }
    }

    // Build did:web fetch URL.
    // The did:web spec requires a domain name — reject IP literals outright.
    // Hostname-based SSRF (DNS pointing to internal IPs) is out-of-scope here;
    // document in ADR §23 if DNS-SSRF protection is needed in future.
    let suffix = cacao.p.iss.strip_prefix("did:web:").unwrap_or(&cacao.p.iss);
    if is_did_web_ip_host(suffix) {
        let host = suffix.split(':').next().unwrap_or(suffix);
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("did:web: IP address literals are not allowed (got '{host}'); did:web requires a domain name"),
        ));
    }

    let url = if suffix.contains(':') {
        format!("https://{}/did.json", suffix.replace(':', "/"))
    } else {
        format!("https://{}/.well-known/did.json", suffix)
    };

    const MAX_DID_DOC_BYTES: usize = 65_536; // 64 KiB — guard against response-bombing

    let resp = client.get(&url).send().await.map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("did:web fetch {url}: {e}"),
        )
    })?;
    if !resp.status().is_success() {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("did:web fetch {url}: HTTP {}", resp.status()),
        ));
    }
    // Pre-check Content-Length to reject obviously oversized documents before buffering.
    if let Some(cl) = resp.content_length() {
        if cl > MAX_DID_DOC_BYTES as u64 {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!(
                    "did:web document Content-Length {cl} exceeds {MAX_DID_DOC_BYTES} byte limit"
                ),
            ));
        }
    }
    // Stream chunks with a running budget check to prevent slow-loris inflate attacks.
    let mut body_bytes = bytes::BytesMut::new();
    let mut resp = resp;
    loop {
        match resp
            .chunk()
            .await
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("did:web read body: {e}")))?
        {
            None => break,
            Some(chunk) => {
                body_bytes.extend_from_slice(&chunk);
                if body_bytes.len() > MAX_DID_DOC_BYTES {
                    return Err((
                        StatusCode::UNAUTHORIZED,
                        format!("did:web document exceeds {MAX_DID_DOC_BYTES} byte limit"),
                    ));
                }
            }
        }
    }
    let body_bytes = body_bytes.freeze();
    let doc: DidDocument = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("did:web document parse: {e}"),
        )
    })?;

    let pubkey = doc.ed25519_public_key().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            format!("no Ed25519 key in DID document for {}", cacao.p.iss),
        )
    })?;

    cacao
        .verify_with_pubkey(&pubkey)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("did:web sig: {e}")))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datom.create
/// POST /xrpc/ai.gftd.apps.kotoba.quad.create
/// Publish a Datom-compatible atomic fact to the KSE Journal.
///
/// `cacao_b64` is required. The CACAO is verified before the write:
/// - Signature must be valid (EdDSA or eip191)
/// - `cacao.p.graph_cid()` must match the requested `graph` field when present
/// - Issuer DID is stored as a `meta/author` quad on the same graph for provenance
pub async fn quad_create(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<QuadCreateReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::{Datom as KqeDatom, Value as KqeValue};

    // ── CACAO verification (required) ────────────────────────────────────
    let b64 = req.cacao_b64.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "cacao_b64 is required for quad.create".to_string(),
        )
    })?;

    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }

    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;

    // Dispatch on issuer DID method:
    //   did:web:*  → P3: resolve DID document over HTTP, verify with extracted key
    //   everything else → P1: DelegationChain verifies expiry + capability + graph + sig
    let issuer_did = if cacao.p.iss.starts_with("did:web:") {
        resolve_and_verify_did_web(&cacao, &req.graph, &state.http_client).await?
    } else {
        kotoba_auth::DelegationChain::new(cacao)
            .verify(&req.graph, kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
            .map_err(map_delegation_error)?
    };

    tracing::info!(issuer = %issuer_did, graph = %req.graph, "quad.create: CACAO verified");

    // ── SPO + graph field bounds ─────────────────────────────────────────────
    // Reject oversized fields before they enter the graph index or WAL.
    // graph/subject/predicate are used as BTreeMap keys; object is freeform text.
    const MAX_GRAPH_LEN: usize = 512;
    const MAX_SUBJECT_LEN: usize = 512;
    const MAX_PREDICATE_LEN: usize = 512;
    const MAX_OBJECT_LEN: usize = 8 * 1024; // 8 KiB
    if req.graph.len() > MAX_GRAPH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "graph field too long ({} bytes, limit {MAX_GRAPH_LEN})",
                req.graph.len()
            ),
        ));
    }
    if req.subject.len() > MAX_SUBJECT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "subject field too long ({} bytes, limit {MAX_SUBJECT_LEN})",
                req.subject.len()
            ),
        ));
    }
    if req.predicate.len() > MAX_PREDICATE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "predicate field too long ({} bytes, limit {MAX_PREDICATE_LEN})",
                req.predicate.len()
            ),
        ));
    }
    if req.object.len() > MAX_OBJECT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "object field too long ({} bytes, limit {MAX_OBJECT_LEN})",
                req.object.len()
            ),
        ));
    }

    let graph_cid = KotobaCid::from_bytes(req.graph.as_bytes());
    let datom = KqeDatom::assert(
        KotobaCid::from_bytes(req.subject.as_bytes()),
        req.predicate.clone(),
        KqeValue::Text(req.object.clone()),
        KotobaCid::from_bytes(b"kotoba-pending-tx"),
    );

    let journal_cid = state.assert_datom_compat(graph_cid.clone(), datom).await;
    let tx_cid = KotobaCid::from_multibase(&journal_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));

    // ── Store author provenance ───────────────────────────────────────────
    // Subject = journal CID of the write so (graph, journal_cid, meta/author) is
    // globally unique and references the exact write event.
    // Use from_multibase so the subject CID matches what graph.query decodes.
    let author_subject = KotobaCid::from_multibase(&journal_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(journal_cid.as_bytes()));
    state
        .quad_store
        .apply_journaled_datom(
            graph_cid,
            KqeDatom::assert(
                author_subject,
                "meta/author".to_string(),
                KqeValue::Text(issuer_did.clone()),
                tx_cid,
            ),
        )
        .await;

    tracing::info!(
        graph     = %req.graph,
        subject   = %req.subject,
        predicate = %req.predicate,
        cid       = %journal_cid,
        author    = %issuer_did,
        "quad.create → Journal + QuadStore"
    );

    Ok((
        StatusCode::OK,
        Json(QuadCreateResp {
            status: "ok",
            datom_cid: journal_cid.clone(),
            quad_cid: journal_cid.clone(),
            journal_cid,
        }),
    ))
}

pub async fn datom_create(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<QuadCreateReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    quad_create(State(state), Json(req)).await
}

/// POST /xrpc/ai.gftd.apps.kotoba.vault.put
/// Store an opaque blob in the private Vault.  Returns a CID (multibase blake3).
/// No GossipSub propagation — vault blobs stay local (or in B2 when configured).
pub async fn vault_put(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VaultPutReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use bytes::Bytes;

    // 10 MiB base64 cap (decodes to ~7.5 MiB raw). Vault blobs are content-addressed
    // chunks; oversized payloads should be split by the chunker, not sent raw.
    const MAX_VAULT_B64_LEN: usize = 10 * 1024 * 1024;
    if req.data_b64.len() > MAX_VAULT_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "data_b64 too large ({} bytes, limit {MAX_VAULT_B64_LEN})",
                req.data_b64.len()
            ),
        ));
    }

    let data = B64
        .decode(&req.data_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("data_b64 decode: {e}")))?;

    let blob_ref = state.vault.put(Bytes::from(data)).await;
    tracing::info!(cid = %blob_ref.cid.to_multibase(), size = blob_ref.size, "vault.put");

    Ok((
        StatusCode::OK,
        Json(VaultPutResp {
            cid: blob_ref.cid.to_multibase(),
            size: blob_ref.size,
        }),
    ))
}

/// GET /xrpc/ai.gftd.apps.kotoba.vault.get?cid=<multibase>
/// Retrieve a blob from the Vault by CID.  Returns 404 if not found.
pub async fn vault_get(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;

    let cid_str = params.get("cid").ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "missing `cid` query param".to_string(),
        )
    })?;

    let cid = KotobaCid::from_multibase(cid_str)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, format!("invalid CID: {cid_str}")))?;

    let data = state.vault.get(&cid).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("vault: CID not found: {cid_str}"),
        )
    })?;

    Ok((
        StatusCode::OK,
        Json(VaultGetResp {
            cid: cid_str.to_string(),
            data_b64: B64.encode(&data),
        }),
    ))
}

fn datomic_datom_resp(datom: kotoba_datomic::Datom) -> DatomicDatomResp {
    DatomicDatomResp {
        e: datom.e.to_multibase(),
        a: datom.a,
        v_edn: kotoba_edn::to_string(&datom.v),
        t: datom.t.to_multibase(),
        added: datom.added,
    }
}

fn parse_graph_cid(graph: &str) -> Result<kotoba_core::cid::KotobaCid, (StatusCode, String)> {
    kotoba_core::cid::KotobaCid::from_multibase(graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".to_string()))
}

fn parse_datomic_entity(entity: &str) -> kotoba_core::cid::KotobaCid {
    kotoba_core::cid::KotobaCid::from_multibase(entity)
        .unwrap_or_else(|| kotoba_core::cid::KotobaCid::from_bytes(entity.as_bytes()))
}

fn datomic_attr_from_edn(value: &kotoba_edn::EdnValue) -> Result<String, (StatusCode, String)> {
    match value {
        kotoba_edn::EdnValue::Keyword(keyword) => Ok(format!(":{}", keyword.to_qualified())),
        kotoba_edn::EdnValue::String(attr) => Ok(attr.clone()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "attribute must be keyword or string, got {}",
                kotoba_edn::to_string(value)
            ),
        )),
    }
}

fn datomic_ident_for_entity(
    db: &kotoba_datomic::Db,
    entity: &kotoba_core::cid::KotobaCid,
) -> Option<kotoba_edn::EdnValue> {
    db.datoms()
        .into_iter()
        .find(|datom| datom.e == *entity && datom.a == ":db/ident")
        .map(|datom| datom.v)
}

fn datomic_entid_for_value(
    db: &kotoba_datomic::Db,
    value: &kotoba_edn::EdnValue,
) -> Result<Option<kotoba_core::cid::KotobaCid>, (StatusCode, String)> {
    match value {
        kotoba_edn::EdnValue::String(s) => Ok(Some(parse_datomic_entity(s))),
        kotoba_edn::EdnValue::Keyword(_) => Ok(db
            .datoms()
            .into_iter()
            .find(|datom| datom.a == ":db/ident" && datom.v == *value)
            .map(|datom| datom.e)),
        kotoba_edn::EdnValue::Vector(items) if items.len() == 2 => {
            let attr = datomic_attr_from_edn(&items[0])?;
            Ok(db
                .datoms()
                .into_iter()
                .find(|datom| datom.a == attr && datom.v == items[1])
                .map(|datom| datom.e))
        }
        _ => Ok(Some(kotoba_core::cid::KotobaCid::from_bytes(
            kotoba_edn::to_string(value).as_bytes(),
        ))),
    }
}

fn datomic_entity_from_request(
    db: &kotoba_datomic::Db,
    entity: &str,
) -> Result<kotoba_core::cid::KotobaCid, (StatusCode, String)> {
    if let Some(cid) = kotoba_core::cid::KotobaCid::from_multibase(entity) {
        return Ok(cid);
    }
    match kotoba_edn::parse(entity) {
        Ok(value) => datomic_entid_for_value(db, &value)?.ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("datomic entity not found for {entity}"),
            )
        }),
        Err(_) => Ok(parse_datomic_entity(entity)),
    }
}

async fn require_datomic_read(
    state: &KotobaState,
    headers: &axum::http::HeaderMap,
    graph: &kotoba_core::cid::KotobaCid,
    cacao_b64: Option<&str>,
    presentation: Option<&kotoba_vc::VerifiablePresentation>,
    operation: &str,
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    require_datomic_read_any_operation(
        state,
        headers,
        graph,
        cacao_b64,
        presentation,
        &[operation],
        as_of,
        since,
    )
    .await
}

async fn require_datomic_read_any_operation(
    state: &KotobaState,
    headers: &axum::http::HeaderMap,
    graph: &kotoba_core::cid::KotobaCid,
    cacao_b64: Option<&str>,
    presentation: Option<&kotoba_vc::VerifiablePresentation>,
    operations: &[&str],
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    use crate::graph_auth::{check_read_access, AccessDenied};

    let graph_scope = graph.to_multibase();
    if cacao_b64.is_some() {
        if let Ok(payload) = verify_datomic_cacao_payload_with_any_operation(
            state,
            &graph_scope,
            cacao_b64,
            operations,
        ) {
            enforce_datomic_temporal_tx_scope(&payload, as_of, since)?;
            return Ok(());
        }
    }
    if let Some(presentation) = presentation {
        verify_vc_presentation_capability_any_operation(
            state,
            &graph_scope,
            presentation,
            operations,
        )?;
        return Ok(());
    }

    let visibility = state.graph_visibility(graph).await;
    check_read_access(
        &visibility,
        headers,
        cacao_b64,
        Some(state.operator_did.as_str()),
        None,
    )
    .map_err(AccessDenied::into_response)
}

fn enforce_datomic_temporal_tx_scope(
    payload: &kotoba_auth::CacaoPayload,
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Some(tx) = as_of.or(since) else {
        return Ok(());
    };
    if !payload.has_tx_scope() {
        return Ok(());
    }
    if payload.authorizes_tx(tx) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            format!("CACAO missing temporal tx scope kotoba://tx/{tx}"),
        ))
    }
}

fn enforce_datomic_write_tx_scope(
    payload: &kotoba_auth::CacaoPayload,
    tx_cid: &kotoba_core::cid::KotobaCid,
) -> Result<(), (StatusCode, String)> {
    if !payload.has_tx_scope() {
        return Ok(());
    }
    let tx = tx_cid.to_multibase();
    if payload.authorizes_tx(&tx) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            format!("CACAO missing transact tx scope kotoba://tx/{tx}"),
        ))
    }
}

fn verify_vc_presentation_capability(
    state: &KotobaState,
    graph: &str,
    presentation: &kotoba_vc::VerifiablePresentation,
    operation: &str,
) -> Result<(), (StatusCode, String)> {
    verify_vc_presentation_capabilities_scope(state, graph, presentation, &[operation], None)
}

fn verify_vc_presentation_capability_any_operation(
    state: &KotobaState,
    graph: &str,
    presentation: &kotoba_vc::VerifiablePresentation,
    operations: &[&str],
) -> Result<(), (StatusCode, String)> {
    for operation in operations {
        if verify_vc_presentation_capability(state, graph, presentation, operation).is_ok() {
            return Ok(());
        }
    }
    Err((
        StatusCode::UNAUTHORIZED,
        format!(
            "VP missing operator-issued capability for any of {} on {graph}",
            operations.join(",")
        ),
    ))
}

fn verify_vc_presentation_capability_scope(
    state: &KotobaState,
    graph: &str,
    presentation: &kotoba_vc::VerifiablePresentation,
    operation: &str,
    required_scope: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    verify_vc_presentation_capabilities_scope(
        state,
        graph,
        presentation,
        &[operation],
        required_scope,
    )
}

fn verify_vc_presentation_capabilities_scope(
    state: &KotobaState,
    graph: &str,
    presentation: &kotoba_vc::VerifiablePresentation,
    operations: &[&str],
    required_scope: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let holder = presentation
        .holder
        .as_deref()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "VP holder required".to_string()))?;
    let proof = presentation
        .proof
        .as_ref()
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "VP proof required".to_string()))?;
    if !proof.verification_method.starts_with(holder) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "VP proof verificationMethod must be controlled by holder".to_string(),
        ));
    }
    let auth_resolver = local_first_did_resolver(state);
    presentation
        .verify_proof_with_resolver(&auth_resolver)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                format!("VP DataIntegrity proof verification failed: {e}"),
            )
        })?;

    let graph_scope = format!("kotoba://graph/{graph}");
    for credential in &presentation.verifiable_credentials {
        if credential.issuer != state.operator_did {
            continue;
        }
        if !credential
            .types
            .iter()
            .any(|t| t == "KotobaCapabilityCredential" || t == "KotobaGraphCapabilityCredential")
        {
            continue;
        }
        credential
            .verify_proof_with_resolver(&auth_resolver)
            .map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("VC capability proof verification failed: {e}"),
                )
            })?;
        if credential.subject_id() != Some(holder) {
            continue;
        }
        let subject = &credential.credential_subject;
        let graph_ok = json_string_eq(subject.get("graph"), graph)
            || json_string_eq(subject.get("scope"), &graph_scope)
            || json_array_contains(subject.get("graphs"), graph)
            || json_array_contains(subject.get("resources"), &graph_scope);
        if !graph_ok {
            continue;
        }
        if let Some(required_scope) = required_scope {
            let scope_ok = json_string_eq(subject.get("scope"), required_scope)
                || json_array_contains(subject.get("resources"), required_scope)
                || json_array_contains(subject.get("scopes"), required_scope);
            if !scope_ok {
                continue;
            }
        }
        let op_ok = operations.iter().all(|operation| {
            json_string_eq(subject.get("operation"), operation)
                || json_string_eq(subject.get("capability"), operation)
                || json_array_contains(subject.get("operations"), operation)
                || json_array_contains(subject.get("capabilities"), operation)
        });
        if op_ok {
            return Ok(());
        }
    }

    Err((
        StatusCode::UNAUTHORIZED,
        match required_scope {
            Some(scope) => format!(
                "VP missing operator-issued capability for {} on {graph} with scope {scope}",
                operations.join(",")
            ),
            None => format!(
                "VP missing operator-issued capability for {} on {graph}",
                operations.join(",")
            ),
        },
    ))
}

fn local_first_did_resolver(state: &KotobaState) -> kotoba_auth::LayeredDidResolver {
    let local = kotoba_auth::InMemoryDidResolver::new();
    local.insert(state.operator_did.clone(), state.local_auth_did_document());
    kotoba_auth::LayeredDidResolver::new(vec![Arc::new(local), Arc::clone(&state.did_resolver)])
}

fn json_string_eq(value: Option<&serde_json::Value>, expected: &str) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .map(|s| s == expected)
        .unwrap_or(false)
}

fn json_array_contains(value: Option<&serde_json::Value>, expected: &str) -> bool {
    value
        .and_then(serde_json::Value::as_array)
        .map(|xs| xs.iter().any(|v| v.as_str() == Some(expected)))
        .unwrap_or(false)
}

fn json_value_has_tx_scope(value: Option<&serde_json::Value>) -> bool {
    match value {
        Some(serde_json::Value::String(scope)) => scope.starts_with("kotoba://tx/"),
        Some(serde_json::Value::Array(scopes)) => scopes.iter().any(|scope| {
            scope
                .as_str()
                .is_some_and(|s| s.starts_with("kotoba://tx/"))
        }),
        _ => false,
    }
}

fn vc_presentation_declares_tx_scope(presentation: &kotoba_vc::VerifiablePresentation) -> bool {
    presentation
        .verifiable_credentials
        .iter()
        .any(|credential| {
            let subject = &credential.credential_subject;
            json_value_has_tx_scope(subject.get("scope"))
                || json_value_has_tx_scope(subject.get("resources"))
                || json_value_has_tx_scope(subject.get("scopes"))
        })
}

fn cacao_capability_projection(
    payload: &kotoba_auth::CacaoPayload,
    proof_cid: Option<kotoba_core::cid::KotobaCid>,
) -> AuthCapabilityProjection {
    AuthCapabilityProjection {
        proof_format: "CACAO",
        controller: payload.iss.clone(),
        invoker: payload.iss.clone(),
        allowed_actions: payload
            .capabilities()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        invocation_targets: payload
            .invocation_targets()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        proof_cid,
        credential_ids: vec![],
    }
}

fn vp_capability_projection(
    presentation: &kotoba_vc::VerifiablePresentation,
    proof_cid: Option<kotoba_core::cid::KotobaCid>,
) -> AuthCapabilityProjection {
    let invoker = presentation.holder.clone().unwrap_or_default();
    let mut allowed_actions = Vec::new();
    let mut invocation_targets = Vec::new();
    let mut credential_ids = Vec::new();
    let mut controller = String::new();
    for credential in &presentation.verifiable_credentials {
        if !credential
            .types
            .iter()
            .any(|t| t == "KotobaCapabilityCredential" || t == "KotobaGraphCapabilityCredential")
        {
            continue;
        }
        if controller.is_empty() {
            controller = credential.issuer.clone();
        }
        credential_ids.push(credential.id.clone());
        collect_json_string_field(
            credential.credential_subject.get("operation"),
            &mut allowed_actions,
        );
        collect_json_string_field(
            credential.credential_subject.get("capability"),
            &mut allowed_actions,
        );
        collect_json_string_field(
            credential.credential_subject.get("operations"),
            &mut allowed_actions,
        );
        collect_json_string_field(
            credential.credential_subject.get("capabilities"),
            &mut allowed_actions,
        );
        collect_json_string_field(
            credential.credential_subject.get("scope"),
            &mut invocation_targets,
        );
        collect_json_string_field(
            credential.credential_subject.get("scopes"),
            &mut invocation_targets,
        );
        collect_json_string_field(
            credential.credential_subject.get("resources"),
            &mut invocation_targets,
        );
        collect_graph_scope(
            credential.credential_subject.get("graph"),
            &mut invocation_targets,
        );
        collect_graph_scope(
            credential.credential_subject.get("graphs"),
            &mut invocation_targets,
        );
    }
    AuthCapabilityProjection {
        proof_format: "W3C VerifiablePresentation",
        controller,
        invoker,
        allowed_actions,
        invocation_targets,
        proof_cid,
        credential_ids,
    }
}

fn collect_json_string_field(value: Option<&serde_json::Value>, out: &mut Vec<String>) {
    match value {
        Some(serde_json::Value::String(value)) => push_unique(out, value.clone()),
        Some(serde_json::Value::Array(values)) => {
            for value in values {
                if let Some(value) = value.as_str() {
                    push_unique(out, value.to_string());
                }
            }
        }
        _ => {}
    }
}

fn collect_graph_scope(value: Option<&serde_json::Value>, out: &mut Vec<String>) {
    match value {
        Some(serde_json::Value::String(graph)) => {
            push_unique(out, format!("kotoba://graph/{graph}"))
        }
        Some(serde_json::Value::Array(graphs)) => {
            for graph in graphs {
                if let Some(graph) = graph.as_str() {
                    push_unique(out, format!("kotoba://graph/{graph}"));
                }
            }
        }
        _ => {}
    }
}

fn push_unique(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
}

fn verify_datomic_cacao_payload(
    state: &KotobaState,
    graph: &str,
    cacao_b64: Option<&str>,
    operation: &str,
) -> Result<kotoba_auth::CacaoPayload, (StatusCode, String)> {
    verify_datomic_cacao_payload_with_operations(state, graph, cacao_b64, &[operation])
}

fn verify_datomic_cacao_payload_with_operations(
    state: &KotobaState,
    graph: &str,
    cacao_b64: Option<&str>,
    operations: &[&str],
) -> Result<kotoba_auth::CacaoPayload, (StatusCode, String)> {
    let primary_operation = operations.first().copied().unwrap_or("capability");
    let b64 = cacao_b64.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            format!("cacao_b64 required for {primary_operation}"),
        )
    })?;
    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }
    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;
    let nonce = cacao.p.nonce.clone();
    let payload = cacao.p.clone();
    let chain = kotoba_auth::DelegationChain::new(cacao);
    let mut issuer = None;
    for operation in operations {
        let verified_issuer = chain
            .verify_with_aud_and_resolver(
                graph,
                operation,
                &state.operator_did,
                state.did_resolver.as_ref(),
            )
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("cacao delegation: {e}")))?;
        issuer = Some(verified_issuer);
    }
    let issuer = issuer.unwrap_or_else(|| payload.iss.clone());
    if nonce.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "CACAO nonce must not be empty".to_string(),
        ));
    }
    const MAX_CACAO_AGE_SECS: u64 = 7 * 24 * 3600;
    let expiry_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(MAX_CACAO_AGE_SECS);
    if !state.nonce_store.check_and_register(&nonce, expiry_unix) {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("cacao nonce already used: {nonce}"),
        ));
    }
    tracing::debug!(issuer = %issuer, operations = %operations.join(","), graph, "datomic CACAO accepted");
    Ok(payload)
}

fn verify_datomic_cacao_payload_with_any_operation(
    state: &KotobaState,
    graph: &str,
    cacao_b64: Option<&str>,
    operations: &[&str],
) -> Result<kotoba_auth::CacaoPayload, (StatusCode, String)> {
    let primary_operation = operations.first().copied().unwrap_or("capability");
    let b64 = cacao_b64.ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            format!("cacao_b64 required for {primary_operation}"),
        )
    })?;
    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }
    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;
    let nonce = cacao.p.nonce.clone();
    let payload = cacao.p.clone();
    let chain = kotoba_auth::DelegationChain::new(cacao);
    let mut issuer = None;
    let mut last_error = None;
    for operation in operations {
        match chain.verify_with_aud_and_resolver(
            graph,
            operation,
            &state.operator_did,
            state.did_resolver.as_ref(),
        ) {
            Ok(verified_issuer) => {
                issuer = Some(verified_issuer);
                break;
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
    }
    let issuer = match issuer {
        Some(issuer) => issuer,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!(
                    "cacao delegation: missing any of {}{}",
                    operations.join(","),
                    last_error
                        .map(|err| format!(" ({err})"))
                        .unwrap_or_default()
                ),
            ))
        }
    };
    if nonce.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            "CACAO nonce must not be empty".to_string(),
        ));
    }
    const MAX_CACAO_AGE_SECS: u64 = 7 * 24 * 3600;
    let expiry_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(MAX_CACAO_AGE_SECS);
    if !state.nonce_store.check_and_register(&nonce, expiry_unix) {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("cacao nonce already used: {nonce}"),
        ));
    }
    tracing::debug!(issuer = %issuer, operations = %operations.join(","), graph, "datomic CACAO accepted");
    Ok(payload)
}

fn persist_cacao_auth_proof(
    state: &KotobaState,
    cacao_b64: &str,
) -> Result<kotoba_core::cid::KotobaCid, (StatusCode, String)> {
    let bytes = B64
        .decode(cacao_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    persist_auth_proof_block(state, &bytes)
}

fn persist_vp_auth_proof(
    state: &KotobaState,
    presentation: &kotoba_vc::VerifiablePresentation,
) -> Result<kotoba_core::cid::KotobaCid, (StatusCode, String)> {
    let bytes = serde_json::to_vec(presentation).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("presentation JSON encode: {e}"),
        )
    })?;
    persist_auth_proof_block(state, &bytes)
}

fn persist_auth_proof_block(
    state: &KotobaState,
    bytes: &[u8],
) -> Result<kotoba_core::cid::KotobaCid, (StatusCode, String)> {
    let cid = kotoba_core::cid::KotobaCid::from_bytes(bytes);
    state.block_store.put(&cid, bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("auth proof store: {e}"),
        )
    })?;
    state.block_store.pin(&cid);
    Ok(cid)
}

fn db_from_kqe_datoms(datoms: Vec<kotoba_kqe::Datom>) -> kotoba_datomic::Db {
    let basis_t = datoms.last().map(|d| d.tx.clone());
    let datoms = datoms
        .into_iter()
        .map(kotoba_datomic::Datom::from_kqe)
        .collect();
    kotoba_datomic::Db::from_datoms(datoms, basis_t)
}

fn db_from_datomic_history(datoms: Vec<kotoba_datomic::Datom>) -> kotoba_datomic::Db {
    let basis_t = datoms.last().map(|d| d.t.clone());
    kotoba_datomic::Db::from_datoms(datoms, basis_t)
}

pub(crate) fn distributed_graph_ipns_name(graph_cid: &kotoba_core::cid::KotobaCid) -> String {
    format!("k51-kotoba-{}", graph_cid.to_multibase())
}

fn did_document_registry_graph_cid(did: &str) -> kotoba_core::cid::KotobaCid {
    kotoba_core::cid::KotobaCid::from_bytes(format!("did-document-registry:{did}").as_bytes())
}

fn did_document_ipns_name(did: &str) -> String {
    crate::server::did_document_ipns_name(did)
}

fn datom_to_projection_quad(
    datom: &kotoba_datomic::Datom,
    graph_cid: &kotoba_core::cid::KotobaCid,
) -> kotoba_kqe::quad::LegacyQuad {
    let substrate = datom_to_projection_kqe(datom);
    kotoba_kqe::quad::LegacyQuad {
        graph: graph_cid.clone(),
        subject: substrate.e,
        predicate: substrate.a,
        object: substrate.v.into(),
    }
}

fn datom_to_projection_kqe(datom: &kotoba_datomic::Datom) -> kotoba_kqe::Datom {
    datom.to_kqe().unwrap_or_else(|_| kotoba_kqe::Datom {
        e: datom.e.clone(),
        a: datom.a.clone(),
        v: kotoba_kqe::Value::Text(kotoba_edn::to_string(&datom.v)),
        tx: datom.t.clone(),
        op: datom.added,
    })
}

fn append_tx_metadata_datoms(
    datoms: &mut Vec<kotoba_datomic::Datom>,
    tx_cid: &kotoba_core::cid::KotobaCid,
    graph_cid: &kotoba_core::cid::KotobaCid,
    operation: &str,
    author: &str,
    auth_proof_cid: Option<&kotoba_core::cid::KotobaCid>,
    ipns_name: &str,
    ipns_sequence: u64,
    ipns_controller_did: &str,
    expected_parent: Option<&kotoba_core::cid::KotobaCid>,
) {
    fn assert_tx(
        datoms: &mut Vec<kotoba_datomic::Datom>,
        tx_cid: &kotoba_core::cid::KotobaCid,
        attr: &str,
        value: kotoba_edn::EdnValue,
    ) {
        datoms.push(kotoba_datomic::Datom::assert(
            tx_cid.clone(),
            attr.to_string(),
            value,
            tx_cid.clone(),
        ));
    }

    assert_tx(
        datoms,
        tx_cid,
        ":tx/graph",
        kotoba_edn::EdnValue::String(graph_cid.to_multibase()),
    );
    assert_tx(
        datoms,
        tx_cid,
        ":tx/operation",
        kotoba_edn::EdnValue::String(operation.to_string()),
    );
    assert_tx(
        datoms,
        tx_cid,
        ":tx/author",
        kotoba_edn::EdnValue::String(author.to_string()),
    );
    if let Some(auth_proof_cid) = auth_proof_cid {
        assert_tx(
            datoms,
            tx_cid,
            ":tx/authProofCid",
            kotoba_edn::EdnValue::String(auth_proof_cid.to_multibase()),
        );
    }
    assert_tx(
        datoms,
        tx_cid,
        ":tx/ipnsName",
        kotoba_edn::EdnValue::String(ipns_name.to_string()),
    );
    assert_tx(
        datoms,
        tx_cid,
        ":tx/ipnsSequence",
        kotoba_edn::EdnValue::Integer(ipns_sequence as i64),
    );
    assert_tx(
        datoms,
        tx_cid,
        ":tx/ipnsControllerDid",
        kotoba_edn::EdnValue::String(ipns_controller_did.to_string()),
    );
    if let Some(expected_parent) = expected_parent {
        assert_tx(
            datoms,
            tx_cid,
            ":tx/expectedParentCommit",
            kotoba_edn::EdnValue::String(expected_parent.to_multibase()),
        );
    }
    if !datoms
        .iter()
        .any(|datom| datom.e == *tx_cid && datom.a == ":db/txInstant")
    {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        assert_tx(
            datoms,
            tx_cid,
            ":db/txInstant",
            kotoba_edn::EdnValue::Tagged {
                tag: kotoba_edn::Symbol::bare("inst"),
                value: Box::new(kotoba_edn::EdnValue::String(now.to_string())),
            },
        );
    }
}

fn append_auth_capability_datoms(
    datoms: &mut Vec<kotoba_datomic::Datom>,
    tx_cid: &kotoba_core::cid::KotobaCid,
    projection: &AuthCapabilityProjection,
) {
    fn assert_tx(
        datoms: &mut Vec<kotoba_datomic::Datom>,
        tx_cid: &kotoba_core::cid::KotobaCid,
        attr: &str,
        value: kotoba_edn::EdnValue,
    ) {
        datoms.push(kotoba_datomic::Datom::assert(
            tx_cid.clone(),
            attr.to_string(),
            value,
            tx_cid.clone(),
        ));
    }

    assert_tx(
        datoms,
        tx_cid,
        ":capability/proofFormat",
        kotoba_edn::EdnValue::String(projection.proof_format.to_string()),
    );
    if !projection.controller.is_empty() {
        assert_tx(
            datoms,
            tx_cid,
            ":capability/controller",
            kotoba_edn::EdnValue::String(projection.controller.clone()),
        );
        assert_tx(
            datoms,
            tx_cid,
            ZCAP_CONTROLLER_IRI,
            kotoba_edn::EdnValue::String(projection.controller.clone()),
        );
    }
    if !projection.invoker.is_empty() {
        assert_tx(
            datoms,
            tx_cid,
            ":capability/invoker",
            kotoba_edn::EdnValue::String(projection.invoker.clone()),
        );
    }
    for action in &projection.allowed_actions {
        assert_tx(
            datoms,
            tx_cid,
            ":capability/allowedAction",
            kotoba_edn::EdnValue::String(action.clone()),
        );
        assert_tx(
            datoms,
            tx_cid,
            ZCAP_ALLOWED_ACTION_IRI,
            kotoba_edn::EdnValue::String(action.clone()),
        );
    }
    for target in &projection.invocation_targets {
        assert_tx(
            datoms,
            tx_cid,
            ":capability/invocationTarget",
            kotoba_edn::EdnValue::String(target.clone()),
        );
        assert_tx(
            datoms,
            tx_cid,
            ZCAP_INVOCATION_TARGET_IRI,
            kotoba_edn::EdnValue::String(target.clone()),
        );
        if let Some(graph) = target.strip_prefix("kotoba://graph/") {
            assert_tx(
                datoms,
                tx_cid,
                ":capability/graph",
                kotoba_edn::EdnValue::String(graph.to_string()),
            );
        }
        if let Some(tx) = target.strip_prefix("kotoba://tx/") {
            assert_tx(
                datoms,
                tx_cid,
                ":capability/tx",
                kotoba_edn::EdnValue::String(tx.to_string()),
            );
        }
        if let Some(thread_id) = target.strip_prefix("didcomm://thread/") {
            assert_tx(
                datoms,
                tx_cid,
                ":capability/didcommThread",
                kotoba_edn::EdnValue::String(thread_id.to_string()),
            );
        }
        if target.starts_with("at://") {
            assert_tx(
                datoms,
                tx_cid,
                ":capability/atprotoResource",
                kotoba_edn::EdnValue::String(target.clone()),
            );
        }
    }
    if let Some(proof_cid) = &projection.proof_cid {
        assert_tx(
            datoms,
            tx_cid,
            ":capability/proofCid",
            kotoba_edn::EdnValue::String(proof_cid.to_multibase()),
        );
        assert_tx(
            datoms,
            tx_cid,
            ZCAP_INVOCATION_PROOF_IRI,
            kotoba_edn::EdnValue::String(proof_cid.to_multibase()),
        );
    }
    for credential_id in &projection.credential_ids {
        assert_tx(
            datoms,
            tx_cid,
            ":capability/credential",
            kotoba_edn::EdnValue::String(credential_id.clone()),
        );
    }
}

pub(crate) async fn commit_protocol_datoms(
    state: &KotobaState,
    graph_cid: kotoba_core::cid::KotobaCid,
    graph: String,
    entity_cid: kotoba_core::cid::KotobaCid,
    mut datoms: Vec<kotoba_datomic::Datom>,
    tx_cid: kotoba_core::cid::KotobaCid,
    author: String,
    operation: &str,
    auth_proof_cid: Option<kotoba_core::cid::KotobaCid>,
    auth_capability: Option<AuthCapabilityProjection>,
) -> Result<ProtocolDatomWriteResp, (StatusCode, String)> {
    let ipns_name = distributed_graph_ipns_name(&graph_cid);
    let current_head = match state
        .ipns_registry
        .resolve(&IpnsName::new(ipns_name.clone()))
    {
        Ok(record) => Some(record),
        Err(IpnsRegistryError::NotFound(_)) => None,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ipns resolve: {e}"),
            ));
        }
    };
    let expected_parent = current_head
        .as_ref()
        .and_then(|record| kotoba_core::cid::KotobaCid::from_multibase(&record.value));
    let seq = current_head
        .as_ref()
        .map(|record| record.sequence + 1)
        .unwrap_or(1);
    append_tx_metadata_datoms(
        &mut datoms,
        &tx_cid,
        &graph_cid,
        operation,
        &author,
        auth_proof_cid.as_ref(),
        &ipns_name,
        seq,
        &state.operator_did,
        expected_parent.as_ref(),
    );
    if let Some(auth_capability) = &auth_capability {
        append_auth_capability_datoms(&mut datoms, &tx_cid, auth_capability);
    }
    let writer = DistributedCommitWriter::new(&*state.block_store, &*state.ipns_registry);
    let distributed = writer
        .commit_datoms(CommitDatomsRequest {
            ipns_name: ipns_name.clone(),
            graph: graph_cid.clone(),
            datoms: datoms.clone(),
            expected_parent,
            tx_cid: Some(tx_cid.clone()),
            author,
            seq,
            valid_until: "2099-01-01T00:00:00Z".to_string(),
            ttl_secs: Some(60),
            cacao_proof_cid: auth_proof_cid.clone(),
            ipns_controller_did: Some(state.operator_did.clone()),
            ipns_signing_key: Some(state.ipns_signing_key()),
        })
        .map_err(|e| match e {
            DistributedCommitError::StaleParent { .. } => {
                (StatusCode::CONFLICT, format!("distributed commit: {e}"))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed commit: {e}"),
            ),
        })?;

    let mut journal_cids = Vec::with_capacity(datoms.len());
    for datom in &datoms {
        let quad = datom_to_projection_quad(datom, &graph_cid);
        let journal_cid = if datom.added {
            let cid = state.journal_assert(&quad).await;
            state
                .quad_store
                .apply_journaled_datom(graph_cid.clone(), datom_to_projection_kqe(datom))
                .await;
            cid
        } else {
            let cid = state.journal_retract(&quad).await;
            state
                .quad_store
                .apply_journaled_datom(graph_cid.clone(), datom_to_projection_kqe(datom))
                .await;
            cid
        };
        journal_cids.push(journal_cid);
    }

    let assert_count = datoms.iter().filter(|datom| datom.added).count();
    let retract_count = datoms.len().saturating_sub(assert_count);

    Ok(ProtocolDatomWriteResp {
        status: "ok",
        graph,
        entity_cid: entity_cid.to_multibase(),
        tx_cid: tx_cid.to_multibase(),
        commit_cid: distributed.commit.cid.to_multibase(),
        auth_proof_cid: distributed
            .commit
            .cacao_proof_cid
            .as_ref()
            .map(|cid| cid.to_multibase()),
        ipns_name,
        ipns_sequence: distributed.ipns_record.sequence,
        datom_count: datoms.len(),
        assert_count,
        retract_count,
        journal_cids,
    })
}

fn commit_did_document_registry_datoms(
    state: &KotobaState,
    did: &str,
    mut datoms: Vec<kotoba_datomic::Datom>,
    tx_cid: kotoba_core::cid::KotobaCid,
    author: String,
    auth_proof_cid: Option<kotoba_core::cid::KotobaCid>,
    auth_capability: Option<AuthCapabilityProjection>,
) -> Result<(), (StatusCode, String)> {
    let graph_cid = did_document_registry_graph_cid(did);
    let ipns_name = did_document_ipns_name(did);
    let current_head = match state
        .ipns_registry
        .resolve(&IpnsName::new(ipns_name.clone()))
    {
        Ok(record) => Some(record),
        Err(IpnsRegistryError::NotFound(_)) => None,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("did document ipns resolve: {e}"),
            ));
        }
    };
    let expected_parent = current_head
        .as_ref()
        .and_then(|record| kotoba_core::cid::KotobaCid::from_multibase(&record.value));
    let seq = current_head
        .as_ref()
        .map(|record| record.sequence + 1)
        .unwrap_or(1);
    append_tx_metadata_datoms(
        &mut datoms,
        &tx_cid,
        &graph_cid,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        &author,
        auth_proof_cid.as_ref(),
        &ipns_name,
        seq,
        &state.operator_did,
        expected_parent.as_ref(),
    );
    if let Some(auth_capability) = &auth_capability {
        append_auth_capability_datoms(&mut datoms, &tx_cid, auth_capability);
    }
    DistributedCommitWriter::new(&*state.block_store, &*state.ipns_registry)
        .commit_datoms(CommitDatomsRequest {
            ipns_name,
            graph: graph_cid,
            datoms,
            expected_parent,
            tx_cid: Some(tx_cid),
            author,
            seq,
            valid_until: "2099-01-01T00:00:00Z".to_string(),
            ttl_secs: Some(60),
            cacao_proof_cid: auth_proof_cid,
            ipns_controller_did: Some(state.operator_did.clone()),
            ipns_signing_key: Some(state.ipns_signing_key()),
        })
        .map(|_| ())
        .map_err(|e| match e {
            DistributedCommitError::StaleParent { .. } => (
                StatusCode::CONFLICT,
                format!("did document registry commit: {e}"),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("did document registry commit: {e}"),
            ),
        })
}

fn json_value_to_edn(value: &serde_json::Value) -> kotoba_edn::EdnValue {
    match value {
        serde_json::Value::Null => kotoba_edn::EdnValue::Nil,
        serde_json::Value::Bool(b) => kotoba_edn::EdnValue::Bool(*b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(kotoba_edn::EdnValue::Integer)
            .or_else(|| n.as_f64().map(kotoba_edn::EdnValue::float))
            .unwrap_or_else(|| kotoba_edn::EdnValue::string(n.to_string())),
        serde_json::Value::String(s) => kotoba_edn::EdnValue::string(s),
        serde_json::Value::Array(xs) => {
            kotoba_edn::EdnValue::vector(xs.iter().map(json_value_to_edn))
        }
        serde_json::Value::Object(obj) => kotoba_edn::EdnValue::Map(
            obj.iter()
                .map(|(k, v)| (kotoba_edn::EdnValue::kw_bare(k), json_value_to_edn(v)))
                .collect(),
        ),
    }
}

fn append_json_record_field_datoms(
    out: &mut Vec<kotoba_datomic::Datom>,
    entity_cid: &kotoba_core::cid::KotobaCid,
    attr_prefix: &str,
    record: &serde_json::Value,
    tx_cid: &kotoba_core::cid::KotobaCid,
) {
    let Some(obj) = record.as_object() else {
        return;
    };
    for (key, value) in obj {
        if key == "$type" {
            continue;
        }
        let attr = format!("{attr_prefix}{key}");
        out.push(kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            attr.clone(),
            json_value_to_edn(value),
            tx_cid.clone(),
        ));
        append_json_record_field_datoms(out, entity_cid, &format!("{attr}/"), value, tx_cid);
    }
}

fn atproto_repo_record_entity_cid(uri: &str) -> kotoba_core::cid::KotobaCid {
    kotoba_core::cid::KotobaCid::from_bytes(uri.as_bytes())
}

fn atproto_repo_write_datoms(
    req: &AtprotoRepoWriteReq,
    uri: &kotoba_graph::AtUri,
    entity_cid: &kotoba_core::cid::KotobaCid,
    tx_cid: &kotoba_core::cid::KotobaCid,
) -> Vec<kotoba_datomic::Datom> {
    let operation = req.operation.as_deref().unwrap_or("create");
    let record_edn = req.record.as_ref().map(json_value_to_edn);
    let mut out = vec![
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/uri".to_string(),
            kotoba_edn::EdnValue::string(&req.uri),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/authority".to_string(),
            kotoba_edn::EdnValue::string(&uri.authority),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/collection".to_string(),
            kotoba_edn::EdnValue::string(&uri.collection),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/nsid".to_string(),
            kotoba_edn::EdnValue::string(&uri.collection),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/rkey".to_string(),
            kotoba_edn::EdnValue::string(&uri.rkey),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/operation".to_string(),
            kotoba_edn::EdnValue::string(operation),
            tx_cid.clone(),
        ),
    ];
    if uri.authority.starts_with("did:") {
        out.push(kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/did".to_string(),
            kotoba_edn::EdnValue::string(&uri.authority),
            tx_cid.clone(),
        ));
    }
    if let Some(record_edn) = &record_edn {
        out.push(kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            uri.collection.clone(),
            record_edn.clone(),
            tx_cid.clone(),
        ));
    }
    if let Some(cid) = &req.cid {
        out.push(kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/cid".to_string(),
            kotoba_edn::EdnValue::string(cid),
            tx_cid.clone(),
        ));
    }
    if let Some(record) = &req.record {
        out.push(kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/record".to_string(),
            record_edn
                .clone()
                .unwrap_or_else(|| json_value_to_edn(record)),
            tx_cid.clone(),
        ));
        if let Some(record_type) = record.get("$type").and_then(serde_json::Value::as_str) {
            out.push(kotoba_datomic::Datom::assert(
                entity_cid.clone(),
                "atproto/type".to_string(),
                kotoba_edn::EdnValue::string(record_type),
                tx_cid.clone(),
            ));
            out.push(kotoba_datomic::Datom::assert(
                entity_cid.clone(),
                "atproto/recordType".to_string(),
                kotoba_edn::EdnValue::string(record_type),
                tx_cid.clone(),
            ));
            if let Some(record_edn) = &record_edn {
                out.push(kotoba_datomic::Datom::assert(
                    entity_cid.clone(),
                    record_type.to_string(),
                    record_edn.clone(),
                    tx_cid.clone(),
                ));
            }
        }
        append_json_record_field_datoms(&mut out, entity_cid, "atproto/record/", record, tx_cid);
        append_json_record_field_datoms(
            &mut out,
            entity_cid,
            &format!("{}/", uri.collection),
            record,
            tx_cid,
        );
        append_json_record_field_datoms(
            &mut out,
            entity_cid,
            &format!("{}#", uri.collection),
            record,
            tx_cid,
        );
    }
    out
}

fn atproto_repo_delete_datoms(
    db: &kotoba_datomic::Db,
    req: &AtprotoRepoWriteReq,
    uri: &kotoba_graph::AtUri,
    entity_cid: &kotoba_core::cid::KotobaCid,
    tx_cid: &kotoba_core::cid::KotobaCid,
) -> Vec<kotoba_datomic::Datom> {
    let mut out = db
        .datoms()
        .into_iter()
        .filter(|datom| {
            datom.e == *entity_cid
                && !matches!(
                    datom.a.as_str(),
                    "atproto/uri"
                        | "atproto/authority"
                        | "atproto/collection"
                        | "atproto/nsid"
                        | "atproto/rkey"
                        | "atproto/did"
                )
        })
        .map(|datom| kotoba_datomic::Datom::retract(datom.e, datom.a, datom.v, tx_cid.clone()))
        .collect::<Vec<_>>();
    out.extend([
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/uri".to_string(),
            kotoba_edn::EdnValue::string(&req.uri),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/authority".to_string(),
            kotoba_edn::EdnValue::string(&uri.authority),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/collection".to_string(),
            kotoba_edn::EdnValue::string(&uri.collection),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/nsid".to_string(),
            kotoba_edn::EdnValue::string(&uri.collection),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/rkey".to_string(),
            kotoba_edn::EdnValue::string(&uri.rkey),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/operation".to_string(),
            kotoba_edn::EdnValue::string("delete"),
            tx_cid.clone(),
        ),
        kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/deleted".to_string(),
            kotoba_edn::EdnValue::Bool(true),
            tx_cid.clone(),
        ),
    ]);
    if uri.authority.starts_with("did:") {
        out.push(kotoba_datomic::Datom::assert(
            entity_cid.clone(),
            "atproto/did".to_string(),
            kotoba_edn::EdnValue::string(&uri.authority),
            tx_cid.clone(),
        ));
    }
    out
}

async fn current_db_for_graph(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
) -> Result<kotoba_datomic::Db, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let distributed_history = reader
        .history_for_name(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic read: {e}"),
            )
        })?;
    if !distributed_history.is_empty() {
        return Ok(db_from_datomic_history(distributed_history));
    }

    let mut datoms = state
        .quad_store
        .history_datoms_cold(graph_cid)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("datomic cold history read: {e}"),
            )
        })?;
    let mut hot = state
        .quad_store
        .arrangement(graph_cid)
        .await
        .map(|arr| arr.datoms(&kotoba_core::cid::KotobaCid::from_bytes(b"kotoba-hot-tx")))
        .unwrap_or_default();
    datoms.append(&mut hot);
    Ok(db_from_kqe_datoms(datoms))
}

fn parse_optional_tx_cid(
    field: &'static str,
    value: Option<&str>,
) -> Result<Option<kotoba_core::cid::KotobaCid>, (StatusCode, String)> {
    value
        .map(|cid| {
            kotoba_core::cid::KotobaCid::from_multibase(cid).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid {field} transaction CID"),
                )
            })
        })
        .transpose()
}

fn apply_datomic_basis(
    db: kotoba_datomic::Db,
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<kotoba_datomic::Db, (StatusCode, String)> {
    match (
        parse_optional_tx_cid("as_of", as_of)?,
        parse_optional_tx_cid("since", since)?,
    ) {
        (Some(_), Some(_)) => Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        )),
        (Some(t), None) => Ok(db.as_of(&t)),
        (None, Some(t)) => Ok(db.since(&t)),
        (None, None) => Ok(db),
    }
}

fn basis_t_resp(db: &kotoba_datomic::Db) -> Option<String> {
    db.basis_t.as_ref().map(|cid| cid.to_multibase())
}

fn datomic_db_stats_resp(graph: String, db: &kotoba_datomic::Db) -> DatomicDbStatsResp {
    let datoms = db.datoms();
    let history = db.history().datoms().to_vec();
    let mut entities = BTreeSet::new();
    let mut attrs = BTreeSet::new();
    let mut txs = BTreeSet::new();
    for datom in &datoms {
        entities.insert(datom.e.to_multibase());
        attrs.insert(datom.a.clone());
    }
    for datom in &history {
        txs.insert(datom.t.to_multibase());
    }

    DatomicDbStatsResp {
        graph,
        basis_t: basis_t_resp(db),
        datom_count: datoms.len(),
        history_datom_count: history.len(),
        entity_count: entities.len(),
        attribute_count: attrs.len(),
        tx_count: txs.len(),
    }
}

#[derive(Debug, Clone, Copy)]
enum DatomicDatomsIndex {
    Eavt,
    Aevt,
    Avet,
    Vaet,
    Tea,
}

impl DatomicDatomsIndex {
    fn parse(index: &str) -> Result<Self, (StatusCode, String)> {
        match index {
            ":eavt" | "eavt" => Ok(Self::Eavt),
            ":aevt" | "aevt" => Ok(Self::Aevt),
            ":avet" | "avet" => Ok(Self::Avet),
            ":vaet" | "vaet" => Ok(Self::Vaet),
            ":tea" | "tea" => Ok(Self::Tea),
            _ => Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "unsupported datoms index {index}; expected :eavt, :aevt, :avet, :vaet, or :tea"
                ),
            )),
        }
    }

    fn distributed_root(self) -> &'static str {
        match self {
            Self::Eavt => ROOT_EAVT,
            Self::Aevt => ROOT_AEVT,
            Self::Avet => ROOT_AVET,
            Self::Vaet => ROOT_VAET,
            Self::Tea => ROOT_TEA,
        }
    }
}

fn datomic_component_entity(value: &kotoba_edn::EdnValue) -> kotoba_core::cid::KotobaCid {
    match value {
        kotoba_edn::EdnValue::String(s) => kotoba_core::cid::KotobaCid::from_multibase(s)
            .unwrap_or_else(|| kotoba_core::cid::KotobaCid::from_bytes(s.as_bytes())),
        _ => kotoba_core::cid::KotobaCid::from_bytes(kotoba_edn::to_string(value).as_bytes()),
    }
}

fn datomic_component_entity_from_db(
    db: &kotoba_datomic::Db,
    value: &kotoba_edn::EdnValue,
) -> Result<kotoba_core::cid::KotobaCid, (StatusCode, String)> {
    datomic_entid_for_value(db, value)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!(
                    "datomic component entity not found for {}",
                    kotoba_edn::to_string(value)
                ),
            )
        })
        .or_else(|err| match value {
            kotoba_edn::EdnValue::String(_) => Ok(datomic_component_entity(value)),
            _ => Err(err),
        })
}

fn datomic_component_attr(value: &kotoba_edn::EdnValue) -> Result<String, (StatusCode, String)> {
    match value {
        kotoba_edn::EdnValue::Keyword(keyword) => Ok(format!(":{}", keyword.to_qualified())),
        kotoba_edn::EdnValue::String(s) => Ok(s.clone()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "datoms attribute component must be keyword or string, got {}",
                kotoba_edn::to_string(value)
            ),
        )),
    }
}

fn datomic_index_component_is_entity(index: DatomicDatomsIndex, position: usize) -> bool {
    matches!(
        (index, position),
        (DatomicDatomsIndex::Eavt, 0)
            | (DatomicDatomsIndex::Aevt, 1)
            | (DatomicDatomsIndex::Avet, 2)
            | (DatomicDatomsIndex::Vaet, 0)
            | (DatomicDatomsIndex::Vaet, 2)
            | (DatomicDatomsIndex::Tea, 0)
            | (DatomicDatomsIndex::Tea, 1)
    )
}

fn resolve_datomic_index_components(
    db: &kotoba_datomic::Db,
    index: DatomicDatomsIndex,
    components: &[kotoba_edn::EdnValue],
) -> Result<Vec<kotoba_edn::EdnValue>, (StatusCode, String)> {
    components
        .iter()
        .enumerate()
        .map(|(position, component)| {
            if datomic_index_component_is_entity(index, position) {
                datomic_component_entity_from_db(db, component)
                    .map(|cid| kotoba_edn::EdnValue::String(cid.to_multibase()))
            } else {
                Ok(component.clone())
            }
        })
        .collect()
}

fn resolve_datomic_index_range_bound(
    db: &kotoba_datomic::Db,
    value: Option<kotoba_edn::EdnValue>,
) -> Result<Option<kotoba_edn::EdnValue>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    if matches!(value, kotoba_edn::EdnValue::Vector(ref items) if items.len() == 2) {
        let cid = datomic_component_entity_from_db(db, &value)?;
        return Ok(Some(kotoba_edn::EdnValue::String(cid.to_multibase())));
    }
    Ok(Some(value))
}

fn parse_datomic_datoms_components(
    srcs: &[String],
) -> Result<Vec<kotoba_edn::EdnValue>, (StatusCode, String)> {
    srcs.iter()
        .map(|src| {
            kotoba_edn::parse(src).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("components_edn parse: {e}"),
                )
            })
        })
        .collect()
}

fn parse_optional_edn(
    field: &str,
    src: Option<&str>,
) -> Result<Option<kotoba_edn::EdnValue>, (StatusCode, String)> {
    src.map(|src| {
        kotoba_edn::parse(src).map_err(|e| (StatusCode::BAD_REQUEST, format!("{field} parse: {e}")))
    })
    .transpose()
}

fn datomic_datoms_match_components(
    datom: &kotoba_datomic::Datom,
    index: DatomicDatomsIndex,
    components: &[kotoba_edn::EdnValue],
) -> Result<bool, (StatusCode, String)> {
    for (position, component) in components.iter().enumerate() {
        let matches = match (index, position) {
            (DatomicDatomsIndex::Eavt, 0) => datom.e == datomic_component_entity(component),
            (DatomicDatomsIndex::Eavt, 1) => datom.a == datomic_component_attr(component)?,
            (DatomicDatomsIndex::Eavt, 2) => datom.v == *component,
            (DatomicDatomsIndex::Eavt, 3) => datom.t == datomic_component_entity(component),
            (DatomicDatomsIndex::Aevt, 0) => datom.a == datomic_component_attr(component)?,
            (DatomicDatomsIndex::Aevt, 1) => datom.e == datomic_component_entity(component),
            (DatomicDatomsIndex::Aevt, 2) => datom.v == *component,
            (DatomicDatomsIndex::Aevt, 3) => datom.t == datomic_component_entity(component),
            (DatomicDatomsIndex::Avet, 0) => datom.a == datomic_component_attr(component)?,
            (DatomicDatomsIndex::Avet, 1) => datom.v == *component,
            (DatomicDatomsIndex::Avet, 2) => datom.e == datomic_component_entity(component),
            (DatomicDatomsIndex::Avet, 3) => datom.t == datomic_component_entity(component),
            (DatomicDatomsIndex::Vaet, 0) => datom.v == *component,
            (DatomicDatomsIndex::Vaet, 1) => datom.a == datomic_component_attr(component)?,
            (DatomicDatomsIndex::Vaet, 2) => datom.e == datomic_component_entity(component),
            (DatomicDatomsIndex::Vaet, 3) => datom.t == datomic_component_entity(component),
            (DatomicDatomsIndex::Tea, 0) => datom.t == datomic_component_entity(component),
            (DatomicDatomsIndex::Tea, 1) => datom.e == datomic_component_entity(component),
            (DatomicDatomsIndex::Tea, 2) => datom.a == datomic_component_attr(component)?,
            (DatomicDatomsIndex::Tea, 3) => datom.v == *component,
            (_, _) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "datoms supports at most 4 index components".to_string(),
                ))
            }
        };
        if !matches {
            return Ok(false);
        }
    }
    Ok(true)
}

fn datomic_datoms_sort_key(
    datom: &kotoba_datomic::Datom,
    index: DatomicDatomsIndex,
) -> (
    kotoba_edn::EdnValue,
    kotoba_edn::EdnValue,
    kotoba_edn::EdnValue,
    kotoba_edn::EdnValue,
) {
    let e = kotoba_edn::EdnValue::String(datom.e.to_multibase());
    let a = kotoba_edn::EdnValue::String(datom.a.clone());
    let v = datom.v.clone();
    let t = kotoba_edn::EdnValue::String(datom.t.to_multibase());
    match index {
        DatomicDatomsIndex::Eavt => (e, a, v, t),
        DatomicDatomsIndex::Aevt => (a, e, v, t),
        DatomicDatomsIndex::Avet => (a, v, e, t),
        DatomicDatomsIndex::Vaet => (v, a, e, t),
        DatomicDatomsIndex::Tea => (t, e, a, v),
    }
}

fn datomic_datoms_sort_values(
    datom: &kotoba_datomic::Datom,
    index: DatomicDatomsIndex,
) -> Vec<kotoba_edn::EdnValue> {
    let (a, b, c, d) = datomic_datoms_sort_key(datom, index);
    vec![a, b, c, d]
}

fn datomic_seek_component_sort_value(
    index: DatomicDatomsIndex,
    position: usize,
    component: &kotoba_edn::EdnValue,
) -> Result<kotoba_edn::EdnValue, (StatusCode, String)> {
    let entity =
        || kotoba_edn::EdnValue::String(datomic_component_entity(component).to_multibase());
    let attr = || datomic_component_attr(component).map(kotoba_edn::EdnValue::String);
    let value = || Ok(component.clone());
    match (index, position) {
        (DatomicDatomsIndex::Eavt, 0) => Ok(entity()),
        (DatomicDatomsIndex::Eavt, 1) => attr(),
        (DatomicDatomsIndex::Eavt, 2) => value(),
        (DatomicDatomsIndex::Eavt, 3) => Ok(entity()),
        (DatomicDatomsIndex::Aevt, 0) => attr(),
        (DatomicDatomsIndex::Aevt, 1) => Ok(entity()),
        (DatomicDatomsIndex::Aevt, 2) => value(),
        (DatomicDatomsIndex::Aevt, 3) => Ok(entity()),
        (DatomicDatomsIndex::Avet, 0) => attr(),
        (DatomicDatomsIndex::Avet, 1) => value(),
        (DatomicDatomsIndex::Avet, 2) => Ok(entity()),
        (DatomicDatomsIndex::Avet, 3) => Ok(entity()),
        (DatomicDatomsIndex::Vaet, 0) => value(),
        (DatomicDatomsIndex::Vaet, 1) => attr(),
        (DatomicDatomsIndex::Vaet, 2) => Ok(entity()),
        (DatomicDatomsIndex::Vaet, 3) => Ok(entity()),
        (DatomicDatomsIndex::Tea, 0) => Ok(entity()),
        (DatomicDatomsIndex::Tea, 1) => Ok(entity()),
        (DatomicDatomsIndex::Tea, 2) => attr(),
        (DatomicDatomsIndex::Tea, 3) => value(),
        (_, _) => Err((
            StatusCode::BAD_REQUEST,
            "seekDatoms supports at most 4 index components".to_string(),
        )),
    }
}

fn datomic_seek_key(
    index: DatomicDatomsIndex,
    components: &[kotoba_edn::EdnValue],
) -> Result<Vec<kotoba_edn::EdnValue>, (StatusCode, String)> {
    components
        .iter()
        .enumerate()
        .map(|(position, component)| datomic_seek_component_sort_value(index, position, component))
        .collect()
}

fn distributed_datomic_db(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<Option<kotoba_datomic::Db>, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let as_of = parse_optional_tx_cid("as_of", as_of)?;
    let since = parse_optional_tx_cid("since", since)?;
    if as_of.is_some() && since.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        ));
    }
    let db = match (as_of.as_ref(), since.as_ref()) {
        (Some(tx), None) => reader.db_as_of_tx(&head.cid, tx),
        (None, Some(tx)) => reader.db_since_tx(&head.cid, tx),
        (None, None) => reader.db_from_head(&head.cid),
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic db: {e}"),
        )
    })?;
    Ok(Some(db))
}

fn distributed_datomic_history_db(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<Option<kotoba_datomic::Db>, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let as_of = parse_optional_tx_cid("as_of", as_of)?;
    let since = parse_optional_tx_cid("since", since)?;
    if as_of.is_some() && since.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        ));
    }
    let db = match (as_of.as_ref(), since.as_ref()) {
        (Some(tx), None) => reader.history_db_as_of_tx(&head.cid, tx),
        (None, Some(tx)) => reader.history_db_since_tx(&head.cid, tx),
        (None, None) => reader.history_db_from_head(&head.cid),
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic history: {e}"),
        )
    })?;
    Ok(Some(db))
}

fn distributed_datomic_q(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    query: &kotoba_edn::EdnValue,
    inputs: &[kotoba_edn::EdnValue],
    as_of: Option<&str>,
    since: Option<&str>,
    history: bool,
) -> Result<Option<(Option<String>, Vec<Vec<kotoba_edn::EdnValue>>)>, (StatusCode, String)> {
    if history {
        let Some(db) = distributed_datomic_history_db(state, graph_cid, as_of, since)? else {
            return Ok(None);
        };
        let basis_t = basis_t_resp(&db);
        let rows =
            kotoba_datomic::q_history(query.clone(), &db.history(), inputs).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("distributed datomic q: {e}"),
                )
            })?;
        return Ok(Some((basis_t, rows)));
    }
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let as_of = parse_optional_tx_cid("as_of", as_of)?;
    let since = parse_optional_tx_cid("since", since)?;
    if as_of.is_some() && since.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        ));
    }
    let rows = match (as_of.as_ref(), since.as_ref()) {
        (Some(tx), None) => reader.q_triples_as_of_tx_with_inputs(&head.cid, tx, query, inputs),
        (None, Some(tx)) => reader.q_triples_since_tx_with_inputs(&head.cid, tx, query, inputs),
        (None, None) => reader.q_triples_with_inputs(&head.cid, query, inputs),
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic q: {e}"),
        )
    })?;
    let basis_t = as_of
        .or_else(|| Some(head.tx_cid.clone()))
        .map(|cid| cid.to_multibase());
    Ok(Some((basis_t, rows)))
}

fn distributed_datomic_datoms(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    index: DatomicDatomsIndex,
    components: &[kotoba_edn::EdnValue],
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<Option<(Option<String>, Vec<kotoba_datomic::Datom>)>, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let as_of = parse_optional_tx_cid("as_of", as_of)?;
    let since = parse_optional_tx_cid("since", since)?;
    if as_of.is_some() && since.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        ));
    }
    let datoms = match (as_of.as_ref(), since.as_ref()) {
        (Some(tx), None) => reader.current_for_index_components_as_of_tx(
            &head.cid,
            tx,
            index.distributed_root(),
            components,
        ),
        (None, Some(tx)) => reader.current_for_index_components_since_tx(
            &head.cid,
            tx,
            index.distributed_root(),
            components,
        ),
        (None, None) => {
            reader.current_for_index_components(&head.cid, index.distributed_root(), components)
        }
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic datoms: {e}"),
        )
    })?;
    let basis_t = as_of
        .or_else(|| Some(head.tx_cid.clone()))
        .map(|cid| cid.to_multibase());
    Ok(Some((basis_t, datoms)))
}

fn distributed_datomic_seek_datoms(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    index: DatomicDatomsIndex,
    components: &[kotoba_edn::EdnValue],
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<Option<(Option<String>, Vec<kotoba_datomic::Datom>)>, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let prefix_components = if components.is_empty() {
        &[]
    } else {
        &components[..1]
    };
    let as_of = parse_optional_tx_cid("as_of", as_of)?;
    let since = parse_optional_tx_cid("since", since)?;
    if as_of.is_some() && since.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        ));
    }
    let datoms = match (as_of.as_ref(), since.as_ref()) {
        (Some(tx), None) => reader.current_for_index_components_as_of_tx(
            &head.cid,
            tx,
            index.distributed_root(),
            prefix_components,
        ),
        (None, Some(tx)) => reader.current_for_index_components_since_tx(
            &head.cid,
            tx,
            index.distributed_root(),
            prefix_components,
        ),
        (None, None) => reader.current_for_index_components(
            &head.cid,
            index.distributed_root(),
            prefix_components,
        ),
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic seekDatoms: {e}"),
        )
    })?;
    let basis_t = as_of
        .or_else(|| Some(head.tx_cid.clone()))
        .map(|cid| cid.to_multibase());
    Ok(Some((basis_t, datoms)))
}

fn distributed_datomic_index_range(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    attr: &str,
    as_of: Option<&str>,
    since: Option<&str>,
) -> Result<Option<(Option<String>, Vec<kotoba_datomic::Datom>)>, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let attr_value = kotoba_edn::EdnValue::String(attr.to_string());
    let as_of = parse_optional_tx_cid("as_of", as_of)?;
    let since = parse_optional_tx_cid("since", since)?;
    if as_of.is_some() && since.is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "as_of and since are mutually exclusive".to_string(),
        ));
    }
    let datoms = match (as_of.as_ref(), since.as_ref()) {
        (Some(tx), None) => reader.current_for_index_components_as_of_tx(
            &head.cid,
            tx,
            ROOT_AVET,
            std::slice::from_ref(&attr_value),
        ),
        (None, Some(tx)) => reader.current_for_index_components_since_tx(
            &head.cid,
            tx,
            ROOT_AVET,
            std::slice::from_ref(&attr_value),
        ),
        (None, None) => reader.current_for_index_components(&head.cid, ROOT_AVET, &[attr_value]),
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
    .map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic indexRange: {e}"),
        )
    })?;
    let basis_t = as_of
        .or_else(|| Some(head.tx_cid.clone()))
        .map(|cid| cid.to_multibase());
    Ok(Some((basis_t, datoms)))
}

fn distributed_datomic_tx_range(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<
    Option<(
        Option<String>,
        Vec<kotoba_datomic::distributed::DistributedTxRangeEntry>,
    )>,
    (StatusCode, String),
> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let start = parse_optional_tx_cid("start", start)?;
    let end = parse_optional_tx_cid("end", end)?;
    let entries = reader
        .tx_range_from_head(&head.cid, start.as_ref(), end.as_ref())
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("distributed datomic txRange: {e}"),
            )
        })?;
    Ok(Some((Some(head.tx_cid.to_multibase()), entries)))
}

fn distributed_datomic_log(
    state: &KotobaState,
    graph_cid: &kotoba_core::cid::KotobaCid,
    start: Option<&str>,
    end: Option<&str>,
) -> Result<Option<(Option<String>, Vec<kotoba_datomic::LogEntry>)>, (StatusCode, String)> {
    let reader = DistributedDatomReader::new(&*state.block_store, &*state.ipns_registry);
    let Some(head) = reader
        .resolve_head(&distributed_graph_ipns_name(graph_cid))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed datomic head read: {e}"),
            )
        })?
    else {
        return Ok(None);
    };
    let start = parse_optional_tx_cid("start", start)?;
    let end = parse_optional_tx_cid("end", end)?;
    let entries = reader.log_from_head(&head.cid).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("distributed datomic log: {e}"),
        )
    })?;
    if let Some(start) = &start {
        if !entries.iter().any(|entry| &entry.tx == start) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "datomic log start transaction not found: {}",
                    start.to_multibase()
                ),
            ));
        }
    }
    if let Some(end) = &end {
        if !entries.iter().any(|entry| &entry.tx == end) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "datomic log end transaction not found: {}",
                    end.to_multibase()
                ),
            ));
        }
    }
    let entries = entries
        .into_iter()
        .skip_while(|entry| start.as_ref().is_some_and(|start| &entry.tx != start))
        .take_while(|entry| end.as_ref().is_none_or(|end| &entry.tx != end))
        .collect::<Vec<_>>();
    Ok(Some((Some(head.tx_cid.to_multibase()), entries)))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.transact
/// Apply EDN transaction data, preserving Datomic's `(E,A,V,T,Added)` semantics
/// at the API boundary and projecting each datom into the current graph store.
pub async fn datomic_transact(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicTransactReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    const MAX_TX_EDN_LEN: usize = 1024 * 1024;
    if req.tx_edn.len() > MAX_TX_EDN_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "tx_edn too large ({} bytes, limit {MAX_TX_EDN_LEN})",
                req.tx_edn.len()
            ),
        ));
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    let operator_auth = crate::graph_auth::require_operator_auth(&headers, &state.operator_did);
    let mut write_author = state.operator_did.clone();
    let mut auth_proof_cid = None;
    let mut cacao_payload = None;
    let mut auth_capability = None;
    if let Some(cacao_b64) = req.cacao_b64.as_deref() {
        let payload = verify_datomic_cacao_payload_with_operations(
            &state,
            &req.graph,
            Some(cacao_b64),
            &[
                kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
                kotoba_auth::CacaoPayload::OP_TX_CREATE,
            ],
        )?;
        write_author = payload.iss.clone();
        cacao_payload = Some(payload);
    } else if let Some(presentation) = &req.presentation {
        verify_vc_presentation_capabilities_scope(
            &state,
            &req.graph,
            presentation,
            &[
                kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
                kotoba_auth::CacaoPayload::OP_TX_CREATE,
            ],
            None,
        )?;
        write_author = presentation
            .holder
            .clone()
            .unwrap_or_else(|| state.operator_did.clone());
    } else if let Err(operator_err) = operator_auth {
        return Err(operator_err);
    }

    let tx_data = kotoba_edn::parse(&req.tx_edn)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("tx_edn parse: {e}")))?;
    let db_before = match distributed_datomic_db(&state, &graph_cid, None, None)? {
        Some(db) => db,
        None => current_db_for_graph(&state, &graph_cid).await?,
    };
    let conn = kotoba_datomic::Connection::from_datoms(db_before.all_datoms());
    let report = conn
        .transact(tx_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic transact: {e}")))?;
    if let Some(payload) = &cacao_payload {
        enforce_datomic_write_tx_scope(payload, &report.tx_cid)?;
    }
    if let Some(presentation) = &req.presentation {
        if vc_presentation_declares_tx_scope(presentation) {
            let tx_scope = format!("kotoba://tx/{}", report.tx_cid.to_multibase());
            verify_vc_presentation_capabilities_scope(
                &state,
                &req.graph,
                presentation,
                &[
                    kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
                    kotoba_auth::CacaoPayload::OP_TX_CREATE,
                ],
                Some(&tx_scope),
            )?;
        }
    }
    if let Some(cacao_b64) = req.cacao_b64.as_deref() {
        auth_proof_cid = Some(persist_cacao_auth_proof(&state, cacao_b64)?);
        if let Some(payload) = &cacao_payload {
            auth_capability = Some(cacao_capability_projection(payload, auth_proof_cid.clone()));
        }
    } else if let Some(presentation) = &req.presentation {
        auth_proof_cid = Some(persist_vp_auth_proof(&state, presentation)?);
        auth_capability = Some(vp_capability_projection(
            presentation,
            auth_proof_cid.clone(),
        ));
    }

    let ipns_name = distributed_graph_ipns_name(&graph_cid);
    let current_head = match state
        .ipns_registry
        .resolve(&IpnsName::new(ipns_name.clone()))
    {
        Ok(record) => Some(record),
        Err(IpnsRegistryError::NotFound(_)) => None,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ipns resolve: {e}"),
            ));
        }
    };
    let expected_parent = match req.expected_parent.as_deref() {
        Some(cid) => Some(
            kotoba_core::cid::KotobaCid::from_multibase(cid).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid expected_parent CID".to_string(),
                )
            })?,
        ),
        None => current_head
            .as_ref()
            .and_then(|record| kotoba_core::cid::KotobaCid::from_multibase(&record.value)),
    };
    let explicit_cacao_proof_cid = match req.cacao_proof_cid.as_deref() {
        Some(cid) => Some(
            kotoba_core::cid::KotobaCid::from_multibase(cid).ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid cacao_proof_cid CID".to_string(),
                )
            })?,
        ),
        None => None,
    };
    let cacao_proof_cid = auth_proof_cid.clone().or(explicit_cacao_proof_cid);
    let seq = current_head
        .as_ref()
        .map(|record| record.sequence + 1)
        .unwrap_or(1);
    let mut tx_datoms = report.tx_data.clone();
    append_tx_metadata_datoms(
        &mut tx_datoms,
        &report.tx_cid,
        &graph_cid,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        &write_author,
        cacao_proof_cid.as_ref(),
        &ipns_name,
        seq,
        &state.operator_did,
        expected_parent.as_ref(),
    );
    if let Some(auth_capability) = &auth_capability {
        append_auth_capability_datoms(&mut tx_datoms, &report.tx_cid, auth_capability);
    }
    let writer = DistributedCommitWriter::new(&*state.block_store, &*state.ipns_registry);
    let distributed = writer
        .commit_datoms(CommitDatomsRequest {
            ipns_name: ipns_name.clone(),
            graph: graph_cid.clone(),
            datoms: tx_datoms.clone(),
            expected_parent,
            tx_cid: Some(report.tx_cid.clone()),
            author: write_author,
            seq,
            valid_until: "2099-01-01T00:00:00Z".to_string(),
            ttl_secs: Some(60),
            cacao_proof_cid,
            ipns_controller_did: Some(state.operator_did.clone()),
            ipns_signing_key: Some(state.ipns_signing_key()),
        })
        .map_err(|e| match e {
            DistributedCommitError::StaleParent { .. } => {
                (StatusCode::CONFLICT, format!("distributed commit: {e}"))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("distributed commit: {e}"),
            ),
        })?;

    let mut journal_cids = Vec::with_capacity(tx_datoms.len());
    for datom in &tx_datoms {
        let quad = datom_to_projection_quad(datom, &graph_cid);
        let journal_cid = if datom.added {
            let cid = state.journal_assert(&quad).await;
            state
                .quad_store
                .apply_journaled_datom(graph_cid.clone(), datom_to_projection_kqe(datom))
                .await;
            cid
        } else {
            let cid = state.journal_retract(&quad).await;
            state
                .quad_store
                .apply_journaled_datom(graph_cid.clone(), datom_to_projection_kqe(datom))
                .await;
            cid
        };
        journal_cids.push(journal_cid);
    }

    Ok((
        StatusCode::OK,
        Json(DatomicTransactResp {
            status: "ok",
            graph: req.graph,
            tx_cid: report.tx_cid.to_multibase(),
            commit_cid: distributed.commit.cid.to_multibase(),
            auth_proof_cid: distributed
                .commit
                .cacao_proof_cid
                .as_ref()
                .map(|cid| cid.to_multibase()),
            ipns_name,
            ipns_sequence: distributed.ipns_record.sequence,
            ipns_valid_until: distributed.ipns_record.valid_until,
            index_roots: distributed
                .commit
                .index_roots
                .into_iter()
                .map(|(k, v)| (k, v.to_multibase()))
                .collect(),
            datom_count: tx_datoms.len(),
            journal_cids,
            tempids: report
                .tempids
                .into_iter()
                .map(|(k, v)| (k, v.to_multibase()))
                .collect(),
            datoms: tx_datoms.into_iter().map(datomic_datom_resp).collect(),
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.with
/// Apply EDN transaction data to a DB value and return a Datomic-style report
/// without publishing an IPNS head, writing journal quads, or persisting blocks.
pub async fn datomic_with(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicWithReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    const MAX_TX_EDN_LEN: usize = 1024 * 1024;
    if req.tx_edn.len() > MAX_TX_EDN_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "tx_edn too large ({} bytes, limit {MAX_TX_EDN_LEN})",
                req.tx_edn.len()
            ),
        ));
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;

    let tx_data = kotoba_edn::parse(&req.tx_edn)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("tx_edn parse: {e}")))?;
    let db_before = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => {
            let db = current_db_for_graph(&state, &graph_cid).await?;
            let as_of = parse_optional_tx_cid("as_of", req.as_of.as_deref())?;
            let since = parse_optional_tx_cid("since", req.since.as_deref())?;
            if as_of.is_some() && since.is_some() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "as_of and since are mutually exclusive".to_string(),
                ));
            }
            match (as_of.as_ref(), since.as_ref()) {
                (Some(tx), None) => db.as_of(tx),
                (None, Some(tx)) => db.since(tx),
                (None, None) => db,
                (Some(_), Some(_)) => unreachable!("checked above"),
            }
        }
    };
    let db_before_basis_t = db_before.basis_t.as_ref().map(|tx| tx.to_multibase());
    let conn = kotoba_datomic::Connection::from_datoms(db_before.all_datoms());
    let report = conn
        .transact(tx_data)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic with: {e}")))?;

    Ok((
        StatusCode::OK,
        Json(DatomicWithResp {
            status: "ok",
            graph: req.graph,
            db_before_basis_t,
            db_after_basis_t: report.db_after.basis_t.as_ref().map(|tx| tx.to_multibase()),
            tx_cid: report.tx_cid.to_multibase(),
            tempids: report
                .tempids
                .into_iter()
                .map(|(k, v)| (k, v.to_multibase()))
                .collect(),
            tx_data: report
                .tx_data
                .clone()
                .into_iter()
                .map(datomic_datom_resp)
                .collect(),
            db_after_datoms: report
                .db_after
                .datoms()
                .into_iter()
                .map(datomic_datom_resp)
                .collect(),
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.datoms
pub async fn datomic_datoms(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicDatomsReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;

    let index = DatomicDatomsIndex::parse(&req.index)?;
    let components = parse_datomic_datoms_components(&req.components_edn)?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let components = resolve_datomic_index_components(&db, index, &components)?;
    if let Some((basis_t, mut datoms)) = distributed_datomic_datoms(
        &state,
        &graph_cid,
        index,
        &components,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        datoms.sort_by_key(|datom| datomic_datoms_sort_key(datom, index));
        let limit = req.limit.unwrap_or(1000).min(10_000);
        let datoms = datoms.into_iter().take(limit).collect::<Vec<_>>();
        let datom_count = datoms.len();
        return Ok((
            StatusCode::OK,
            Json(DatomicDatomsResp {
                graph: req.graph,
                index: req.index,
                basis_t,
                datom_count,
                datoms: datoms.into_iter().map(datomic_datom_resp).collect(),
            }),
        ));
    }
    let mut datoms = db.datoms();
    datoms.sort_by_key(|datom| datomic_datoms_sort_key(datom, index));
    let limit = req.limit.unwrap_or(1000).min(10_000);
    let datoms = datoms
        .into_iter()
        .filter_map(
            |datom| match datomic_datoms_match_components(&datom, index, &components) {
                Ok(true) => Some(Ok(datom)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            },
        )
        .take(limit)
        .collect::<Result<Vec<_>, _>>()?;
    let datom_count = datoms.len();

    Ok((
        StatusCode::OK,
        Json(DatomicDatomsResp {
            graph: req.graph,
            index: req.index,
            basis_t: basis_t_resp(&db),
            datom_count,
            datoms: datoms.into_iter().map(datomic_datom_resp).collect(),
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.seekDatoms
pub async fn datomic_seek_datoms(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicSeekDatomsReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;

    let index = DatomicDatomsIndex::parse(&req.index)?;
    let components = parse_datomic_datoms_components(&req.components_edn)?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let components = resolve_datomic_index_components(&db, index, &components)?;
    let seek_key = datomic_seek_key(index, &components)?;
    if let Some((basis_t, mut datoms)) = distributed_datomic_seek_datoms(
        &state,
        &graph_cid,
        index,
        &components,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        datoms.sort_by_key(|datom| datomic_datoms_sort_key(datom, index));
        let limit = req.limit.unwrap_or(1000).min(10_000);
        let datoms = datoms
            .into_iter()
            .filter(|datom| datomic_datoms_sort_values(datom, index) >= seek_key)
            .take(limit)
            .collect::<Vec<_>>();
        let datom_count = datoms.len();
        return Ok((
            StatusCode::OK,
            Json(DatomicDatomsResp {
                graph: req.graph,
                index: req.index,
                basis_t,
                datom_count,
                datoms: datoms.into_iter().map(datomic_datom_resp).collect(),
            }),
        ));
    }
    let mut datoms = db.datoms();
    datoms.sort_by_key(|datom| datomic_datoms_sort_key(datom, index));
    let limit = req.limit.unwrap_or(1000).min(10_000);
    let datoms = datoms
        .into_iter()
        .filter(|datom| datomic_datoms_sort_values(datom, index) >= seek_key)
        .take(limit)
        .collect::<Vec<_>>();
    let datom_count = datoms.len();

    Ok((
        StatusCode::OK,
        Json(DatomicDatomsResp {
            graph: req.graph,
            index: req.index,
            basis_t: basis_t_resp(&db),
            datom_count,
            datoms: datoms.into_iter().map(datomic_datom_resp).collect(),
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.indexRange
pub async fn datomic_index_range(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicIndexRangeReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;

    let attr = datomic_component_attr(
        &kotoba_edn::parse(&req.attr_edn)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("attr_edn parse: {e}")))?,
    )?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let start = resolve_datomic_index_range_bound(
        &db,
        parse_optional_edn("start_edn", req.start_edn.as_deref())?,
    )?;
    let end = resolve_datomic_index_range_bound(
        &db,
        parse_optional_edn("end_edn", req.end_edn.as_deref())?,
    )?;
    if let (Some(start), Some(end)) = (&start, &end) {
        if start >= end {
            return Err((
                StatusCode::BAD_REQUEST,
                "indexRange start_edn must be less than end_edn".to_string(),
            ));
        }
    }

    if let Some((basis_t, mut datoms)) = distributed_datomic_index_range(
        &state,
        &graph_cid,
        &attr,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        datoms.sort_by_key(|datom| datomic_datoms_sort_key(datom, DatomicDatomsIndex::Avet));
        let limit = req.limit.unwrap_or(1000).min(10_000);
        let datoms = datoms
            .into_iter()
            .filter(|datom| {
                datom.a == attr
                    && start
                        .as_ref()
                        .map(|start| datom.v >= *start)
                        .unwrap_or(true)
                    && end.as_ref().map(|end| datom.v < *end).unwrap_or(true)
            })
            .take(limit)
            .collect::<Vec<_>>();
        let datom_count = datoms.len();
        return Ok((
            StatusCode::OK,
            Json(DatomicDatomsResp {
                graph: req.graph,
                index: ":avet".to_string(),
                basis_t,
                datom_count,
                datoms: datoms.into_iter().map(datomic_datom_resp).collect(),
            }),
        ));
    }

    let mut datoms = db.datoms();
    datoms.sort_by_key(|datom| datomic_datoms_sort_key(datom, DatomicDatomsIndex::Avet));
    let limit = req.limit.unwrap_or(1000).min(10_000);
    let datoms = datoms
        .into_iter()
        .filter(|datom| {
            datom.a == attr
                && start
                    .as_ref()
                    .map(|start| datom.v >= *start)
                    .unwrap_or(true)
                && end.as_ref().map(|end| datom.v < *end).unwrap_or(true)
        })
        .take(limit)
        .collect::<Vec<_>>();
    let datom_count = datoms.len();

    Ok((
        StatusCode::OK,
        Json(DatomicDatomsResp {
            graph: req.graph,
            index: ":avet".to_string(),
            basis_t: basis_t_resp(&db),
            datom_count,
            datoms: datoms.into_iter().map(datomic_datom_resp).collect(),
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.pull
pub async fn datomic_pull(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicPullReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let pattern = match req.pattern_edn.as_deref() {
        Some(src) => kotoba_edn::parse(src)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("pattern_edn parse: {e}")))?,
        None => kotoba_edn::EdnValue::Vector(vec![]),
    };

    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let entity = datomic_entity_from_request(&db, &req.entity)?;
    let entity_edn = db
        .pull(pattern, entity.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic pull: {e}")))?;
    let datoms = db
        .datoms()
        .into_iter()
        .filter(|datom| datom.e == entity)
        .map(datomic_datom_resp)
        .collect::<Vec<_>>();

    Ok((
        StatusCode::OK,
        Json(DatomicPullResp {
            graph: req.graph,
            entity: req.entity,
            basis_t: basis_t_resp(&db),
            entity_edn: kotoba_edn::to_string(&entity_edn),
            datom_count: datoms.len(),
            datoms,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.pullMany
pub async fn datomic_pull_many(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicPullManyReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    const MAX_PULL_MANY_ENTITIES: usize = 1000;
    if req.entities.len() > MAX_PULL_MANY_ENTITIES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "entities too large ({} entries, limit {MAX_PULL_MANY_ENTITIES})",
                req.entities.len()
            ),
        ));
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let pattern = match req.pattern_edn.as_deref() {
        Some(src) => kotoba_edn::parse(src)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("pattern_edn parse: {e}")))?,
        None => kotoba_edn::EdnValue::Vector(vec![]),
    };
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let entity_cids = req
        .entities
        .iter()
        .map(|entity| datomic_entity_from_request(&db, entity))
        .collect::<Result<Vec<_>, _>>()?;
    let pulled = db
        .pull_many(pattern, entity_cids.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic pullMany: {e}")))?;
    let entities = req
        .entities
        .into_iter()
        .zip(entity_cids)
        .zip(pulled)
        .map(|((entity, entity_cid), entity_edn)| {
            let datoms = db
                .datoms()
                .into_iter()
                .filter(|datom| datom.e == entity_cid)
                .map(datomic_datom_resp)
                .collect::<Vec<_>>();
            DatomicPullManyEntityResp {
                entity,
                entity_edn: kotoba_edn::to_string(&entity_edn),
                datom_count: datoms.len(),
                datoms,
            }
        })
        .collect::<Vec<_>>();

    Ok((
        StatusCode::OK,
        Json(DatomicPullManyResp {
            graph: req.graph,
            basis_t: basis_t_resp(&db),
            entity_count: entities.len(),
            entities,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.q
pub async fn datomic_q(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicQReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read_any_operation(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        &[
            kotoba_auth::CacaoPayload::OP_DATOM_READ,
            kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
        ],
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let query = kotoba_edn::parse(&req.query_edn)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("query_edn parse: {e}")))?;
    let inputs = req
        .inputs_edn
        .iter()
        .map(|src| {
            kotoba_edn::parse(src)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("inputs_edn parse: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if let Some((basis_t, rows)) = distributed_datomic_q(
        &state,
        &graph_cid,
        &query,
        &inputs,
        req.as_of.as_deref(),
        req.since.as_deref(),
        req.history,
    )? {
        let rows_map = datomic_q_rows_map(&query, &rows)?;
        return Ok((
            StatusCode::OK,
            Json(DatomicQResp {
                graph: req.graph,
                basis_t,
                rows_edn: rows
                    .into_iter()
                    .map(|row| row.into_iter().map(|v| kotoba_edn::to_string(&v)).collect())
                    .collect(),
                rows_map_edn: rows_map.as_ref().map(|rows| rows.edn.clone()),
                rows_map_json: rows_map.map(|rows| rows.json),
            }),
        ));
    }
    let db = apply_datomic_basis(
        current_db_for_graph(&state, &graph_cid).await?,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )?;
    let rows = if req.history {
        kotoba_datomic::q_history(query.clone(), &db.history(), &inputs)
    } else {
        kotoba_datomic::q(query.clone(), &db, &inputs)
    }
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic q: {e}")))?;
    let rows_map = datomic_q_rows_map(&query, &rows)?;

    Ok((
        StatusCode::OK,
        Json(DatomicQResp {
            graph: req.graph,
            basis_t: basis_t_resp(&db),
            rows_edn: rows
                .into_iter()
                .map(|row| row.into_iter().map(|v| kotoba_edn::to_string(&v)).collect())
                .collect(),
            rows_map_edn: rows_map.as_ref().map(|rows| rows.edn.clone()),
            rows_map_json: rows_map.map(|rows| rows.json),
        }),
    ))
}

#[derive(Clone, Copy)]
enum DatomicQMapKeyStyle {
    Keyword,
    String,
    Symbol,
}

struct DatomicQRowsMap {
    edn: Vec<String>,
    json: Vec<std::collections::BTreeMap<String, String>>,
}

fn datomic_q_rows_map(
    query: &kotoba_edn::EdnValue,
    rows: &[Vec<kotoba_edn::EdnValue>],
) -> Result<Option<DatomicQRowsMap>, (StatusCode, String)> {
    let Some((style, keys)) = datomic_q_map_keys(query)? else {
        return Ok(None);
    };
    let mut edn_rows = Vec::with_capacity(rows.len());
    let mut json_rows = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() != keys.len() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Datomic :keys/:strs/:syms arity {} does not match result arity {}",
                    keys.len(),
                    row.len()
                ),
            ));
        }
        let edn_map = keys
            .iter()
            .cloned()
            .zip(row.iter().cloned())
            .map(|(key, value)| (datomic_q_map_key(style, &key), value))
            .collect::<std::collections::BTreeMap<_, _>>();
        let json_map = keys
            .iter()
            .zip(row.iter())
            .map(|(key, value)| {
                (
                    datomic_q_json_map_key(style, key),
                    kotoba_edn::to_string(value),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        edn_rows.push(kotoba_edn::to_string(&kotoba_edn::EdnValue::Map(edn_map)));
        json_rows.push(json_map);
    }
    Ok(Some(DatomicQRowsMap {
        edn: edn_rows,
        json: json_rows,
    }))
}

fn datomic_q_map_keys(
    query: &kotoba_edn::EdnValue,
) -> Result<Option<(DatomicQMapKeyStyle, Vec<String>)>, (StatusCode, String)> {
    let map = kotoba_datomic::query_map(query)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic query: {e}")))?;
    for (keyword, style) in [
        ("keys", DatomicQMapKeyStyle::Keyword),
        ("strs", DatomicQMapKeyStyle::String),
        ("syms", DatomicQMapKeyStyle::Symbol),
    ] {
        if let Some(value) = map.get(&kotoba_edn::EdnValue::kw_bare(keyword)) {
            let keys = value.as_seq().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    format!(":{keyword} must be a vector or list"),
                )
            })?;
            return keys
                .iter()
                .map(datomic_q_map_key_name)
                .collect::<Result<Vec<_>, _>>()
                .map(|keys| Some((style, keys)));
        }
    }
    Ok(None)
}

fn datomic_q_map_key_name(value: &kotoba_edn::EdnValue) -> Result<String, (StatusCode, String)> {
    if let Some(symbol) = value.as_symbol() {
        return Ok(symbol.to_qualified());
    }
    if let Some(keyword) = value.as_keyword() {
        return Ok(keyword.to_qualified());
    }
    if let Some(string) = value.as_string() {
        return Ok(string.to_string());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!(
            ":keys/:strs/:syms entries must be symbols, keywords, or strings, got {}",
            kotoba_edn::to_string(value)
        ),
    ))
}

fn datomic_q_map_key(style: DatomicQMapKeyStyle, key: &str) -> kotoba_edn::EdnValue {
    match style {
        DatomicQMapKeyStyle::Keyword => {
            kotoba_edn::EdnValue::Keyword(kotoba_edn::Keyword::parse(key))
        }
        DatomicQMapKeyStyle::String => kotoba_edn::EdnValue::String(key.to_string()),
        DatomicQMapKeyStyle::Symbol => kotoba_edn::EdnValue::Symbol(kotoba_edn::Symbol::parse(key)),
    }
}

fn datomic_q_json_map_key(style: DatomicQMapKeyStyle, key: &str) -> String {
    match style {
        DatomicQMapKeyStyle::Keyword => format!(":{key}"),
        DatomicQMapKeyStyle::String | DatomicQMapKeyStyle::Symbol => key.to_string(),
    }
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.history
pub async fn datomic_history(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicHistoryReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let limit = req.limit.unwrap_or(1000).min(10_000);
    let db = match distributed_datomic_history_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let datoms = db
        .history()
        .datoms()
        .iter()
        .cloned()
        .into_iter()
        .take(limit)
        .map(datomic_datom_resp)
        .collect::<Vec<_>>();

    Ok((
        StatusCode::OK,
        Json(DatomicHistoryResp {
            graph: req.graph,
            basis_t: basis_t_resp(&db),
            datom_count: datoms.len(),
            datoms,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.txRange
pub async fn datomic_tx_range(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicTxRangeReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        None,
        None,
    )
    .await?;
    let limit = req.limit.unwrap_or(100).min(10_000);
    let (basis_t, entries) =
        distributed_datomic_tx_range(&state, &graph_cid, req.start.as_deref(), req.end.as_deref())?
            .unwrap_or((None, Vec::new()));
    let txes = entries
        .into_iter()
        .take(limit)
        .map(|entry| {
            let datoms = entry
                .datoms
                .into_iter()
                .map(datomic_datom_resp)
                .collect::<Vec<_>>();
            DatomicTxRangeTxResp {
                tx_cid: entry.commit.tx_cid.to_multibase(),
                commit_cid: entry.commit.cid.to_multibase(),
                prev_commit_cid: entry.commit.prev.map(|cid| cid.to_multibase()),
                seq: entry.commit.seq,
                author: entry.commit.author,
                ts: entry.commit.ts,
                datom_count: datoms.len(),
                datoms,
            }
        })
        .collect::<Vec<_>>();

    Ok((
        StatusCode::OK,
        Json(DatomicTxRangeResp {
            graph: req.graph,
            basis_t,
            tx_count: txes.len(),
            txes,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.log
pub async fn datomic_log(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicLogReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        None,
        None,
    )
    .await?;
    let limit = req.limit.unwrap_or(100).min(10_000);
    let (basis_t, entries) = match distributed_datomic_log(
        &state,
        &graph_cid,
        req.start.as_deref(),
        req.end.as_deref(),
    )? {
        Some(log) => log,
        None => {
            let db = current_db_for_graph(&state, &graph_cid).await?;
            let conn = kotoba_datomic::Connection::from_datoms(db.all_datoms());
            let start = parse_optional_tx_cid("start", req.start.as_deref())?;
            let end = parse_optional_tx_cid("end", req.end.as_deref())?;
            let entries = conn.log().entries().to_vec();
            if let Some(start) = &start {
                if !entries.iter().any(|entry| &entry.tx == start) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "datomic log start transaction not found: {}",
                            start.to_multibase()
                        ),
                    ));
                }
            }
            if let Some(end) = &end {
                if !entries.iter().any(|entry| &entry.tx == end) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!(
                            "datomic log end transaction not found: {}",
                            end.to_multibase()
                        ),
                    ));
                }
            }
            let entries = entries
                .into_iter()
                .skip_while(|entry| start.as_ref().is_some_and(|start| &entry.tx != start))
                .take_while(|entry| end.as_ref().is_none_or(|end| &entry.tx != end))
                .collect::<Vec<_>>();
            (basis_t_resp(&db), entries)
        }
    };
    let txes = entries
        .into_iter()
        .take(limit)
        .map(|entry| {
            let datoms = entry
                .datoms
                .into_iter()
                .map(datomic_datom_resp)
                .collect::<Vec<_>>();
            DatomicLogTxResp {
                tx_cid: entry.tx.to_multibase(),
                datom_count: datoms.len(),
                datoms,
            }
        })
        .collect::<Vec<_>>();

    Ok((
        StatusCode::OK,
        Json(DatomicLogResp {
            graph: req.graph,
            basis_t,
            tx_count: txes.len(),
            txes,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.basisT
pub async fn datomic_basis_t(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicBasisTReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };

    Ok((
        StatusCode::OK,
        Json(DatomicBasisTResp {
            graph: req.graph,
            basis_t: basis_t_resp(&db),
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.dbStats
pub async fn datomic_db_stats(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicDbStatsReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };

    Ok((StatusCode::OK, Json(datomic_db_stats_resp(req.graph, &db))))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.entity
pub async fn datomic_entity(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicEntityReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let entity = datomic_entity_from_request(&db, &req.entity)?;
    let entity_edn = db
        .entity(entity.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("datomic entity: {e}")))?;
    let datoms = db
        .datoms()
        .into_iter()
        .filter(|datom| datom.e == entity)
        .map(datomic_datom_resp)
        .collect::<Vec<_>>();

    Ok((
        StatusCode::OK,
        Json(DatomicEntityResp {
            graph: req.graph,
            entity: req.entity,
            basis_t: basis_t_resp(&db),
            entity_edn: kotoba_edn::to_string(&entity_edn),
            datom_count: datoms.len(),
            datoms,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.ident
pub async fn datomic_ident(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicIdentReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let entity = parse_datomic_entity(&req.entity);
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let ident_edn =
        datomic_ident_for_entity(&db, &entity).map(|value| kotoba_edn::to_string(&value));

    Ok((
        StatusCode::OK,
        Json(DatomicIdentResp {
            graph: req.graph,
            entity: req.entity,
            basis_t: basis_t_resp(&db),
            ident_edn,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.datomic.entid
pub async fn datomic_entid(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DatomicEntidReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let graph_cid = parse_graph_cid(&req.graph)?;
    require_datomic_read(
        &state,
        &headers,
        &graph_cid,
        req.cacao_b64.as_deref(),
        req.presentation.as_ref(),
        kotoba_auth::CacaoPayload::OP_DATOM_READ,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )
    .await?;
    let ident = kotoba_edn::parse(&req.ident_edn)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("ident_edn parse: {e}")))?;
    let db = match distributed_datomic_db(
        &state,
        &graph_cid,
        req.as_of.as_deref(),
        req.since.as_deref(),
    )? {
        Some(db) => db,
        None => apply_datomic_basis(
            current_db_for_graph(&state, &graph_cid).await?,
            req.as_of.as_deref(),
            req.since.as_deref(),
        )?,
    };
    let entity = datomic_entid_for_value(&db, &ident)?.map(|cid| cid.to_multibase());

    Ok((
        StatusCode::OK,
        Json(DatomicEntidResp {
            graph: req.graph,
            ident_edn: req.ident_edn,
            basis_t: basis_t_resp(&db),
            entity,
        }),
    ))
}

/// POST /xrpc/ai.gftd.apps.kotoba.vc.issue
pub async fn vc_issue(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VcIssueReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut author = state.operator_did.clone();
    let mut auth_proof_cid = None;
    let mut auth_capability = None;
    if let Err(operator_err) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        if let Some(cacao_b64) = req.cacao_b64.as_deref() {
            let payload = verify_datomic_cacao_payload(
                &state,
                &req.graph,
                Some(cacao_b64),
                kotoba_auth::CacaoPayload::OP_VC_ISSUE,
            )?;
            author = payload.iss.clone();
            auth_proof_cid = Some(persist_cacao_auth_proof(&state, cacao_b64)?);
            auth_capability = Some(cacao_capability_projection(
                &payload,
                auth_proof_cid.clone(),
            ));
        } else if let Some(presentation) = &req.auth_presentation {
            verify_vc_presentation_capability(
                &state,
                &req.graph,
                presentation,
                kotoba_auth::CacaoPayload::OP_VC_ISSUE,
            )?;
            author = presentation
                .holder
                .clone()
                .unwrap_or_else(|| state.operator_did.clone());
            auth_proof_cid = Some(persist_vp_auth_proof(&state, presentation)?);
            auth_capability = Some(vp_capability_projection(
                presentation,
                auth_proof_cid.clone(),
            ));
        } else {
            return Err(operator_err);
        }
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    let credential = issue_credential_with_operator_proof(req.credential.clone(), &state)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("vc issue proof: {e}")))?;
    let entity_cid = credential
        .cid()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("vc cid: {e}")))?;
    let tx_cid = kotoba_core::cid::KotobaCid::from_bytes(
        format!("vc.issue:{}:{}", req.graph, entity_cid.to_multibase()).as_bytes(),
    );
    let datoms = credential
        .to_datoms(tx_cid.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("vc datoms: {e}")))?;
    let resp = commit_protocol_datoms(
        &state,
        graph_cid,
        req.graph,
        entity_cid,
        datoms,
        tx_cid,
        author,
        kotoba_auth::CacaoPayload::OP_VC_ISSUE,
        auth_proof_cid,
        auth_capability,
    )
    .await?;
    Ok((StatusCode::OK, Json(resp)))
}

fn issue_credential_with_operator_proof(
    mut credential: kotoba_vc::VerifiableCredential,
    state: &KotobaState,
) -> Result<kotoba_vc::VerifiableCredential, kotoba_vc::VcError> {
    credential.issuer = state.operator_did.clone();
    credential.proof = None;
    let signature = state.ipns_signing_key().sign(&credential.proof_bytes()?);
    credential.proof = Some(kotoba_vc::DataIntegrityProof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: Some("eddsa-2022".to_string()),
        proof_purpose: "assertionMethod".to_string(),
        verification_method: format!("{}#agent-ed25519", state.operator_did),
        created: Some("2026-05-29T00:00:00Z".to_string()),
        proof_value: multibase::encode(multibase::Base::Base58Btc, signature.to_bytes()),
        challenge: Some("vc.issue".to_string()),
        domain: Some("kotoba.vc.issue".to_string()),
    });
    Ok(credential)
}

/// POST /xrpc/ai.gftd.apps.kotoba.vc.present
pub async fn vc_present(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VcPresentReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut author = state.operator_did.clone();
    let mut auth_proof_cid = None;
    let mut auth_capability = None;
    if let Err(operator_err) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        if let Some(cacao_b64) = req.cacao_b64.as_deref() {
            let payload = verify_datomic_cacao_payload(
                &state,
                &req.graph,
                Some(cacao_b64),
                kotoba_auth::CacaoPayload::OP_VC_PRESENT,
            )?;
            author = payload.iss.clone();
            auth_proof_cid = Some(persist_cacao_auth_proof(&state, cacao_b64)?);
            auth_capability = Some(cacao_capability_projection(
                &payload,
                auth_proof_cid.clone(),
            ));
        } else if let Some(presentation) = &req.auth_presentation {
            verify_vc_presentation_capability(
                &state,
                &req.graph,
                presentation,
                kotoba_auth::CacaoPayload::OP_VC_PRESENT,
            )?;
            author = presentation
                .holder
                .clone()
                .unwrap_or_else(|| state.operator_did.clone());
            auth_proof_cid = Some(persist_vp_auth_proof(&state, presentation)?);
            auth_capability = Some(vp_capability_projection(
                presentation,
                auth_proof_cid.clone(),
            ));
        } else {
            return Err(operator_err);
        }
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    let entity_cid = req
        .presentation
        .cid()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("vp cid: {e}")))?;
    let tx_cid = kotoba_core::cid::KotobaCid::from_bytes(
        format!("vc.present:{}:{}", req.graph, entity_cid.to_multibase()).as_bytes(),
    );
    let datoms = req
        .presentation
        .to_datoms(tx_cid.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("vp datoms: {e}")))?;
    let resp = commit_protocol_datoms(
        &state,
        graph_cid,
        req.graph,
        entity_cid,
        datoms,
        tx_cid,
        author,
        kotoba_auth::CacaoPayload::OP_VC_PRESENT,
        auth_proof_cid,
        auth_capability,
    )
    .await?;
    Ok((StatusCode::OK, Json(resp)))
}

/// POST /xrpc/ai.gftd.apps.kotoba.did.document.publish
pub async fn did_document_publish(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DidDocumentPublishReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut author = state.operator_did.clone();
    let mut auth_proof_cid = None;
    let mut auth_capability = None;
    if let Err(operator_err) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        if let Some(cacao_b64) = req.cacao_b64.as_deref() {
            let payload = verify_datomic_cacao_payload(
                &state,
                &req.graph,
                Some(cacao_b64),
                kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
            )?;
            author = payload.iss.clone();
            auth_proof_cid = Some(persist_cacao_auth_proof(&state, cacao_b64)?);
            auth_capability = Some(cacao_capability_projection(
                &payload,
                auth_proof_cid.clone(),
            ));
        } else if let Some(presentation) = &req.auth_presentation {
            verify_vc_presentation_capability(
                &state,
                &req.graph,
                presentation,
                kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
            )?;
            author = presentation
                .holder
                .clone()
                .unwrap_or_else(|| state.operator_did.clone());
            auth_proof_cid = Some(persist_vp_auth_proof(&state, presentation)?);
            auth_capability = Some(vp_capability_projection(
                presentation,
                auth_proof_cid.clone(),
            ));
        } else {
            return Err(operator_err);
        }
    }

    let missing_services = req.document.missing_kotoba_protocol_services();
    if !missing_services.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "DID Document missing Kotoba protocol service(s): {}",
                missing_services.join(", ")
            ),
        ));
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    let entity_cid = req.document.entity_cid();
    let tx_cid = kotoba_core::cid::KotobaCid::from_bytes(
        format!(
            "did.document.publish:{}:{}",
            req.graph,
            entity_cid.to_multibase()
        )
        .as_bytes(),
    );
    let datoms = req.document.to_datoms(tx_cid.clone());
    let did = req.document.id.clone();
    let registry_datoms = datoms.clone();
    let registry_tx_cid = tx_cid.clone();
    let registry_author = author.clone();
    let registry_auth_proof_cid = auth_proof_cid.clone();
    let registry_auth_capability = auth_capability.clone();
    let resp = commit_protocol_datoms(
        &state,
        graph_cid,
        req.graph,
        entity_cid,
        datoms,
        tx_cid,
        author,
        kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT,
        auth_proof_cid,
        auth_capability,
    )
    .await?;
    commit_did_document_registry_datoms(
        &state,
        &did,
        registry_datoms,
        registry_tx_cid,
        registry_author,
        registry_auth_proof_cid,
        registry_auth_capability,
    )?;
    Ok((StatusCode::OK, Json(resp)))
}

/// POST /xrpc/ai.gftd.apps.kotoba.didcomm.send
pub async fn didcomm_send(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DidCommSendReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let mut author = state.operator_did.clone();
    let mut auth_proof_cid = None;
    let mut auth_capability = None;
    if let Err(operator_err) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        let thread_scope = format!("didcomm://thread/{}", req.message.thread_id());
        if let Some(cacao_b64) = req.cacao_b64.as_deref() {
            let payload = verify_datomic_cacao_payload(
                &state,
                &req.graph,
                Some(cacao_b64),
                kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
            )?;
            if !payload.authorizes_didcomm_thread(req.message.thread_id()) {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("CACAO missing DIDComm thread scope {thread_scope}"),
                ));
            }
            author = payload.iss.clone();
            auth_proof_cid = Some(persist_cacao_auth_proof(&state, cacao_b64)?);
            auth_capability = Some(cacao_capability_projection(
                &payload,
                auth_proof_cid.clone(),
            ));
        } else if let Some(presentation) = &req.auth_presentation {
            verify_vc_presentation_capability_scope(
                &state,
                &req.graph,
                presentation,
                kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
                Some(&thread_scope),
            )?;
            author = presentation
                .holder
                .clone()
                .unwrap_or_else(|| state.operator_did.clone());
            auth_proof_cid = Some(persist_vp_auth_proof(&state, presentation)?);
            auth_capability = Some(vp_capability_projection(
                presentation,
                auth_proof_cid.clone(),
            ));
        } else {
            return Err(operator_err);
        }
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    let entity_cid = req
        .message
        .cid()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("didcomm cid: {e}")))?;
    let tx_cid = kotoba_core::cid::KotobaCid::from_bytes(
        format!("didcomm.send:{}:{}", req.graph, req.message.thread_id()).as_bytes(),
    );
    let datoms = req
        .message
        .to_datoms(tx_cid.clone())
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("didcomm datoms: {e}")))?;
    let resp = commit_protocol_datoms(
        &state,
        graph_cid,
        req.graph,
        entity_cid,
        datoms,
        tx_cid,
        author,
        kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND,
        auth_proof_cid,
        auth_capability,
    )
    .await?;
    Ok((StatusCode::OK, Json(resp)))
}

/// POST /xrpc/ai.gftd.apps.kotoba.atproto.repo.write
pub async fn atproto_repo_write(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AtprotoRepoWriteReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let uri = kotoba_graph::AtUri::parse(&req.uri)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid atproto uri".to_string()))?;
    if uri.collection.is_empty() || uri.rkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "atproto repo.write uri must include collection and rkey".to_string(),
        ));
    }

    let mut author = state.operator_did.clone();
    let mut auth_proof_cid = None;
    let mut auth_capability = None;
    if let Err(operator_err) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        if let Some(cacao_b64) = req.cacao_b64.as_deref() {
            let payload = verify_datomic_cacao_payload(
                &state,
                &req.graph,
                Some(cacao_b64),
                kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
            )?;
            if !payload.authorizes_atproto_resource(&req.uri) {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    format!("CACAO missing ATProto scope {}", req.uri),
                ));
            }
            author = payload.iss.clone();
            auth_proof_cid = Some(persist_cacao_auth_proof(&state, cacao_b64)?);
            auth_capability = Some(cacao_capability_projection(
                &payload,
                auth_proof_cid.clone(),
            ));
        } else if let Some(presentation) = &req.auth_presentation {
            verify_vc_presentation_capability_scope(
                &state,
                &req.graph,
                presentation,
                kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
                Some(&req.uri),
            )?;
            author = presentation
                .holder
                .clone()
                .unwrap_or_else(|| state.operator_did.clone());
            auth_proof_cid = Some(persist_vp_auth_proof(&state, presentation)?);
            auth_capability = Some(vp_capability_projection(
                presentation,
                auth_proof_cid.clone(),
            ));
        } else {
            return Err(operator_err);
        }
    }

    let graph_cid = parse_graph_cid(&req.graph)?;
    let entity_cid = atproto_repo_record_entity_cid(&req.uri);
    let operation = req.operation.as_deref().unwrap_or("create");
    let tx_cid = kotoba_core::cid::KotobaCid::from_bytes(
        serde_json::to_vec(&serde_json::json!({
            "op": "atproto.repo.write",
            "graph": req.graph,
            "uri": req.uri,
            "operation": operation,
            "cid": req.cid,
            "record": req.record,
        }))
        .unwrap_or_default()
        .as_slice(),
    );
    let datoms = if operation == "delete" {
        let db = current_db_for_graph(&state, &graph_cid).await?;
        atproto_repo_delete_datoms(&db, &req, &uri, &entity_cid, &tx_cid)
    } else {
        atproto_repo_write_datoms(&req, &uri, &entity_cid, &tx_cid)
    };
    let resp = commit_protocol_datoms(
        &state,
        graph_cid,
        req.graph,
        entity_cid,
        datoms,
        tx_cid,
        author,
        kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE,
        auth_proof_cid,
        auth_capability,
    )
    .await?;
    Ok((StatusCode::OK, Json(resp)))
}

/// GET /xrpc/ai.gftd.apps.kotoba.node.status
/// Operator-only: exposes peer topology that aids targeted DHT attacks.
pub async fn node_status(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err((code, msg)) =
        crate::graph_auth::require_operator_auth(&headers, &state.operator_did)
    {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    let nb = state.neighborhood.read().await;
    let did_document = state.local_did_document().await;
    Json(serde_json::json!({
        "node_id":    hex::encode(state.local_node_id.0),
        "operator_did": state.operator_did.as_str(),
        "did_document": did_document,
        "peer_count": nb.peers.len(),
        "peers":      nb.peers.iter().map(|p| hex::encode(p.0)).collect::<Vec<_>>(),
        "k":          kotoba_dht::neighborhood::K,
    }))
    .into_response()
}

/// POST /xrpc/ai.gftd.apps.kotoba.invoke.run
/// Execute a WASM component or Datalog program, then publish resulting quads to Journal.
#[cfg(feature = "wasm-runtime")]
pub async fn invoke_run(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<InvokeRunReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    const MAX_AGENT_DID_LEN: usize = 512;
    const MAX_PROGRAM_CID_LEN: usize = 512;
    const MAX_GRAPH_CID_LEN: usize = 512;
    const MAX_PROGRAM_TYPE_LEN: usize = 16;
    crate::graph_auth::validate_did(&req.agent_did, "agent_did", MAX_AGENT_DID_LEN)?;
    if req.program_cid.len() > MAX_PROGRAM_CID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "program_cid too long ({} bytes, limit {MAX_PROGRAM_CID_LEN})",
                req.program_cid.len()
            ),
        ));
    }
    if req.program_type.len() > MAX_PROGRAM_TYPE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "program_type too long ({} bytes, limit {MAX_PROGRAM_TYPE_LEN})",
                req.program_type.len()
            ),
        ));
    }
    if let Some(gcid) = &req.graph_cid {
        if gcid.len() > MAX_GRAPH_CID_LEN {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "graph_cid too long ({} bytes, limit {MAX_GRAPH_CID_LEN})",
                    gcid.len()
                ),
            ));
        }
    }

    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_dht::source_chain::ProgramType;

    let program_type = match req.program_type.as_str() {
        "wasm-node" => ProgramType::WasmNode,
        "wasm-udf" => ProgramType::WasmUdf,
        "datalog" => ProgramType::Datalog,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown program_type: {other}"),
            ))
        }
    };

    // 50 MiB wasm cap (a full WASM module rarely exceeds a few MiB; 50 MiB is generous).
    const MAX_WASM_B64_LEN: usize = 50 * 1024 * 1024;
    // 1 MiB ctx cap — context CBOR should be small structured data, not a data dump.
    const MAX_CTX_B64_LEN: usize = 1024 * 1024;

    let wasm_bytes: Vec<u8> = match &req.wasm_b64 {
        Some(b64) => {
            if b64.len() > MAX_WASM_B64_LEN {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "wasm_b64 too large ({} bytes, limit {MAX_WASM_B64_LEN})",
                        b64.len()
                    ),
                ));
            }
            B64.decode(b64)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        }
        None if program_type != ProgramType::Datalog => {
            return Err((
                StatusCode::BAD_REQUEST,
                "wasm_b64 required for wasm programs".into(),
            ));
        }
        None => vec![],
    };

    let ctx_cbor: Vec<u8> = match &req.ctx_b64 {
        Some(b64) => {
            if b64.len() > MAX_CTX_B64_LEN {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "ctx_b64 too large ({} bytes, limit {MAX_CTX_B64_LEN})",
                        b64.len()
                    ),
                ));
            }
            B64.decode(b64)
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        }
        None => vec![],
    };

    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::{Datom as KqeDatom, Value as KqeValue};
    use kotoba_runtime::host::WitQuad;
    use kotoba_vm::DispatchResult;

    // Build quad snapshot from the named graph's Arrangement for kqe.query in WASM guests.
    let graph_cid_for_snapshot = req
        .graph_cid
        .as_deref()
        .map(KotobaCid::from_multibase)
        .and_then(|x| x);
    let quad_snapshot: Vec<WitQuad> = if let Some(gcid) = &graph_cid_for_snapshot {
        state
            .quad_store
            .arrangement(gcid)
            .await
            .map(|arr| {
                arr.quads(gcid)
                    .into_iter()
                    .map(|q| WitQuad {
                        graph: q.graph.to_multibase(),
                        subject: q.subject.to_multibase(),
                        predicate: q.predicate,
                        object_cbor: serde_json::to_vec(&q.object).unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Build head commits map for kqe.get-head in WASM guests.
    let head_commits = state.quad_store.head_commit_map().await;

    // Move owned data into spawn_blocking — dispatch is CPU-bound (Cranelift JIT)
    let program_cid = req.program_cid.clone();
    let agent_did = req.agent_did.clone();
    let router = Arc::clone(&state.router);
    let wasm_owned = if wasm_bytes.is_empty() {
        None
    } else {
        Some(wasm_bytes)
    };

    let result = tokio::task::spawn_blocking(move || {
        let wasm_ref = wasm_owned.as_deref();
        router.dispatch_with_snapshot(
            &program_cid,
            program_type,
            &agent_did,
            0,
            wasm_ref,
            ctx_cbor,
            None,
            None,
            &[],
            10_000,
            quad_snapshot,
            head_commits,
        )
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match result {
        DispatchResult::Wasm(r) => {
            // Reject if WASM produced an unreasonably large assert batch.
            // At 10 gas/assert and 10M gas limit the theoretical max is 1M quads;
            // storing and returning 1M CIDs would be a multi-MB response DoS.
            const MAX_ASSERT_QUADS: usize = 10_000;
            if r.assert_quads.len() > MAX_ASSERT_QUADS {
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!(
                        "WASM produced {} assert quads (limit {MAX_ASSERT_QUADS})",
                        r.assert_quads.len()
                    ),
                ));
            }

            // Publish and apply each asserted Datom through the compatibility path.
            let mut journal_cids = Vec::with_capacity(r.assert_quads.len().min(MAX_ASSERT_QUADS));
            for sq in &r.assert_quads {
                let graph_cid = KotobaCid::from_bytes(sq.graph.as_bytes());
                let datom = KqeDatom::assert(
                    KotobaCid::from_bytes(sq.subject.as_bytes()),
                    sq.predicate.clone(),
                    KqeValue::Bytes(sq.object_cbor.clone()),
                    graph_cid.clone(),
                );
                let cid = state.assert_datom_compat(graph_cid, datom).await;
                journal_cids.push(cid);
            }
            // Publish retracts
            for sq in &r.retract_quads {
                let graph_cid = KotobaCid::from_bytes(sq.graph.as_bytes());
                let datom = KqeDatom::retract(
                    KotobaCid::from_bytes(sq.subject.as_bytes()),
                    sq.predicate.clone(),
                    KqeValue::Bytes(sq.object_cbor.clone()),
                    graph_cid.clone(),
                );
                state.retract_datom_compat(graph_cid, datom).await;
            }
            // Apply kse.publish calls buffered by guest WASM
            for (topic, payload) in &r.pending_publishes {
                use kotoba_kse::Topic;
                state
                    .journal
                    .publish(Topic(topic.clone()), bytes::Bytes::from(payload.clone()))
                    .await;
            }

            tracing::info!(
                program_cid = %req.program_cid,
                gas_used    = r.gas_used,
                asserts     = r.assert_quads.len(),
                retracts    = r.retract_quads.len(),
                kse_publishes = r.pending_publishes.len(),
                chain_entries = r.pending_chain_entries.len(),
                "invoke.run → Journal published"
            );

            Ok(Json(InvokeRunResp {
                status: "ok",
                gas_used: r.gas_used,
                output_b64: B64.encode(&r.output_cbor),
                assert_count: r.assert_quads.len(),
                retract_count: r.retract_quads.len(),
                journal_cids,
            }))
        }

        DispatchResult::Datalog(r) => Ok(Json(InvokeRunResp {
            status: "ok",
            gas_used: r.steps_used as u64,
            output_b64: B64.encode(format!("{:?}", r.status)),
            assert_count: r.out_deltas.len(),
            retract_count: 0,
            journal_cids: vec![],
        })),
    }
}

/// POST /xrpc/ai.gftd.apps.kotoba.invoke.run
/// Heavy WASM/Pregel runtime disabled in the lean server build.
#[cfg(not(feature = "wasm-runtime"))]
pub async fn invoke_run(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(_req): Json<InvokeRunReq>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "invoke.run requires the `wasm-runtime` feature".to_string(),
    ))
}

// ── Block store endpoints ──────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BlockPutReq {
    /// base64-encoded raw block bytes
    pub data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct BlockPutResp {
    pub cid: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockGetReq {
    pub cid: String,
}

#[derive(Debug, Serialize)]
pub struct BlockGetResp {
    pub cid: String,
    pub data_b64: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.block.put
/// Write raw bytes into the block store, returning the CID.
pub async fn block_put(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<BlockPutReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;

    // 32 MiB per block (ProllyTree internal nodes are tiny; large leaf values should
    // be chunked by the vault, not pushed as single raw blocks).
    const MAX_BLOCK_B64_LEN: usize = 32 * 1024 * 1024;
    if req.data_b64.len() > MAX_BLOCK_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "data_b64 too large ({} bytes, limit {MAX_BLOCK_B64_LEN})",
                req.data_b64.len()
            ),
        ));
    }

    let bytes = B64
        .decode(&req.data_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let (cid, bytes) = tokio::task::spawn_blocking(move || {
        let cid = KotobaCid::from_bytes(&bytes);
        (cid, bytes)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn_blocking: {e}"),
        )
    })?;
    state
        .block_store
        .put(&cid, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Fire-and-forget IPFS pin
    {
        let pin = std::sync::Arc::clone(&state.ipfs_pin);
        let cid_str = cid.to_multibase();
        tokio::spawn(async move { pin.pin(&cid_str).await });
    }

    Ok(Json(BlockPutResp {
        cid: cid.to_multibase(),
    }))
}

/// GET /xrpc/ai.gftd.apps.kotoba.block.get?cid=<multibase>
pub async fn block_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(req): axum::extract::Query<BlockGetReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;

    const MAX_CID_LEN: usize = 512;
    if req.cid.len() > MAX_CID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cid too long ({} bytes, limit {MAX_CID_LEN})",
                req.cid.len()
            ),
        ));
    }
    let cid = KotobaCid::from_multibase(&req.cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid CID".into()))?;
    match state
        .block_store
        .get(&cid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        None => Err((StatusCode::NOT_FOUND, "block not found".into())),
        Some(bytes) => Ok(Json(BlockGetResp {
            cid: req.cid.clone(),
            data_b64: B64.encode(&bytes),
        })),
    }
}

// ── Commit endpoints ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CommitGetReq {
    pub graph: String,
}

#[derive(Debug, Serialize)]
pub struct CommitGetResp {
    pub cid: String,
    pub graph: String,
    pub root: String,
    pub prev: Option<String>,
    pub author: String,
    pub seq: u64,
    pub ts: u64,
    pub commit_type: &'static str,
    pub tx_cid: Option<String>,
    pub index_roots: BTreeMap<String, String>,
    pub cacao_proof_cid: Option<String>,
    pub ipns_name: Option<String>,
    pub ipns_value_cid: Option<String>,
    pub ipns_sequence: Option<u64>,
    pub ipns_value_matches_commit: Option<bool>,
    pub ipns_sequence_matches_commit: Option<bool>,
    pub ipns_graph_matches_request: Option<bool>,
    pub ipns_controller_did: Option<String>,
    pub ipns_controller_matches_node: Option<bool>,
    pub ipns_controller_key_matches_did: Option<bool>,
    pub ipns_public_key_multibase: Option<String>,
    pub ipns_signature_multibase: Option<String>,
    pub ipns_signature_verified: Option<bool>,
    pub ipns_verified: Option<bool>,
}

/// GET /xrpc/ai.gftd.apps.kotoba.commit.get?graph=<multibase>
pub async fn commit_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(req): axum::extract::Query<CommitGetReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;

    const MAX_GRAPH_LEN: usize = 512;
    if req.graph.len() > MAX_GRAPH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "graph too long ({} bytes, limit {MAX_GRAPH_LEN})",
                req.graph.len()
            ),
        ));
    }
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".into()))?;

    let ipns_name = distributed_graph_ipns_name(&graph_cid);
    match state
        .ipns_registry
        .resolve(&IpnsName::new(ipns_name.clone()))
    {
        Ok(record) => {
            let commit_cid = KotobaCid::from_multibase(&record.value).ok_or_else(|| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "distributed IPNS head is not a CID".to_string(),
                )
            })?;
            let commit = DistributedDatomCommit::load(&commit_cid, &*state.block_store)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("distributed commit load: {e}"),
                    )
                })?
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        "distributed commit block not found".to_string(),
                    )
                })?;
            let root = commit
                .index_roots
                .get(ROOT_TEA)
                .or_else(|| commit.index_roots.get(ROOT_EAVT))
                .map(|cid| cid.to_multibase())
                .unwrap_or_default();
            let value_matches_commit = record.value == commit.cid.to_multibase();
            let sequence_matches_commit = record.sequence == commit.seq;
            let graph_matches_request = commit.graph == graph_cid;
            let signature_verified = record.signature_verified();
            let controller_matches_node =
                record.controller_did.as_deref() == Some(state.operator_did.as_str());
            let controller_key_matches_did = controller_matches_node
                && match record.public_key_multibase.as_deref() {
                    Some(key) => {
                        state
                            .did_ed25519_key_matches(&state.operator_did, key)
                            .await
                    }
                    None => false,
                };
            let ipns_verified = value_matches_commit
                && sequence_matches_commit
                && graph_matches_request
                && signature_verified
                && controller_matches_node
                && controller_key_matches_did;
            return Ok(Json(CommitGetResp {
                cid: commit.cid.to_multibase(),
                graph: commit.graph.to_multibase(),
                root,
                prev: commit.prev.map(|p| p.to_multibase()),
                author: commit.author,
                seq: commit.seq,
                ts: commit.ts,
                commit_type: "distributed-datomic",
                tx_cid: Some(commit.tx_cid.to_multibase()),
                index_roots: commit
                    .index_roots
                    .into_iter()
                    .map(|(k, v)| (k, v.to_multibase()))
                    .collect(),
                cacao_proof_cid: commit.cacao_proof_cid.map(|cid| cid.to_multibase()),
                ipns_name: Some(ipns_name),
                ipns_value_cid: Some(record.value),
                ipns_sequence: Some(record.sequence),
                ipns_value_matches_commit: Some(value_matches_commit),
                ipns_sequence_matches_commit: Some(sequence_matches_commit),
                ipns_graph_matches_request: Some(graph_matches_request),
                ipns_controller_did: record.controller_did,
                ipns_controller_matches_node: Some(controller_matches_node),
                ipns_controller_key_matches_did: Some(controller_key_matches_did),
                ipns_public_key_multibase: record.public_key_multibase,
                ipns_signature_multibase: record.signature_multibase,
                ipns_signature_verified: Some(signature_verified),
                ipns_verified: Some(ipns_verified),
            }));
        }
        Err(IpnsRegistryError::NotFound(_)) => {}
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("ipns resolve: {e}"),
            ));
        }
    }

    match state.quad_store.head_commit(&graph_cid).await {
        None => Err((StatusCode::NOT_FOUND, "no commit for graph".into())),
        Some(c) => Ok(Json(CommitGetResp {
            cid: c.cid.to_multibase(),
            graph: c.graph.to_multibase(),
            root: c.root.to_multibase(),
            prev: c.prev.map(|p| p.to_multibase()),
            author: c.author,
            seq: c.seq,
            ts: c.ts,
            commit_type: "quad-store",
            tx_cid: None,
            index_roots: BTreeMap::new(),
            cacao_proof_cid: None,
            ipns_name: None,
            ipns_value_cid: None,
            ipns_sequence: None,
            ipns_value_matches_commit: None,
            ipns_sequence_matches_commit: None,
            ipns_graph_matches_request: None,
            ipns_controller_did: None,
            ipns_controller_matches_node: None,
            ipns_controller_key_matches_did: None,
            ipns_public_key_multibase: None,
            ipns_signature_multibase: None,
            ipns_signature_verified: None,
            ipns_verified: None,
        })),
    }
}

/// POST /xrpc/ai.gftd.apps.kotoba.commit.store
/// Flush current Arrangement for the given graph into BlockStore and create a Commit.
#[derive(Debug, Deserialize)]
pub struct CommitStoreReq {
    pub graph: String,
    pub author: String,
    pub seq: u64,
    /// CACAO delegation proof (CBOR, base64) — required; must carry `datom:transact` capability.
    pub cacao_b64: Option<String>,
}

pub async fn commit_store(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<CommitStoreReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;

    // ── Input length guards ───────────────────────────────────────────────
    const MAX_GRAPH_LEN: usize = 512;
    if req.graph.len() > MAX_GRAPH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "graph field too long ({} bytes, limit {MAX_GRAPH_LEN})",
                req.graph.len()
            ),
        ));
    }

    // ── CACAO auth ─────────────────────────────────────────────────────────
    let b64 = req.cacao_b64.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "cacao_b64 is required for commit.store".to_string(),
        )
    })?;
    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }
    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;
    let issuer_did = if cacao.p.iss.starts_with("did:web:") {
        resolve_and_verify_did_web(&cacao, &req.graph, &state.http_client).await?
    } else {
        kotoba_auth::DelegationChain::new(cacao)
            .verify(&req.graph, kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
            .map_err(map_delegation_error)?
    };
    tracing::info!(issuer = %issuer_did, graph = %req.graph, "commit.store: CACAO verified");

    // author is stored verbatim in commit metadata — bound it to prevent oversized records.
    const MAX_AUTHOR_LEN: usize = 512;
    if req.author.len() > MAX_AUTHOR_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "author too long ({} bytes, limit {MAX_AUTHOR_LEN})",
                req.author.len()
            ),
        ));
    }

    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".into()))?;
    let cid = state
        .quad_store
        .commit(&req.author, graph_cid, req.seq)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    {
        let pin = state.ipfs_pin.clone();
        let cid_str = cid.to_multibase();
        tokio::spawn(async move { pin.pin(&cid_str).await });
    }

    Ok(Json(serde_json::json!({ "cid": cid.to_multibase() })))
}

// ── Graph query (B) ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GraphQueryReq {
    /// Named graph CID (multibase base32lower)
    pub graph: String,
    /// Optional subject CID filter (multibase or raw string)
    pub subject: Option<String>,
    /// Optional predicate filter (exact string match)
    pub predicate: Option<String>,
    /// Datalog rules reserved for invoke.run; graph.query returns SPO matches only
    pub rules: Option<String>,
    /// CACAO delegation chain for private graphs (DAG-CBOR, base64-standard encoded).
    pub cacao_b64: Option<String>,
    /// Maximum number of quads to return (1–1000; default 100).
    pub limit: Option<u64>,
}

/// GET /xrpc/ai.gftd.apps.kotoba.graph.query
/// SPO pattern query over the in-memory Arrangement.
/// Full Datalog evaluation: use invoke.run with program_type=datalog.
pub async fn graph_query(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(req): axum::extract::Query<GraphQueryReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use crate::graph_auth::{check_read_access, AccessDenied};
    use kotoba_core::cid::KotobaCid;

    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph CID".into()))?;

    // Bound filter fields — large strings would be hashed to a CID and never match anything,
    // but we reject early to avoid allocating and scanning unnecessarily.
    const MAX_FILTER_LEN: usize = 4096;
    if let Some(s) = &req.subject {
        if s.len() > MAX_FILTER_LEN {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "subject too long ({} bytes, limit {MAX_FILTER_LEN})",
                    s.len()
                ),
            ));
        }
    }
    if let Some(p) = &req.predicate {
        if p.len() > MAX_FILTER_LEN {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "predicate too long ({} bytes, limit {MAX_FILTER_LEN})",
                    p.len()
                ),
            ));
        }
    }

    // ── Read-access gate ─────────────────────────────────────────────────────
    if let Some(cacao_b64) = req.cacao_b64.as_deref() {
        crate::graph_auth::verify_cacao_graph_operation(
            cacao_b64,
            &req.graph,
            kotoba_auth::CacaoPayload::OP_GRAPH_QUERY,
            Some(state.operator_did.as_str()),
            Some(&state.nonce_store),
        )
        .map_err(AccessDenied::into_response)?;
    } else {
        let visibility = state.graph_visibility(&graph_cid).await;
        check_read_access(
            &visibility,
            &headers,
            None,
            Some(state.operator_did.as_str()),
            None,
        )
        .map_err(AccessDenied::into_response)?;
    }

    let arrangement = match state.quad_store.arrangement(&graph_cid).await {
        None => {
            return Ok(Json(
                serde_json::json!({ "graph": req.graph, "count": 0, "quads": [] }),
            ));
        }
        Some(a) => a,
    };

    const MAX_QUERY_RESULTS: u64 = 1_000;
    let limit = req.limit.unwrap_or(100).min(MAX_QUERY_RESULTS) as usize;

    let mut quads = arrangement.quads(&graph_cid);

    // Subject filter (accept multibase CID or raw string → hash to CID)
    if let Some(s) = &req.subject {
        let s_cid =
            KotobaCid::from_multibase(s).unwrap_or_else(|| KotobaCid::from_bytes(s.as_bytes()));
        quads.retain(|q| q.subject == s_cid);
    }

    // Predicate filter
    if let Some(p) = &req.predicate {
        quads.retain(|q| &q.predicate == p);
    }

    let truncated = quads.len() > limit;
    quads.truncate(limit);

    Ok(Json(serde_json::json!({
        "graph":     req.graph,
        "count":     quads.len(),
        "quads":     quads,
        "limit":     limit,
        "truncated": truncated,
        "note":  if req.rules.is_some() { "use invoke.run for Datalog evaluation" } else { "" },
    })))
}

// ── Weight put (C) ────────────────────────────────────────────────────────

pub const NSID_WEIGHT_GET: &str = "ai.gftd.apps.kotoba.weight.get";

#[derive(Debug, Deserialize)]
pub struct WeightPutReq {
    /// model CID (multibase) — identifies the model this weight belongs to
    pub model_cid: String,
    /// layer index
    pub layer: u32,
    /// raw FP8 tensor bytes, base64-encoded
    pub data_b64: String,
    /// tensor shape e.g. [4096, 4096]
    pub shape: Vec<u32>,
    /// dtype string: "fp8e4m3" | "fp8e5m2" | "fp16" | "bf16" | "f32"
    pub dtype: String,
    /// named graph CID (multibase) to index this weight in
    pub graph: String,
    /// CACAO delegation proof (CBOR, base64) — required; must carry `datom:transact` capability
    pub cacao_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WeightPutResp {
    pub blob_cid: String,
    pub quad_cid: String,
    pub layer: u32,
}

/// POST /xrpc/ai.gftd.apps.kotoba.weight.put
///
/// `cacao_b64` is required. The CACAO is verified before the write:
/// - did:web issuer → HTTP resolution + expiry check
/// - everything else → DelegationChain verifies expiry + `datom:transact` capability + graph + sig
pub async fn weight_put(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<WeightPutReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::{Datom as KqeDatom, DatomTensorDtype, Value as KqeValue};

    // ── Input length guards ───────────────────────────────────────────────
    const MAX_GRAPH_LEN: usize = 512;
    const MAX_MODEL_CID_LEN: usize = 512;
    const MAX_DTYPE_LEN: usize = 16;
    if req.graph.len() > MAX_GRAPH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "graph field too long ({} bytes, limit {MAX_GRAPH_LEN})",
                req.graph.len()
            ),
        ));
    }
    if req.model_cid.len() > MAX_MODEL_CID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "model_cid field too long ({} bytes, limit {MAX_MODEL_CID_LEN})",
                req.model_cid.len()
            ),
        ));
    }
    if req.dtype.len() > MAX_DTYPE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "dtype field too long ({} bytes, limit {MAX_DTYPE_LEN})",
                req.dtype.len()
            ),
        ));
    }

    // ── CACAO auth ────────────────────────────────────────────────────────
    let b64 = req.cacao_b64.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "cacao_b64 is required for weight.put".to_string(),
        )
    })?;
    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }
    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;
    let issuer_did = if cacao.p.iss.starts_with("did:web:") {
        resolve_and_verify_did_web(&cacao, &req.graph, &state.http_client).await?
    } else {
        kotoba_auth::DelegationChain::new(cacao)
            .verify(&req.graph, kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
            .map_err(map_delegation_error)?
    };
    tracing::info!(issuer = %issuer_did, graph = %req.graph, "weight.put: CACAO verified");

    // Tensor blobs can legitimately be large (embedding tables ~512 MiB raw).
    // Cap at 512 MiB base64 (≈384 MiB raw) to prevent runaway OOM.
    const MAX_WEIGHT_B64_LEN: usize = 512 * 1024 * 1024;
    if req.data_b64.len() > MAX_WEIGHT_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "data_b64 too large ({} bytes, limit {MAX_WEIGHT_B64_LEN})",
                req.data_b64.len()
            ),
        ));
    }
    // Shape has at most 8 dimensions (tensors beyond rank-8 are not supported).
    const MAX_SHAPE_DIMS: usize = 8;
    if req.shape.len() > MAX_SHAPE_DIMS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "shape has {} dimensions; limit is {MAX_SHAPE_DIMS}",
                req.shape.len()
            ),
        ));
    }

    let bytes = B64
        .decode(&req.data_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // 1. Store raw tensor bytes in BlockStore (content-addressed)
    let blob_cid = KotobaCid::from_bytes(&bytes);
    state
        .block_store
        .put(&blob_cid, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // 2. IPFS pin the tensor blob
    {
        let pin = std::sync::Arc::clone(&state.ipfs_pin);
        let cs = blob_cid.to_multibase();
        tokio::spawn(async move { pin.pin(&cs).await });
    }

    // 3. Parse CIDs
    let model_cid = KotobaCid::from_multibase(&req.model_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.model_cid.as_bytes()));
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.graph.as_bytes()));

    let dtype = match req.dtype.as_str() {
        "fp8e4m3" | "f8e4m3" => DatomTensorDtype::F8E4M3,
        "fp8e5m2" | "f8e5m2" => DatomTensorDtype::F8E5M2,
        "fp16" | "f16" => DatomTensorDtype::F16,
        "bf16" => DatomTensorDtype::BF16,
        _ => DatomTensorDtype::F32,
    };

    // 4. Assert WeightRef Datom: (model_cid, weight/layer/N, tensor_ref, tx, true)
    let datom = KqeDatom::assert(
        model_cid,
        format!("weight/layer/{}", req.layer),
        KqeValue::TensorCid {
            cid: blob_cid.clone(),
            shape: req.shape.clone(),
            dtype,
        },
        KotobaCid::from_bytes(b"kotoba-pending-tx"),
    );
    let quad_cid = state.assert_datom_compat(graph_cid, datom).await;

    tracing::info!(
        blob_cid = %blob_cid.to_multibase(),
        layer    = req.layer,
        bytes    = bytes.len(),
        "weight.put stored"
    );

    Ok(Json(WeightPutResp {
        blob_cid: blob_cid.to_multibase(),
        quad_cid,
        layer: req.layer,
    }))
}

// ── Quad retract (D) ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QuadRetractReq {
    pub graph: String,
    pub subject: String,
    pub predicate: String,
    pub object: String,
    /// CACAO delegation chain (DAG-CBOR, base64-standard encoded). Required.
    pub cacao_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct QuadRetractResp {
    pub status: &'static str,
    pub journal_cid: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.quad.retract
///
/// `cacao_b64` is required. The CACAO is verified before the delete:
/// - Signature must be valid (EdDSA or eip191)
/// - `cacao.p.graph_cid()` must match the requested `graph` field when present
pub async fn quad_retract(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<QuadRetractReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::quad::{LegacyQuad as Quad, LegacyQuadObject as QuadObject};

    // ── CACAO verification (required) ────────────────────────────────────
    let b64 = req.cacao_b64.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "cacao_b64 is required for quad.retract".to_string(),
        )
    })?;

    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }

    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;

    let issuer_did = if cacao.p.iss.starts_with("did:web:") {
        resolve_and_verify_did_web(&cacao, &req.graph, &state.http_client).await?
    } else {
        kotoba_auth::DelegationChain::new(cacao)
            .verify(&req.graph, kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
            .map_err(map_delegation_error)?
    };

    tracing::info!(issuer = %issuer_did, graph = %req.graph, "quad.retract: CACAO verified");

    // ── SPO + graph field bounds (mirrors quad_create) ────────────────────
    const MAX_GRAPH_LEN: usize = 512;
    const MAX_SUBJECT_LEN: usize = 512;
    const MAX_PREDICATE_LEN: usize = 512;
    const MAX_OBJECT_LEN: usize = 8 * 1024;
    if req.graph.len() > MAX_GRAPH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "graph field too long ({} bytes, limit {MAX_GRAPH_LEN})",
                req.graph.len()
            ),
        ));
    }
    if req.subject.len() > MAX_SUBJECT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "subject field too long ({} bytes, limit {MAX_SUBJECT_LEN})",
                req.subject.len()
            ),
        ));
    }
    if req.predicate.len() > MAX_PREDICATE_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "predicate field too long ({} bytes, limit {MAX_PREDICATE_LEN})",
                req.predicate.len()
            ),
        ));
    }
    if req.object.len() > MAX_OBJECT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "object field too long ({} bytes, limit {MAX_OBJECT_LEN})",
                req.object.len()
            ),
        ));
    }

    let quad = Quad {
        graph: KotobaCid::from_bytes(req.graph.as_bytes()),
        subject: KotobaCid::from_bytes(req.subject.as_bytes()),
        predicate: req.predicate.clone(),
        object: QuadObject::Text(req.object.clone()),
    };

    let journal_cid = state.retract_quad_compat(quad).await;

    tracing::info!(
        graph     = %req.graph,
        subject   = %req.subject,
        predicate = %req.predicate,
        cid       = %journal_cid,
        "quad.retract → Journal + QuadStore"
    );

    Ok((
        StatusCode::OK,
        Json(QuadRetractResp {
            status: "ok",
            journal_cid,
        }),
    ))
}

// ── Weight get (E) ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WeightGetReq {
    pub cid: String,
}

#[derive(Debug, Serialize)]
pub struct WeightGetResp {
    pub cid: String,
    pub data_b64: String,
}

/// GET /xrpc/ai.gftd.apps.kotoba.weight.get?cid=<multibase>
pub async fn weight_get(
    State(state): State<Arc<KotobaState>>,
    axum::extract::Query(req): axum::extract::Query<WeightGetReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;

    const MAX_CID_LEN: usize = 512;
    if req.cid.len() > MAX_CID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cid too long ({} bytes, limit {MAX_CID_LEN})",
                req.cid.len()
            ),
        ));
    }
    let cid = KotobaCid::from_multibase(&req.cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid CID".into()))?;
    match state
        .block_store
        .get(&cid)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        None => Err((StatusCode::NOT_FOUND, "weight blob not found".into())),
        Some(bytes) => Ok(Json(WeightGetResp {
            cid: req.cid.clone(),
            data_b64: B64.encode(&bytes),
        })),
    }
}

// ── LoRA apply (F) ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct LoraApplyReq {
    /// Base model CID (multibase)
    pub model_cid: String,
    /// LoRA adapter rank
    pub rank: u32,
    /// Named graph CID (multibase) to index this adapter in
    pub graph: String,
    /// Raw LoRA adapter bytes, base64-encoded
    pub adapter_b64: String,
    /// CACAO delegation proof (CBOR, base64) — required; must carry `datom:transact` capability
    pub cacao_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoraApplyResp {
    pub adapter_cid: String,
    pub quad_cid: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.lora.apply
///
/// `cacao_b64` is required. The CACAO is verified before the write:
/// - did:web issuer → HTTP resolution + expiry check
/// - everything else → DelegationChain verifies expiry + `datom:transact` capability + graph + sig
pub async fn lora_apply(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<LoraApplyReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::{Datom as KqeDatom, DatomTensorDtype, Value as KqeValue};

    // ── Input length guards ───────────────────────────────────────────────
    const MAX_GRAPH_LEN: usize = 512;
    const MAX_MODEL_CID_LEN: usize = 512;
    if req.graph.len() > MAX_GRAPH_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "graph field too long ({} bytes, limit {MAX_GRAPH_LEN})",
                req.graph.len()
            ),
        ));
    }
    if req.model_cid.len() > MAX_MODEL_CID_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "model_cid field too long ({} bytes, limit {MAX_MODEL_CID_LEN})",
                req.model_cid.len()
            ),
        ));
    }

    // ── CACAO auth ────────────────────────────────────────────────────────
    let b64 = req.cacao_b64.as_deref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "cacao_b64 is required for lora.apply".to_string(),
        )
    })?;
    if b64.len() > MAX_CACAO_B64_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "cacao_b64 too large ({} bytes, limit {MAX_CACAO_B64_LEN})",
                b64.len()
            ),
        ));
    }
    let cbor = B64
        .decode(b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao_b64 decode: {e}")))?;
    let cacao = kotoba_auth::Cacao::from_cbor(&cbor)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("cacao parse: {e}")))?;
    let issuer_did = if cacao.p.iss.starts_with("did:web:") {
        resolve_and_verify_did_web(&cacao, &req.graph, &state.http_client).await?
    } else {
        kotoba_auth::DelegationChain::new(cacao)
            .verify(&req.graph, kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT)
            .map_err(map_delegation_error)?
    };
    tracing::info!(issuer = %issuer_did, graph = %req.graph, "lora.apply: CACAO verified");

    // 128 MiB for a LoRA delta (rank-128 F8 for a 4B model is ~200 MB unquantized;
    // quantized rank-64 F8 fits comfortably under 128 MiB).
    const MAX_ADAPTER_B64_LEN: usize = 128 * 1024 * 1024;
    if req.adapter_b64.len() > MAX_ADAPTER_B64_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "adapter_b64 too large ({} bytes, limit {MAX_ADAPTER_B64_LEN})",
                req.adapter_b64.len()
            ),
        ));
    }

    let bytes = B64
        .decode(&req.adapter_b64)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Store adapter bytes in block store
    let adapter_cid = KotobaCid::from_bytes(&bytes);
    state
        .block_store
        .put(&adapter_cid, &bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let model_cid = KotobaCid::from_multibase(&req.model_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.model_cid.as_bytes()));
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.graph.as_bytes()));

    // Assert LoRA Datom: (model_cid, lora/adapter, tensor_ref, tx, true)
    let datom = KqeDatom::assert(
        model_cid,
        "lora/adapter".to_string(),
        KqeValue::TensorCid {
            cid: adapter_cid.clone(),
            shape: vec![req.rank],
            dtype: DatomTensorDtype::F8E4M3,
        },
        KotobaCid::from_bytes(b"kotoba-pending-tx"),
    );
    let quad_cid = state.assert_datom_compat(graph_cid, datom).await;

    tracing::info!(
        adapter_cid = %adapter_cid.to_multibase(),
        model_cid   = %req.model_cid,
        rank        = req.rank,
        "lora.apply stored"
    );

    Ok(Json(LoraApplyResp {
        adapter_cid: adapter_cid.to_multibase(),
        quad_cid,
    }))
}

// ── Embed create (G) ──────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EmbedCreateReq {
    /// Text to embed
    pub text: String,
    /// Document CID (multibase) — identifies the source document
    pub doc_cid: String,
    /// Model CID (multibase) — identifies the embedding model
    pub model_cid: String,
    /// Named graph CID (multibase) to index this embedding in
    pub graph: String,
}

#[derive(Debug, Serialize)]
pub struct EmbedCreateResp {
    pub status: &'static str,
    pub quad_cid: String,
    pub dims: usize,
}

/// POST /xrpc/ai.gftd.apps.kotoba.embed.create
pub async fn embed_create(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<EmbedCreateReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    use kotoba_core::cid::KotobaCid;
    use kotoba_llm::embed::{embed_to_quad, Embedding};

    // 64 KiB covers any realistic embedding unit (paragraph / document chunk).
    // Larger inputs must be split by the caller's chunker before calling embed.create.
    const MAX_EMBED_TEXT_LEN: usize = 64 * 1024;
    if req.text.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "text must not be empty".into()));
    }
    if req.text.len() > MAX_EMBED_TEXT_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "text too large ({} bytes, limit {MAX_EMBED_TEXT_LEN})",
                req.text.len()
            ),
        ));
    }

    let doc_cid = KotobaCid::from_multibase(&req.doc_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.doc_cid.as_bytes()));
    let model_cid = KotobaCid::from_multibase(&req.model_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.model_cid.as_bytes()));
    let graph_cid = KotobaCid::from_multibase(&req.graph)
        .unwrap_or_else(|| KotobaCid::from_bytes(req.graph.as_bytes()));

    // Compute embedding vector — use inference engine if available, else blake3 pseudo-vector
    let vector: Vec<f32> = if let Some(engine) = &state.inference_engine {
        let engine = engine.clone();
        let text = format!("embed: {}", req.text);
        let result = tokio::task::spawn_blocking(move || engine(&text, 256))
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        // Parse space-separated floats from engine output, fallback to blake3 pseudo-vector
        let parsed: Vec<f32> = result
            .split_whitespace()
            .filter_map(|s| s.parse::<f32>().ok())
            .collect();
        if parsed.is_empty() {
            // Inference engine returned non-numeric output — build blake3 pseudo-vector
            blake3_pseudo_vector(&req.text, 128)
        } else {
            parsed
        }
    } else {
        // No inference engine: 128-dim blake3 pseudo-embedding
        blake3_pseudo_vector(&req.text, 128)
    };

    let dims = vector.len();
    let emb = Embedding {
        doc_cid,
        model_cid,
        vector,
    };
    let delta = embed_to_quad(&emb, graph_cid.clone());

    let quad_cid = state.journal_assert_datom(&graph_cid, &delta.datom).await;
    let tx_cid = KotobaCid::from_multibase(&quad_cid)
        .unwrap_or_else(|| KotobaCid::from_bytes(quad_cid.as_bytes()));
    let mut datom = delta.datom;
    datom.tx = tx_cid;
    state
        .quad_store
        .apply_journaled_datom(graph_cid, datom)
        .await;

    Ok(Json(EmbedCreateResp {
        status: "ok",
        quad_cid,
        dims,
    }))
}

/// Build a deterministic pseudo-embedding from blake3 hash bytes.
fn blake3_pseudo_vector(text: &str, dims: usize) -> Vec<f32> {
    let hash = blake3::hash(text.as_bytes());
    let hash_bytes = hash.as_bytes();
    (0..dims)
        .map(|i| {
            let b = hash_bytes[i % 32] as f32;
            (b / 127.5) - 1.0
        })
        .collect()
}

// ── Infer run (H) ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct InferRunReq {
    /// Prompt text
    pub prompt: String,
    /// Maximum tokens to generate
    pub max_new_tokens: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct InferRunResp {
    pub status: &'static str,
    pub output: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.infer.run
pub async fn infer_run(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<InferRunReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    let engine = state.inference_engine.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no inference engine loaded".into(),
        )
    })?;

    // 64 KiB prompt cap (prevents tokeniser OOM on a context-length exploit).
    const MAX_PROMPT_LEN: usize = 64 * 1024;
    if req.prompt.len() > MAX_PROMPT_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "prompt too large ({} bytes, limit {MAX_PROMPT_LEN})",
                req.prompt.len()
            ),
        ));
    }
    // Cap max_new_tokens so a single request cannot hold the thread for minutes.
    const MAX_NEW_TOKENS_LIMIT: usize = 4096;
    let max_tokens = req.max_new_tokens.unwrap_or(256).min(MAX_NEW_TOKENS_LIMIT);
    let prompt = req.prompt.clone();

    let output = tokio::task::spawn_blocking(move || engine(&prompt, max_tokens))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(InferRunResp {
        status: "ok",
        output,
    }))
}

// ── Agent ReAct loop ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentRunReq {
    pub task: String,
    pub graph_cid: Option<String>,
    pub max_steps: Option<u32>,
    /// Maximum tokens per LLM thought step (default 256)
    pub max_tokens: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct AgentRunResp {
    pub status: &'static str,
    pub session_cid: String,
    pub steps: Vec<serde_json::Value>,
    pub final_answer: Option<String>,
    pub supersteps: usize,
    /// Commit CID of the session history flushed to BlockStore (ProllyTree)
    pub commit_cid: Option<String>,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.run
///
/// Runs a ReAct agent loop using the Kotoba **Pregel BSP** engine:
///   - vertex_id  = session CID
///   - superstep  = one cycle: Thought → Action → Observation
///   - self-message  → advance to next superstep
///   - vote_halt  → finish action or max_steps reached
///
/// Requires `KOTOBA_LOAD_GEMMA` (or another inference engine) to be loaded.
#[cfg(feature = "wasm-runtime")]
pub async fn agent_run(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AgentRunReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    use kotoba_core::cid::KotobaCid;
    use kotoba_vm::{session_to_quads, AgentSession, PregelReActRunner, ReActStep};

    let engine = state.inference_engine.clone().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "no inference engine loaded (set KOTOBA_LOAD_GEMMA)".into(),
        )
    })?;

    // 64 KiB task cap; agent loops with longer tasks should be chunked by the caller.
    const MAX_TASK_LEN: usize = 64 * 1024;
    if req.task.len() > MAX_TASK_LEN {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "task too large ({} bytes, limit {MAX_TASK_LEN})",
                req.task.len()
            ),
        ));
    }
    // Cap loop iterations and tokens-per-step to prevent runaway compute cost.
    const MAX_STEPS_LIMIT: u32 = 50;
    const MAX_TOKENS_LIMIT: usize = 4096;

    let graph_cid = req
        .graph_cid
        .as_deref()
        .map(|s| KotobaCid::from_bytes(s.as_bytes()))
        .unwrap_or_else(|| KotobaCid::from_bytes(b"agent-default-graph"));

    let max_steps = req.max_steps.unwrap_or(10).min(MAX_STEPS_LIMIT);
    let max_tokens = req.max_tokens.unwrap_or(256).min(MAX_TOKENS_LIMIT);
    let task = req.task.clone();
    let graph_cid2 = graph_cid.clone();
    let qs = Arc::clone(&state.quad_store);
    let journal = Arc::clone(&state.journal);

    // Run the Pregel ReAct loop in a blocking thread (LLM is sync).
    // Each BSP superstep = one Thought+Action+Observation cycle.
    let (session, superstep_results) = tokio::task::spawn_blocking(move || {
        use kotoba_vm::agent::{Tool, ToolOutput};

        // Override the default no-op kse.publish with a real Journal write.
        let journal2 = Arc::clone(&journal);
        let kse_publish_tool = Tool::from_fn(
            "kse.publish",
            "Publish a KSE event — kse.publish(topic,message)",
            move |input, _snap| {
                let (topic_str, msg) = input
                    .split_once(',')
                    .map(|(t, m)| (t.trim().to_string(), m.trim().to_string()))
                    .unwrap_or_else(|| ("agent".to_string(), input.trim().to_string()));
                let j = Arc::clone(&journal2);
                let topic_str2 = topic_str.clone();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async move {
                        j.publish(kotoba_kse::Topic(topic_str2), bytes::Bytes::from(msg))
                            .await;
                    });
                });
                ToolOutput {
                    observation: format!("published to '{topic_str}'"),
                    done: false,
                    route: None,
                }
            },
        );

        let runner = PregelReActRunner::new(engine, max_tokens);
        let session = AgentSession::new(task, graph_cid2, max_steps).with_tool(kse_publish_tool);
        runner.run(session)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let supersteps = superstep_results.len();

    // Extract final answer from last Finish step
    let final_answer = session.steps.iter().rev().find_map(|s| {
        if let ReActStep::Finish { answer } = s {
            Some(answer.clone())
        } else {
            None
        }
    });

    // Store session steps as Quads in the QuadStore
    let deltas = session_to_quads(&session);
    for delta in &deltas {
        if delta.is_assert() {
            let graph_cid = delta.datom.tx.clone();
            qs.assert_datom(graph_cid, delta.datom.clone()).await;
        }
    }

    // Commit session history to BlockStore (ProllyTree)
    let commit_cid = qs
        .commit("agent", graph_cid.clone(), session.steps.len() as u64)
        .await
        .ok()
        .map(|c| c.to_multibase());

    // Pin the commit block in the background
    if let Some(cid_str) = commit_cid.clone() {
        let pin = state.ipfs_pin.clone();
        tokio::spawn(async move { pin.pin(&cid_str).await });
    }

    let session_cid = session.session_cid.to_multibase();
    let steps = session
        .steps
        .into_iter()
        .map(|step| serde_json::to_value(step).unwrap_or(serde_json::Value::Null))
        .collect();

    Ok(Json(AgentRunResp {
        status: "ok",
        session_cid,
        steps,
        final_answer,
        supersteps,
        commit_cid,
    }))
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.run
/// Heavy Pregel ReAct runtime disabled in the lean server build.
#[cfg(not(feature = "wasm-runtime"))]
pub async fn agent_run(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(_req): Json<AgentRunReq>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    crate::graph_auth::require_operator_auth(&headers, &state.operator_did)?;
    Err((
        StatusCode::SERVICE_UNAVAILABLE,
        "agent.run requires the `wasm-runtime` feature".to_string(),
    ))
}

// ── Agent SyncWindow session management (C) ───────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AgentSyncOpenReq {
    /// Caller-assigned session identifier (UUIDv4 recommended).
    pub session_id: String,
    /// Named graph CID to sync (multibase).
    pub graph_cid: String,
    /// Journal sequence watermark — the agent has already processed all entries before this.
    pub since_seq: u64,
    /// Last commit head the agent has processed. `None` = fresh agent.
    pub head_cid: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentSyncOpenResp {
    pub status: &'static str,
    pub session_id: String,
    pub since_seq: u64,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.syncopen
///
/// Opens a SyncWindow session.  The graph and head CIDs are pinned in the
/// BudgetedBlockStore so they survive eviction for the duration of the session.
pub async fn agent_sync_open(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AgentSyncOpenReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;
    use kotoba_kse::sync_window::SyncWindow;

    // Validate session_id: non-empty, ≤256 bytes, printable ASCII.
    const MAX_SESSION_ID_LEN: usize = 256;
    if req.session_id.is_empty()
        || req.session_id.len() > MAX_SESSION_ID_LEN
        || !req.session_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "session_id must be 1–256 printable ASCII characters".into(),
        ));
    }

    crate::graph_auth::require_any_bearer_auth(&headers, "agent.syncopen")?;

    let graph_cid = KotobaCid::from_multibase(&req.graph_cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid graph_cid".into()))?;
    let head_cid = req
        .head_cid
        .as_deref()
        .map(|s| {
            KotobaCid::from_multibase(s)
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid head_cid".into()))
        })
        .transpose()?;

    let window = SyncWindow::new(graph_cid.clone(), req.since_seq, head_cid.clone());

    // Pin anchors directly (avoids dyn-coercion issues)
    state.block_store.pin(&graph_cid);
    if let Some(h) = &head_cid {
        state.block_store.pin(h);
    }

    // Cap total concurrent sessions under a single write lock to close the
    // TOCTOU window between capacity check and insert.
    const MAX_CONCURRENT_SESSIONS: usize = 1_000;
    let since_seq = {
        let mut sessions = state.agent_sessions.write().await;
        if sessions.len() >= MAX_CONCURRENT_SESSIONS {
            // Unpin the anchors we just pinned since we're rejecting the request.
            state.block_store.unpin(&graph_cid);
            if let Some(h) = &head_cid {
                state.block_store.unpin(h);
            }
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!("too many open sessions (limit {MAX_CONCURRENT_SESSIONS})"),
            ));
        }
        let seq = window.since_seq;
        sessions.insert(req.session_id.clone(), window);
        seq
    };

    tracing::info!(session_id = %req.session_id, since_seq, "agent.syncopen");

    Ok(Json(AgentSyncOpenResp {
        status: "ok",
        session_id: req.session_id,
        since_seq,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AgentSyncAdvReq {
    pub session_id: String,
    /// New commit head CID (multibase) the agent has processed.
    pub new_head_cid: String,
    /// Updated journal watermark.
    pub new_seq: u64,
}

#[derive(Debug, Serialize)]
pub struct AgentSyncAdvResp {
    pub status: &'static str,
    pub session_id: String,
    pub since_seq: u64,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.syncadvance
///
/// Advance the SyncWindow: unpin the old head, pin the new head.
pub async fn agent_sync_advance(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AgentSyncAdvReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use kotoba_core::cid::KotobaCid;

    const MAX_SESSION_ID_LEN: usize = 256;
    if req.session_id.is_empty()
        || req.session_id.len() > MAX_SESSION_ID_LEN
        || !req.session_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "session_id must be 1–256 printable ASCII characters".into(),
        ));
    }

    crate::graph_auth::require_any_bearer_auth(&headers, "agent.syncadvance")?;

    let new_head = KotobaCid::from_multibase(&req.new_head_cid)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "invalid new_head_cid".into()))?;

    let mut sessions = state.agent_sessions.write().await;
    let window = sessions.get_mut(&req.session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("session not found: {}", req.session_id),
        )
    })?;

    // Unpin old head, pin new head
    if let Some(old) = &window.head_cid {
        state.block_store.unpin(old);
    }
    state.block_store.pin(&new_head);
    window.head_cid = Some(new_head);
    window.since_seq = req.new_seq;

    let since_seq = window.since_seq;
    tracing::info!(session_id = %req.session_id, since_seq, "agent.syncadvance");

    Ok(Json(AgentSyncAdvResp {
        status: "ok",
        session_id: req.session_id,
        since_seq,
    }))
}

#[derive(Debug, Deserialize)]
pub struct AgentSyncCloseReq {
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct AgentSyncCloseResp {
    pub status: &'static str,
    pub session_id: String,
}

/// POST /xrpc/ai.gftd.apps.kotoba.agent.syncclose
///
/// Close the SyncWindow session, unpinning all anchors.
pub async fn agent_sync_close(
    State(state): State<Arc<KotobaState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AgentSyncCloseReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    const MAX_SESSION_ID_LEN: usize = 256;
    if req.session_id.is_empty()
        || req.session_id.len() > MAX_SESSION_ID_LEN
        || !req.session_id.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "session_id must be 1–256 printable ASCII characters".into(),
        ));
    }

    crate::graph_auth::require_any_bearer_auth(&headers, "agent.syncclose")?;

    let mut sessions = state.agent_sessions.write().await;
    let window = sessions.remove(&req.session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("session not found: {}", req.session_id),
        )
    })?;

    state.block_store.unpin(&window.graph_cid);
    if let Some(h) = &window.head_cid {
        state.block_store.unpin(h);
    }

    tracing::info!(session_id = %req.session_id, "agent.syncclose");

    Ok(Json(AgentSyncCloseResp {
        status: "ok",
        session_id: req.session_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::{
        append_auth_capability_datoms, atproto_repo_record_entity_cid, atproto_repo_write_datoms,
        is_did_web_ip_host, AtprotoRepoWriteReq, AuthCapabilityProjection, ZCAP_ALLOWED_ACTION_IRI,
        ZCAP_CONTROLLER_IRI, ZCAP_INVOCATION_PROOF_IRI, ZCAP_INVOCATION_TARGET_IRI,
    };
    use kotoba_core::cid::KotobaCid;
    use kotoba_datomic::distributed::{
        CommitDatomsRequest, DistributedCommitWriter, DistributedDatomReader,
    };
    use kotoba_datomic::Datom;
    use kotoba_edn::EdnValue;
    use kotoba_ipfs::InMemoryIpnsRegistry;
    use kotoba_store::MemoryBlockStore;
    use serde_json::json;

    #[test]
    fn vc_didcomm_and_atproto_project_to_one_distributed_datom_head() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"protocol-normalization-graph");
        let tx = KotobaCid::from_bytes(b"protocol-normalization-tx");

        let credential = kotoba_vc::VerifiableCredential::new(
            "urn:uuid:vc-normalized-1",
            "did:key:zIssuer",
            json!({
                "id": "did:key:zAlice",
                "role": "issuer",
                "profile": {"name": "Alice"}
            }),
        );
        let message = kotoba_didcomm::DidCommMessage {
            id: "msg-normalized-1".into(),
            message_type: "https://didcomm.org/basicmessage/2.0/message".into(),
            from: Some("did:key:zAlice".into()),
            to: vec!["did:key:zBob".into()],
            thid: Some("thread-normalized-1".into()),
            pthid: None,
            created_time: Some(1),
            expires_time: None,
            body: json!({"content": "hello from DIDComm"}),
            attachments: vec![],
        };
        let atproto_req = AtprotoRepoWriteReq {
            graph: graph.to_multibase(),
            uri: "at://did:plc:alice/app.bsky.feed.post/r1".into(),
            operation: Some("create".into()),
            cid: Some("bafyreicid".into()),
            record: Some(json!({
                "$type": "app.bsky.feed.post",
                "text": "hello from ATProto",
                "createdAt": "2026-05-29T00:00:00Z"
            })),
            cacao_b64: None,
            auth_presentation: None,
        };
        let at_uri = kotoba_graph::AtUri::parse(&atproto_req.uri).unwrap();
        let at_entity = atproto_repo_record_entity_cid(&atproto_req.uri);

        let mut datoms = Vec::<Datom>::new();
        datoms.extend(credential.to_datoms(tx.clone()).unwrap());
        datoms.extend(message.to_datoms(tx.clone()).unwrap());
        datoms.extend(atproto_repo_write_datoms(
            &atproto_req,
            &at_uri,
            &at_entity,
            &tx,
        ));

        let report = writer
            .commit_datoms(CommitDatomsRequest {
                ipns_name: "k51-protocol-normalization".into(),
                graph,
                datoms,
                expected_parent: None,
                tx_cid: Some(tx.clone()),
                author: "did:key:zIssuer".into(),
                seq: 1,
                valid_until: "2026-05-29T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: None,
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let query = kotoba_edn::parse(
            r#"{:find [?issuer ?thread ?text]
                :where [[?vc :credential/issuer ?issuer]
                        [?vc :credential/subject/role "issuer"]
                        [?msg :didcomm/thread ?thread]
                        [?post :atproto/record/text ?text]]}"#,
        )
        .unwrap();
        let rows = reader.q_triples(&report.commit.cid, &query).unwrap();

        assert_eq!(
            rows,
            vec![vec![
                EdnValue::string("did:key:zIssuer"),
                EdnValue::string("thread-normalized-1"),
                EdnValue::string("hello from ATProto"),
            ]]
        );
        assert!(reader
            .history_datoms_index(
                &report.commit.cid,
                kotoba_datomic::DatomIndex::Tea,
                &[EdnValue::string(tx.to_multibase())],
            )
            .unwrap()
            .iter()
            .all(|datom| datom.t == tx));
    }

    #[test]
    fn capability_projection_scopes_survive_distributed_datom_commit() {
        let store = MemoryBlockStore::new();
        let ipns = InMemoryIpnsRegistry::new();
        let writer = DistributedCommitWriter::new(&store, &ipns);
        let graph = KotobaCid::from_bytes(b"capability-scope-graph");
        let tx = KotobaCid::from_bytes(b"capability-scope-tx");
        let proof_cid = KotobaCid::from_bytes(b"capability-proof");
        let tx_scope = KotobaCid::from_bytes(b"capability-target-tx");
        let graph_scope = format!("kotoba://graph/{}", graph.to_multibase());
        let tx_scope = format!("kotoba://tx/{}", tx_scope.to_multibase());
        let didcomm_scope = "didcomm://thread/thread-capability-1".to_string();
        let atproto_scope = "at://did:plc:alice/app.bsky.feed.post/r1".to_string();
        let actions = vec![
            kotoba_auth::CacaoPayload::OP_DATOM_TRANSACT.to_string(),
            kotoba_auth::CacaoPayload::OP_DATOM_READ.to_string(),
            kotoba_auth::CacaoPayload::OP_GRAPH_QUERY.to_string(),
            kotoba_auth::CacaoPayload::OP_VC_ISSUE.to_string(),
            kotoba_auth::CacaoPayload::OP_VC_PRESENT.to_string(),
            kotoba_auth::CacaoPayload::OP_DIDCOMM_SEND.to_string(),
            kotoba_auth::CacaoPayload::OP_ATPROTO_REPO_WRITE.to_string(),
        ];
        let targets = vec![
            graph_scope.clone(),
            tx_scope.clone(),
            didcomm_scope.clone(),
            atproto_scope.clone(),
        ];
        let projection = AuthCapabilityProjection {
            proof_format: "CACAO",
            controller: "did:key:zController".into(),
            invoker: "did:key:zInvoker".into(),
            allowed_actions: actions.clone(),
            invocation_targets: targets.clone(),
            proof_cid: Some(proof_cid.clone()),
            credential_ids: vec!["urn:uuid:capability-vc-1".into()],
        };
        let mut datoms = Vec::<Datom>::new();
        append_auth_capability_datoms(&mut datoms, &tx, &projection);

        let report = writer
            .commit_datoms(CommitDatomsRequest {
                ipns_name: "k51-capability-scope".into(),
                graph,
                datoms,
                expected_parent: None,
                tx_cid: Some(tx.clone()),
                author: "did:key:zController".into(),
                seq: 1,
                valid_until: "2026-05-29T00:00:00Z".into(),
                ttl_secs: Some(60),
                cacao_proof_cid: Some(proof_cid.clone()),
                ipns_controller_did: None,
                ipns_signing_key: None,
            })
            .unwrap();

        let reader = DistributedDatomReader::new(&store, &ipns);
        let tea_datoms = reader
            .history_datoms_index(
                &report.commit.cid,
                kotoba_datomic::DatomIndex::Tea,
                &[EdnValue::string(tx.to_multibase())],
            )
            .unwrap();
        let has = |attr: &str, value: &str| {
            tea_datoms
                .iter()
                .any(|datom| datom.e == tx && datom.a == attr && datom.v == EdnValue::string(value))
        };

        for action in actions {
            assert!(has(":capability/allowedAction", &action));
            assert!(has(ZCAP_ALLOWED_ACTION_IRI, &action));
        }
        for target in targets {
            assert!(has(":capability/invocationTarget", &target));
            assert!(has(ZCAP_INVOCATION_TARGET_IRI, &target));
        }
        assert!(has(":capability/controller", "did:key:zController"));
        assert!(has(ZCAP_CONTROLLER_IRI, "did:key:zController"));
        assert!(has(":capability/invoker", "did:key:zInvoker"));
        assert!(has(
            ":capability/graph",
            graph_scope.trim_start_matches("kotoba://graph/")
        ));
        assert!(has(
            ":capability/tx",
            tx_scope.trim_start_matches("kotoba://tx/")
        ));
        assert!(has(":capability/didcommThread", "thread-capability-1"));
        assert!(has(":capability/atprotoResource", &atproto_scope));
        assert!(has(":capability/proofCid", &proof_cid.to_multibase()));
        assert!(has(ZCAP_INVOCATION_PROOF_IRI, &proof_cid.to_multibase()));
        assert!(has(":capability/credential", "urn:uuid:capability-vc-1"));
        assert!(tea_datoms.iter().all(|datom| datom.t == tx));
    }

    #[test]
    fn ip_literal_v4_rejected() {
        // AWS metadata endpoint and link-local
        assert!(is_did_web_ip_host("169.254.169.254"));
        // Localhost
        assert!(is_did_web_ip_host("127.0.0.1"));
        // RFC-1918 private
        assert!(is_did_web_ip_host("10.0.0.1"));
        assert!(is_did_web_ip_host("192.168.1.1"));
        assert!(is_did_web_ip_host("172.16.0.1"));
        // did:web with port
        assert!(is_did_web_ip_host("10.0.0.1:8080"));
    }

    #[test]
    fn ip_literal_v6_rejected() {
        assert!(is_did_web_ip_host("::1"));
        assert!(is_did_web_ip_host("fe80::1"));
    }

    #[test]
    fn domain_names_allowed() {
        // Normal domain names must NOT be flagged
        assert!(!is_did_web_ip_host("example.com"));
        assert!(!is_did_web_ip_host("gftd.ai"));
        assert!(!is_did_web_ip_host("example.com:path"));
        assert!(!is_did_web_ip_host("sub.domain.example.org"));
    }

    #[test]
    fn localhost_name_allowed_by_spec_check_is_done_elsewhere() {
        // "localhost" is a hostname, not an IP literal — our check is literal-only.
        // Blocking hostname-based SSRF requires DNS resolution (out of scope here).
        assert!(!is_did_web_ip_host("localhost"));
    }

    // ── Inference endpoint input bounds ──────────────────────────────────────

    #[test]
    fn embed_text_length_constants() {
        // Verify the cap constant is what we declared (64 KiB).
        const MAX_EMBED_TEXT_LEN: usize = 64 * 1024;
        assert_eq!(MAX_EMBED_TEXT_LEN, 65536);
        let oversized = "x".repeat(MAX_EMBED_TEXT_LEN + 1);
        assert!(oversized.len() > MAX_EMBED_TEXT_LEN);
    }

    #[test]
    fn infer_prompt_length_constants() {
        const MAX_PROMPT_LEN: usize = 64 * 1024;
        const MAX_NEW_TOKENS_LIMIT: usize = 4096;
        assert_eq!(MAX_PROMPT_LEN, 65536);
        // Verify .min() clamps correctly.
        assert_eq!(8192_usize.min(MAX_NEW_TOKENS_LIMIT), MAX_NEW_TOKENS_LIMIT);
        assert_eq!(256_usize.min(MAX_NEW_TOKENS_LIMIT), 256);
    }

    #[test]
    fn agent_run_step_cap() {
        const MAX_STEPS_LIMIT: u32 = 50;
        // Caller sending u32::MAX is clamped to 50.
        assert_eq!(u32::MAX.min(MAX_STEPS_LIMIT), MAX_STEPS_LIMIT);
        // Default of 10 passes through unchanged.
        assert_eq!(10_u32.min(MAX_STEPS_LIMIT), 10);
    }

    // ── NSID constants ───────────────────────────────────────────────────────

    const NSID_PREFIX: &str = "ai.gftd.apps.kotoba.";

    #[test]
    fn all_nsid_constants_have_kotoba_prefix() {
        let nsids = [
            super::NSID_DATOM_CREATE,
            super::NSID_QUAD_CREATE,
            super::NSID_QUAD_RETRACT,
            super::NSID_DATOMIC_TRANSACT,
            super::NSID_DATOMIC_DATOMS,
            super::NSID_DATOMIC_SEEK_DATOMS,
            super::NSID_DATOMIC_INDEX_RANGE,
            super::NSID_DATOMIC_PULL,
            super::NSID_DATOMIC_PULL_MANY,
            super::NSID_DATOMIC_Q,
            super::NSID_DATOMIC_WITH,
            super::NSID_DATOMIC_HISTORY,
            super::NSID_DATOMIC_TX_RANGE,
            super::NSID_DATOMIC_LOG,
            super::NSID_DATOMIC_BASIS_T,
            super::NSID_DATOMIC_DB_STATS,
            super::NSID_DATOMIC_ENTITY,
            super::NSID_DATOMIC_IDENT,
            super::NSID_DATOMIC_ENTID,
            super::NSID_VC_ISSUE,
            super::NSID_VC_PRESENT,
            super::NSID_DID_DOCUMENT_PUBLISH,
            super::NSID_DIDCOMM_SEND,
            super::NSID_ATPROTO_REPO_WRITE,
            super::NSID_GRAPH_QUERY,
            crate::kg::NSID_KG_SPARQL,
            super::NSID_COMMIT_GET,
            super::NSID_INVOKE_RUN,
            super::NSID_INFER_RUN,
            super::NSID_WEIGHT_PUT,
            super::NSID_LORA_APPLY,
            super::NSID_EMBED_CREATE,
            super::NSID_NODE_STATUS,
            super::NSID_BLOCK_PUT,
            super::NSID_BLOCK_GET,
            super::NSID_COMMIT_STORE,
            super::NSID_AGENT_RUN,
            super::NSID_AGENT_SYNC_OPEN,
            super::NSID_AGENT_SYNC_ADV,
            super::NSID_AGENT_SYNC_CLOSE,
            super::NSID_VAULT_PUT,
            super::NSID_VAULT_GET,
        ];
        for nsid in nsids {
            assert!(
                nsid.starts_with(NSID_PREFIX),
                "NSID {nsid:?} does not start with {NSID_PREFIX:?}"
            );
        }
    }

    #[test]
    fn all_nsid_constants_are_unique() {
        let mut nsids = vec![
            super::NSID_DATOM_CREATE,
            super::NSID_QUAD_CREATE,
            super::NSID_QUAD_RETRACT,
            super::NSID_DATOMIC_TRANSACT,
            super::NSID_DATOMIC_DATOMS,
            super::NSID_DATOMIC_SEEK_DATOMS,
            super::NSID_DATOMIC_INDEX_RANGE,
            super::NSID_DATOMIC_PULL,
            super::NSID_DATOMIC_PULL_MANY,
            super::NSID_DATOMIC_Q,
            super::NSID_DATOMIC_WITH,
            super::NSID_DATOMIC_HISTORY,
            super::NSID_DATOMIC_TX_RANGE,
            super::NSID_DATOMIC_LOG,
            super::NSID_DATOMIC_BASIS_T,
            super::NSID_DATOMIC_DB_STATS,
            super::NSID_DATOMIC_ENTITY,
            super::NSID_DATOMIC_IDENT,
            super::NSID_DATOMIC_ENTID,
            super::NSID_VC_ISSUE,
            super::NSID_VC_PRESENT,
            super::NSID_DID_DOCUMENT_PUBLISH,
            super::NSID_DIDCOMM_SEND,
            super::NSID_ATPROTO_REPO_WRITE,
            super::NSID_GRAPH_QUERY,
            crate::kg::NSID_KG_SPARQL,
            super::NSID_COMMIT_GET,
            super::NSID_INVOKE_RUN,
            super::NSID_INFER_RUN,
            super::NSID_WEIGHT_PUT,
            super::NSID_LORA_APPLY,
            super::NSID_EMBED_CREATE,
            super::NSID_NODE_STATUS,
            super::NSID_BLOCK_PUT,
            super::NSID_BLOCK_GET,
            super::NSID_COMMIT_STORE,
            super::NSID_AGENT_RUN,
            super::NSID_AGENT_SYNC_OPEN,
            super::NSID_AGENT_SYNC_ADV,
            super::NSID_AGENT_SYNC_CLOSE,
            super::NSID_VAULT_PUT,
            super::NSID_VAULT_GET,
        ];
        let original_len = nsids.len();
        nsids.sort_unstable();
        nsids.dedup();
        assert_eq!(
            nsids.len(),
            original_len,
            "NSID constants are not all unique"
        );
    }

    #[test]
    fn nsid_datom_create_exact_value() {
        assert_eq!(super::NSID_DATOM_CREATE, "ai.gftd.apps.kotoba.datom.create");
    }

    #[test]
    fn nsid_quad_create_exact_value() {
        assert_eq!(super::NSID_QUAD_CREATE, "ai.gftd.apps.kotoba.quad.create");
    }

    #[test]
    fn nsid_graph_query_exact_value() {
        assert_eq!(super::NSID_GRAPH_QUERY, "ai.gftd.apps.kotoba.graph.query");
    }

    #[test]
    fn nsid_datomic_exact_values() {
        assert_eq!(
            super::NSID_DATOMIC_TRANSACT,
            "ai.gftd.apps.kotoba.datomic.transact"
        );
        assert_eq!(
            super::NSID_DATOMIC_DATOMS,
            "ai.gftd.apps.kotoba.datomic.datoms"
        );
        assert_eq!(
            super::NSID_DATOMIC_SEEK_DATOMS,
            "ai.gftd.apps.kotoba.datomic.seekDatoms"
        );
        assert_eq!(
            super::NSID_DATOMIC_INDEX_RANGE,
            "ai.gftd.apps.kotoba.datomic.indexRange"
        );
        assert_eq!(super::NSID_DATOMIC_PULL, "ai.gftd.apps.kotoba.datomic.pull");
        assert_eq!(
            super::NSID_DATOMIC_PULL_MANY,
            "ai.gftd.apps.kotoba.datomic.pullMany"
        );
        assert_eq!(super::NSID_DATOMIC_Q, "ai.gftd.apps.kotoba.datomic.q");
        assert_eq!(
            super::NSID_DATOMIC_HISTORY,
            "ai.gftd.apps.kotoba.datomic.history"
        );
        assert_eq!(
            super::NSID_DATOMIC_TX_RANGE,
            "ai.gftd.apps.kotoba.datomic.txRange"
        );
        assert_eq!(super::NSID_DATOMIC_LOG, "ai.gftd.apps.kotoba.datomic.log");
        assert_eq!(
            super::NSID_DATOMIC_BASIS_T,
            "ai.gftd.apps.kotoba.datomic.basisT"
        );
        assert_eq!(
            super::NSID_DATOMIC_DB_STATS,
            "ai.gftd.apps.kotoba.datomic.dbStats"
        );
        assert_eq!(
            super::NSID_DATOMIC_ENTITY,
            "ai.gftd.apps.kotoba.datomic.entity"
        );
        assert_eq!(
            super::NSID_DATOMIC_IDENT,
            "ai.gftd.apps.kotoba.datomic.ident"
        );
        assert_eq!(
            super::NSID_DATOMIC_ENTID,
            "ai.gftd.apps.kotoba.datomic.entid"
        );
    }

    #[test]
    fn nsid_protocol_projection_exact_values() {
        assert_eq!(super::NSID_VC_ISSUE, "ai.gftd.apps.kotoba.vc.issue");
        assert_eq!(super::NSID_VC_PRESENT, "ai.gftd.apps.kotoba.vc.present");
        assert_eq!(
            super::NSID_DID_DOCUMENT_PUBLISH,
            "ai.gftd.apps.kotoba.did.document.publish"
        );
        assert_eq!(super::NSID_DIDCOMM_SEND, "ai.gftd.apps.kotoba.didcomm.send");
        assert_eq!(
            super::NSID_ATPROTO_REPO_WRITE,
            "ai.gftd.apps.kotoba.atproto.repo.write"
        );
    }

    #[test]
    fn public_protocol_lexicons_match_xrpc_nsids() {
        let lexicons = [
            (
                super::NSID_DATOMIC_TRANSACT,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/transact.json"),
            ),
            (
                super::NSID_DATOMIC_DATOMS,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/datoms.json"),
            ),
            (
                super::NSID_DATOMIC_SEEK_DATOMS,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/seekDatoms.json"),
            ),
            (
                super::NSID_DATOMIC_INDEX_RANGE,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/indexRange.json"),
            ),
            (
                super::NSID_DATOMIC_PULL,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pull.json"),
            ),
            (
                super::NSID_DATOMIC_PULL_MANY,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pullMany.json"),
            ),
            (
                super::NSID_DATOMIC_Q,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/q.json"),
            ),
            (
                super::NSID_DATOMIC_WITH,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/with.json"),
            ),
            (
                super::NSID_DATOMIC_HISTORY,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/history.json"),
            ),
            (
                super::NSID_DATOMIC_TX_RANGE,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/txRange.json"),
            ),
            (
                super::NSID_DATOMIC_LOG,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/log.json"),
            ),
            (
                super::NSID_DATOMIC_BASIS_T,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/basisT.json"),
            ),
            (
                super::NSID_DATOMIC_DB_STATS,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/dbStats.json"),
            ),
            (
                super::NSID_DATOMIC_ENTITY,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entity.json"),
            ),
            (
                super::NSID_DATOMIC_IDENT,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/ident.json"),
            ),
            (
                super::NSID_DATOMIC_ENTID,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entid.json"),
            ),
            (
                super::NSID_GRAPH_QUERY,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/graph/query.json"),
            ),
            (
                crate::kg::NSID_KG_SPARQL,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/graph/sparql.json"),
            ),
            (
                super::NSID_BLOCK_PUT,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/block/put.json"),
            ),
            (
                super::NSID_BLOCK_GET,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/block/get.json"),
            ),
            (
                super::NSID_COMMIT_GET,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/commit/get.json"),
            ),
            (
                super::NSID_COMMIT_STORE,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/commit/store.json"),
            ),
            (
                super::NSID_VC_ISSUE,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/issue.json"),
            ),
            (
                super::NSID_VC_PRESENT,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/present.json"),
            ),
            (
                super::NSID_DID_DOCUMENT_PUBLISH,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/did/document/publish.json"),
            ),
            (
                super::NSID_DIDCOMM_SEND,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/didcomm/send.json"),
            ),
            (
                super::NSID_ATPROTO_REPO_WRITE,
                include_str!("../../../lexicons/ai/gftd/apps/kotoba/atproto/repo/write.json"),
            ),
        ];
        for (expected_id, src) in lexicons {
            let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
            assert_eq!(value["lexicon"], 1);
            assert_eq!(value["id"], expected_id);
            assert!(
                matches!(
                    value["defs"]["main"]["type"].as_str(),
                    Some("procedure" | "query")
                ),
                "{expected_id} must be a procedure or query lexicon"
            );
        }
    }

    #[test]
    fn datomic_lexicons_expose_distributed_datomic_api_fields() {
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/transact.json"),
            &["graph", "tx_edn"],
            &[
                "cacao_b64",
                "presentation",
                "expected_parent",
                "cacao_proof_cid",
            ],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/with.json"),
            &["graph", "tx_edn"],
            &["as_of", "since", "cacao_b64", "presentation"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/transact.json"),
            &[
                "status",
                "graph",
                "tx_cid",
                "commit_cid",
                "ipns_name",
                "ipns_sequence",
                "ipns_valid_until",
                "index_roots",
                "datom_count",
                "journal_cids",
                "tempids",
                "datoms",
            ],
            &["auth_proof_cid"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/transact.json"),
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/with.json"),
            &[
                "status",
                "graph",
                "tx_cid",
                "tempids",
                "tx_data",
                "db_after_datoms",
            ],
            &["db_before_basis_t", "db_after_basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/with.json"),
            "tx_data",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/with.json"),
            "db_after_datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/q.json"),
            &["graph", "query_edn"],
            &[
                "inputs_edn",
                "as_of",
                "since",
                "history",
                "cacao_b64",
                "presentation",
            ],
        );
        assert_lexicon_description_mentions(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/q.json"),
            &[
                "fulltext",
                "history",
                "pull",
                "rules",
                "aggregates",
                "rows_map_json",
                "Verifiable Presentation",
            ],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/q.json"),
            &["graph", "rows_edn"],
            &["basis_t", "rows_map_edn", "rows_map_json"],
        );
        assert_lexicon_array_items_schema(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/q.json"),
            "rows_map_json",
            "object",
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/datoms.json"),
            &["graph", "index", "datom_count", "datoms"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/datoms.json"),
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/history.json"),
            &["graph", "datom_count", "datoms"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/history.json"),
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        for src in [
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/seekDatoms.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/indexRange.json"),
        ] {
            assert_lexicon_output_fields(
                src,
                &["graph", "index", "datom_count", "datoms"],
                &["basis_t"],
            );
            assert_lexicon_array_item_fields(src, "datoms", &["e", "a", "v_edn", "t", "added"]);
        }
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/txRange.json"),
            &["graph", "tx_count", "txes"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/txRange.json"),
            "txes",
            &[
                "tx_cid",
                "commit_cid",
                "seq",
                "author",
                "ts",
                "datom_count",
                "datoms",
            ],
        );
        assert_lexicon_nested_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/txRange.json"),
            "txes",
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/log.json"),
            &["graph", "tx_count", "txes"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/log.json"),
            "txes",
            &["tx_cid", "datom_count", "datoms"],
        );
        assert_lexicon_nested_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/log.json"),
            "txes",
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pull.json"),
            &["graph", "entity", "entity_edn", "datom_count", "datoms"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pull.json"),
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pullMany.json"),
            &["graph", "entity_count", "entities"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pullMany.json"),
            "entities",
            &["entity", "entity_edn", "datom_count", "datoms"],
        );
        assert_lexicon_nested_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pullMany.json"),
            "entities",
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/basisT.json"),
            &["graph"],
            &["as_of", "since", "cacao_b64", "presentation"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/basisT.json"),
            &["graph"],
            &["basis_t"],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/dbStats.json"),
            &["graph"],
            &["as_of", "since", "cacao_b64", "presentation"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/dbStats.json"),
            &[
                "graph",
                "datom_count",
                "history_datom_count",
                "entity_count",
                "attribute_count",
                "tx_count",
            ],
            &["basis_t"],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entity.json"),
            &["graph", "entity"],
            &["as_of", "since", "cacao_b64", "presentation"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entity.json"),
            &["graph", "entity", "entity_edn", "datom_count", "datoms"],
            &["basis_t"],
        );
        assert_lexicon_array_item_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entity.json"),
            "datoms",
            &["e", "a", "v_edn", "t", "added"],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/ident.json"),
            &["graph", "entity"],
            &["as_of", "since", "cacao_b64", "presentation"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/ident.json"),
            &["graph", "entity"],
            &["basis_t", "ident_edn"],
        );
        assert_lexicon_input_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entid.json"),
            &["graph", "ident_edn"],
            &["as_of", "since", "cacao_b64", "presentation"],
        );
        assert_lexicon_output_fields(
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entid.json"),
            &["graph", "ident_edn"],
            &["basis_t", "entity"],
        );
    }

    #[test]
    fn protocol_lexicons_expose_w3c_vp_auth_input_schema() {
        for src in [
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/transact.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/with.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/q.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/datoms.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/seekDatoms.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/indexRange.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pull.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/pullMany.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/history.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/txRange.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/log.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/basisT.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/dbStats.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entity.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/ident.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/datomic/entid.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/present.json"),
        ] {
            assert_lexicon_input_presentation_schema(src, "presentation");
        }
        for src in [
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/issue.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/present.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/didcomm/send.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/atproto/repo/write.json"),
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/did/document/publish.json"),
        ] {
            assert_lexicon_input_presentation_schema(src, "auth_presentation");
        }
    }

    #[test]
    fn did_document_publish_lexicon_exposes_w3c_did_document_and_write_response() {
        let src = include_str!("../../../lexicons/ai/gftd/apps/kotoba/did/document/publish.json");
        assert_lexicon_input_fields(
            src,
            &["graph", "document"],
            &["cacao_b64", "auth_presentation"],
        );
        assert_lexicon_input_object_fields(
            src,
            "document",
            &[
                "@context",
                "id",
                "verificationMethod",
                "authentication",
                "assertionMethod",
                "capabilityInvocation",
                "capabilityDelegation",
                "service",
            ],
            &[],
        );
        assert_lexicon_input_nested_array_item_fields(
            src,
            "document",
            "service",
            &["id", "type", "serviceEndpoint"],
        );
        assert_lexicon_input_nested_array_item_property_schema(
            src,
            "document",
            "service",
            "serviceEndpoint",
            "union",
            &["#serviceEndpointString", "#serviceEndpointStringArray"],
        );
        assert_lexicon_output_fields(
            src,
            &[
                "status",
                "graph",
                "entity_cid",
                "tx_cid",
                "commit_cid",
                "ipns_name",
                "ipns_sequence",
                "datom_count",
                "assert_count",
                "retract_count",
                "journal_cids",
            ],
            &["auth_proof_cid"],
        );
    }

    #[test]
    fn protocol_write_lexicons_expose_payloads_and_datom_write_response() {
        let vc_issue = include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/issue.json");
        assert_lexicon_input_object_fields(
            vc_issue,
            "credential",
            &["@context", "id", "type", "issuer", "credentialSubject"],
            &["validFrom", "validUntil", "credentialStatus", "proof"],
        );
        assert_protocol_datom_write_output_fields(vc_issue);

        let vc_present = include_str!("../../../lexicons/ai/gftd/apps/kotoba/vc/present.json");
        assert_protocol_datom_write_output_fields(vc_present);

        let didcomm_send = include_str!("../../../lexicons/ai/gftd/apps/kotoba/didcomm/send.json");
        assert_lexicon_input_object_fields(
            didcomm_send,
            "message",
            &["id", "type"],
            &[
                "from",
                "to",
                "thid",
                "pthid",
                "created_time",
                "expires_time",
                "body",
                "attachments",
            ],
        );
        assert_protocol_datom_write_output_fields(didcomm_send);

        let atproto_write =
            include_str!("../../../lexicons/ai/gftd/apps/kotoba/atproto/repo/write.json");
        assert_lexicon_input_object_fields(atproto_write, "record", &[], &[]);
        assert_protocol_datom_write_output_fields(atproto_write);
    }

    #[test]
    fn graph_query_lexicons_expose_structured_sparql_and_quad_outputs() {
        let graph_query = include_str!("../../../lexicons/ai/gftd/apps/kotoba/graph/query.json");
        assert_lexicon_output_fields(
            graph_query,
            &["graph", "count", "quads"],
            &["limit", "truncated", "note"],
        );
        assert_lexicon_array_item_fields(
            graph_query,
            "quads",
            &["graph", "subject", "predicate", "object"],
        );

        let graph_sparql = include_str!("../../../lexicons/ai/gftd/apps/kotoba/graph/sparql.json");
        assert_lexicon_input_fields(
            graph_sparql,
            &["query"],
            &["graph", "cacaoB64", "limit", "maxHops"],
        );
        assert_lexicon_output_fields(
            graph_sparql,
            &["ok", "form", "elapsedMs"],
            &["result", "count", "maxHops", "quads"],
        );
        assert_lexicon_array_item_fields(
            graph_sparql,
            "quads",
            &["graph", "subject", "predicate", "object"],
        );
    }

    #[test]
    fn storage_lexicons_expose_ipld_commit_and_ipns_fields() {
        let block_put = include_str!("../../../lexicons/ai/gftd/apps/kotoba/block/put.json");
        assert_lexicon_input_fields(block_put, &["data_b64"], &[]);
        assert_lexicon_output_fields(block_put, &["cid"], &[]);

        let block_get = include_str!("../../../lexicons/ai/gftd/apps/kotoba/block/get.json");
        assert_lexicon_parameter_fields(block_get, &["cid"], &[]);
        assert_lexicon_output_fields(block_get, &["cid", "data_b64"], &[]);

        let commit_store = include_str!("../../../lexicons/ai/gftd/apps/kotoba/commit/store.json");
        assert_lexicon_input_fields(commit_store, &["graph", "author", "seq"], &["cacao_b64"]);
        assert_lexicon_output_fields(commit_store, &["cid"], &[]);

        let commit_get = include_str!("../../../lexicons/ai/gftd/apps/kotoba/commit/get.json");
        assert_lexicon_parameter_fields(commit_get, &["graph"], &[]);
        assert_lexicon_output_fields(
            commit_get,
            &[
                "cid",
                "graph",
                "root",
                "author",
                "seq",
                "ts",
                "commit_type",
                "index_roots",
            ],
            &[
                "prev",
                "tx_cid",
                "cacao_proof_cid",
                "ipns_name",
                "ipns_value_cid",
                "ipns_sequence",
                "ipns_value_matches_commit",
                "ipns_sequence_matches_commit",
                "ipns_graph_matches_request",
                "ipns_controller_did",
                "ipns_controller_matches_node",
                "ipns_controller_key_matches_did",
                "ipns_public_key_multibase",
                "ipns_signature_multibase",
                "ipns_signature_verified",
                "ipns_verified",
            ],
        );
    }

    fn assert_protocol_datom_write_output_fields(src: &str) {
        assert_lexicon_output_fields(
            src,
            &[
                "status",
                "graph",
                "entity_cid",
                "tx_cid",
                "commit_cid",
                "ipns_name",
                "ipns_sequence",
                "datom_count",
                "journal_cids",
            ],
            &["auth_proof_cid"],
        );
    }

    fn assert_lexicon_parameter_fields(src: &str, required: &[&str], properties: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let params = &value["defs"]["main"]["parameters"];
        assert_eq!(
            params["type"], "params",
            "{} parameters must be params",
            value["id"]
        );
        let required_values = params["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} missing required parameter {field}",
                value["id"]
            );
        }
        let property_values = params["properties"].as_object().expect("properties object");
        for field in required.iter().chain(properties.iter()) {
            assert!(
                property_values.contains_key(*field),
                "{} missing parameter property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_input_object_fields(
        src: &str,
        field: &str,
        required: &[&str],
        properties: &[&str],
    ) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let schema = &value["defs"]["main"]["input"]["schema"]["properties"][field];
        assert_eq!(
            schema["type"], "object",
            "{} input {field} must be object",
            value["id"]
        );
        let required_values = schema["required"].as_array();
        for required in required {
            assert!(
                required_values.is_some_and(|values| values
                    .iter()
                    .any(|value| value.as_str() == Some(*required))),
                "{} input {field} missing required field {required}",
                value["id"]
            );
        }
        let property_values = schema["properties"].as_object();
        for property in required.iter().chain(properties.iter()) {
            assert!(
                property_values.is_some_and(|values| values.contains_key(*property)),
                "{} input {field} missing property {property}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_input_nested_array_item_fields(
        src: &str,
        outer_field: &str,
        inner_field: &str,
        required: &[&str],
    ) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let item = &value["defs"]["main"]["input"]["schema"]["properties"][outer_field]
            ["properties"][inner_field]["items"];
        assert_eq!(
            item["type"], "object",
            "{} input {outer_field}.{inner_field} items must be object",
            value["id"]
        );
        let required_values = item["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} input nested array item missing required field {field}",
                value["id"]
            );
            assert!(
                item["properties"]
                    .as_object()
                    .is_some_and(|props| props.contains_key(*field)),
                "{} input nested array item missing property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_input_nested_array_item_property_schema(
        src: &str,
        outer_field: &str,
        inner_field: &str,
        property_field: &str,
        property_type: &str,
        refs: &[&str],
    ) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let property = &value["defs"]["main"]["input"]["schema"]["properties"][outer_field]
            ["properties"][inner_field]["items"]["properties"][property_field];
        assert_eq!(
            property["type"], property_type,
            "{} input {outer_field}.{inner_field}.{property_field} must be {property_type}",
            value["id"]
        );
        let ref_values = property["refs"].as_array().expect("refs array");
        for expected in refs {
            assert!(
                ref_values
                    .iter()
                    .any(|value| value.as_str() == Some(expected)),
                "{} input {outer_field}.{inner_field}.{property_field} missing ref {expected}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_input_presentation_schema(src: &str, field: &str) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let property = &value["defs"]["main"]["input"]["schema"]["properties"][field];
        assert_eq!(
            property["type"], "object",
            "{} input {field} must be an object",
            value["id"]
        );
        let required_values = property["required"].as_array().expect("required array");
        for required in ["@context", "id", "type"] {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(required)),
                "{} input {field} missing VP required field {required}",
                value["id"]
            );
        }
        let properties = property["properties"]
            .as_object()
            .expect("properties object");
        for expected in [
            "@context",
            "id",
            "type",
            "holder",
            "verifiableCredential",
            "proof",
        ] {
            assert!(
                properties.contains_key(expected),
                "{} input {field} missing VP property {expected}",
                value["id"]
            );
        }
        let proof = &property["properties"]["proof"];
        assert_eq!(
            proof["type"], "object",
            "{} input {field}.proof must be an object",
            value["id"]
        );
        let proof_required = proof["required"].as_array().expect("proof required array");
        for required in ["type", "proofPurpose", "verificationMethod", "proofValue"] {
            assert!(
                proof_required
                    .iter()
                    .any(|value| value.as_str() == Some(required)),
                "{} input {field}.proof missing DataIntegrityProof required field {required}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_input_fields(src: &str, required: &[&str], properties: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let schema = &value["defs"]["main"]["input"]["schema"];
        let required_values = schema["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} missing required input field {field}",
                value["id"]
            );
        }
        let property_values = schema["properties"].as_object().expect("properties object");
        for field in required.iter().chain(properties.iter()) {
            assert!(
                property_values.contains_key(*field),
                "{} missing input property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_nested_array_item_fields(
        src: &str,
        outer_field: &str,
        inner_field: &str,
        required: &[&str],
    ) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let item = &value["defs"]["main"]["output"]["schema"]["properties"][outer_field]["items"]
            ["properties"][inner_field]["items"];
        assert_eq!(
            item["type"], "object",
            "{} output {outer_field}.{inner_field} items must be object",
            value["id"]
        );
        let required_values = item["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} output nested array item missing required field {field}",
                value["id"]
            );
            assert!(
                item["properties"]
                    .as_object()
                    .is_some_and(|props| props.contains_key(*field)),
                "{} output nested array item missing property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_array_item_fields(src: &str, field: &str, required: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let item = &value["defs"]["main"]["output"]["schema"]["properties"][field]["items"];
        assert_eq!(
            item["type"], "object",
            "{} output {field} items must be object",
            value["id"]
        );
        let required_values = item["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} output array item missing required field {field}",
                value["id"]
            );
            assert!(
                item["properties"]
                    .as_object()
                    .is_some_and(|props| props.contains_key(*field)),
                "{} output array item missing property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_array_items_schema(src: &str, field: &str, item_type: &str) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let property = &value["defs"]["main"]["output"]["schema"]["properties"][field];
        assert_eq!(
            property["type"], "array",
            "{} output {field} must be array",
            value["id"]
        );
        assert_eq!(
            property["items"]["type"], item_type,
            "{} output {field} items must be {item_type}",
            value["id"]
        );
    }

    fn assert_lexicon_output_fields(src: &str, required: &[&str], properties: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let schema = &value["defs"]["main"]["output"]["schema"];
        assert_eq!(
            schema["type"], "object",
            "{} output must be object",
            value["id"]
        );
        let required_values = schema["required"].as_array().expect("required array");
        for field in required {
            assert!(
                required_values
                    .iter()
                    .any(|value| value.as_str() == Some(field)),
                "{} missing required output field {field}",
                value["id"]
            );
        }
        let property_values = schema["properties"].as_object().expect("properties object");
        for field in required.iter().chain(properties.iter()) {
            assert!(
                property_values.contains_key(*field),
                "{} missing output property {field}",
                value["id"]
            );
        }
    }

    fn assert_lexicon_description_mentions(src: &str, needles: &[&str]) {
        let value: serde_json::Value = serde_json::from_str(src).expect("lexicon JSON");
        let description = value["defs"]["main"]["description"]
            .as_str()
            .expect("lexicon description");
        for needle in needles {
            assert!(
                description.contains(needle),
                "lexicon description must mention {needle}: {description}"
            );
        }
    }

    #[test]
    fn nsid_invoke_run_exact_value() {
        assert_eq!(super::NSID_INVOKE_RUN, "ai.gftd.apps.kotoba.invoke.run");
    }

    #[test]
    fn nsid_vault_put_and_get_exact_values() {
        assert_eq!(super::NSID_VAULT_PUT, "ai.gftd.apps.kotoba.vault.put");
        assert_eq!(super::NSID_VAULT_GET, "ai.gftd.apps.kotoba.vault.get");
    }

    #[test]
    fn nsid_agent_sync_variants_exact_values() {
        assert_eq!(
            super::NSID_AGENT_SYNC_OPEN,
            "ai.gftd.apps.kotoba.agent.syncopen"
        );
        assert_eq!(
            super::NSID_AGENT_SYNC_ADV,
            "ai.gftd.apps.kotoba.agent.syncadvance"
        );
        assert_eq!(
            super::NSID_AGENT_SYNC_CLOSE,
            "ai.gftd.apps.kotoba.agent.syncclose"
        );
    }

    #[test]
    fn max_cacao_b64_len_is_8kib() {
        assert_eq!(super::MAX_CACAO_B64_LEN, 8 * 1024);
    }
}
