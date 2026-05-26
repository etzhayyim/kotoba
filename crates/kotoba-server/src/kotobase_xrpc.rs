/// kotobase XRPC handlers — multi-tenant pinning service (ADR-2605260001)
///
/// NSIDs: ai.gftd.apps.kotobase.*
///
/// Tenant data lives in kotoba's own QuadStore under namespaced graphs:
///   kotobase/accounts/{tenant_did}  — tier + metadata
///   kotobase/pins/{tenant_did}      — per-pin records
///
/// Quota tiers:
///   free:    3 pins,  100 MB
///   starter: 50 pins,   5 GB  ($9/mo — Stripe stub)
///   pro:    500 pins,  50 GB  ($49/mo — Stripe stub)

pub const NSID_ACCOUNT_CREATE: &str = "ai.gftd.apps.kotobase.accountCreate";
pub const NSID_ACCOUNT_STATUS: &str = "ai.gftd.apps.kotobase.accountStatus";
pub const NSID_PIN_CREATE:     &str = "ai.gftd.apps.kotobase.pinCreate";
pub const NSID_PIN_LIST:       &str = "ai.gftd.apps.kotobase.pinList";
pub const NSID_PIN_DELETE:     &str = "ai.gftd.apps.kotobase.pinDelete";
pub const NSID_USAGE_GET:      &str = "ai.gftd.apps.kotobase.usageGet";

use std::sync::Arc;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use crate::server::KotobaState;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_core::cid::KotobaCid;

// ── Quota constants ────────────────────────────────────────────────────────

const QUOTA_FREE_PINS:     i64 = 3;
const QUOTA_FREE_BYTES:    i64 = 100 * 1024 * 1024;
const QUOTA_STARTER_PINS:  i64 = 50;
const QUOTA_STARTER_BYTES: i64 = 5 * 1024 * 1024 * 1024;
const QUOTA_PRO_PINS:      i64 = 500;
const QUOTA_PRO_BYTES:     i64 = 50 * 1024 * 1024 * 1024;

fn quota_for_tier(tier: &str) -> (i64, i64) {
    match tier {
        "starter" => (QUOTA_STARTER_PINS, QUOTA_STARTER_BYTES),
        "pro"     => (QUOTA_PRO_PINS,     QUOTA_PRO_BYTES),
        _         => (QUOTA_FREE_PINS,    QUOTA_FREE_BYTES),
    }
}

// ── CID helpers ────────────────────────────────────────────────────────────

fn cid(s: &str) -> KotobaCid { KotobaCid::from_bytes(s.as_bytes()) }

fn text_quad(graph: &str, subject: &str, predicate: &str, value: &str) -> Quad {
    Quad {
        graph:     cid(graph),
        subject:   cid(subject),
        predicate: predicate.to_string(),
        object:    QuadObject::Text(value.to_string()),
    }
}

fn int_quad(graph: &str, subject: &str, predicate: &str, value: i64) -> Quad {
    Quad {
        graph:     cid(graph),
        subject:   cid(subject),
        predicate: predicate.to_string(),
        object:    QuadObject::Integer(value),
    }
}

// ── Arrangement read helpers ───────────────────────────────────────────────

async fn get_text(state: &KotobaState, graph: &str, subject: &str, predicate: &str) -> Option<String> {
    let arr = state.quad_store.arrangement(&cid(graph)).await?;
    arr.get_objects(&cid(subject), predicate)
        .into_iter()
        .find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None })
}

#[allow(dead_code)]
async fn get_int(state: &KotobaState, graph: &str, subject: &str, predicate: &str) -> i64 {
    if let Some(arr) = state.quad_store.arrangement(&cid(graph)).await {
        arr.get_objects(&cid(subject), predicate)
            .into_iter()
            .find_map(|o| if let QuadObject::Integer(v) = o { Some(*v) } else { None })
            .unwrap_or(0)
    } else {
        0
    }
}

async fn read_tier(state: &KotobaState, tenant_did: &str) -> String {
    let g = format!("kotobase/accounts/{tenant_did}");
    get_text(state, &g, tenant_did, "kotobase/account/tier")
        .await
        .unwrap_or_else(|| "free".to_string())
}

/// Count pins optionally filtered by status; also sums size_bytes.
async fn count_pins(state: &KotobaState, tenant_did: &str, status_filter: Option<&str>) -> (i64, i64) {
    let g   = format!("kotobase/pins/{tenant_did}");
    let arr = match state.quad_store.arrangement(&cid(&g)).await {
        Some(a) => a,
        None    => return (0, 0),
    };
    let pin_subjects = arr.get_subjects_by_predicate("kotobase/pin/cid");
    let mut count = 0i64;
    let mut bytes = 0i64;
    for subj_cid in pin_subjects {
        if let Some(sf) = status_filter {
            let status = arr.get_objects(&subj_cid, "kotobase/pin/status")
                .into_iter()
                .find_map(|o| if let QuadObject::Text(t) = o { Some(t.as_str().to_string()) } else { None })
                .unwrap_or_default();
            if status != sf { continue; }
        }
        count += 1;
        let sz: i64 = arr.get_objects(&subj_cid, "kotobase/pin/size_bytes")
            .into_iter()
            .find_map(|o| if let QuadObject::Integer(v) = o { Some(*v) } else { None })
            .unwrap_or(0);
        bytes += sz;
    }
    (count, bytes)
}

fn now_unix_str() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn new_pin_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("pin_{ms:016x}")
}

// ── Request / Response types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AccountCreateReq {
    pub display_name: Option<String>,
    pub tier:         Option<String>,
    pub tenant_did:   String,
}

#[derive(Debug, Serialize)]
pub struct AccountCreateResp {
    pub ok:         bool,
    pub tenant_did: String,
    pub tier:       String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:      Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AccountStatusReq {
    pub tenant_did: String,
}

#[derive(Debug, Serialize)]
pub struct AccountStatusResp {
    pub ok:          bool,
    pub tenant_did:  String,
    pub tier:        String,
    pub quota_pins:  i64,
    pub quota_bytes: i64,
    pub used_pins:   i64,
    pub used_bytes:  i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at:  Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:       Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TripleInput {
    pub subject:   String,
    pub predicate: String,
    pub object:    String,
}

#[derive(Debug, Deserialize)]
pub struct QuadsInput {
    pub graph:   String,
    pub triples: Option<Vec<TripleInput>>,
}

#[derive(Debug, Deserialize)]
pub struct PinCreateReq {
    pub name:            String,
    pub cid:             Option<String>,
    pub quads:           Option<QuadsInput>,
    pub size_hint_bytes: Option<i64>,
    pub tenant_did:      String,
}

#[derive(Debug, Serialize)]
pub struct PinCreateResp {
    pub ok:         bool,
    pub pin_id:     String,
    pub cid:        String,
    pub status:     String,
    pub size_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error:      Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PinListReq {
    pub tenant_did: String,
    pub status:     Option<String>,
    pub limit:      Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct PinRecord {
    pub pin_id:      String,
    pub name:        String,
    pub cid:         String,
    pub status:      String,
    pub size_bytes:  i64,
    pub created_at:  String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs_status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PinListResp {
    pub ok:    bool,
    pub pins:  Vec<PinRecord>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct PinDeleteReq {
    pub pin_id:     String,
    pub tenant_did: String,
}

#[derive(Debug, Serialize)]
pub struct PinDeleteResp {
    pub ok:    bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UsageGetReq {
    pub tenant_did: String,
}

#[derive(Debug, Serialize)]
pub struct UsageGetResp {
    pub ok:              bool,
    pub tenant_did:      String,
    pub tier:            String,
    pub pin_count:       i64,
    pub pinned_count:    i64,
    pub pinning_count:   i64,
    pub failed_count:    i64,
    pub total_bytes:     i64,
    pub quota_pins:      i64,
    pub quota_bytes:     i64,
    pub remaining_pins:  i64,
    pub remaining_bytes: i64,
}

// ── Handlers ──────────────────────────────────────────────────────────────

pub async fn handle_account_create(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<AccountCreateReq>,
) -> impl IntoResponse {
    let tier = req.tier.as_deref().unwrap_or("free").to_string();
    let now  = now_unix_str();
    let g    = format!("kotobase/accounts/{}", req.tenant_did);

    let quads = vec![
        text_quad(&g, &req.tenant_did, "kotobase/account/tier",       &tier),
        text_quad(&g, &req.tenant_did, "kotobase/account/created_at", &now),
    ];
    state.quad_store.assert_batch_silent(quads).await;

    (StatusCode::OK, Json(AccountCreateResp {
        ok: true,
        tenant_did: req.tenant_did,
        tier,
        created_at: now,
        error: None,
    }))
}

pub async fn handle_account_status(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<AccountStatusReq>,
) -> impl IntoResponse {
    let tier = read_tier(&state, &req.tenant_did).await;
    let (quota_pins, quota_bytes) = quota_for_tier(&tier);
    let (used_pins, used_bytes)   = count_pins(&state, &req.tenant_did, None).await;

    let g = format!("kotobase/accounts/{}", req.tenant_did);
    let created_at = get_text(&state, &g, &req.tenant_did, "kotobase/account/created_at").await;

    (StatusCode::OK, Json(AccountStatusResp {
        ok: true,
        tenant_did: req.tenant_did,
        tier,
        quota_pins,
        quota_bytes,
        used_pins,
        used_bytes,
        created_at,
        error: None,
    }))
}

pub async fn handle_pin_create(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<PinCreateReq>,
) -> impl IntoResponse {
    if req.cid.is_none() == req.quads.is_none() {
        return (StatusCode::BAD_REQUEST, Json(PinCreateResp {
            ok: false, pin_id: String::new(), cid: String::new(),
            status: "failed".into(), size_bytes: 0,
            error: Some("provide exactly one of: cid, quads".into()),
        }));
    }

    // Quota check
    let tier = read_tier(&state, &req.tenant_did).await;
    let (quota_pins, quota_bytes) = quota_for_tier(&tier);
    let (used_pins, used_bytes)   = count_pins(&state, &req.tenant_did, None).await;
    let size = req.size_hint_bytes.unwrap_or(0);

    if quota_pins >= 0 && used_pins >= quota_pins {
        return (StatusCode::TOO_MANY_REQUESTS, Json(PinCreateResp {
            ok: false, pin_id: String::new(), cid: String::new(),
            status: "failed".into(), size_bytes: 0,
            error: Some(format!("QuotaExceeded: tier={tier} pins={used_pins}/{quota_pins}")),
        }));
    }
    if quota_bytes >= 0 && size > 0 && used_bytes + size > quota_bytes {
        return (StatusCode::TOO_MANY_REQUESTS, Json(PinCreateResp {
            ok: false, pin_id: String::new(), cid: String::new(),
            status: "failed".into(), size_bytes: 0,
            error: Some(format!("QuotaExceeded: tier={tier} bytes={used_bytes}+{size}>{quota_bytes}")),
        }));
    }

    // Resolve CID
    let resolved_cid = if let Some(c) = req.cid.as_deref() {
        c.to_string()
    } else {
        let qi      = req.quads.as_ref().unwrap();
        let graph   = format!("{}/{}", req.tenant_did, qi.graph);
        let mut quads = Vec::new();
        for t in qi.triples.as_deref().unwrap_or(&[]) {
            quads.push(text_quad(&graph, &t.subject, &t.predicate, &t.object));
        }
        let gc = KotobaCid::from_bytes(graph.as_bytes());
        state.quad_store.assert_batch_silent(quads).await;
        gc.to_multibase()
    };

    let pin_id = new_pin_id();
    let now    = now_unix_str();
    let pin_g  = format!("kotobase/pins/{}", req.tenant_did);

    let pin_quads = vec![
        text_quad(&pin_g, &pin_id, "kotobase/pin/cid",        &resolved_cid),
        text_quad(&pin_g, &pin_id, "kotobase/pin/name",       &req.name),
        text_quad(&pin_g, &pin_id, "kotobase/pin/status",     "pinning"),
        int_quad( &pin_g, &pin_id, "kotobase/pin/size_bytes",  size),
        text_quad(&pin_g, &pin_id, "kotobase/pin/created_at", &now),
    ];
    state.quad_store.assert_batch_silent(pin_quads).await;

    // Fire-and-forget IPFS pin
    if let Some(ipfs) = &state.ipfs_pin {
        let ipfs_c    = Arc::clone(ipfs);
        let cid_c     = resolved_cid.clone();
        let state_c   = Arc::clone(&state);
        let pin_id_c  = pin_id.clone();
        let pin_g_c   = pin_g.clone();
        tokio::spawn(async move {
            ipfs_c.pin(&cid_c).await;
            let done = vec![
                text_quad(&pin_g_c, &pin_id_c, "kotobase/pin/status",      "pinned"),
                text_quad(&pin_g_c, &pin_id_c, "kotobase/pin/ipfs_status", "pinned"),
            ];
            state_c.quad_store.assert_batch_silent(done).await;
        });
    } else {
        // No IPFS — mark pinned immediately (Sled-only local storage)
        let done = vec![text_quad(&pin_g, &pin_id, "kotobase/pin/status", "pinned")];
        state.quad_store.assert_batch_silent(done).await;
    }

    (StatusCode::OK, Json(PinCreateResp {
        ok:     true,
        pin_id,
        cid:    resolved_cid,
        status: if state.ipfs_pin.is_some() { "pinning" } else { "pinned" }.into(),
        size_bytes: size,
        error:  None,
    }))
}

pub async fn handle_pin_list(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<PinListReq>,
) -> impl IntoResponse {
    let limit = req.limit.unwrap_or(20).min(100);
    let g     = format!("kotobase/pins/{}", req.tenant_did);
    let gc    = cid(&g);

    let arr = match state.quad_store.arrangement(&gc).await {
        Some(a) => a,
        None    => return (StatusCode::OK, Json(PinListResp { ok: true, pins: vec![], total: 0 })),
    };

    let pin_subjects = arr.get_subjects_by_predicate("kotobase/pin/cid");
    let mut records: Vec<PinRecord> = pin_subjects.iter()
        .filter_map(|subj_cid| {
            let get_text_local = |pred: &str| -> Option<String> {
                arr.get_objects(subj_cid, pred)
                    .into_iter()
                    .find_map(|o| if let QuadObject::Text(t) = o { Some(t.clone()) } else { None })
            };
            let get_int_local = |pred: &str| -> i64 {
                arr.get_objects(subj_cid, pred)
                    .into_iter()
                    .find_map(|o| if let QuadObject::Integer(v) = o { Some(*v) } else { None })
                    .unwrap_or(0)
            };

            let pin_id     = subj_cid.to_multibase();
            let cid_val    = get_text_local("kotobase/pin/cid")?;
            let name       = get_text_local("kotobase/pin/name").unwrap_or_default();
            let status     = get_text_local("kotobase/pin/status").unwrap_or_else(|| "pinning".into());
            let ipfs_status = get_text_local("kotobase/pin/ipfs_status");
            let size_bytes  = get_int_local("kotobase/pin/size_bytes");
            let created_at  = get_text_local("kotobase/pin/created_at").unwrap_or_default();

            if let Some(sf) = req.status.as_deref() {
                if status != sf { return None; }
            }
            Some(PinRecord { pin_id, name, cid: cid_val, status, ipfs_status, size_bytes, created_at })
        })
        .collect();

    let total = records.len();
    records.truncate(limit);

    (StatusCode::OK, Json(PinListResp { ok: true, pins: records, total }))
}

pub async fn handle_pin_delete(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<PinDeleteReq>,
) -> impl IntoResponse {
    let g     = format!("kotobase/pins/{}", req.tenant_did);
    let gc    = cid(&g);
    let subj  = cid(&req.pin_id);

    let arr = match state.quad_store.arrangement(&gc).await {
        Some(a) => a,
        None => return (StatusCode::NOT_FOUND, Json(PinDeleteResp {
            ok: false, error: Some("NotFound: no pins for this tenant".into()),
        })),
    };

    let quads = arr.get_subject_quads(&gc, &subj);
    if quads.is_empty() {
        return (StatusCode::NOT_FOUND, Json(PinDeleteResp {
            ok: false, error: Some("NotFound: pin not found".into()),
        }));
    }

    for q in quads {
        state.quad_store.retract_silent(q).await;
    }

    (StatusCode::OK, Json(PinDeleteResp { ok: true, error: None }))
}

pub async fn handle_usage_get(
    State(state): State<Arc<KotobaState>>,
    Json(req): Json<UsageGetReq>,
) -> impl IntoResponse {
    let tier = read_tier(&state, &req.tenant_did).await;
    let (quota_pins, quota_bytes) = quota_for_tier(&tier);
    let (pin_count, total_bytes)  = count_pins(&state, &req.tenant_did, None).await;
    let (pinned_count, _)         = count_pins(&state, &req.tenant_did, Some("pinned")).await;
    let (pinning_count, _)        = count_pins(&state, &req.tenant_did, Some("pinning")).await;
    let (failed_count, _)         = count_pins(&state, &req.tenant_did, Some("failed")).await;

    let remaining_pins  = if quota_pins  < 0 { -1 } else { (quota_pins  - pin_count).max(0) };
    let remaining_bytes = if quota_bytes < 0 { -1 } else { (quota_bytes - total_bytes).max(0) };

    (StatusCode::OK, Json(UsageGetResp {
        ok: true,
        tenant_did: req.tenant_did,
        tier,
        pin_count,
        pinned_count,
        pinning_count,
        failed_count,
        total_bytes,
        quota_pins,
        quota_bytes,
        remaining_pins,
        remaining_bytes,
    }))
}

// ── NSID list for test invariant ──────────────────────────────────────────

pub const ALL_NSIDS: &[&str] = &[
    NSID_ACCOUNT_CREATE,
    NSID_ACCOUNT_STATUS,
    NSID_PIN_CREATE,
    NSID_PIN_LIST,
    NSID_PIN_DELETE,
    NSID_USAGE_GET,
];
