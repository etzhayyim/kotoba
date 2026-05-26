/// Signal Protocol XRPC endpoints.
/// NSIDs: ai.gftd.signal.{register.prekeys, get.prekey.bundle, send.message, send.group.message}
///
/// These endpoints make kotoba-server the SSoT for Signal Protocol E2E,
/// superseding `@gftd/signal` (`10-protocol/signal/`).

pub const NSID_SIGNAL_REGISTER_PREKEYS:      &str = "ai.gftd.signal.register.prekeys";
pub const NSID_SIGNAL_GET_PREKEY_BUNDLE:     &str = "ai.gftd.signal.get.prekey.bundle";
pub const NSID_SIGNAL_SEND_MESSAGE:          &str = "ai.gftd.signal.send.message";
pub const NSID_SIGNAL_SEND_GROUP_MESSAGE:    &str = "ai.gftd.signal.send.group.message";
pub const NSID_SIGNAL_DISTRIBUTE_SENDER_KEY: &str = "ai.gftd.signal.distribute.sender.key";

use std::sync::Arc;
use axum::{
    Json,
    extract::{State, Query},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use kotoba_signal::message::SignalMessage;
use crate::server::KotobaState;

// Soft caps — prevent shelf key exhaustion and oversized payloads.
const MAX_DID_LEN:       usize = 512;
const MAX_DEVICE_ID_LEN: usize = 128;
const MAX_GROUP_ID_LEN:  usize = 128;
const MAX_PAYLOAD_BYTES: usize = 256 * 1024; // 256 KiB per encrypted message

/// Thin wrapper — delegates to the shared validator in `graph_auth`.
fn validate_signal_did(did: &str, field: &str) -> Result<(), (StatusCode, String)> {
    crate::graph_auth::validate_did(did, field, MAX_DID_LEN)
}

/// Verify caller owns `did` via Bearer JWT `sub` claim.
fn require_signal_auth(
    headers: &HeaderMap,
    did: &str,
    operator_did: &str,
) -> Result<(), (StatusCode, String)> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            tracing::warn!("signal auth: missing Bearer token");
            (StatusCode::UNAUTHORIZED, "Authorization: Bearer <token> required".to_string())
        })?;
    if crate::graph_auth::jwt_exp_elapsed(token) {
        tracing::warn!("signal auth: expired JWT");
        return Err((StatusCode::UNAUTHORIZED, "Bearer token has expired".to_string()));
    }
    let sub = crate::graph_auth::jwt_sub(token)
        .ok_or_else(|| {
            tracing::warn!("signal auth: JWT missing sub claim");
            (StatusCode::UNAUTHORIZED, "Bearer token missing sub claim".to_string())
        })?;
    if sub == did || sub == operator_did {
        Ok(())
    } else {
        tracing::warn!(sub = %sub, did = %did, "signal auth: sub mismatch");
        Err((StatusCode::UNAUTHORIZED,
            format!("Bearer sub does not match did {did:?}")))
    }
}

// ── registerPrekeys ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPrekeysReq {
    pub did:              String,
    pub device_id:        String,
    /// Serialised `IdentityKey` (JSON).
    pub identity_key:     serde_json::Value,
    /// Serialised `PreKeyBundle` (JSON) — signed_prekey + one_time_prekeys.
    pub prekey_bundle:    serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterPrekeysResp {
    pub status: &'static str,
    pub did:    String,
}

pub async fn register_prekeys(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<RegisterPrekeysReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    validate_signal_did(&req.did, "did")?;
    if req.device_id.is_empty() || req.device_id.len() > MAX_DEVICE_ID_LEN {
        return Err((StatusCode::BAD_REQUEST,
            format!("device_id must be 1–{MAX_DEVICE_ID_LEN} bytes")));
    }
    require_signal_auth(&headers, &req.did, &state.operator_did)?;

    let bundle_bytes = serde_json::to_vec(&req.prekey_bundle)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("prekey_bundle serialize: {e}")))?;
    let ik_bytes = serde_json::to_vec(&req.identity_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("identity_key serialize: {e}")))?;

    let key = format!("signal/bundle/{}/{}", req.did, req.device_id);
    state.shelf.put("KOTOBA_SIGNAL", key, bytes::Bytes::from(bundle_bytes)).await;
    let ik_key = format!("signal/identity/{}/{}", req.did, req.device_id);
    state.shelf.put("KOTOBA_SIGNAL", ik_key, bytes::Bytes::from(ik_bytes)).await;
    Ok(Json(RegisterPrekeysResp { status: "ok", did: req.did }))
}

// ── getPrekeyBundle ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPreKeyBundleQuery {
    pub did:       String,
    pub device_id: Option<String>,
}

pub async fn get_prekey_bundle(
    State(state): State<Arc<KotobaState>>,
    Query(q): Query<GetPreKeyBundleQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    validate_signal_did(&q.did, "did")?;
    let device_id = q.device_id.as_deref().unwrap_or("default");
    let bundle_key = format!("signal/bundle/{}/{}", q.did, device_id);
    let ik_key     = format!("signal/identity/{}/{}", q.did, device_id);

    let bundle_bytes = state.shelf.get("KOTOBA_SIGNAL", &bundle_key).await;
    let ik_bytes     = state.shelf.get("KOTOBA_SIGNAL", &ik_key).await;

    Ok(match (bundle_bytes, ik_bytes) {
        (Some(b), Some(ik)) => {
            let bundle: serde_json::Value = serde_json::from_slice(&b)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR,
                    format!("stored prekey bundle is malformed: {e}")))?;
            let identity_key: serde_json::Value = serde_json::from_slice(&ik)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR,
                    format!("stored identity key is malformed: {e}")))?;
            Json(serde_json::json!({
                "did": q.did,
                "deviceId": device_id,
                "identityKey": identity_key,
                "bundle": bundle,
            })).into_response()
        }
        _ => (StatusCode::NOT_FOUND, Json(serde_json::json!({
            "error": "prekey bundle not found",
            "did": q.did,
        }))).into_response(),
    })
}

// ── sendMessage ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageReq {
    pub signal_message: serde_json::Value,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMessageResp {
    pub status:     &'static str,
    pub message_id: String,
}

pub async fn send_message(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<SendMessageReq>,
) -> impl IntoResponse {
    let raw_len = serde_json::to_vec(&req.signal_message)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if raw_len > MAX_PAYLOAD_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": format!("signal_message exceeds {MAX_PAYLOAD_BYTES} bytes") })),
        ).into_response();
    }

    let msg: SignalMessage = match serde_json::from_value(req.signal_message.clone()) {
        Ok(m) => m,
        Err(e) => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": e.to_string() })),
        ).into_response(),
    };

    // Require the caller to prove ownership of signal_message.sender_did.
    if let Err((code, err_msg)) = require_signal_auth(&headers, &msg.sender_did, &state.operator_did) {
        return (code, Json(serde_json::json!({ "error": err_msg }))).into_response();
    }

    let topic_name = format!("signal/inbox/{}/{}", msg.recipient_did, msg.device_id);
    let topic = kotoba_kse::topic::Topic(format!("kotoba/{topic_name}"));
    let payload_vec = match serde_json::to_vec(&req.signal_message) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("signal_message serialize: {e}") }))).into_response(),
    };
    let entry = state.journal.publish(topic, bytes::Bytes::from(payload_vec)).await;

    Json(SendMessageResp {
        status: "ok",
        message_id: entry.cid.to_multibase(),
    }).into_response()
}

// ── sendGroupMessage ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendGroupMessageReq {
    pub group_id:     String,
    pub sender_did:   String,
    pub sender_key_message: serde_json::Value,
}

pub async fn send_group_message(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<SendGroupMessageReq>,
) -> impl IntoResponse {
    if req.group_id.is_empty() || req.group_id.len() > MAX_GROUP_ID_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("group_id must be 1–{MAX_GROUP_ID_LEN} bytes") })),
        ).into_response();
    }
    if let Err((code, msg)) = validate_signal_did(&req.sender_did, "sender_did") {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if let Err((code, err_msg)) = require_signal_auth(&headers, &req.sender_did, &state.operator_did) {
        return (code, Json(serde_json::json!({ "error": err_msg }))).into_response();
    }
    let raw_len = serde_json::to_vec(&req.sender_key_message)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if raw_len > MAX_PAYLOAD_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": format!("sender_key_message exceeds {MAX_PAYLOAD_BYTES} bytes") })),
        ).into_response();
    }

    let topic = kotoba_kse::topic::Topic(
        format!("kotoba/signal/group/{}", req.group_id),
    );
    let payload_vec = match serde_json::to_vec(&req.sender_key_message) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("sender_key_message serialize: {e}") }))).into_response(),
    };
    let entry = state.journal.publish(topic, bytes::Bytes::from(payload_vec)).await;

    Json(serde_json::json!({
        "status": "ok",
        "messageId": entry.cid.to_multibase(),
        "groupId": req.group_id,
    })).into_response()
}

// ── distributeSenderKey ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DistributeSenderKeyReq {
    /// Recipient DID — receives the distribution via their 1:1 inbox.
    pub recipient_did:  String,
    pub recipient_device: String,
    /// SenderKeyDistribution serialised as a SignalMessage ciphertext.
    pub signal_message: serde_json::Value,
}

pub async fn distribute_sender_key(
    State(state): State<Arc<KotobaState>>,
    headers: HeaderMap,
    Json(req): Json<DistributeSenderKeyReq>,
) -> impl IntoResponse {
    if let Err((code, msg)) = validate_signal_did(&req.recipient_did, "recipient_did") {
        return (code, Json(serde_json::json!({ "error": msg }))).into_response();
    }
    if req.recipient_device.is_empty() || req.recipient_device.len() > MAX_DEVICE_ID_LEN {
        return (StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("recipient_device must be 1–{MAX_DEVICE_ID_LEN} bytes") })),
        ).into_response();
    }
    let raw_len = serde_json::to_vec(&req.signal_message)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if raw_len > MAX_PAYLOAD_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({ "error": format!("signal_message exceeds {MAX_PAYLOAD_BYTES} bytes") })),
        ).into_response();
    }
    // Require any authenticated caller (the sender distributing their key).
    // We verify: Bearer present + non-expired + has sub claim.
    if let Err((code, err_msg)) = crate::graph_auth::require_any_bearer_auth(&headers, "distribute_sender_key") {
        return (code, Json(serde_json::json!({ "error": err_msg }))).into_response();
    }

    let topic = kotoba_kse::topic::Topic(
        format!("kotoba/signal/inbox/{}/{}", req.recipient_did, req.recipient_device),
    );
    let payload_vec = match serde_json::to_vec(&req.signal_message) {
        Ok(v) => v,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("signal_message serialize: {e}") }))).into_response(),
    };
    let entry = state.journal.publish(topic, bytes::Bytes::from(payload_vec)).await;

    Json(serde_json::json!({
        "status": "ok",
        "messageId": entry.cid.to_multibase(),
    })).into_response()
}

// ── NSID invariant tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNAL_NSIDS: &[&str] = &[
        NSID_SIGNAL_REGISTER_PREKEYS,
        NSID_SIGNAL_GET_PREKEY_BUNDLE,
        NSID_SIGNAL_SEND_MESSAGE,
        NSID_SIGNAL_SEND_GROUP_MESSAGE,
        NSID_SIGNAL_DISTRIBUTE_SENDER_KEY,
    ];

    #[test]
    fn all_signal_nsids_have_correct_prefix() {
        for nsid in SIGNAL_NSIDS {
            assert!(
                nsid.starts_with("ai.gftd.signal."),
                "Signal NSID must start with ai.gftd.signal.: {nsid}"
            );
        }
    }

    #[test]
    fn all_signal_nsids_alphanumeric_dotted() {
        for nsid in SIGNAL_NSIDS {
            assert!(
                nsid.chars().all(|c| c.is_ascii_alphanumeric() || c == '.'),
                "NSID must be alphanumeric+dots: {nsid}"
            );
        }
    }

    #[test]
    fn all_signal_nsids_unique() {
        let mut seen = std::collections::HashSet::new();
        for nsid in SIGNAL_NSIDS {
            assert!(seen.insert(*nsid), "duplicate NSID: {nsid}");
        }
    }
}
