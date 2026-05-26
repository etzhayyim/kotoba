//! Request fingerprint middleware.
//!
//! Every inbound XRPC / MCP request is fingerprinted with blake3 and stored
//! as Datoms in the `kotoba/audit/requests` named graph.  Storage is
//! fire-and-forget (background task) so latency impact is negligible.
//!
//! Quads emitted per request:
//! - `(audit_graph, request_cid, "request/method",  Text(method))`
//! - `(audit_graph, request_cid, "request/path",    Text(path))`
//! - `(audit_graph, request_cid, "request/node_id", Text(hex_node_id))`
//! - `(audit_graph, request_cid, "request/ts_unix", Integer(unix_secs))`
//! - `(audit_graph, request_cid, "request/peer_ip", Text(ip))` — when available

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{Quad, QuadObject};

use crate::server::KotobaState;

/// Named audit graph for request fingerprints.
/// CID is derived from a fixed seed so it is stable across restarts.
fn audit_graph_cid() -> KotobaCid {
    KotobaCid::from_bytes(b"kotoba/audit/requests/v1")
}

/// Derive a request CID from method + path + timestamp + node_id bytes.
fn request_cid(method: &str, path: &str, ts: u64, node_id: &[u8; 32]) -> KotobaCid {
    let mut buf = Vec::with_capacity(method.len() + path.len() + 8 + 32);
    buf.extend_from_slice(method.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(path.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&ts.to_le_bytes());
    buf.push(b'|');
    buf.extend_from_slice(node_id);
    KotobaCid::from_bytes(&buf)
}

/// Maximum length for a stored IP string (IPv6 max is 39 chars; 64 is generous).
const MAX_AUDIT_IP_LEN: usize = 64;

/// Extract client IP from `X-Forwarded-For` or `X-Real-IP` headers.
fn extract_ip(req: &Request<Body>) -> Option<String> {
    let headers = req.headers();
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            // Take the first (leftmost) address — the original client.
            let ip = s.split(',').next().unwrap_or(s).trim();
            return Some(ip.chars().take(MAX_AUDIT_IP_LEN).collect());
        }
    }
    if let Some(rip) = headers.get("x-real-ip") {
        if let Ok(s) = rip.to_str() {
            return Some(s.trim().chars().take(MAX_AUDIT_IP_LEN).collect());
        }
    }
    None
}

/// Maximum path length stored in audit Quads.  Paths longer than this are
/// truncated to prevent unbounded Quad object growth from crafted URLs.
const MAX_AUDIT_PATH_LEN: usize = 512;

/// Axum middleware: fingerprint every request and store Datoms asynchronously.
///
/// Does NOT use `ConnectInfo` (the server is behind a proxy; use
/// `X-Forwarded-For` / `X-Real-IP` headers instead).
pub async fn fingerprint_middleware(
    State(state): State<Arc<KotobaState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let method = req.method().as_str().to_string();
    let raw    = req.uri().path();
    let path   = if raw.len() > MAX_AUDIT_PATH_LEN {
        // Walk back from MAX_AUDIT_PATH_LEN to a valid UTF-8 char boundary so
        // the byte-index slice does not panic on multi-byte characters.
        let mut end = MAX_AUDIT_PATH_LEN;
        while !raw.is_char_boundary(end) { end -= 1; }
        format!("{}…", &raw[..end])
    } else {
        raw.to_string()
    };
    let peer_ip  = extract_ip(&req);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let node_id  = state.local_node_id.0;
    let req_cid  = request_cid(&method, &path, ts, &node_id);
    let graph    = audit_graph_cid();
    let node_hex = hex::encode(node_id);

    // Fire-and-forget: clone what we need into the background task.
    let quad_store = Arc::clone(&state.quad_store);
    let method_c  = method.clone();
    let path_c    = path.clone();
    let peer_ip_c = peer_ip.clone();

    tokio::spawn(async move {
        let quads = build_request_quads(
            graph, req_cid, &method_c, &path_c, &node_hex, ts, peer_ip_c.as_deref(),
        );
        for quad in quads {
            quad_store.assert(quad).await;
        }
    });

    // Continue to the actual handler.
    next.run(req).await
}

/// Build the set of audit Quads for a single request.
fn build_request_quads(
    graph:    KotobaCid,
    subject:  KotobaCid,
    method:   &str,
    path:     &str,
    node_hex: &str,
    ts:       u64,
    peer_ip:  Option<&str>,
) -> Vec<Quad> {
    let mut quads = vec![
        Quad {
            graph: graph.clone(),
            subject: subject.clone(),
            predicate: "request/method".to_string(),
            object: QuadObject::Text(method.to_string()),
        },
        Quad {
            graph: graph.clone(),
            subject: subject.clone(),
            predicate: "request/path".to_string(),
            object: QuadObject::Text(path.to_string()),
        },
        Quad {
            graph: graph.clone(),
            subject: subject.clone(),
            predicate: "request/node_id".to_string(),
            object: QuadObject::Text(node_hex.to_string()),
        },
        Quad {
            graph: graph.clone(),
            subject: subject.clone(),
            predicate: "request/ts_unix".to_string(),
            object: QuadObject::Integer(ts as i64),
        },
    ];

    if let Some(ip) = peer_ip {
        quads.push(Quad {
            graph,
            subject,
            predicate: "request/peer_ip".to_string(),
            object: QuadObject::Text(ip.to_string()),
        });
    }

    quads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_graph_is_stable() {
        let a = audit_graph_cid();
        let b = audit_graph_cid();
        assert_eq!(a.0, b.0, "audit graph CID must be deterministic");
    }

    #[test]
    fn request_cid_differs_by_path() {
        let node = [0u8; 32];
        let c1 = request_cid("GET", "/xrpc/foo", 1000, &node);
        let c2 = request_cid("GET", "/xrpc/bar", 1000, &node);
        assert_ne!(c1.0, c2.0);
    }

    #[test]
    fn build_quads_count_with_ip() {
        let graph   = audit_graph_cid();
        let subject = KotobaCid::from_bytes(b"test-req");
        let quads   = build_request_quads(graph, subject, "POST", "/mcp", "deadbeef", 42, Some("1.2.3.4"));
        assert_eq!(quads.len(), 5);
    }

    #[test]
    fn build_quads_count_without_ip() {
        let graph   = audit_graph_cid();
        let subject = KotobaCid::from_bytes(b"test-req");
        let quads   = build_request_quads(graph, subject, "GET", "/health", "deadbeef", 42, None);
        assert_eq!(quads.len(), 4);
    }

    #[test]
    fn request_cid_differs_by_method() {
        let node = [1u8; 32];
        let c1 = request_cid("GET",  "/xrpc/foo", 1000, &node);
        let c2 = request_cid("POST", "/xrpc/foo", 1000, &node);
        assert_ne!(c1.0, c2.0, "CID should differ when method changes");
    }

    #[test]
    fn request_cid_differs_by_timestamp() {
        let node = [2u8; 32];
        let c1 = request_cid("GET", "/xrpc/foo", 1000, &node);
        let c2 = request_cid("GET", "/xrpc/foo", 1001, &node);
        assert_ne!(c1.0, c2.0, "CID should differ when timestamp changes");
    }

    #[test]
    fn request_cid_differs_by_node_id() {
        let node_a = [0u8; 32];
        let node_b = [1u8; 32];
        let c1 = request_cid("GET", "/xrpc/foo", 1000, &node_a);
        let c2 = request_cid("GET", "/xrpc/foo", 1000, &node_b);
        assert_ne!(c1.0, c2.0, "CID should differ when node_id changes");
    }

    #[test]
    fn request_cid_is_deterministic() {
        let node = [0xABu8; 32];
        let c1 = request_cid("PUT", "/mcp", 9999, &node);
        let c2 = request_cid("PUT", "/mcp", 9999, &node);
        assert_eq!(c1.0, c2.0, "same inputs must produce same CID");
    }

    #[test]
    fn build_quads_have_expected_predicates() {
        let graph   = audit_graph_cid();
        let subject = KotobaCid::from_bytes(b"pred-test");
        let quads   = build_request_quads(graph, subject, "DELETE", "/path", "ff00", 100, Some("10.0.0.1"));

        let predicates: Vec<&str> = quads.iter().map(|q| q.predicate.as_str()).collect();
        assert!(predicates.contains(&"request/method"),  "should have request/method quad");
        assert!(predicates.contains(&"request/path"),    "should have request/path quad");
        assert!(predicates.contains(&"request/node_id"), "should have request/node_id quad");
        assert!(predicates.contains(&"request/ts_unix"), "should have request/ts_unix quad");
        assert!(predicates.contains(&"request/peer_ip"), "should have request/peer_ip quad when IP provided");
    }

    #[test]
    fn max_audit_constants_values() {
        assert_eq!(MAX_AUDIT_IP_LEN, 64);
        assert_eq!(MAX_AUDIT_PATH_LEN, 512);
    }

    // ── path truncation edge cases ────────────────────────────────────────────

    #[test]
    fn path_short_of_limit_is_not_truncated() {
        // A path shorter than MAX_AUDIT_PATH_LEN must pass through unchanged.
        let short = "/xrpc/ai.gftd.apps.kotoba.graph.query";
        assert!(short.len() < MAX_AUDIT_PATH_LEN);
        // Simulate the truncation logic used in fingerprint_middleware.
        let result = if short.len() > MAX_AUDIT_PATH_LEN {
            let mut end = MAX_AUDIT_PATH_LEN;
            while !short.is_char_boundary(end) { end -= 1; }
            format!("{}…", &short[..end])
        } else {
            short.to_string()
        };
        assert_eq!(result, short);
    }

    #[test]
    fn path_truncation_on_multibyte_boundary_does_not_panic() {
        // Construct a path of exactly MAX_AUDIT_PATH_LEN + 3 bytes where the
        // byte at MAX_AUDIT_PATH_LEN falls inside a 3-byte UTF-8 character (€).
        // Without the char-boundary walk-back this would panic with:
        //   "byte index N is not a char boundary"
        let prefix = "/".repeat(MAX_AUDIT_PATH_LEN - 1); // 511 ASCII bytes
        let multibyte = "€";                              // 3 bytes: 0xE2 0x82 0xAC
        let long_path = format!("{prefix}{multibyte}abc"); // byte 512 = 0x82 (not boundary)
        assert!(long_path.len() > MAX_AUDIT_PATH_LEN);
        // Should not panic
        let mut end = MAX_AUDIT_PATH_LEN;
        while !long_path.is_char_boundary(end) { end -= 1; }
        let truncated = format!("{}…", &long_path[..end]);
        assert!(truncated.ends_with('…'), "truncated path must end with ellipsis");
        // The char boundary walk-back must have settled at byte 511 (= before '€')
        assert_eq!(end, MAX_AUDIT_PATH_LEN - 1);
    }

    #[test]
    fn path_truncation_ascii_at_exact_limit_keeps_full_limit() {
        // An all-ASCII path of exactly MAX_AUDIT_PATH_LEN + 1 bytes:
        // char boundary is at every byte, so end stays at MAX_AUDIT_PATH_LEN.
        let long_path = "a".repeat(MAX_AUDIT_PATH_LEN + 1);
        let mut end = MAX_AUDIT_PATH_LEN;
        while !long_path.is_char_boundary(end) { end -= 1; }
        assert_eq!(end, MAX_AUDIT_PATH_LEN, "ASCII boundary walk-back must be a no-op");
        let truncated = format!("{}…", &long_path[..end]);
        assert_eq!(truncated.len(), MAX_AUDIT_PATH_LEN + "…".len());
    }
}
