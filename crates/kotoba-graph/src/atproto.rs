// AT Protocol bridge for KOTOBA
//
// Mapping:
//   AT DID      → KotobaCid::from_bytes(did.as_bytes())
//   AT collection NSID → KotobaCid::from_bytes(nsid.as_bytes())
//   AT URI      → Quad(graph=collection_cid, subject=did_cid, pred=rkey, object=record_cid_or_text)
//   AT CID str  → KotobaCid (parse multibase, validate CIDv1 dag-cbor blake3)
//   Jetstream commit event → (Topic("jetstream/<collection>"), Quad)
//   Jetstream identity event → (Topic("jetstream/identity"), Quad(pred="handle", object=Text(handle)))

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kse::topic::Topic;

// ── KotobaCid helpers ─────────────────────────────────────────────────────────

/// Hash a DID string with blake3 → KotobaCid (stable, content-addressed entity id).
pub fn did_to_cid(did: &str) -> KotobaCid {
    KotobaCid::from_bytes(did.as_bytes())
}

/// Hash an NSID (collection) string → KotobaCid (stable named graph id per collection).
pub fn collection_to_cid(collection: &str) -> KotobaCid {
    KotobaCid::from_bytes(collection.as_bytes())
}

/// Parse an AT Protocol CID multibase string → KotobaCid.
///
/// AT CIDs are CIDv1 dag-cbor blake3-256 (36 bytes).
/// - `b` prefix → base32lower (RFC 4648 no-pad)
/// - `z` prefix → base58btc (not supported yet; logs a warning and returns None)
pub fn at_cid_str_to_kotoba(s: &str) -> Option<KotobaCid> {
    let (prefix, rest) = s.split_at(1);
    match prefix {
        "b" => {
            // base32lower — data_encoding expects uppercase; convert first
            let upper = rest.to_uppercase();
            let bytes = data_encoding::BASE32_NOPAD.decode(upper.as_bytes()).ok()?;
            validate_cid_bytes(&bytes)
        }
        "z" => {
            tracing::warn!("at_cid_str_to_kotoba: base58btc (z prefix) not yet supported: {}", s);
            None
        }
        other => {
            tracing::warn!("at_cid_str_to_kotoba: unknown multibase prefix {:?}", other);
            None
        }
    }
}

fn validate_cid_bytes(bytes: &[u8]) -> Option<KotobaCid> {
    if bytes.len() != 36 {
        tracing::warn!("at_cid_str_to_kotoba: expected 36 bytes, got {}", bytes.len());
        return None;
    }
    // CIDv1 dag-cbor blake3-256 layout:
    //   [0] = 1 (version)  [1] = 0x71 (dag-cbor)  [2] = 0x1e (blake3)  [3] = 32 (hash len)
    if bytes[0] != 1 || bytes[1] != KotobaCid::CODEC_DAG_CBOR || bytes[2] != KotobaCid::MH_BLAKE3 || bytes[3] != 32 {
        tracing::warn!(
            "at_cid_str_to_kotoba: invalid CID header {:02x} {:02x} {:02x} {:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        );
        return None;
    }
    let mut arr = [0u8; 36];
    arr.copy_from_slice(bytes);
    Some(KotobaCid(arr))
}

// ── AtUri ────────────────────────────────────────────────────────────────────

/// Parsed AT Protocol URI: `at://{authority}/{collection}/{rkey}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtUri {
    /// DID or handle (authority component)
    pub authority: String,
    /// Collection NSID
    pub collection: String,
    /// Record key (may be empty for collection-level URIs)
    pub rkey: String,
}

impl AtUri {
    /// Parse an `at://` URI string.
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("at://")?;
        let mut parts = rest.splitn(3, '/');
        let authority = parts.next()?.to_string();
        let collection = parts.next().unwrap_or("").to_string();
        let rkey = parts.next().unwrap_or("").to_string();

        if authority.is_empty() {
            return None;
        }
        Some(Self { authority, collection, rkey })
    }

    /// Convert to EAVT Quad.
    ///
    /// - `graph`   = `collection_to_cid(&self.collection)`
    /// - `subject` = `did_to_cid(&self.authority)`
    /// - `pred`    = `self.rkey`
    /// - `object`  = `QuadObject::Cid(record_cid)` if provided, else `QuadObject::Text("at://{self}")`
    pub fn to_quad(&self, record_cid: Option<KotobaCid>) -> Quad {
        Quad {
            graph:     collection_to_cid(&self.collection),
            subject:   did_to_cid(&self.authority),
            predicate: self.rkey.clone(),
            object:    match record_cid {
                Some(cid) => QuadObject::Cid(cid),
                None      => QuadObject::Text(format!("at://{self}")),
            },
        }
    }
}

impl std::fmt::Display for AtUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rkey.is_empty() {
            write!(f, "at://{}/{}", self.authority, self.collection)
        } else {
            write!(f, "at://{}/{}/{}", self.authority, self.collection, self.rkey)
        }
    }
}

// ── Jetstream event types ────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct JetstreamEvent {
    pub did:      String,
    pub time_us:  u64,
    pub kind:     String,
    pub commit:   Option<JetstreamCommit>,
    pub identity: Option<JetstreamIdentity>,
    pub account:  Option<JetstreamAccount>,
}

#[derive(Debug, serde::Deserialize)]
pub struct JetstreamCommit {
    pub rev:        String,
    pub operation:  String,  // "create" | "update" | "delete"
    pub collection: String,
    pub rkey:       String,
    pub cid:        Option<String>,           // AT CID string (None for delete)
    pub record:     Option<serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
pub struct JetstreamIdentity {
    pub did:    String,
    pub handle: Option<String>,
    pub seq:    Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct JetstreamAccount {
    pub did:    String,
    pub active: bool,
    pub status: Option<String>,
}

// ── Jetstream → (Topic, Quad) ─────────────────────────────────────────────────

/// Convert a raw Jetstream JSON event to `(Topic, Quad)` suitable for KOTOBA ingest.
///
/// Returns `None` for unknown or malformed events.
pub fn jetstream_event_to_quad(json: &[u8]) -> Option<(Topic, Quad)> {
    let event: JetstreamEvent = serde_json::from_slice(json)
        .map_err(|e| tracing::warn!("jetstream_event_to_quad: parse error: {e}"))
        .ok()?;

    match event.kind.as_str() {
        "commit" => {
            let commit = event.commit.as_ref()?;
            let topic = jetstream_subject_to_topic(&commit.collection);
            let graph   = collection_to_cid(&commit.collection);
            let subject = did_to_cid(&event.did);
            let object = match &commit.cid {
                Some(cid_str) => {
                    let kc = at_cid_str_to_kotoba(cid_str)?;
                    QuadObject::Cid(kc)
                }
                None => QuadObject::Text("delete".to_string()),
            };
            let quad = Quad {
                graph,
                subject,
                predicate: commit.rkey.clone(),
                object,
            };
            Some((topic, quad))
        }

        "identity" => {
            let identity = event.identity.as_ref()?;
            let topic   = Topic("jetstream/identity".to_string());
            let graph   = collection_to_cid("com.atproto.identity");
            let subject = did_to_cid(&event.did);
            let quad = Quad {
                graph,
                subject,
                predicate: "handle".to_string(),
                object:    QuadObject::Text(identity.handle.clone().unwrap_or_default()),
            };
            Some((topic, quad))
        }

        "account" => {
            let account = event.account.as_ref()?;
            let topic   = Topic("jetstream/account".to_string());
            let graph   = collection_to_cid("com.atproto.account");
            let subject = did_to_cid(&event.did);
            let quad = Quad {
                graph,
                subject,
                predicate: "active".to_string(),
                object:    QuadObject::Bool(account.active),
            };
            Some((topic, quad))
        }

        other => {
            tracing::warn!("jetstream_event_to_quad: unknown kind {:?}", other);
            None
        }
    }
}

/// Map an AT Protocol collection NSID to a KSE Topic: `jetstream/{collection}`.
pub fn jetstream_subject_to_topic(collection: &str) -> Topic {
    Topic(format!("jetstream/{collection}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_uri_parse_full() {
        let uri = AtUri::parse("at://did:plc:abc/app.bsky.feed.post/3xyz").unwrap();
        assert_eq!(uri.authority, "did:plc:abc");
        assert_eq!(uri.collection, "app.bsky.feed.post");
        assert_eq!(uri.rkey, "3xyz");
    }

    #[test]
    fn at_uri_to_quad_has_correct_pred() {
        let uri = AtUri::parse("at://did:plc:abc/app.bsky.feed.post/3xyz").unwrap();
        let quad = uri.to_quad(None);
        assert_eq!(quad.predicate, "3xyz");
    }

    #[test]
    fn did_to_cid_is_stable() {
        let c1 = did_to_cid("did:plc:xyz123");
        let c2 = did_to_cid("did:plc:xyz123");
        assert_eq!(c1, c2);
    }

    #[test]
    fn collection_cid_differs_by_nsid() {
        let c1 = collection_to_cid("app.bsky.feed.post");
        let c2 = collection_to_cid("app.bsky.feed.like");
        assert_ne!(c1, c2);
    }

    #[test]
    fn jetstream_commit_event_to_quad() {
        let json = br#"{
            "did": "did:plc:test",
            "time_us": 1000,
            "kind": "commit",
            "commit": {
                "rev": "3abc",
                "operation": "create",
                "collection": "app.bsky.feed.post",
                "rkey": "3xyz",
                "cid": null,
                "record": {"$type": "app.bsky.feed.post", "text": "hello"}
            }
        }"#;
        let (topic, quad) = jetstream_event_to_quad(json).unwrap();
        assert!(topic.0.starts_with("jetstream/app.bsky.feed.post"));
        assert_eq!(quad.predicate, "3xyz");
    }

    #[test]
    fn jetstream_identity_event_to_quad() {
        let json = br#"{
            "did": "did:plc:test",
            "time_us": 1000,
            "kind": "identity",
            "identity": { "did": "did:plc:test", "handle": "alice.bsky.social" }
        }"#;
        let (topic, quad) = jetstream_event_to_quad(json).unwrap();
        assert_eq!(topic.0, "jetstream/identity");
        assert_eq!(quad.predicate, "handle");
        assert!(matches!(quad.object, QuadObject::Text(ref s) if s == "alice.bsky.social"));
    }

    #[test]
    fn at_cid_roundtrip_via_kotoba_cid() {
        // Create a KotobaCid, convert to multibase, parse back
        let data = b"test block data";
        let cid = KotobaCid::from_bytes(data);
        let multibase = cid.to_multibase();
        // Should parse back to the same cid
        let parsed = at_cid_str_to_kotoba(&multibase).unwrap();
        assert_eq!(parsed, cid);
    }

    #[test]
    fn at_uri_display_with_rkey() {
        let uri = AtUri {
            authority:  "did:plc:abc".to_string(),
            collection: "app.bsky.feed.post".to_string(),
            rkey:       "3xyz".to_string(),
        };
        assert_eq!(uri.to_string(), "at://did:plc:abc/app.bsky.feed.post/3xyz");
    }

    #[test]
    fn at_uri_display_without_rkey() {
        let uri = AtUri {
            authority:  "did:plc:abc".to_string(),
            collection: "app.bsky.feed.post".to_string(),
            rkey:       String::new(),
        };
        assert_eq!(uri.to_string(), "at://did:plc:abc/app.bsky.feed.post");
    }

    #[test]
    fn at_cid_invalid_prefix_returns_none() {
        assert!(at_cid_str_to_kotoba("mINVALIDSTUFF").is_none());
    }

    #[test]
    fn jetstream_account_event_to_quad() {
        let json = br#"{
            "did": "did:plc:test",
            "time_us": 1000,
            "kind": "account",
            "account": { "did": "did:plc:test", "active": true }
        }"#;
        let (topic, quad) = jetstream_event_to_quad(json).unwrap();
        assert_eq!(topic.0, "jetstream/account");
        assert_eq!(quad.predicate, "active");
        assert!(matches!(quad.object, QuadObject::Bool(true)));
    }
}
