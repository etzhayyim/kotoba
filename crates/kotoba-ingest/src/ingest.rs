//! Core email ingest: parse RFC 2822 → E2E encrypt → QuadStore assert.

use std::sync::Arc;
use anyhow::{Context, Result};
use bytes::Bytes;
use mail_parser::{Address, MessageParser};

use kotoba_core::cid::KotobaCid;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kse::Vault;
use kotoba_graph::QuadStore;
use kotoba_crypto::AgentCrypto;

/// Ingest raw RFC 2822 emails into the kotoba encrypted quad graph.
pub struct EmailIngestor {
    /// Opaque crypto engine — encrypts/decrypts but never exposes raw key bytes.
    pub crypto:    Arc<dyn AgentCrypto>,
    /// Content-addressed blob vault (stores encrypted body bytes).
    pub vault:     Arc<Vault>,
    pub quad_store: Arc<QuadStore>,
    pub graph_cid:  KotobaCid,
    pub owner_did:  String,
}

impl EmailIngestor {
    pub fn new(
        crypto:    Arc<dyn AgentCrypto>,
        vault:     Arc<Vault>,
        quad_store: Arc<QuadStore>,
        owner_did:  String,
    ) -> Self {
        let graph_cid = graph_cid_for(&owner_did);
        Self { crypto, vault, quad_store, graph_cid, owner_did }
    }

    /// Ingest a single raw RFC 2822 message.  Returns the email's CID.
    ///
    /// Idempotent: the same Message-ID always maps to the same CID so
    /// re-ingesting a message is a no-op at the QuadStore level.
    pub async fn ingest_raw(&self, raw: &[u8], thread_id: &str) -> Result<KotobaCid> {
        let msg = MessageParser::default()
            .parse(raw)
            .ok_or_else(|| anyhow::anyhow!("mail-parser: failed to parse message"))?;

        // Stable CID: prefer Message-ID; fallback to blake3 of raw bytes
        let message_id = msg.message_id().unwrap_or("").to_string();
        let email_cid = if message_id.is_empty() {
            KotobaCid::from_bytes(blake3::hash(raw).as_bytes())
        } else {
            KotobaCid::from_bytes(message_id.as_bytes())
        };

        // ── 1. body → Vault (AES-256-GCM ciphertext blob) ───────────────────
        let body_text = msg.body_text(0)
            .map(|c| c.into_owned())
            .unwrap_or_default();
        let enc_body = self.crypto
            .encrypt_blob(body_text.as_bytes())
            .await
            .context("AgentCrypto::encrypt_blob body failed")?;
        let blob_ref = self.vault.put(Bytes::from(enc_body)).await;

        // ── 2. PII fields → signal:v1: envelope ─────────────────────────────
        let from_str    = addr_header(msg.from());
        let to_str      = addr_header(msg.to());
        let subject_str = msg.subject().unwrap_or("").to_string();

        let enc_from = self.crypto
            .seal_field(b"email/from", &from_str)
            .await
            .context("encrypt from")?;
        let enc_to = self.crypto
            .seal_field(b"email/to", &to_str)
            .await
            .context("encrypt to")?;
        let enc_subject = self.crypto
            .seal_field(b"email/subject", &subject_str)
            .await
            .context("encrypt subject")?;

        let date_str = msg.date()
            .map(|d| d.to_timestamp().to_string())
            .unwrap_or_else(|| unix_now().to_string());

        // ── 3. QuadStore assert (also Journal-published by quad_store.assert) ─
        let fields: &[(&str, String)] = &[
            ("email/message_id",  message_id.clone()),
            ("email/from",        enc_from),
            ("email/to",          enc_to),
            ("email/subject",     enc_subject),
            ("email/body_cid",    blob_ref.cid.to_multibase()),
            ("email/date",        date_str),
            ("email/thread_id",   thread_id.to_string()),
        ];
        for (predicate, object) in fields {
            self.quad_store.assert(Quad {
                graph:     self.graph_cid.clone(),
                subject:   email_cid.clone(),
                predicate: predicate.to_string(),
                object:    QuadObject::Text(object.clone()),
            }).await;
        }

        tracing::info!(
            message_id,
            cid = %email_cid.to_multibase(),
            owner = %self.owner_did,
            "email ingested (E2E encrypted)"
        );
        Ok(email_cid)
    }

    /// Decrypt the body blob stored for a given `BlobRef` CID (multibase).
    pub async fn decrypt_body(&self, body_cid_mb: &str) -> Result<String> {
        let cid = KotobaCid::from_multibase(body_cid_mb)
            .ok_or_else(|| anyhow::anyhow!("invalid body_cid multibase: {body_cid_mb}"))?;
        let enc_bytes = self.vault.get(&cid).await
            .ok_or_else(|| anyhow::anyhow!("body blob not found in vault: {body_cid_mb}"))?;
        let pt = self.crypto.decrypt_blob(&enc_bytes).await
            .context("AgentCrypto::decrypt_blob body failed")?;
        String::from_utf8(pt.to_vec())
            .context("body is not valid UTF-8")
    }
}

/// Derive the inbox named-graph CID for an owner DID.
pub fn graph_cid_for(owner_did: &str) -> KotobaCid {
    KotobaCid::from_bytes(format!("email/inbox/{owner_did}").as_bytes())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr_header(addr: Option<&Address<'_>>) -> String {
    match addr {
        None => String::new(),
        Some(Address::List(list)) => list.iter()
            .map(|a| format!(
                "{} <{}>",
                a.name.as_deref().unwrap_or(""),
                a.address.as_deref().unwrap_or(""),
            ))
            .collect::<Vec<_>>()
            .join(", "),
        Some(Address::Group(groups)) => groups.iter()
            .flat_map(|g| g.addresses.iter())
            .map(|a| format!(
                "{} <{}>",
                a.name.as_deref().unwrap_or(""),
                a.address.as_deref().unwrap_or(""),
            ))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use kotoba_kse::{Journal, Vault};
    use kotoba_graph::QuadStore;
    use kotoba_store::MemoryBlockStore;
    use kotoba_crypto::{AgentCrypto, VaultKeyedCrypto};
    use zeroize::Zeroizing;

    fn test_crypto() -> Arc<dyn AgentCrypto> {
        let key = Zeroizing::new([0x42u8; 32]);
        Arc::new(VaultKeyedCrypto::new(key))
    }

    fn make_ingestor() -> EmailIngestor {
        let journal     = Arc::new(Journal::new());
        let block_store = Arc::new(MemoryBlockStore::new()) as Arc<dyn kotoba_core::store::BlockStore + Send + Sync>;
        let quad_store  = Arc::new(QuadStore::new(journal, block_store));
        let vault       = Arc::new(Vault::new());
        EmailIngestor::new(
            test_crypto(),
            vault,
            quad_store,
            "did:plc:test".to_string(),
        )
    }

    const SAMPLE_EMAIL: &[u8] = b"From: Alice <alice@example.com>\r\n\
        To: Bob <bob@example.com>\r\n\
        Subject: Test message\r\n\
        Message-ID: <test-001@example.com>\r\n\
        Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
        \r\n\
        Hello from kotoba-ingest!";

    #[tokio::test]
    async fn ingest_returns_cid() {
        let ing = make_ingestor();
        let cid = ing.ingest_raw(SAMPLE_EMAIL, "thread-001").await.unwrap();
        assert!(!cid.to_multibase().is_empty());
    }

    #[tokio::test]
    async fn ingest_is_idempotent_same_message_id() {
        let ing = make_ingestor();
        let cid1 = ing.ingest_raw(SAMPLE_EMAIL, "t1").await.unwrap();
        let cid2 = ing.ingest_raw(SAMPLE_EMAIL, "t1").await.unwrap();
        assert_eq!(cid1, cid2, "same Message-ID must produce same CID");
    }

    #[tokio::test]
    async fn body_stored_as_ciphertext_not_plaintext() {
        let ing = make_ingestor();
        let cid = ing.ingest_raw(SAMPLE_EMAIL, "t").await.unwrap();

        // Verify body_cid quad exists
        let graph_cid   = graph_cid_for("did:plc:test");
        let arrangement = ing.quad_store.arrangement(&graph_cid).await
            .expect("arrangement must exist after ingest");
        let body_cid_objs = arrangement.get_objects(&cid, "email/body_cid");
        assert_eq!(body_cid_objs.len(), 1, "body_cid quad must exist");

        // Retrieve the body blob and verify it is encrypted (not plaintext)
        if let kotoba_kqe::quad::QuadObject::Text(body_cid_mb) = &body_cid_objs[0] {
            let vault_cid = KotobaCid::from_multibase(body_cid_mb).unwrap();
            let enc_blob = ing.vault.get(&vault_cid).await.expect("blob must be in vault");
            // Encrypted blob should NOT contain the plaintext
            assert!(
                !enc_blob.windows(b"Hello from".len()).any(|w| w == b"Hello from"),
                "body blob must not contain plaintext"
            );
        } else {
            panic!("expected Text for body_cid");
        }
    }

    #[tokio::test]
    async fn subject_stored_as_signal_envelope() {
        let ing = make_ingestor();
        let cid = ing.ingest_raw(SAMPLE_EMAIL, "t").await.unwrap();

        let graph_cid = graph_cid_for("did:plc:test");
        let arr = ing.quad_store.arrangement(&graph_cid).await.unwrap();
        let subj_objs = arr.get_objects(&cid, "email/subject");
        assert_eq!(subj_objs.len(), 1);
        if let kotoba_kqe::quad::QuadObject::Text(enc) = &subj_objs[0] {
            assert!(enc.starts_with("signal:v1:"), "subject must be signal:v1: envelope, got: {enc}");
        } else {
            panic!("expected Text object for email/subject");
        }
    }

    #[tokio::test]
    async fn decrypt_body_roundtrip() {
        let ing = make_ingestor();
        let _cid = ing.ingest_raw(SAMPLE_EMAIL, "t").await.unwrap();

        let graph_cid   = graph_cid_for("did:plc:test");
        let arrangement = ing.quad_store.arrangement(&graph_cid).await.unwrap();
        let body_cid_objs = arrangement.get_objects(&_cid, "email/body_cid");
        if let kotoba_kqe::quad::QuadObject::Text(body_cid_mb) = &body_cid_objs[0] {
            let body = ing.decrypt_body(body_cid_mb).await.unwrap();
            assert!(body.contains("Hello from kotoba-ingest!"), "body={body}");
        } else {
            panic!("expected Text for body_cid");
        }
    }
}
