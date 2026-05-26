pub mod did_document;
pub mod cacao;
pub mod delegation;
pub mod eth;
pub mod did_key;
pub mod resolver;

pub use did_document::{DidDocument, VerificationMethod, ServiceEndpoint};
pub use cacao::{Cacao, CacaoHeader, CacaoPayload, CacaoSig, CacaoError};
pub use delegation::{DelegationChain, DelegationError};
pub use eth::{eth_address_to_erc725_did, personal_sign_hash, recover_eth_address};
pub use did_key::{parse_ed25519_did_key, ed25519_pubkey_to_did_key};
pub use resolver::{DidDocumentResolver, DidResolverError, InMemoryDidResolver};

#[cfg(test)]
mod tests {
    use super::*;
    use cacao::{Cacao, CacaoHeader, CacaoPayload, CacaoSig};
    use bytes::Bytes;

    // ── eth helpers ────────────────────────────────────────────────────────

    #[test]
    fn personal_sign_hash_is_deterministic() {
        let h1 = eth::personal_sign_hash(b"hello");
        let h2 = eth::personal_sign_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn personal_sign_hash_differs_for_different_messages() {
        let h1 = eth::personal_sign_hash(b"hello");
        let h2 = eth::personal_sign_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn parse_eth_address_did_pkh() {
        let did = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";
        let addr = eth::parse_eth_address_from_did(did).expect("valid did:pkh");
        assert_eq!(hex::encode(addr), "ab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
    }

    #[test]
    fn parse_eth_address_erc725() {
        let did = "did:erc725:gftd:260425:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";
        let addr = eth::parse_eth_address_from_did(did).expect("valid did:erc725");
        assert_eq!(hex::encode(addr), "ab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
    }

    #[test]
    fn parse_eth_address_invalid_length_errors() {
        let did = "did:pkh:eip155:1:0xdeadbeef"; // only 4 bytes
        assert!(eth::parse_eth_address_from_did(did).is_err());
    }

    #[test]
    fn eth_address_to_erc725_did_format() {
        let addr = [0xabu8, 0x16, 0xa9, 0x6d, 0x35, 0x9e, 0xc2, 0x6a,
                    0x11, 0xe2, 0xc2, 0xb3, 0xd8, 0xf8, 0xb8, 0x94,
                    0x2d, 0x5b, 0xfc, 0xdb];
        let did = eth_address_to_erc725_did(&addr);
        assert!(did.starts_with("did:erc725:gftd:260425:0x"));
        assert!(did.contains("ab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"));
    }

    #[test]
    fn recover_eth_address_wrong_length_errors() {
        let hash = [0u8; 32];
        let short_sig = vec![0u8; 32]; // not 65 bytes
        assert!(eth::recover_eth_address(&hash, &short_sig).is_err());
    }

    // ── CacaoPayload resource accessors ────────────────────────────────────

    fn test_payload(resources: Vec<String>) -> CacaoPayload {
        CacaoPayload {
            iss: "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb".into(),
            aud: "kotoba://test".into(),
            issued_at: "2026-05-25T00:00:00Z".into(),
            expiry: None,
            nonce: "test123".into(),
            domain: "kotoba.test".into(),
            statement: None,
            version: "1".into(),
            resources,
        }
    }

    #[test]
    fn payload_graph_cid_extracts_correctly() {
        let p = test_payload(vec!["kotoba://graph/bafygraphcid123".into()]);
        assert_eq!(p.graph_cid(), Some("bafygraphcid123"));
    }

    #[test]
    fn payload_capability_extracts_correctly() {
        let p = test_payload(vec!["kotoba://can/quad:write".into()]);
        assert_eq!(p.capability(), Some("quad:write"));
    }

    #[test]
    fn payload_proof_cid_extracts_correctly() {
        let p = test_payload(vec!["kotoba://prf/bafyproofcid456".into()]);
        assert_eq!(p.proof_cid(), Some("bafyproofcid456"));
    }

    #[test]
    fn payload_resource_accessors_return_none_when_absent() {
        let p = test_payload(vec!["https://example.com".into()]);
        assert!(p.graph_cid().is_none());
        assert!(p.capability().is_none());
        assert!(p.proof_cid().is_none());
    }

    // ── Cacao::siwe_message ────────────────────────────────────────────────

    #[test]
    fn siwe_message_contains_required_fields() {
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: test_payload(vec![]),
            s: CacaoSig { t: "eip191".into(), s: "0x00".into() },
        };
        let msg = cacao.siwe_message();
        assert!(msg.contains("kotoba.test wants you to sign in"));
        assert!(msg.contains("URI: kotoba://test"));
        assert!(msg.contains("Version: 1"));
        assert!(msg.contains("Nonce: test123"));
        assert!(msg.contains("Issued At: 2026-05-25T00:00:00Z"));
    }

    #[test]
    fn siwe_message_includes_statement_when_present() {
        let mut p = test_payload(vec![]);
        p.statement = Some("Grant access to Kotoba graph".into());
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p,
            s: CacaoSig { t: "eip191".into(), s: "0x00".into() },
        };
        let msg = cacao.siwe_message();
        assert!(msg.contains("Grant access to Kotoba graph"));
    }

    #[test]
    fn siwe_message_includes_resources_when_present() {
        let p = test_payload(vec![
            "kotoba://graph/bafy123".into(),
            "kotoba://can/quad:write".into(),
        ]);
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p,
            s: CacaoSig { t: "eip191".into(), s: "0x00".into() },
        };
        let msg = cacao.siwe_message();
        assert!(msg.contains("Resources:"));
        assert!(msg.contains("- kotoba://graph/bafy123"));
    }

    // ── Cacao::verify_signature — error paths ─────────────────────────────

    #[test]
    fn verify_signature_unsupported_type_errors() {
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: test_payload(vec![]),
            s: CacaoSig { t: "secp256r1".into(), s: "deaddead".into() },
        };
        let err = cacao.verify_signature().unwrap_err();
        assert!(matches!(err, CacaoError::UnsupportedSigType(_)));
    }

    #[test]
    fn verify_signature_bad_hex_errors() {
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: test_payload(vec![]),
            s: CacaoSig { t: "eip191".into(), s: "not_hex!!".into() },
        };
        assert!(cacao.verify_signature().is_err());
    }

    // ── Cacao::verify_signature — full eip191 roundtrip ───────────────────

    #[test]
    fn verify_signature_eip191_roundtrip() {
        use k256::ecdsa::SigningKey;
        use sha3::{Digest, Keccak256};

        // Known 32-byte test private key
        let sk_bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ];
        let sk = SigningKey::from_bytes((&sk_bytes).into())
            .expect("valid test key");

        // Derive ETH address
        let pk = sk.verifying_key();
        let point = pk.to_encoded_point(false);
        let keccak = Keccak256::digest(&point.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&keccak[12..]);
        let did = eth_address_to_erc725_did(&addr);

        // Build CACAO with a temporary placeholder sig (will be replaced)
        let payload = CacaoPayload {
            iss: did,
            aud: "kotoba://test".into(),
            issued_at: "2026-05-25T00:00:00Z".into(),
            expiry: None,
            nonce: "roundtrip-nonce".into(),
            domain: "kotoba.test".into(),
            statement: None,
            version: "1".into(),
            resources: vec![],
        };
        let mut cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: payload,
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };

        // Compute the SIWE message and sign it
        let msg = cacao.siwe_message();
        let hash = eth::personal_sign_hash(msg.as_bytes());

        let (sig, rec_id) = sk.sign_prehash_recoverable(&hash)
            .expect("sign_prehash_recoverable");

        // Encode as 65 bytes (r||s||v), v = rec_id + 27 (MetaMask legacy)
        let mut sig65 = sig.to_bytes().to_vec();
        sig65.push(u8::from(rec_id) + 27);
        cacao.s.s = hex::encode(&sig65);

        let result = cacao.verify_signature();
        assert!(result.is_ok(), "verify_signature failed: {:?}", result.err());
    }

    // ── Cacao::verify_signature — EdDSA roundtrip ─────────────────────────

    #[test]
    fn verify_signature_eddsa_roundtrip() {
        use ed25519_dalek::{Signer, SigningKey};
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let sk = SigningKey::from_bytes(&[13u8; 32]);
        let pk = sk.verifying_key();
        let did = did_key::ed25519_pubkey_to_did_key(pk.as_bytes());

        let payload = CacaoPayload {
            iss: did.clone(),
            aud: "kotoba://test".into(),
            issued_at: "2026-05-26T00:00:00Z".into(),
            expiry: None,
            nonce: "eddsa-nonce".into(),
            domain: "kotoba.test".into(),
            statement: None,
            version: "1".into(),
            resources: vec!["kotoba://can/quad:write".into()],
        };
        let mut cacao = Cacao {
            h: CacaoHeader { t: "caip122".into() },
            p: payload,
            s: CacaoSig { t: "EdDSA".into(), s: String::new() },
        };

        let msg = cacao.siwe_message();
        let sig = sk.sign(msg.as_bytes());
        cacao.s.s = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        let result = cacao.verify_signature();
        assert!(result.is_ok(), "EdDSA verify failed: {:?}", result.err());
        assert_eq!(result.unwrap(), did);
    }

    // ── DelegationChain ────────────────────────────────────────────────────

    #[test]
    fn delegation_chain_new_stores_cacao() {
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: test_payload(vec![]),
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };
        let chain = delegation::DelegationChain::new(cacao);
        assert_eq!(chain.chain.len(), 1);
    }

    #[test]
    fn delegation_chain_empty_cbor_errors() {
        let result = delegation::DelegationChain::from_cbor(b"");
        assert!(result.is_err());
    }

    #[test]
    fn delegation_verify_chain_depth_exceeded_errors() {
        let cacao1 = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p: test_payload(vec![]),
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };
        let cacao2 = cacao1.clone();
        let mut chain = delegation::DelegationChain::new(cacao1);
        chain.chain.push(cacao2); // forge a second link
        let err = chain.verify("graph_cid", "quad:write").unwrap_err();
        assert!(
            matches!(err, DelegationError::ChainDepthExceeded(2)),
            "expected ChainDepthExceeded(2), got {err:?}"
        );
    }

    #[test]
    fn delegation_verify_expired_returns_expired_error() {
        let mut p = test_payload(vec![]);
        p.expiry = Some("2020-01-01T00:00:00Z".into()); // clearly in the past
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p,
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };
        let chain = delegation::DelegationChain::new(cacao);
        let err = chain.verify("graph_cid", "quad:write").unwrap_err();
        assert!(matches!(err, DelegationError::Expired), "expected Expired, got {err:?}");
    }

    #[test]
    fn delegation_verify_non_utc_exp_returns_invalid_expiry() {
        let mut p = test_payload(vec![]);
        // +09:00 offset: would corrupt lexicographic comparison against `...Z` now_iso
        p.expiry = Some("2099-01-01T09:00:00+09:00".into());
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p,
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };
        let chain = delegation::DelegationChain::new(cacao);
        let err = chain.verify("graph_cid", "quad:write").unwrap_err();
        assert!(matches!(err, DelegationError::InvalidExpiry(_)),
            "expected InvalidExpiry, got {err:?}");
    }

    #[test]
    fn delegation_verify_old_cacao_without_exp_is_rejected() {
        let mut p = test_payload(vec![]);
        // issued more than 7 days ago — should be rejected by max-age check
        p.issued_at = "2020-01-01T00:00:00Z".into();
        p.expiry = None;
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p,
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };
        let chain = delegation::DelegationChain::new(cacao);
        let err = chain.verify("graph_cid", "quad:write").unwrap_err();
        assert!(matches!(err, DelegationError::Expired),
            "expected Expired (max-age), got {err:?}");
    }

    #[test]
    fn delegation_verify_invalid_iat_format_is_rejected() {
        let mut p = test_payload(vec![]);
        p.issued_at = "not-a-date".into();
        p.expiry = None;
        let cacao = Cacao {
            h: CacaoHeader { t: "eip4361".into() },
            p,
            s: CacaoSig { t: "eip191".into(), s: "00".into() },
        };
        let chain = delegation::DelegationChain::new(cacao);
        let err = chain.verify("graph_cid", "quad:write").unwrap_err();
        assert!(matches!(err, DelegationError::InvalidExpiry(_)),
            "expected InvalidExpiry, got {err:?}");
    }

    // ── DidDocument ────────────────────────────────────────────────────────

    fn test_did_doc() -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:erc725:gftd:260425:0xtest".into(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![
                ServiceEndpoint {
                    id: "#kotoba".into(),
                    service_type: "KotobaNode".into(),
                    endpoint: did_document::ServiceEndpointValue::Single(
                        "/ip4/127.0.0.1/tcp/4001".into()
                    ),
                },
                ServiceEndpoint {
                    id: "#graphs".into(),
                    service_type: "KotobaGraphMembership".into(),
                    endpoint: did_document::ServiceEndpointValue::Multiple(vec![
                        "bafy123".into(),
                        "bafy456".into(),
                    ]),
                },
            ],
        }
    }

    #[test]
    fn did_document_kotoba_endpoint() {
        let doc = test_did_doc();
        assert_eq!(doc.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
    }

    #[test]
    fn did_document_kotoba_endpoint_none_when_absent() {
        let mut doc = test_did_doc();
        doc.service.retain(|s| s.service_type != "KotobaNode");
        assert!(doc.kotoba_endpoint().is_none());
    }

    #[test]
    fn did_document_graph_memberships() {
        let doc = test_did_doc();
        let graphs = doc.graph_memberships();
        assert_eq!(graphs.len(), 2);
        assert!(graphs.contains(&"bafy123"));
        assert!(graphs.contains(&"bafy456"));
    }

    #[test]
    fn did_document_json_roundtrip() {
        let doc = test_did_doc();
        let json = serde_json::to_string(&doc).expect("serialize");
        let doc2: DidDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(doc.id, doc2.id);
        assert_eq!(doc.service.len(), doc2.service.len());
    }
}
