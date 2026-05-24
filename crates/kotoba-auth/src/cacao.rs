use serde::{Deserialize, Serialize};

/// CACAO — Chain Agnostic Capability Authorization Object (CAIP-74)
/// Used as UCAN-like delegation chain via resources[] URI encoding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cacao {
    pub h: CacaoHeader,
    pub p: CacaoPayload,
    pub s: CacaoSig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoHeader {
    /// "eip4361" | "caip122"
    pub t: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoPayload {
    /// Issuer DID (did:pkh or did:key)
    pub iss: String,
    /// Audience (this Kotoba node's DID)
    pub aud: String,
    #[serde(rename = "iat")]
    pub issued_at: String,
    #[serde(rename = "exp")]
    pub expiry: Option<String>,
    pub nonce: String,
    /// Capability resources as URIs
    /// e.g. ["kotoba://graph/bafy...", "kotoba://can/graph/write", "kotoba://prf/bafy..."]
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoSig {
    /// "eip191" | "EdDSA"
    pub t: String,
    pub s: String, // hex or base64
}

impl CacaoPayload {
    pub fn graph_cid(&self) -> Option<&str> {
        self.resources.iter()
            .find(|r| r.starts_with("kotoba://graph/"))
            .map(|r| &r["kotoba://graph/".len()..])
    }

    pub fn capability(&self) -> Option<&str> {
        self.resources.iter()
            .find(|r| r.starts_with("kotoba://can/"))
            .map(|r| &r["kotoba://can/".len()..])
    }

    pub fn proof_cid(&self) -> Option<&str> {
        self.resources.iter()
            .find(|r| r.starts_with("kotoba://prf/"))
            .map(|r| &r["kotoba://prf/".len()..])
    }
}
