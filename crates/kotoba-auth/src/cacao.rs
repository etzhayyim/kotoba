use serde::{Deserialize, Serialize};
use thiserror::Error;
use super::eth;
use super::did_key;

#[derive(Debug, Error)]
pub enum CacaoError {
    #[error("cbor parse: {0}")]
    ParseError(String),
    #[error("unsupported sig type: {0}")]
    UnsupportedSigType(String),
    #[error("eth sig error: {0}")]
    EthSig(#[from] eth::EthError),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("address mismatch: expected {expected}, got {got}")]
    AddressMismatch { expected: String, got: String },
    #[error("did:key parse error: {0}")]
    DidKeyParse(String),
    #[error("ed25519 verification error: {0}")]
    Ed25519(String),
}

/// CACAO — Chain Agnostic Capability Authorization Object (CAIP-74)
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
    /// Issuer DID (did:pkh:eip155:N:0x... or did:erc725:...)
    pub iss: String,
    /// Audience (this Kotoba node's DID or URI)
    pub aud: String,
    #[serde(rename = "iat")]
    pub issued_at: String,
    #[serde(rename = "exp")]
    pub expiry: Option<String>,
    pub nonce: String,
    /// Requesting domain (e.g. "kotoba.example.com")
    #[serde(default)]
    pub domain: String,
    /// EIP-4361 optional statement
    #[serde(default)]
    pub statement: Option<String>,
    /// Message version (default "1")
    #[serde(default = "default_version")]
    pub version: String,
    /// Capability resources as URIs
    #[serde(default)]
    pub resources: Vec<String>,
}

fn default_version() -> String { "1".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacaoSig {
    /// "eip191" | "EdDSA"
    pub t: String,
    pub s: String, // hex (with or without 0x prefix) or base64
}

impl Cacao {
    /// Parse CACAO from DAG-CBOR bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CacaoError> {
        ciborium::from_reader(bytes)
            .map_err(|e| CacaoError::ParseError(e.to_string()))
    }

    /// Reconstruct the EIP-4361 plaintext message that was signed.
    pub fn siwe_message(&self) -> String {
        let p = &self.p;
        // Extract address from iss (last colon-separated segment)
        let address = p.iss.split(':').last().unwrap_or(&p.iss);
        // Extract chain id from did:pkh:eip155:N:0x... → "N"
        // NOTE: for did:erc725:gftd:260425:0x... this returns "260425" (date code),
        // not a real EVM chain ID. TODO: future verification should handle this case
        // explicitly and map date codes to chain IDs or require did:pkh format.
        let chain_id = p.iss.split(':')
            .rev().nth(1)
            .unwrap_or("1");

        let mut lines = Vec::new();
        lines.push(format!("{} wants you to sign in with your Ethereum account:", p.domain));
        lines.push(address.to_string());
        lines.push(String::new());
        if let Some(stmt) = &p.statement {
            lines.push(stmt.clone());
            lines.push(String::new());
        }
        lines.push(format!("URI: {}", p.aud));
        lines.push(format!("Version: {}", p.version));
        lines.push(format!("Chain ID: {}", chain_id));
        lines.push(format!("Nonce: {}", p.nonce));
        lines.push(format!("Issued At: {}", p.issued_at));
        if let Some(exp) = &p.expiry {
            lines.push(format!("Expiration Time: {}", exp));
        }
        if !p.resources.is_empty() {
            lines.push("Resources:".to_string());
            for r in &p.resources {
                lines.push(format!("- {}", r));
            }
        }
        lines.join("\n")
    }

    /// Verify the CACAO signature.
    ///
    /// - `"eip191"` — EIP-191 personal_sign + secp256k1 recovery.
    ///   Returns `did:erc725:gftd:260425:0x{addr}`.
    /// - `"EdDSA"` — Ed25519 signature over the SIWE plaintext.
    ///   Issuer must be `did:key:z6Mk...`. Returns the issuer DID unchanged.
    pub fn verify_signature(&self) -> Result<String, CacaoError> {
        match self.s.t.as_str() {
            "eip191" => {
                let expected_addr = eth::parse_eth_address_from_did(&self.p.iss)?;
                let msg = self.siwe_message();
                let hash = eth::personal_sign_hash(msg.as_bytes());
                let sig_hex = self.s.s.trim_start_matches("0x");
                let sig_bytes = hex::decode(sig_hex)?;
                let recovered = eth::recover_eth_address(&hash, &sig_bytes)?;
                if recovered != expected_addr {
                    return Err(CacaoError::AddressMismatch {
                        expected: hex::encode(expected_addr),
                        got:      hex::encode(recovered),
                    });
                }
                Ok(eth::eth_address_to_erc725_did(&recovered))
            }
            "EdDSA" => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                let pubkey_bytes = did_key::parse_ed25519_did_key(&self.p.iss)
                    .map_err(|e| CacaoError::DidKeyParse(e.to_string()))?;
                let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
                    .map_err(|e| CacaoError::Ed25519(e.to_string()))?;

                let msg = self.siwe_message();
                let sig_bytes = decode_sig_bytes(&self.s.s)?;

                let sig_arr: [u8; 64] = sig_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| CacaoError::Ed25519(format!(
                        "expected 64-byte signature, got {}", sig_bytes.len()
                    )))?;
                let signature = Signature::from_bytes(&sig_arr);

                verifying_key
                    .verify(msg.as_bytes(), &signature)
                    .map_err(|e| CacaoError::Ed25519(e.to_string()))?;

                Ok(self.p.iss.clone())
            }
            other => Err(CacaoError::UnsupportedSigType(other.to_string())),
        }
    }
}

/// Decode a signature string — tries base64url (no-pad) first, then hex.
fn decode_sig_bytes(s: &str) -> Result<Vec<u8>, CacaoError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    // base64url (no padding) — typical for did:key / EdDSA CACAO
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(s) {
        return Ok(bytes);
    }
    // hex fallback (with or without 0x prefix)
    let s = s.trim_start_matches("0x");
    hex::decode(s).map_err(CacaoError::Hex)
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
