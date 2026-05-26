use serde::{Deserialize, Serialize};

const X25519_KEY_TYPE: &str  = "X25519KeyAgreementKey2020";
const ED25519_KEY_TYPE_2020: &str = "Ed25519VerificationKey2020";
const ED25519_KEY_TYPE_2018: &str = "Ed25519VerificationKey2018";

/// DID Document — Kotoba Vertex declaration
/// capabilityInvocation key → Source Chain write right
/// capabilityDelegation key → CACAO delegation issuance
/// service[KotobaNode] → 8-bit frame endpoint (libp2p multiaddr)
/// service[KotobaGraphMembership] → Pregel Edge declaration (graph subscriptions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
    #[serde(rename = "capabilityInvocation")]
    pub capability_invocation: Vec<String>,
    #[serde(rename = "capabilityDelegation")]
    pub capability_delegation: Vec<String>,
    pub service: Vec<ServiceEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub key_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub endpoint: ServiceEndpointValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServiceEndpointValue {
    Single(String),
    Multiple(Vec<String>),
}

impl DidDocument {
    pub fn kotoba_endpoint(&self) -> Option<&str> {
        self.service.iter()
            .find(|s| s.service_type == "KotobaNode")
            .and_then(|s| match &s.endpoint {
                ServiceEndpointValue::Single(u) => Some(u.as_str()),
                _ => None,
            })
    }

    pub fn graph_memberships(&self) -> Vec<&str> {
        self.service.iter()
            .find(|s| s.service_type == "KotobaGraphMembership")
            .and_then(|s| match &s.endpoint {
                ServiceEndpointValue::Multiple(v) => Some(v.iter().map(|s| s.as_str()).collect()),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// Extract the X25519 key agreement public key from `verificationMethod`.
    ///
    /// Returns `None` if no `X25519KeyAgreementKey2020` entry is present or
    /// if the multibase-encoded key cannot be decoded to exactly 32 bytes.
    pub fn x25519_public_key(&self) -> Option<[u8; 32]> {
        let vm = self.verification_method
            .iter()
            .find(|vm| vm.key_type == X25519_KEY_TYPE)?;

        let (_base, raw) = multibase::decode(&vm.public_key_multibase).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        Some(key)
    }

    /// Extract the Ed25519 verification public key from `verificationMethod`.
    ///
    /// Searches for `Ed25519VerificationKey2020` or `Ed25519VerificationKey2018`.
    /// Returns `None` if no matching entry is present or the multibase-encoded
    /// key cannot be decoded to exactly 32 bytes.
    pub fn ed25519_public_key(&self) -> Option<[u8; 32]> {
        let vm = self.verification_method.iter().find(|vm| {
            vm.key_type == ED25519_KEY_TYPE_2020 || vm.key_type == ED25519_KEY_TYPE_2018
        })?;

        let (_base, raw) = multibase::decode(&vm.public_key_multibase).ok()?;
        if raw.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        Some(key)
    }
}
