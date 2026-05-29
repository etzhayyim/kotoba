//! W3C Verifiable Credential / Presentation model for Kotoba.
//!
//! This crate is the protocol boundary for VC Data Model 2.0 objects.  The
//! storage boundary remains Kotoba Datom: every credential and presentation can
//! be projected into `(E,A,V,T,Added)` facts.

use kotoba_core::cid::KotobaCid;
use kotoba_datomic::Datom;
use kotoba_edn::EdnValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VC_CONTEXT_V2: &str = "https://www.w3.org/ns/credentials/v2";
pub const DATA_INTEGRITY_CONTEXT: &str = "https://w3id.org/security/data-integrity/v2";

pub const ATTR_CREDENTIAL_ID: &str = "credential/id";
pub const ATTR_CREDENTIAL_TYPE: &str = "credential/type";
pub const ATTR_CREDENTIAL_ISSUER: &str = "credential/issuer";
pub const ATTR_CREDENTIAL_SUBJECT: &str = "credential/subject";
pub const ATTR_CREDENTIAL_VALID_FROM: &str = "credential/validFrom";
pub const ATTR_CREDENTIAL_VALID_UNTIL: &str = "credential/validUntil";
pub const ATTR_CREDENTIAL_STATUS: &str = "credential/status";
pub const ATTR_CREDENTIAL_STATUS_ID: &str = "credential/status/id";
pub const ATTR_CREDENTIAL_STATUS_TYPE: &str = "credential/status/type";
pub const ATTR_CREDENTIAL_PROOF: &str = "credential/proof";
pub const ATTR_CREDENTIAL_PROOF_TYPE: &str = "credential/proof/type";
pub const ATTR_CREDENTIAL_PROOF_CRYPTOSUITE: &str = "credential/proof/cryptosuite";
pub const ATTR_CREDENTIAL_PROOF_PURPOSE: &str = "credential/proof/proofPurpose";
pub const ATTR_CREDENTIAL_PROOF_VERIFICATION_METHOD: &str = "credential/proof/verificationMethod";
pub const ATTR_CREDENTIAL_PROOF_CREATED: &str = "credential/proof/created";
pub const ATTR_CREDENTIAL_PROOF_VALUE: &str = "credential/proof/proofValue";
pub const ATTR_CREDENTIAL_PROOF_CHALLENGE: &str = "credential/proof/challenge";
pub const ATTR_CREDENTIAL_PROOF_DOMAIN: &str = "credential/proof/domain";
pub const ATTR_CREDENTIAL_SUBJECT_FIELD_PREFIX: &str = "credential/subject/";
pub const ATTR_PRESENTATION_ID: &str = "presentation/id";
pub const ATTR_PRESENTATION_HOLDER: &str = "presentation/holder";
pub const ATTR_PRESENTATION_CREDENTIAL: &str = "presentation/credential";
pub const ATTR_PRESENTATION_PROOF: &str = "presentation/proof";
pub const ATTR_PRESENTATION_PROOF_TYPE: &str = "presentation/proof/type";
pub const ATTR_PRESENTATION_PROOF_CRYPTOSUITE: &str = "presentation/proof/cryptosuite";
pub const ATTR_PRESENTATION_PROOF_PURPOSE: &str = "presentation/proof/proofPurpose";
pub const ATTR_PRESENTATION_PROOF_VERIFICATION_METHOD: &str =
    "presentation/proof/verificationMethod";
pub const ATTR_PRESENTATION_PROOF_CREATED: &str = "presentation/proof/created";
pub const ATTR_PRESENTATION_PROOF_VALUE: &str = "presentation/proof/proofValue";
pub const ATTR_PRESENTATION_PROOF_CHALLENGE: &str = "presentation/proof/challenge";
pub const ATTR_PRESENTATION_PROOF_DOMAIN: &str = "presentation/proof/domain";
pub const ATTR_VC_ID_IRI: &str = "https://www.w3.org/2018/credentials#id";
pub const ATTR_VC_TYPE_IRI: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const ATTR_VC_ISSUER_IRI: &str = "https://www.w3.org/2018/credentials#issuer";
pub const ATTR_VC_CREDENTIAL_SUBJECT_IRI: &str =
    "https://www.w3.org/2018/credentials#credentialSubject";
pub const ATTR_VC_VALID_FROM_IRI: &str = "https://www.w3.org/2018/credentials#validFrom";
pub const ATTR_VC_VALID_UNTIL_IRI: &str = "https://www.w3.org/2018/credentials#validUntil";
pub const ATTR_VC_CREDENTIAL_STATUS_IRI: &str =
    "https://www.w3.org/2018/credentials#credentialStatus";
pub const ATTR_VC_PROOF_IRI: &str = "https://w3id.org/security#proof";
pub const ATTR_VP_HOLDER_IRI: &str = "https://www.w3.org/2018/credentials#holder";
pub const ATTR_VP_VERIFIABLE_CREDENTIAL_IRI: &str =
    "https://www.w3.org/2018/credentials#verifiableCredential";

/// W3C VC Data Model credentialSubject.
///
/// VC 2.0 permits object-valued or graph-shaped subject payloads, so Kotoba
/// keeps this as JSON-LD at the wire boundary and projects it to Datoms at the
/// storage boundary.
pub type CredentialSubject = serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum VcError {
    #[error("json encode: {0}")]
    Json(String),
    #[error("missing proof")]
    MissingProof,
    #[error("unsupported proof type: {0}")]
    UnsupportedProofType(String),
    #[error("verification method does not match controller DID")]
    VerificationMethodControllerMismatch,
    #[error("did:key parse: {0}")]
    DidKey(String),
    #[error("proofValue decode: {0}")]
    ProofValueDecode(String),
    #[error("invalid Ed25519 signature length: expected 64, got {0}")]
    InvalidSignatureLength(usize),
    #[error("ed25519 verification: {0}")]
    Ed25519(String),
    #[error("did resolver: {0}")]
    DidResolver(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataIntegrityProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cryptosuite: Option<String>,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialStatus {
    pub id: String,
    #[serde(rename = "type")]
    pub status_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    pub issuer: String,
    #[serde(rename = "validFrom", default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(
        rename = "validUntil",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_until: Option<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(
        rename = "credentialStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_status: Option<CredentialStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub types: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
    #[serde(rename = "verifiableCredential", default)]
    pub verifiable_credentials: Vec<VerifiableCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,
}

impl VerifiableCredential {
    pub fn new(
        id: impl Into<String>,
        issuer: impl Into<String>,
        subject: CredentialSubject,
    ) -> Self {
        Self {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: id.into(),
            types: vec!["VerifiableCredential".to_string()],
            issuer: issuer.into(),
            valid_from: None,
            valid_until: None,
            credential_subject: subject,
            credential_status: None,
            proof: None,
        }
    }

    pub fn cid(&self) -> Result<KotobaCid, VcError> {
        let bytes = serde_json::to_vec(self).map_err(|e| VcError::Json(e.to_string()))?;
        Ok(KotobaCid::from_bytes(&bytes))
    }

    pub fn subject_id(&self) -> Option<&str> {
        self.credential_subject
            .get("id")
            .and_then(serde_json::Value::as_str)
    }

    pub fn to_datoms(&self, tx: KotobaCid) -> Result<Vec<Datom>, VcError> {
        let e = self.cid()?;
        let subject = json_to_edn(&self.credential_subject);
        let types = string_vec(&self.types);
        let mut out = vec![
            datom(
                &e,
                ATTR_CREDENTIAL_ID,
                EdnValue::string(self.id.clone()),
                &tx,
            ),
            datom(&e, ATTR_VC_ID_IRI, EdnValue::string(self.id.clone()), &tx),
            datom(
                &e,
                ATTR_CREDENTIAL_ISSUER,
                EdnValue::string(self.issuer.clone()),
                &tx,
            ),
            datom(
                &e,
                ATTR_VC_ISSUER_IRI,
                EdnValue::string(self.issuer.clone()),
                &tx,
            ),
            datom(&e, ATTR_CREDENTIAL_TYPE, types.clone(), &tx),
            datom(&e, ATTR_VC_TYPE_IRI, types, &tx),
            datom(&e, ATTR_CREDENTIAL_SUBJECT, subject.clone(), &tx),
            datom(&e, ATTR_VC_CREDENTIAL_SUBJECT_IRI, subject, &tx),
        ];
        if let Some(subject_id) = self.subject_id() {
            out.push(datom(
                &e,
                "credential/subjectId",
                EdnValue::string(subject_id),
                &tx,
            ));
        }
        append_subject_field_datoms(&mut out, &e, &self.credential_subject, &tx);
        if let Some(valid_from) = &self.valid_from {
            out.push(datom(
                &e,
                ATTR_CREDENTIAL_VALID_FROM,
                EdnValue::string(valid_from),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_VC_VALID_FROM_IRI,
                EdnValue::string(valid_from),
                &tx,
            ));
        }
        if let Some(valid_until) = &self.valid_until {
            out.push(datom(
                &e,
                ATTR_CREDENTIAL_VALID_UNTIL,
                EdnValue::string(valid_until),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_VC_VALID_UNTIL_IRI,
                EdnValue::string(valid_until),
                &tx,
            ));
        }
        if let Some(status) = &self.credential_status {
            let status_value = EdnValue::map([
                (EdnValue::kw_bare("id"), EdnValue::string(&status.id)),
                (
                    EdnValue::kw_bare("type"),
                    EdnValue::string(&status.status_type),
                ),
            ]);
            out.push(datom(&e, ATTR_CREDENTIAL_STATUS, status_value.clone(), &tx));
            out.push(datom(&e, ATTR_VC_CREDENTIAL_STATUS_IRI, status_value, &tx));
            append_credential_status_datoms(&mut out, &e, status, &tx);
        }
        if let Some(proof) = &self.proof {
            let proof_value = proof_to_edn(proof);
            out.push(datom(&e, ATTR_CREDENTIAL_PROOF, proof_value.clone(), &tx));
            out.push(datom(&e, ATTR_VC_PROOF_IRI, proof_value, &tx));
            append_proof_datoms(&mut out, &e, proof, ProofDatomPrefix::Credential, &tx);
        }
        Ok(out)
    }

    pub fn proof_bytes(&self) -> Result<Vec<u8>, VcError> {
        let mut proofless = self.clone();
        proofless.proof = None;
        serde_json::to_vec(&proofless).map_err(|e| VcError::Json(e.to_string()))
    }

    pub fn verify_did_key_proof(&self) -> Result<(), VcError> {
        let proof = self.proof.as_ref().ok_or(VcError::MissingProof)?;
        verify_data_integrity_proof(&self.issuer, proof, &self.proof_bytes()?)
    }

    pub fn verify_proof_with_resolver(
        &self,
        resolver: &dyn kotoba_auth::resolver::DidDocumentResolver,
    ) -> Result<(), VcError> {
        let proof = self.proof.as_ref().ok_or(VcError::MissingProof)?;
        verify_data_integrity_proof_with_resolver(
            &self.issuer,
            proof,
            &self.proof_bytes()?,
            resolver,
        )
    }
}

impl VerifiablePresentation {
    pub fn cid(&self) -> Result<KotobaCid, VcError> {
        let bytes = serde_json::to_vec(self).map_err(|e| VcError::Json(e.to_string()))?;
        Ok(KotobaCid::from_bytes(&bytes))
    }

    pub fn to_datoms(&self, tx: KotobaCid) -> Result<Vec<Datom>, VcError> {
        let e = self.cid()?;
        let types = string_vec(&self.types);
        let mut out = vec![
            datom(
                &e,
                ATTR_PRESENTATION_ID,
                EdnValue::string(self.id.clone()),
                &tx,
            ),
            datom(&e, ATTR_VC_ID_IRI, EdnValue::string(self.id.clone()), &tx),
            datom(&e, "presentation/type", types.clone(), &tx),
            datom(&e, ATTR_VC_TYPE_IRI, types, &tx),
        ];
        if let Some(holder) = &self.holder {
            out.push(datom(
                &e,
                ATTR_PRESENTATION_HOLDER,
                EdnValue::string(holder),
                &tx,
            ));
            out.push(datom(&e, ATTR_VP_HOLDER_IRI, EdnValue::string(holder), &tx));
        }
        for vc in &self.verifiable_credentials {
            let vc_cid = vc.cid()?.to_multibase();
            out.push(datom(
                &e,
                ATTR_PRESENTATION_CREDENTIAL,
                EdnValue::string(&vc_cid),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_VP_VERIFIABLE_CREDENTIAL_IRI,
                EdnValue::string(&vc_cid),
                &tx,
            ));
            out.extend(vc.to_datoms(tx.clone())?);
        }
        if let Some(proof) = &self.proof {
            let proof_value = proof_to_edn(proof);
            out.push(datom(&e, ATTR_PRESENTATION_PROOF, proof_value.clone(), &tx));
            out.push(datom(&e, ATTR_VC_PROOF_IRI, proof_value, &tx));
            append_proof_datoms(&mut out, &e, proof, ProofDatomPrefix::Presentation, &tx);
        }
        Ok(out)
    }

    pub fn proof_bytes(&self) -> Result<Vec<u8>, VcError> {
        let mut proofless = self.clone();
        proofless.proof = None;
        serde_json::to_vec(&proofless).map_err(|e| VcError::Json(e.to_string()))
    }

    pub fn verify_did_key_proof(&self) -> Result<(), VcError> {
        let holder = self.holder.as_deref().ok_or(VcError::MissingProof)?;
        let proof = self.proof.as_ref().ok_or(VcError::MissingProof)?;
        verify_data_integrity_proof(holder, proof, &self.proof_bytes()?)
    }

    pub fn verify_proof_with_resolver(
        &self,
        resolver: &dyn kotoba_auth::resolver::DidDocumentResolver,
    ) -> Result<(), VcError> {
        let holder = self.holder.as_deref().ok_or(VcError::MissingProof)?;
        let proof = self.proof.as_ref().ok_or(VcError::MissingProof)?;
        verify_data_integrity_proof_with_resolver(holder, proof, &self.proof_bytes()?, resolver)
    }
}

fn verify_data_integrity_proof(
    controller_did: &str,
    proof: &DataIntegrityProof,
    payload: &[u8],
) -> Result<(), VcError> {
    if proof.proof_type != "DataIntegrityProof" && proof.proof_type != "Ed25519Signature2020" {
        return Err(VcError::UnsupportedProofType(proof.proof_type.clone()));
    }
    if !proof.verification_method.starts_with(controller_did) {
        return Err(VcError::VerificationMethodControllerMismatch);
    }
    let pubkey = kotoba_auth::parse_ed25519_did_key(controller_did)
        .map_err(|e| VcError::DidKey(e.to_string()))?;
    let (_, signature_bytes) = multibase::decode(&proof.proof_value)
        .map_err(|e| VcError::ProofValueDecode(e.to_string()))?;
    let sig_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VcError::InvalidSignatureLength(signature_bytes.len()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey)
        .map_err(|e| VcError::Ed25519(e.to_string()))?;
    verifying_key
        .verify_strict(payload, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .map_err(|e| VcError::Ed25519(e.to_string()))
}

fn verify_data_integrity_proof_with_resolver(
    controller_did: &str,
    proof: &DataIntegrityProof,
    payload: &[u8],
    resolver: &dyn kotoba_auth::resolver::DidDocumentResolver,
) -> Result<(), VcError> {
    if proof.proof_type != "DataIntegrityProof" && proof.proof_type != "Ed25519Signature2020" {
        return Err(VcError::UnsupportedProofType(proof.proof_type.clone()));
    }
    if !proof.verification_method.starts_with(controller_did) {
        return Err(VcError::VerificationMethodControllerMismatch);
    }
    let doc = resolver
        .resolve(controller_did)
        .map_err(|e| VcError::DidResolver(e.to_string()))?;
    let pubkey = doc.ed25519_public_key().ok_or_else(|| {
        VcError::DidResolver(format!(
            "no Ed25519 key in DID Document for {controller_did}"
        ))
    })?;
    verify_data_integrity_proof_with_pubkey(proof, payload, &pubkey)
}

fn verify_data_integrity_proof_with_pubkey(
    proof: &DataIntegrityProof,
    payload: &[u8],
    pubkey: &[u8; 32],
) -> Result<(), VcError> {
    let (_, signature_bytes) = multibase::decode(&proof.proof_value)
        .map_err(|e| VcError::ProofValueDecode(e.to_string()))?;
    let sig_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VcError::InvalidSignatureLength(signature_bytes.len()))?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|e| VcError::Ed25519(e.to_string()))?;
    verifying_key
        .verify_strict(payload, &ed25519_dalek::Signature::from_bytes(&sig_arr))
        .map_err(|e| VcError::Ed25519(e.to_string()))
}

fn datom(e: &KotobaCid, a: &str, v: EdnValue, tx: &KotobaCid) -> Datom {
    Datom::assert(e.clone(), a.to_string(), v, tx.clone())
}

fn append_credential_status_datoms(
    out: &mut Vec<Datom>,
    e: &KotobaCid,
    status: &CredentialStatus,
    tx: &KotobaCid,
) {
    out.push(datom(
        e,
        ATTR_CREDENTIAL_STATUS_ID,
        EdnValue::string(&status.id),
        tx,
    ));
    out.push(datom(
        e,
        ATTR_CREDENTIAL_STATUS_TYPE,
        EdnValue::string(&status.status_type),
        tx,
    ));
}

#[derive(Debug, Clone, Copy)]
enum ProofDatomPrefix {
    Credential,
    Presentation,
}

impl ProofDatomPrefix {
    fn attrs(self) -> ProofDatomAttrs {
        match self {
            Self::Credential => ProofDatomAttrs {
                proof_type: ATTR_CREDENTIAL_PROOF_TYPE,
                cryptosuite: ATTR_CREDENTIAL_PROOF_CRYPTOSUITE,
                proof_purpose: ATTR_CREDENTIAL_PROOF_PURPOSE,
                verification_method: ATTR_CREDENTIAL_PROOF_VERIFICATION_METHOD,
                created: ATTR_CREDENTIAL_PROOF_CREATED,
                proof_value: ATTR_CREDENTIAL_PROOF_VALUE,
                challenge: ATTR_CREDENTIAL_PROOF_CHALLENGE,
                domain: ATTR_CREDENTIAL_PROOF_DOMAIN,
            },
            Self::Presentation => ProofDatomAttrs {
                proof_type: ATTR_PRESENTATION_PROOF_TYPE,
                cryptosuite: ATTR_PRESENTATION_PROOF_CRYPTOSUITE,
                proof_purpose: ATTR_PRESENTATION_PROOF_PURPOSE,
                verification_method: ATTR_PRESENTATION_PROOF_VERIFICATION_METHOD,
                created: ATTR_PRESENTATION_PROOF_CREATED,
                proof_value: ATTR_PRESENTATION_PROOF_VALUE,
                challenge: ATTR_PRESENTATION_PROOF_CHALLENGE,
                domain: ATTR_PRESENTATION_PROOF_DOMAIN,
            },
        }
    }
}

struct ProofDatomAttrs {
    proof_type: &'static str,
    cryptosuite: &'static str,
    proof_purpose: &'static str,
    verification_method: &'static str,
    created: &'static str,
    proof_value: &'static str,
    challenge: &'static str,
    domain: &'static str,
}

fn append_proof_datoms(
    out: &mut Vec<Datom>,
    e: &KotobaCid,
    proof: &DataIntegrityProof,
    prefix: ProofDatomPrefix,
    tx: &KotobaCid,
) {
    let attrs = prefix.attrs();
    out.push(datom(
        e,
        attrs.proof_type,
        EdnValue::string(&proof.proof_type),
        tx,
    ));
    out.push(datom(
        e,
        attrs.proof_purpose,
        EdnValue::string(&proof.proof_purpose),
        tx,
    ));
    out.push(datom(
        e,
        attrs.verification_method,
        EdnValue::string(&proof.verification_method),
        tx,
    ));
    out.push(datom(
        e,
        attrs.proof_value,
        EdnValue::string(&proof.proof_value),
        tx,
    ));
    if let Some(cryptosuite) = &proof.cryptosuite {
        out.push(datom(
            e,
            attrs.cryptosuite,
            EdnValue::string(cryptosuite),
            tx,
        ));
    }
    if let Some(created) = &proof.created {
        out.push(datom(e, attrs.created, EdnValue::string(created), tx));
    }
    if let Some(challenge) = &proof.challenge {
        out.push(datom(e, attrs.challenge, EdnValue::string(challenge), tx));
    }
    if let Some(domain) = &proof.domain {
        out.push(datom(e, attrs.domain, EdnValue::string(domain), tx));
    }
}

fn string_vec(xs: &[String]) -> EdnValue {
    EdnValue::vector(xs.iter().cloned().map(EdnValue::string))
}

fn proof_to_edn(proof: &DataIntegrityProof) -> EdnValue {
    let mut m = BTreeMap::new();
    m.insert(
        EdnValue::kw_bare("type"),
        EdnValue::string(&proof.proof_type),
    );
    m.insert(
        EdnValue::kw_bare("proofPurpose"),
        EdnValue::string(&proof.proof_purpose),
    );
    m.insert(
        EdnValue::kw_bare("verificationMethod"),
        EdnValue::string(&proof.verification_method),
    );
    m.insert(
        EdnValue::kw_bare("proofValue"),
        EdnValue::string(&proof.proof_value),
    );
    if let Some(cryptosuite) = &proof.cryptosuite {
        m.insert(
            EdnValue::kw_bare("cryptosuite"),
            EdnValue::string(cryptosuite),
        );
    }
    if let Some(created) = &proof.created {
        m.insert(EdnValue::kw_bare("created"), EdnValue::string(created));
    }
    if let Some(challenge) = &proof.challenge {
        m.insert(EdnValue::kw_bare("challenge"), EdnValue::string(challenge));
    }
    if let Some(domain) = &proof.domain {
        m.insert(EdnValue::kw_bare("domain"), EdnValue::string(domain));
    }
    EdnValue::Map(m)
}

fn json_to_edn(value: &serde_json::Value) -> EdnValue {
    match value {
        serde_json::Value::Null => EdnValue::Nil,
        serde_json::Value::Bool(b) => EdnValue::Bool(*b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(EdnValue::Integer)
            .or_else(|| n.as_f64().map(EdnValue::float))
            .unwrap_or_else(|| EdnValue::string(n.to_string())),
        serde_json::Value::String(s) => EdnValue::string(s),
        serde_json::Value::Array(xs) => EdnValue::vector(xs.iter().map(json_to_edn)),
        serde_json::Value::Object(obj) => EdnValue::Map(
            obj.iter()
                .map(|(k, v)| (EdnValue::kw_bare(k), json_to_edn(v)))
                .collect(),
        ),
    }
}

fn append_subject_field_datoms(
    out: &mut Vec<Datom>,
    e: &KotobaCid,
    subject: &serde_json::Value,
    tx: &KotobaCid,
) {
    append_json_field_datoms(out, e, ATTR_CREDENTIAL_SUBJECT_FIELD_PREFIX, subject, tx);
}

fn append_json_field_datoms(
    out: &mut Vec<Datom>,
    e: &KotobaCid,
    attr_prefix: &str,
    value: &serde_json::Value,
    tx: &KotobaCid,
) {
    let Some(obj) = value.as_object() else {
        return;
    };
    for (key, value) in obj {
        let attr = format!("{attr_prefix}{}", subject_field_attr_key(key));
        match value {
            serde_json::Value::Null => {}
            serde_json::Value::Object(_) => {
                out.push(datom(e, &attr, json_to_edn(value), tx));
                append_json_field_datoms(out, e, &format!("{attr}/"), value, tx);
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    if !value.is_object() && !value.is_null() {
                        out.push(datom(e, &attr, json_to_edn(value), tx));
                    }
                }
            }
            _ => out.push(datom(e, &attr, json_to_edn(value), tx)),
        }
    }
}

fn subject_field_attr_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credential_subject_is_public_json_ld_wire_type() {
        let subject: CredentialSubject = json!({
            "id": "did:key:zAlice",
            "role": "admin"
        });
        let vc = VerifiableCredential::new("urn:uuid:vc-subject", "did:key:zIssuer", subject);
        assert_eq!(vc.subject_id(), Some("did:key:zAlice"));
        assert_eq!(
            vc.credential_subject.get("role").and_then(|v| v.as_str()),
            Some("admin")
        );
    }

    #[test]
    fn credential_projects_to_required_datoms() {
        let vc = VerifiableCredential::new(
            "urn:uuid:vc-1",
            "did:key:zIssuer",
            json!({
                "id": "did:key:zAlice",
                "role": "admin",
                "profile": {"name": "Alice", "region": "JP"}
            }),
        );
        let tx = KotobaCid::from_bytes(b"tx");
        let datoms = vc.to_datoms(tx).unwrap();
        assert!(datoms.iter().any(|d| d.a == ATTR_CREDENTIAL_ID));
        assert!(datoms.iter().any(|d| d.a == ATTR_VC_ID_IRI));
        assert!(datoms.iter().any(|d| d.a == ATTR_CREDENTIAL_ISSUER));
        assert!(datoms.iter().any(|d| d.a == ATTR_VC_ISSUER_IRI));
        assert!(datoms.iter().any(|d| d.a == ATTR_VC_TYPE_IRI));
        assert!(datoms.iter().any(|d| d.a == ATTR_VC_CREDENTIAL_SUBJECT_IRI));
        assert!(datoms.iter().any(|d| d.a == "credential/subjectId"));
        assert!(datoms
            .iter()
            .any(|d| d.a == "credential/subject/role" && d.v == EdnValue::string("admin")));
        assert!(datoms
            .iter()
            .any(|d| d.a == "credential/subject/profile/name" && d.v == EdnValue::string("Alice")));
        assert!(datoms
            .iter()
            .any(|d| d.a == "credential/subject/profile/region" && d.v == EdnValue::string("JP")));
        assert!(datoms.iter().all(|d| d.added));
    }

    #[test]
    fn credential_projects_status_and_data_integrity_proof_fields_to_datoms() {
        let mut vc = VerifiableCredential::new(
            "urn:uuid:vc-proof",
            "did:key:zIssuer",
            json!({"id": "did:key:zAlice"}),
        );
        vc.credential_status = Some(CredentialStatus {
            id: "kotoba://credential/status/1".into(),
            status_type: "KotobaCredentialStatus".into(),
        });
        vc.proof = Some(DataIntegrityProof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: Some("eddsa-2022".into()),
            proof_purpose: "assertionMethod".into(),
            verification_method: "did:key:zIssuer#key-1".into(),
            created: Some("2026-05-29T00:00:00Z".into()),
            proof_value: "zProofValue".into(),
            challenge: Some("challenge-1".into()),
            domain: Some("kotoba.example".into()),
        });

        let datoms = vc.to_datoms(KotobaCid::from_bytes(b"tx")).unwrap();

        assert!(datoms.iter().any(|d| {
            d.a == ATTR_CREDENTIAL_STATUS_ID
                && d.v == EdnValue::string("kotoba://credential/status/1")
        }));
        assert!(datoms.iter().any(|d| {
            d.a == ATTR_CREDENTIAL_STATUS_TYPE && d.v == EdnValue::string("KotobaCredentialStatus")
        }));
        for (attr, value) in [
            (ATTR_CREDENTIAL_PROOF_TYPE, "DataIntegrityProof"),
            (ATTR_CREDENTIAL_PROOF_CRYPTOSUITE, "eddsa-2022"),
            (ATTR_CREDENTIAL_PROOF_PURPOSE, "assertionMethod"),
            (
                ATTR_CREDENTIAL_PROOF_VERIFICATION_METHOD,
                "did:key:zIssuer#key-1",
            ),
            (ATTR_CREDENTIAL_PROOF_CREATED, "2026-05-29T00:00:00Z"),
            (ATTR_CREDENTIAL_PROOF_VALUE, "zProofValue"),
            (ATTR_CREDENTIAL_PROOF_CHALLENGE, "challenge-1"),
            (ATTR_CREDENTIAL_PROOF_DOMAIN, "kotoba.example"),
        ] {
            assert!(
                datoms
                    .iter()
                    .any(|d| d.a == attr && d.v == EdnValue::string(value)),
                "missing proof datom {attr}"
            );
        }
        let proof_map = datoms
            .iter()
            .find(|d| d.a == ATTR_CREDENTIAL_PROOF)
            .map(|d| &d.v)
            .expect("proof map datom");
        assert!(
            kotoba_edn::to_string(proof_map).contains(":challenge \"challenge-1\""),
            "{proof_map:?}"
        );
        assert!(
            kotoba_edn::to_string(proof_map).contains(":domain \"kotoba.example\""),
            "{proof_map:?}"
        );
    }

    #[test]
    fn presentation_projects_embedded_credential_datoms() {
        let vc = VerifiableCredential::new(
            "urn:uuid:vc-2",
            "did:key:zIssuer",
            json!({"id": "did:key:zAlice"}),
        );
        let vp = VerifiablePresentation {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vp-1".into(),
            types: vec!["VerifiablePresentation".into()],
            holder: Some("did:key:zAlice".into()),
            verifiable_credentials: vec![vc],
            proof: None,
        };
        let datoms = vp.to_datoms(KotobaCid::from_bytes(b"tx")).unwrap();
        assert!(datoms.iter().any(|d| d.a == ATTR_PRESENTATION_CREDENTIAL));
        assert!(datoms
            .iter()
            .any(|d| d.a == ATTR_VP_VERIFIABLE_CREDENTIAL_IRI));
        assert!(datoms.iter().any(|d| d.a == ATTR_VP_HOLDER_IRI));
        assert!(datoms
            .iter()
            .any(|d| d.a == ATTR_CREDENTIAL_ID && d.v == EdnValue::string("urn:uuid:vc-2")));
        assert!(datoms
            .iter()
            .any(|d| d.a == ATTR_VC_ID_IRI && d.v == EdnValue::string("urn:uuid:vc-2")));
        assert!(datoms
            .iter()
            .any(|d| d.a == ATTR_CREDENTIAL_ISSUER && d.v == EdnValue::string("did:key:zIssuer")));
    }

    #[test]
    fn presentation_projects_data_integrity_proof_fields_to_datoms() {
        let vp = VerifiablePresentation {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vp-proof".into(),
            types: vec!["VerifiablePresentation".into()],
            holder: Some("did:key:zAlice".into()),
            verifiable_credentials: vec![],
            proof: Some(DataIntegrityProof {
                proof_type: "DataIntegrityProof".into(),
                cryptosuite: Some("eddsa-2022".into()),
                proof_purpose: "authentication".into(),
                verification_method: "did:key:zAlice#key-1".into(),
                created: Some("2026-05-29T00:00:00Z".into()),
                proof_value: "zVpProofValue".into(),
                challenge: Some("vp-challenge".into()),
                domain: Some("kotoba.example".into()),
            }),
        };

        let datoms = vp.to_datoms(KotobaCid::from_bytes(b"tx")).unwrap();

        for (attr, value) in [
            (ATTR_PRESENTATION_PROOF_TYPE, "DataIntegrityProof"),
            (ATTR_PRESENTATION_PROOF_CRYPTOSUITE, "eddsa-2022"),
            (ATTR_PRESENTATION_PROOF_PURPOSE, "authentication"),
            (
                ATTR_PRESENTATION_PROOF_VERIFICATION_METHOD,
                "did:key:zAlice#key-1",
            ),
            (ATTR_PRESENTATION_PROOF_CREATED, "2026-05-29T00:00:00Z"),
            (ATTR_PRESENTATION_PROOF_VALUE, "zVpProofValue"),
            (ATTR_PRESENTATION_PROOF_CHALLENGE, "vp-challenge"),
            (ATTR_PRESENTATION_PROOF_DOMAIN, "kotoba.example"),
        ] {
            assert!(
                datoms
                    .iter()
                    .any(|d| d.a == attr && d.v == EdnValue::string(value)),
                "missing presentation proof datom {attr}"
            );
        }
    }

    #[test]
    fn presentation_did_key_proof_verifies_and_rejects_tamper() {
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let holder = kotoba_auth::ed25519_pubkey_to_did_key(sk.verifying_key().as_bytes());
        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vc-cap".into(),
            types: vec![
                "VerifiableCredential".into(),
                "KotobaCapabilityCredential".into(),
            ],
            issuer: "did:key:zIssuer".into(),
            valid_from: None,
            valid_until: None,
            credential_subject: json!({"id": holder, "operations": ["graph:query"]}),
            credential_status: None,
            proof: None,
        };
        let mut vp = VerifiablePresentation {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vp-cap".into(),
            types: vec!["VerifiablePresentation".into()],
            holder: Some(holder.clone()),
            verifiable_credentials: vec![vc],
            proof: None,
        };
        let sig = sk.sign(&vp.proof_bytes().unwrap());
        vp.proof = Some(DataIntegrityProof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: Some("eddsa-2022".into()),
            proof_purpose: "authentication".into(),
            verification_method: format!("{holder}#key-1"),
            created: None,
            proof_value: multibase::encode(multibase::Base::Base58Btc, sig.to_bytes()),
            challenge: None,
            domain: None,
        });

        vp.verify_did_key_proof().unwrap();
        vp.verifiable_credentials[0].credential_subject =
            json!({"id": holder, "operations": ["datom:transact"]});
        assert!(vp.verify_did_key_proof().is_err());
    }

    #[test]
    fn presentation_proof_with_resolver_accepts_non_did_key_holder() {
        use ed25519_dalek::{Signer, SigningKey};
        use kotoba_auth::did_document::{DidDocument, VerificationMethod, ED25519_KEY_TYPE_2020};
        use kotoba_auth::resolver::InMemoryDidResolver;

        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let holder = "did:plc:alice";
        let vc = VerifiableCredential {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vc-cap-resolver".into(),
            types: vec![
                "VerifiableCredential".into(),
                "KotobaCapabilityCredential".into(),
            ],
            issuer: "did:kotoba:operator".into(),
            valid_from: None,
            valid_until: None,
            credential_subject: json!({"id": holder, "operations": ["graph:query"]}),
            credential_status: None,
            proof: None,
        };
        let mut vp = VerifiablePresentation {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vp-cap-resolver".into(),
            types: vec!["VerifiablePresentation".into()],
            holder: Some(holder.to_string()),
            verifiable_credentials: vec![vc],
            proof: None,
        };
        let sig = sk.sign(&vp.proof_bytes().unwrap());
        vp.proof = Some(DataIntegrityProof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: Some("eddsa-2022".into()),
            proof_purpose: "authentication".into(),
            verification_method: format!("{holder}#key-1"),
            created: None,
            proof_value: multibase::encode(multibase::Base::Base58Btc, sig.to_bytes()),
            challenge: None,
            domain: None,
        });

        let mut doc = DidDocument::empty(holder);
        doc.verification_method.push(VerificationMethod {
            id: format!("{holder}#key-1"),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: holder.to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                sk.verifying_key().as_bytes(),
            ),
        });
        let resolver = InMemoryDidResolver::new();
        resolver.insert(holder, doc);

        assert!(vp.verify_did_key_proof().is_err());
        vp.verify_proof_with_resolver(&resolver).unwrap();
    }

    #[test]
    fn credential_proof_with_resolver_accepts_non_did_key_issuer() {
        use ed25519_dalek::{Signer, SigningKey};
        use kotoba_auth::did_document::{DidDocument, VerificationMethod, ED25519_KEY_TYPE_2020};
        use kotoba_auth::resolver::InMemoryDidResolver;

        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let issuer = "did:web:issuer.example";
        let mut vc = VerifiableCredential {
            context: vec![VC_CONTEXT_V2.to_string()],
            id: "urn:uuid:vc-resolver-proof".into(),
            types: vec!["VerifiableCredential".into()],
            issuer: issuer.to_string(),
            valid_from: None,
            valid_until: None,
            credential_subject: json!({"id": "did:plc:alice", "role": "admin"}),
            credential_status: None,
            proof: None,
        };
        let sig = sk.sign(&vc.proof_bytes().unwrap());
        vc.proof = Some(DataIntegrityProof {
            proof_type: "DataIntegrityProof".into(),
            cryptosuite: Some("eddsa-2022".into()),
            proof_purpose: "assertionMethod".into(),
            verification_method: format!("{issuer}#key-1"),
            created: None,
            proof_value: multibase::encode(multibase::Base::Base58Btc, sig.to_bytes()),
            challenge: None,
            domain: None,
        });

        let mut doc = DidDocument::empty(issuer);
        doc.verification_method.push(VerificationMethod {
            id: format!("{issuer}#key-1"),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: issuer.to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                sk.verifying_key().as_bytes(),
            ),
        });
        let resolver = InMemoryDidResolver::new();
        resolver.insert(issuer, doc);

        assert!(vc.verify_did_key_proof().is_err());
        vc.verify_proof_with_resolver(&resolver).unwrap();
    }
}
