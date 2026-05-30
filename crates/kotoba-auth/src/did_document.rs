use serde::{Deserialize, Serialize};

const X25519_KEY_TYPE: &str = "X25519KeyAgreementKey2020";
pub const ED25519_KEY_TYPE_2020: &str = "Ed25519VerificationKey2020";
const ED25519_KEY_TYPE_2018: &str = "Ed25519VerificationKey2018";
pub const DID_CONTEXT_V1: &str = "https://www.w3.org/ns/did/v1";
pub const DIDCOMM_MESSAGING_SERVICE: &str = "DIDCommMessaging";
pub const ATPROTO_PDS_SERVICE: &str = "AtprotoPersonalDataServer";
pub const KOTOBA_NODE_SERVICE: &str = "KotobaNode";
pub const KOTOBA_GRAPH_MEMBERSHIP_SERVICE: &str = "KotobaGraphMembership";
pub const KOTOBA_PROTOCOL_DID_SERVICES: [&str; 4] = [
    DIDCOMM_MESSAGING_SERVICE,
    ATPROTO_PDS_SERVICE,
    KOTOBA_NODE_SERVICE,
    KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
];
pub const ATTR_DID_ID: &str = "did/id";
pub const ATTR_DID_CONTEXT: &str = "did/context";
pub const ATTR_DID_VERIFICATION_METHOD: &str = "did/verificationMethod";
pub const ATTR_DID_AUTHENTICATION: &str = "did/authentication";
pub const ATTR_DID_ASSERTION_METHOD: &str = "did/assertionMethod";
pub const ATTR_DID_KEY_AGREEMENT: &str = "did/keyAgreement";
pub const ATTR_DID_CAPABILITY_INVOCATION: &str = "did/capabilityInvocation";
pub const ATTR_DID_CAPABILITY_DELEGATION: &str = "did/capabilityDelegation";
pub const ATTR_DID_SERVICE_ID: &str = "did/service/id";
pub const ATTR_DID_SERVICE_TYPE: &str = "did/service/type";
pub const ATTR_DID_SERVICE_ENDPOINT: &str = "did/service/endpoint";
pub const ATTR_DID_CORE_ID: &str = "https://www.w3.org/ns/did#id";
pub const ATTR_DID_CORE_VERIFICATION_METHOD: &str = "https://www.w3.org/ns/did#verificationMethod";
pub const ATTR_DID_CORE_AUTHENTICATION: &str = "https://www.w3.org/ns/did#authentication";
pub const ATTR_DID_CORE_ASSERTION_METHOD: &str = "https://www.w3.org/ns/did#assertionMethod";
pub const ATTR_DID_CORE_KEY_AGREEMENT: &str = "https://www.w3.org/ns/did#keyAgreement";
pub const ATTR_DID_CORE_CAPABILITY_INVOCATION: &str =
    "https://www.w3.org/ns/did#capabilityInvocation";
pub const ATTR_DID_CORE_CAPABILITY_DELEGATION: &str =
    "https://www.w3.org/ns/did#capabilityDelegation";
pub const ATTR_DID_CORE_SERVICE: &str = "https://www.w3.org/ns/did#service";
pub const ATTR_DID_CORE_SERVICE_ENDPOINT: &str = "https://www.w3.org/ns/did#serviceEndpoint";
pub const ATTR_RDF_TYPE: &str = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type";
pub const ATTR_DID_ENTITY_CID: &str = "did/entityCid";
pub const ATTR_DID_METHOD: &str = "did/method";
pub const ATTR_DID_HAS_KOTOBA_PROTOCOL_SERVICES: &str = "did/hasKotobaProtocolServices";
pub const ATTR_DID_DIDCOMM_MESSAGING_ENDPOINT: &str = "did/didcommMessagingEndpoint";
pub const ATTR_DID_ATPROTO_PDS_ENDPOINT: &str = "did/atprotoPdsEndpoint";
pub const ATTR_DID_KOTOBA_NODE_ENDPOINT: &str = "did/kotobaNodeEndpoint";
pub const ATTR_DID_KOTOBA_GRAPH_MEMBERSHIP: &str = "did/kotobaGraphMembership";

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
    #[serde(default, rename = "keyAgreement")]
    pub key_agreement: Vec<String>,
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
    Object(serde_json::Map<String, serde_json::Value>),
}

impl ServiceEndpointValue {
    fn values(&self) -> Vec<&str> {
        match self {
            Self::Single(value) => vec![value.as_str()],
            Self::Multiple(values) => values.iter().map(String::as_str).collect(),
            Self::Object(value) => value
                .get("uri")
                .or_else(|| value.get("endpoint"))
                .and_then(serde_json::Value::as_str)
                .into_iter()
                .collect(),
        }
    }

    fn primary_uri(&self) -> Option<&str> {
        match self {
            Self::Single(value) => Some(value.as_str()),
            Self::Multiple(_) => None,
            Self::Object(value) => value
                .get("uri")
                .or_else(|| value.get("endpoint"))
                .and_then(serde_json::Value::as_str),
        }
    }
}

impl DidDocument {
    pub fn empty(id: impl Into<String>) -> Self {
        Self {
            context: vec![DID_CONTEXT_V1.to_string()],
            id: id.into(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        }
    }

    pub fn service_by_type(&self, service_type: &str) -> Option<&ServiceEndpoint> {
        self.service
            .iter()
            .find(|service| service.service_type == service_type)
    }

    pub fn kotoba_endpoint(&self) -> Option<&str> {
        self.service_by_type(KOTOBA_NODE_SERVICE)
            .and_then(|s| s.endpoint.primary_uri())
    }

    pub fn didcomm_endpoint(&self) -> Option<&str> {
        self.service_by_type(DIDCOMM_MESSAGING_SERVICE)
            .and_then(|s| s.endpoint.primary_uri())
    }

    pub fn atproto_pds_endpoint(&self) -> Option<&str> {
        self.service_by_type(ATPROTO_PDS_SERVICE)
            .and_then(|s| s.endpoint.primary_uri())
    }

    pub fn graph_memberships(&self) -> Vec<&str> {
        self.service_by_type(KOTOBA_GRAPH_MEMBERSHIP_SERVICE)
            .and_then(|s| match &s.endpoint {
                ServiceEndpointValue::Single(u) => Some(vec![u.as_str()]),
                ServiceEndpointValue::Multiple(v) => Some(v.iter().map(|s| s.as_str()).collect()),
                ServiceEndpointValue::Object(_) => None,
            })
            .unwrap_or_default()
    }

    pub fn missing_kotoba_protocol_services(&self) -> Vec<&'static str> {
        KOTOBA_PROTOCOL_DID_SERVICES
            .iter()
            .copied()
            .filter(|service_type| self.service_by_type(service_type).is_none())
            .collect()
    }

    pub fn has_kotoba_protocol_services(&self) -> bool {
        self.missing_kotoba_protocol_services().is_empty()
    }

    /// Extract the X25519 key agreement public key from `verificationMethod`.
    ///
    /// Returns `None` if no `X25519KeyAgreementKey2020` entry is present or
    /// if the multibase-encoded key cannot be decoded to exactly 32 bytes.
    pub fn x25519_public_key(&self) -> Option<[u8; 32]> {
        let vm = self
            .key_agreement
            .iter()
            .find_map(|key_id| self.verification_method.iter().find(|vm| vm.id == *key_id))
            .or_else(|| {
                self.verification_method
                    .iter()
                    .find(|vm| vm.key_type == X25519_KEY_TYPE)
            })?;

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

    pub fn has_ed25519_public_key_multibase(&self, public_key_multibase: &str) -> bool {
        let Ok((_base, expected)) = multibase::decode(public_key_multibase) else {
            return false;
        };
        if expected.len() != 32 {
            return false;
        }
        self.verification_method.iter().any(|vm| {
            (vm.key_type == ED25519_KEY_TYPE_2020 || vm.key_type == ED25519_KEY_TYPE_2018)
                && multibase::decode(&vm.public_key_multibase)
                    .map(|(_, raw)| raw == expected)
                    .unwrap_or(false)
        })
    }

    pub fn push_single_service(
        &mut self,
        fragment: &str,
        service_type: &str,
        endpoint: impl Into<String>,
    ) {
        self.service.push(ServiceEndpoint {
            id: format!("{}#{}", self.id, fragment.trim_start_matches('#')),
            service_type: service_type.to_string(),
            endpoint: ServiceEndpointValue::Single(endpoint.into()),
        });
    }

    pub fn ensure_single_service(
        &mut self,
        fragment: &str,
        service_type: &str,
        endpoint: impl Into<String>,
    ) {
        if self.service_by_type(service_type).is_none() {
            self.push_single_service(fragment, service_type, endpoint);
        }
    }

    pub fn push_graph_membership_service<I, S>(&mut self, memberships: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.service.push(ServiceEndpoint {
            id: format!("{}#kotoba-graphs", self.id),
            service_type: KOTOBA_GRAPH_MEMBERSHIP_SERVICE.to_string(),
            endpoint: ServiceEndpointValue::Multiple(
                memberships.into_iter().map(Into::into).collect(),
            ),
        });
    }

    pub fn ensure_graph_membership_service<I, S>(&mut self, memberships: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        if self
            .service_by_type(KOTOBA_GRAPH_MEMBERSHIP_SERVICE)
            .is_none()
        {
            self.push_graph_membership_service(memberships);
        }
    }

    pub fn entity_cid(&self) -> kotoba_core::cid::KotobaCid {
        kotoba_core::cid::KotobaCid::from_bytes(self.id.as_bytes())
    }

    pub fn to_datoms(&self, tx: kotoba_core::cid::KotobaCid) -> Vec<kotoba_datomic::Datom> {
        let e = self.entity_cid();
        let mut out = vec![
            did_datom(
                &e,
                ATTR_DID_ENTITY_CID,
                kotoba_datomic::Value::string(e.to_multibase()),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_ID,
                kotoba_datomic::Value::string(&self.id),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CORE_ID,
                kotoba_datomic::Value::string(&self.id),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_METHOD,
                kotoba_datomic::Value::string(did_method_name(&self.id)),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_HAS_KOTOBA_PROTOCOL_SERVICES,
                kotoba_datomic::Value::Bool(self.has_kotoba_protocol_services()),
                &tx,
            ),
            did_datom(&e, ATTR_DID_CONTEXT, string_vec(&self.context), &tx),
            did_datom(
                &e,
                ATTR_DID_AUTHENTICATION,
                string_vec(&self.authentication),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CORE_AUTHENTICATION,
                string_vec(&self.authentication),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_ASSERTION_METHOD,
                string_vec(&self.assertion_method),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CORE_ASSERTION_METHOD,
                string_vec(&self.assertion_method),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_KEY_AGREEMENT,
                string_vec(&self.key_agreement),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CORE_KEY_AGREEMENT,
                string_vec(&self.key_agreement),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CAPABILITY_INVOCATION,
                string_vec(&self.capability_invocation),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CORE_CAPABILITY_INVOCATION,
                string_vec(&self.capability_invocation),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CAPABILITY_DELEGATION,
                string_vec(&self.capability_delegation),
                &tx,
            ),
            did_datom(
                &e,
                ATTR_DID_CORE_CAPABILITY_DELEGATION,
                string_vec(&self.capability_delegation),
                &tx,
            ),
        ];
        for vm in &self.verification_method {
            out.push(did_datom(
                &e,
                ATTR_DID_VERIFICATION_METHOD,
                verification_method_value(vm),
                &tx,
            ));
            out.push(did_datom(
                &e,
                ATTR_DID_CORE_VERIFICATION_METHOD,
                verification_method_value(vm),
                &tx,
            ));
        }
        for service in &self.service {
            let service_entity = kotoba_core::cid::KotobaCid::from_bytes(service.id.as_bytes());
            for (attr, endpoint) in protocol_service_endpoint_datoms(service) {
                out.push(did_datom(&e, attr, endpoint, &tx));
            }
            out.push(did_datom(
                &e,
                ATTR_DID_CORE_SERVICE,
                kotoba_datomic::Value::string(&service.id),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_DID_ID,
                kotoba_datomic::Value::string(&self.id),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_DID_CORE_ID,
                kotoba_datomic::Value::string(&service.id),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_DID_SERVICE_ID,
                kotoba_datomic::Value::string(&service.id),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_DID_SERVICE_TYPE,
                kotoba_datomic::Value::string(&service.service_type),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_RDF_TYPE,
                kotoba_datomic::Value::string(&service.service_type),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_DID_SERVICE_ENDPOINT,
                service_endpoint_value(&service.endpoint),
                &tx,
            ));
            out.push(did_datom(
                &service_entity,
                ATTR_DID_CORE_SERVICE_ENDPOINT,
                service_endpoint_value(&service.endpoint),
                &tx,
            ));
        }
        out
    }

    pub fn from_datoms(did: &str, datoms: &[kotoba_datomic::Datom]) -> Option<Self> {
        let e = kotoba_core::cid::KotobaCid::from_bytes(did.as_bytes());
        let current = kotoba_datomic::current_datoms(datoms);
        if !current.iter().any(|datom| {
            datom.e == e
                && matches!(datom.a.as_str(), ATTR_DID_ID | ATTR_DID_CORE_ID)
                && datom.v == kotoba_datomic::Value::string(did)
        }) {
            return None;
        }

        let mut doc = DidDocument::empty(did);
        for datom in current.iter().filter(|datom| datom.e == e) {
            match datom.a.as_str() {
                ATTR_DID_CONTEXT => doc.context = string_list(&datom.v),
                ATTR_DID_AUTHENTICATION | ATTR_DID_CORE_AUTHENTICATION => {
                    doc.authentication = string_list(&datom.v)
                }
                ATTR_DID_ASSERTION_METHOD | ATTR_DID_CORE_ASSERTION_METHOD => {
                    doc.assertion_method = string_list(&datom.v)
                }
                ATTR_DID_KEY_AGREEMENT | ATTR_DID_CORE_KEY_AGREEMENT => {
                    doc.key_agreement = string_list(&datom.v)
                }
                ATTR_DID_CAPABILITY_INVOCATION | ATTR_DID_CORE_CAPABILITY_INVOCATION => {
                    doc.capability_invocation = string_list(&datom.v)
                }
                ATTR_DID_CAPABILITY_DELEGATION | ATTR_DID_CORE_CAPABILITY_DELEGATION => {
                    doc.capability_delegation = string_list(&datom.v)
                }
                ATTR_DID_VERIFICATION_METHOD | ATTR_DID_CORE_VERIFICATION_METHOD => {
                    if let Some(vm) = verification_method_from_value(&datom.v) {
                        if !doc
                            .verification_method
                            .iter()
                            .any(|existing| existing.id == vm.id)
                        {
                            doc.verification_method.push(vm);
                        }
                    }
                }
                _ => {}
            }
        }

        let mut service_entities: Vec<kotoba_core::cid::KotobaCid> = current
            .iter()
            .filter(|datom| datom.a == ATTR_DID_ID && datom.v == kotoba_datomic::Value::string(did))
            .map(|datom| datom.e.clone())
            .filter(|service_entity| service_entity != &e)
            .collect();
        for service_entity in current
            .iter()
            .filter(|datom| datom.e == e && datom.a == ATTR_DID_CORE_SERVICE)
            .filter_map(|datom| datom.v.as_string())
            .map(|service_id| kotoba_core::cid::KotobaCid::from_bytes(service_id.as_bytes()))
        {
            if !service_entities.contains(&service_entity) {
                service_entities.push(service_entity);
            }
        }

        for service_id in service_entities {
            let mut id = None;
            let mut service_type = None;
            let mut endpoint = None;
            for datom in current.iter().filter(|datom| datom.e == service_id) {
                match datom.a.as_str() {
                    ATTR_DID_SERVICE_ID | ATTR_DID_CORE_ID => {
                        id = datom.v.as_string().map(ToOwned::to_owned)
                    }
                    ATTR_DID_SERVICE_TYPE | ATTR_RDF_TYPE => {
                        service_type = datom.v.as_string().map(ToOwned::to_owned)
                    }
                    ATTR_DID_SERVICE_ENDPOINT | ATTR_DID_CORE_SERVICE_ENDPOINT => {
                        endpoint = service_endpoint_from_value(&datom.v)
                    }
                    _ => {}
                }
            }
            if let (Some(id), Some(service_type), Some(endpoint)) = (id, service_type, endpoint) {
                doc.service.push(ServiceEndpoint {
                    id,
                    service_type,
                    endpoint,
                });
            }
        }

        Some(doc)
    }
}

fn did_method_name(did: &str) -> &str {
    did.split(':').nth(1).unwrap_or("")
}

fn did_datom(
    e: &kotoba_core::cid::KotobaCid,
    a: &str,
    v: kotoba_datomic::Value,
    tx: &kotoba_core::cid::KotobaCid,
) -> kotoba_datomic::Datom {
    kotoba_datomic::Datom::assert(e.clone(), a.to_string(), v, tx.clone())
}

fn protocol_service_endpoint_datoms(
    service: &ServiceEndpoint,
) -> Vec<(&'static str, kotoba_datomic::Value)> {
    match service.service_type.as_str() {
        DIDCOMM_MESSAGING_SERVICE => vec![(
            ATTR_DID_DIDCOMM_MESSAGING_ENDPOINT,
            service_endpoint_value(&service.endpoint),
        )],
        ATPROTO_PDS_SERVICE => vec![(
            ATTR_DID_ATPROTO_PDS_ENDPOINT,
            service_endpoint_value(&service.endpoint),
        )],
        KOTOBA_NODE_SERVICE => vec![(
            ATTR_DID_KOTOBA_NODE_ENDPOINT,
            service_endpoint_value(&service.endpoint),
        )],
        KOTOBA_GRAPH_MEMBERSHIP_SERVICE => service
            .endpoint
            .values()
            .into_iter()
            .map(|membership| {
                (
                    ATTR_DID_KOTOBA_GRAPH_MEMBERSHIP,
                    kotoba_datomic::Value::string(membership),
                )
            })
            .collect(),
        _ => vec![],
    }
}

fn string_vec(values: &[String]) -> kotoba_datomic::Value {
    kotoba_datomic::Value::vector(values.iter().cloned().map(kotoba_datomic::Value::string))
}

fn verification_method_value(vm: &VerificationMethod) -> kotoba_datomic::Value {
    kotoba_datomic::Value::map([
        (
            kotoba_datomic::Value::kw_bare("id"),
            kotoba_datomic::Value::string(&vm.id),
        ),
        (
            kotoba_datomic::Value::kw_bare("type"),
            kotoba_datomic::Value::string(&vm.key_type),
        ),
        (
            kotoba_datomic::Value::kw_bare("controller"),
            kotoba_datomic::Value::string(&vm.controller),
        ),
        (
            kotoba_datomic::Value::kw_bare("publicKeyMultibase"),
            kotoba_datomic::Value::string(&vm.public_key_multibase),
        ),
    ])
}

fn service_endpoint_value(endpoint: &ServiceEndpointValue) -> kotoba_datomic::Value {
    match endpoint {
        ServiceEndpointValue::Single(endpoint) => kotoba_datomic::Value::string(endpoint),
        ServiceEndpointValue::Multiple(endpoints) => string_vec(endpoints),
        ServiceEndpointValue::Object(endpoint) => json_object_to_datomic_value(endpoint),
    }
}

fn string_list(value: &kotoba_datomic::Value) -> Vec<String> {
    match value {
        kotoba_datomic::Value::Vector(values) | kotoba_datomic::Value::List(values) => values
            .iter()
            .filter_map(|value| value.as_string().map(ToOwned::to_owned))
            .collect(),
        kotoba_datomic::Value::String(value) => vec![value.clone()],
        _ => vec![],
    }
}

fn verification_method_from_value(value: &kotoba_datomic::Value) -> Option<VerificationMethod> {
    let map = value.as_map()?;
    Some(VerificationMethod {
        id: map
            .get(&kotoba_datomic::Value::kw_bare("id"))?
            .as_string()?
            .to_string(),
        key_type: map
            .get(&kotoba_datomic::Value::kw_bare("type"))?
            .as_string()?
            .to_string(),
        controller: map
            .get(&kotoba_datomic::Value::kw_bare("controller"))?
            .as_string()?
            .to_string(),
        public_key_multibase: map
            .get(&kotoba_datomic::Value::kw_bare("publicKeyMultibase"))?
            .as_string()?
            .to_string(),
    })
}

fn service_endpoint_from_value(value: &kotoba_datomic::Value) -> Option<ServiceEndpointValue> {
    if let Some(endpoint) = value.as_string() {
        return Some(ServiceEndpointValue::Single(endpoint.to_string()));
    }
    if let Some(map) = value.as_map() {
        return Some(ServiceEndpointValue::Object(datomic_map_to_json_object(
            map,
        )));
    }
    let endpoints = string_list(value);
    (!endpoints.is_empty()).then_some(ServiceEndpointValue::Multiple(endpoints))
}

fn json_object_to_datomic_value(
    value: &serde_json::Map<String, serde_json::Value>,
) -> kotoba_datomic::Value {
    kotoba_datomic::Value::map(value.iter().map(|(key, value)| {
        (
            kotoba_datomic::Value::kw_bare(key),
            json_to_datomic_value(value),
        )
    }))
}

fn json_to_datomic_value(value: &serde_json::Value) -> kotoba_datomic::Value {
    match value {
        serde_json::Value::Null => kotoba_datomic::Value::Nil,
        serde_json::Value::Bool(value) => kotoba_datomic::Value::Bool(*value),
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(kotoba_datomic::Value::Integer)
            .or_else(|| value.as_f64().map(kotoba_datomic::Value::float))
            .unwrap_or_else(|| kotoba_datomic::Value::string(value.to_string())),
        serde_json::Value::String(value) => kotoba_datomic::Value::string(value),
        serde_json::Value::Array(values) => {
            kotoba_datomic::Value::vector(values.iter().map(json_to_datomic_value))
        }
        serde_json::Value::Object(value) => json_object_to_datomic_value(value),
    }
}

fn datomic_map_to_json_object(
    map: &std::collections::BTreeMap<kotoba_datomic::Value, kotoba_datomic::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    map.iter()
        .filter_map(|(key, value)| {
            datomic_key_to_json_key(key).map(|key| (key, datomic_value_to_json(value)))
        })
        .collect()
}

fn datomic_key_to_json_key(value: &kotoba_datomic::Value) -> Option<String> {
    match value {
        kotoba_datomic::Value::Keyword(keyword) => Some(keyword.to_qualified()),
        kotoba_datomic::Value::String(value) => Some(value.clone()),
        _ => None,
    }
}

fn datomic_value_to_json(value: &kotoba_datomic::Value) -> serde_json::Value {
    match value {
        kotoba_datomic::Value::Nil => serde_json::Value::Null,
        kotoba_datomic::Value::Bool(value) => serde_json::Value::Bool(*value),
        kotoba_datomic::Value::Integer(value) => serde_json::Value::Number((*value).into()),
        kotoba_datomic::Value::BigInt(value) | kotoba_datomic::Value::BigDec(value) => {
            serde_json::Value::String(value.clone())
        }
        kotoba_datomic::Value::Float(value) => serde_json::Number::from_f64(value.into_inner())
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        kotoba_datomic::Value::Char(value) => serde_json::Value::String(value.to_string()),
        kotoba_datomic::Value::String(value) => serde_json::Value::String(value.clone()),
        kotoba_datomic::Value::Symbol(symbol) => serde_json::Value::String(symbol.to_qualified()),
        kotoba_datomic::Value::Keyword(keyword) => {
            serde_json::Value::String(keyword.to_qualified())
        }
        kotoba_datomic::Value::Vector(values) | kotoba_datomic::Value::List(values) => {
            serde_json::Value::Array(values.iter().map(datomic_value_to_json).collect())
        }
        kotoba_datomic::Value::Set(values) => {
            serde_json::Value::Array(values.iter().map(datomic_value_to_json).collect())
        }
        kotoba_datomic::Value::Map(map) => {
            serde_json::Value::Object(datomic_map_to_json_object(map))
        }
        kotoba_datomic::Value::Tagged { tag, value } => serde_json::json!({
            "tag": tag.to_qualified(),
            "value": datomic_value_to_json(value),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_doc(id: &str) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: id.to_string(),
            verification_method: vec![],
            authentication: vec![],
            assertion_method: vec![],
            key_agreement: vec![],
            capability_invocation: vec![],
            capability_delegation: vec![],
            service: vec![],
        }
    }

    fn with_service(
        mut doc: DidDocument,
        stype: &str,
        endpoint: ServiceEndpointValue,
    ) -> DidDocument {
        doc.service.push(ServiceEndpoint {
            id: format!("{}#{}", doc.id, stype),
            service_type: stype.to_string(),
            endpoint,
        });
        doc
    }

    // ── kotoba_endpoint ───────────────────────────────────────────────────────

    #[test]
    fn kotoba_endpoint_returns_none_when_absent() {
        let doc = base_doc("did:key:zTest");
        assert!(doc.kotoba_endpoint().is_none());
    }

    #[test]
    fn kotoba_endpoint_returns_single_url() {
        let doc = with_service(
            base_doc("did:key:zTest"),
            "KotobaNode",
            ServiceEndpointValue::Single("/ip4/127.0.0.1/tcp/4001".to_string()),
        );
        assert_eq!(doc.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
    }

    #[test]
    fn kotoba_endpoint_returns_none_for_multiple_value() {
        let doc = with_service(
            base_doc("did:key:zTest"),
            "KotobaNode",
            ServiceEndpointValue::Multiple(vec!["/ip4/1.2.3.4/tcp/4001".to_string()]),
        );
        assert!(doc.kotoba_endpoint().is_none());
    }

    // ── graph_memberships ─────────────────────────────────────────────────────

    #[test]
    fn graph_memberships_returns_empty_when_absent() {
        assert!(base_doc("did:key:z").graph_memberships().is_empty());
    }

    #[test]
    fn graph_memberships_returns_list() {
        let doc = with_service(
            base_doc("did:key:z"),
            KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
            ServiceEndpointValue::Multiple(vec![
                "graph-cid-1".to_string(),
                "graph-cid-2".to_string(),
            ]),
        );
        let memberships = doc.graph_memberships();
        assert_eq!(memberships.len(), 2);
        assert!(memberships.contains(&"graph-cid-1"));
    }

    #[test]
    fn didcomm_and_atproto_service_helpers_return_single_endpoints() {
        let mut doc = DidDocument::empty("did:key:zServices");
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://mediator/abc",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );

        assert_eq!(doc.didcomm_endpoint(), Some("didcomm://mediator/abc"));
        assert_eq!(doc.atproto_pds_endpoint(), Some("https://pds.example.com"));
    }

    #[test]
    fn didcomm_object_service_endpoint_roundtrips_through_datoms() {
        let mut doc = DidDocument::empty("did:plc:didcommobject");
        doc.service.push(ServiceEndpoint {
            id: "did:plc:didcommobject#didcomm".into(),
            service_type: DIDCOMM_MESSAGING_SERVICE.into(),
            endpoint: ServiceEndpointValue::Object(
                serde_json::json!({
                    "uri": "didcomm://mediator/object",
                    "accept": ["didcomm/v2"],
                    "routingKeys": ["did:key:zMediator#key-x25519"]
                })
                .as_object()
                .unwrap()
                .clone(),
            ),
        });
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        doc.push_graph_membership_service(["kotoba://graph/object"]);

        let datoms = doc.to_datoms(kotoba_core::cid::KotobaCid::from_bytes(
            b"didcomm-object-service-tx",
        ));
        assert!(datoms.iter().any(|datom| {
            datom.a == ATTR_DID_DIDCOMM_MESSAGING_ENDPOINT
                && datom
                    .v
                    .as_map()
                    .and_then(|map| map.get(&kotoba_datomic::Value::kw_bare("uri")))
                    == Some(&kotoba_datomic::Value::string("didcomm://mediator/object"))
        }));

        let restored =
            DidDocument::from_datoms("did:plc:didcommobject", &datoms).expect("restore DID doc");
        assert_eq!(
            restored.didcomm_endpoint(),
            Some("didcomm://mediator/object")
        );
        let endpoint = &restored
            .service_by_type(DIDCOMM_MESSAGING_SERVICE)
            .expect("didcomm service")
            .endpoint;
        match endpoint {
            ServiceEndpointValue::Object(endpoint) => {
                assert_eq!(
                    endpoint.get("uri").and_then(serde_json::Value::as_str),
                    Some("didcomm://mediator/object")
                );
                assert_eq!(
                    endpoint
                        .get("accept")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|values| values.first())
                        .and_then(serde_json::Value::as_str),
                    Some("didcomm/v2")
                );
                assert_eq!(
                    endpoint
                        .get("routingKeys")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|values| values.first())
                        .and_then(serde_json::Value::as_str),
                    Some("did:key:zMediator#key-x25519")
                );
            }
            _ => panic!("DIDComm service endpoint must remain object-valued"),
        }
    }

    #[test]
    fn did_document_matches_ed25519_public_key_multibase() {
        let public_key = [7u8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, public_key);
        let mut doc = DidDocument::empty("did:key:zKey");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zKey#agent-ed25519".to_string(),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: "did:key:zKey".to_string(),
            public_key_multibase: encoded.clone(),
        });

        assert!(doc.has_ed25519_public_key_multibase(&encoded));
        assert!(!doc.has_ed25519_public_key_multibase(&multibase::encode(
            multibase::Base::Base58Btc,
            [9u8; 32]
        )));
        assert!(!doc.has_ed25519_public_key_multibase("not-multibase"));
    }

    #[test]
    fn graph_membership_builder_uses_kotoba_service_type() {
        let mut doc = DidDocument::empty("did:key:zGraphs");
        doc.push_graph_membership_service(["kotoba://graph/a", "kotoba://graph/b"]);
        assert_eq!(
            doc.service_by_type(KOTOBA_GRAPH_MEMBERSHIP_SERVICE)
                .unwrap()
                .service_type,
            KOTOBA_GRAPH_MEMBERSHIP_SERVICE
        );
        assert_eq!(
            doc.graph_memberships(),
            vec!["kotoba://graph/a", "kotoba://graph/b"]
        );
    }

    #[test]
    fn kotoba_protocol_service_check_requires_all_protocol_services() {
        let mut doc = DidDocument::empty("did:key:zProtocolServices");
        assert_eq!(
            doc.missing_kotoba_protocol_services(),
            vec![
                DIDCOMM_MESSAGING_SERVICE,
                ATPROTO_PDS_SERVICE,
                KOTOBA_NODE_SERVICE,
                KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
            ]
        );
        assert!(!doc.has_kotoba_protocol_services());

        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://agent/inbox",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        doc.push_graph_membership_service(["kotoba://graph/a"]);

        assert!(doc.missing_kotoba_protocol_services().is_empty());
        assert!(doc.has_kotoba_protocol_services());
    }

    #[test]
    fn did_document_projects_protocol_services_to_datoms() {
        let mut doc = DidDocument::empty("did:key:zDatomServices");
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://mediator/abc",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        doc.push_graph_membership_service(["kotoba://graph/a", "kotoba://graph/b"]);
        let tx = kotoba_core::cid::KotobaCid::from_bytes(b"did-doc-tx");

        let datoms = doc.to_datoms(tx.clone());

        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_ID
                && datom.v == kotoba_datomic::Value::string("did:key:zDatomServices")
                && datom.t == tx
                && datom.added
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_ENTITY_CID
                && datom.v == kotoba_datomic::Value::string(doc.entity_cid().to_multibase())
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_METHOD
                && datom.v == kotoba_datomic::Value::string("key")
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_HAS_KOTOBA_PROTOCOL_SERVICES
                && datom.v == kotoba_datomic::Value::Bool(true)
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_DIDCOMM_MESSAGING_ENDPOINT
                && datom.v == kotoba_datomic::Value::string("didcomm://mediator/abc")
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_ATPROTO_PDS_ENDPOINT
                && datom.v == kotoba_datomic::Value::string("https://pds.example.com")
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_KOTOBA_NODE_ENDPOINT
                && datom.v == kotoba_datomic::Value::string("/ip4/127.0.0.1/tcp/4001")
        }));
        for membership in ["kotoba://graph/a", "kotoba://graph/b"] {
            assert!(
                datoms.iter().any(|datom| {
                    datom.e == doc.entity_cid()
                        && datom.a == ATTR_DID_KOTOBA_GRAPH_MEMBERSHIP
                        && datom.v == kotoba_datomic::Value::string(membership)
                }),
                "missing graph membership projection {membership}"
            );
        }
        for service_type in [
            DIDCOMM_MESSAGING_SERVICE,
            ATPROTO_PDS_SERVICE,
            KOTOBA_NODE_SERVICE,
            KOTOBA_GRAPH_MEMBERSHIP_SERVICE,
        ] {
            assert!(
                datoms.iter().any(|datom| {
                    datom.a == ATTR_DID_SERVICE_TYPE
                        && datom.v == kotoba_datomic::Value::string(service_type)
                }),
                "missing service type datom for {service_type}"
            );
            assert!(
                datoms.iter().any(|datom| {
                    datom.a == ATTR_RDF_TYPE
                        && datom.v == kotoba_datomic::Value::string(service_type)
                }),
                "missing RDF type alias datom for {service_type}"
            );
        }
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_CORE_SERVICE
                && datom.v == kotoba_datomic::Value::string("did:key:zDatomServices#didcomm")
        }));
        assert!(datoms.iter().any(|datom| {
            datom.e == doc.entity_cid()
                && datom.a == ATTR_DID_CORE_KEY_AGREEMENT
                && datom.v == kotoba_datomic::Value::vector(Vec::<kotoba_datomic::Value>::new())
        }));
        assert!(datoms.iter().any(|datom| {
            datom.a == ATTR_DID_SERVICE_ENDPOINT
                && datom.v
                    == kotoba_datomic::Value::vector([
                        kotoba_datomic::Value::string("kotoba://graph/a"),
                        kotoba_datomic::Value::string("kotoba://graph/b"),
                    ])
        }));
        assert!(datoms.iter().any(|datom| {
            datom.a == ATTR_DID_CORE_SERVICE_ENDPOINT
                && datom.v
                    == kotoba_datomic::Value::vector([
                        kotoba_datomic::Value::string("kotoba://graph/a"),
                        kotoba_datomic::Value::string("kotoba://graph/b"),
                    ])
        }));
    }

    #[test]
    fn did_document_roundtrips_through_datoms() {
        let mut doc = DidDocument::empty("did:key:zDatomRoundtrip");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zDatomRoundtrip#key-1".to_string(),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: "did:key:zDatomRoundtrip".to_string(),
            public_key_multibase: multibase::encode(multibase::Base::Base58Btc, [7u8; 32]),
        });
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zDatomRoundtrip#x25519-1".to_string(),
            key_type: X25519_KEY_TYPE.to_string(),
            controller: "did:key:zDatomRoundtrip".to_string(),
            public_key_multibase: multibase::encode(multibase::Base::Base58Btc, [8u8; 32]),
        });
        doc.authentication
            .push("did:key:zDatomRoundtrip#key-1".to_string());
        doc.key_agreement
            .push("did:key:zDatomRoundtrip#x25519-1".to_string());
        doc.capability_invocation
            .push("did:key:zDatomRoundtrip#key-1".to_string());
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://mediator/roundtrip",
        );
        doc.push_single_service(
            "atproto-pds",
            ATPROTO_PDS_SERVICE,
            "https://pds.example.com",
        );
        doc.push_single_service(
            "kotoba-node",
            KOTOBA_NODE_SERVICE,
            "/ip4/127.0.0.1/tcp/4001",
        );
        doc.push_graph_membership_service(["kotoba://graph/a", "kotoba://graph/b"]);
        let datoms = doc.to_datoms(kotoba_core::cid::KotobaCid::from_bytes(b"did-doc-tx"));

        let restored =
            DidDocument::from_datoms("did:key:zDatomRoundtrip", &datoms).expect("restore DID doc");

        assert_eq!(restored.id, doc.id);
        assert_eq!(restored.authentication, doc.authentication);
        assert_eq!(restored.key_agreement, doc.key_agreement);
        assert_eq!(restored.capability_invocation, doc.capability_invocation);
        assert_eq!(
            restored.verification_method[0].public_key_multibase,
            doc.verification_method[0].public_key_multibase
        );
        assert_eq!(
            restored.didcomm_endpoint(),
            Some("didcomm://mediator/roundtrip")
        );
        assert_eq!(
            restored.atproto_pds_endpoint(),
            Some("https://pds.example.com")
        );
        assert_eq!(restored.kotoba_endpoint(), Some("/ip4/127.0.0.1/tcp/4001"));
        assert_eq!(
            restored.graph_memberships(),
            vec!["kotoba://graph/a", "kotoba://graph/b"]
        );
    }

    #[test]
    fn did_document_restores_from_w3c_did_core_iri_datoms() {
        let mut doc = DidDocument::empty("did:key:zDidCoreIri");
        doc.authentication
            .push("did:key:zDidCoreIri#key-1".to_string());
        doc.push_single_service(
            "didcomm",
            DIDCOMM_MESSAGING_SERVICE,
            "didcomm://mediator/iri",
        );
        doc.push_graph_membership_service(["kotoba://graph/iri"]);
        let datoms = doc
            .to_datoms(kotoba_core::cid::KotobaCid::from_bytes(b"did-core-iri-tx"))
            .into_iter()
            .filter(|datom| {
                datom.a.starts_with("https://www.w3.org/ns/did#") || datom.a == ATTR_RDF_TYPE
            })
            .collect::<Vec<_>>();

        let restored =
            DidDocument::from_datoms("did:key:zDidCoreIri", &datoms).expect("restore DID doc");

        assert_eq!(restored.authentication, doc.authentication);
        assert_eq!(restored.didcomm_endpoint(), Some("didcomm://mediator/iri"));
        assert_eq!(restored.graph_memberships(), vec!["kotoba://graph/iri"]);
    }

    // ── key extraction ────────────────────────────────────────────────────────

    #[test]
    fn ed25519_public_key_returns_none_when_absent() {
        assert!(base_doc("did:key:z").ed25519_public_key().is_none());
    }

    #[test]
    fn x25519_public_key_returns_none_when_absent() {
        assert!(base_doc("did:key:z").x25519_public_key().is_none());
    }

    #[test]
    fn ed25519_public_key_extracted_correctly() {
        let raw_key = [0x42u8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, &raw_key);
        let mut doc = base_doc("did:key:z");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:z#key-1".to_string(),
            key_type: "Ed25519VerificationKey2020".to_string(),
            controller: "did:key:z".to_string(),
            public_key_multibase: encoded,
        });
        let extracted = doc.ed25519_public_key().unwrap();
        assert_eq!(extracted, raw_key);
    }

    #[test]
    fn x25519_public_key_prefers_w3c_key_agreement_relationship() {
        let first_key = [0xABu8; 32];
        let agreed_key = [0xCDu8; 32];
        let mut doc = base_doc("did:key:zX25519Agreement");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zX25519Agreement#unreferenced-x25519".to_string(),
            key_type: X25519_KEY_TYPE.to_string(),
            controller: "did:key:zX25519Agreement".to_string(),
            public_key_multibase: multibase::encode(multibase::Base::Base58Btc, first_key),
        });
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zX25519Agreement#agreement-x25519".to_string(),
            key_type: X25519_KEY_TYPE.to_string(),
            controller: "did:key:zX25519Agreement".to_string(),
            public_key_multibase: multibase::encode(multibase::Base::Base58Btc, agreed_key),
        });
        doc.key_agreement
            .push("did:key:zX25519Agreement#agreement-x25519".to_string());

        assert_eq!(doc.x25519_public_key().unwrap(), agreed_key);
    }

    // ── JSON roundtrip ────────────────────────────────────────────────────────

    #[test]
    fn did_document_json_roundtrip() {
        let doc = base_doc("did:key:zTestRoundtrip");
        let json = serde_json::to_string(&doc).unwrap();
        let back: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, doc.id);
    }

    // ── x25519 key extraction ─────────────────────────────────────────────────

    #[test]
    fn x25519_public_key_extracted_correctly() {
        let raw_key = [0xABu8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, &raw_key);
        let mut doc = base_doc("did:key:zX25519");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zX25519#key-x25519".to_string(),
            key_type: X25519_KEY_TYPE.to_string(),
            controller: "did:key:zX25519".to_string(),
            public_key_multibase: encoded,
        });
        let extracted = doc.x25519_public_key().unwrap();
        assert_eq!(extracted, raw_key);
    }

    #[test]
    fn x25519_wrong_length_returns_none() {
        // Encode only 16 bytes — should fail the 32-byte length check
        let short_key = [0x01u8; 16];
        let encoded = multibase::encode(multibase::Base::Base58Btc, &short_key);
        let mut doc = base_doc("did:key:zShort");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zShort#key-1".to_string(),
            key_type: X25519_KEY_TYPE.to_string(),
            controller: "did:key:zShort".to_string(),
            public_key_multibase: encoded,
        });
        assert!(doc.x25519_public_key().is_none());
    }

    // ── Ed25519 2018 type ─────────────────────────────────────────────────────

    #[test]
    fn ed25519_2018_type_is_recognised() {
        let raw_key = [0x55u8; 32];
        let encoded = multibase::encode(multibase::Base::Base58Btc, &raw_key);
        let mut doc = base_doc("did:key:z2018");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:z2018#key-1".to_string(),
            key_type: ED25519_KEY_TYPE_2018.to_string(),
            controller: "did:key:z2018".to_string(),
            public_key_multibase: encoded,
        });
        let extracted = doc.ed25519_public_key().unwrap();
        assert_eq!(extracted, raw_key);
    }

    // ── kotoba_endpoint ignores non-KotobaNode services ───────────────────────

    #[test]
    fn kotoba_endpoint_ignores_non_kotoba_node_service() {
        let mut doc = with_service(
            base_doc("did:key:zMulti"),
            "OtherService",
            ServiceEndpointValue::Single("https://other.example.com".to_string()),
        );
        doc.service.push(ServiceEndpoint {
            id: "did:key:zMulti#kotoba".to_string(),
            service_type: "KotobaNode".to_string(),
            endpoint: ServiceEndpointValue::Single("/ip4/10.0.0.1/tcp/4001".to_string()),
        });
        assert_eq!(doc.kotoba_endpoint(), Some("/ip4/10.0.0.1/tcp/4001"));
    }

    // ── graph_memberships with Single endpoint ────────────────────────────────

    #[test]
    fn graph_memberships_single_endpoint_returns_one_membership() {
        let doc = with_service(
            base_doc("did:key:zSingle"),
            "KotobaGraphMembership",
            ServiceEndpointValue::Single("only-one".to_string()),
        );
        assert_eq!(doc.graph_memberships(), vec!["only-one"]);
    }

    // ── malformed JSON deserialization ────────────────────────────────────────

    #[test]
    fn malformed_json_returns_error() {
        let bad_json = r#"{"id": "did:key:z", "broken json: }"#;
        let result: Result<DidDocument, _> = serde_json::from_str(bad_json);
        assert!(result.is_err(), "malformed JSON must fail to deserialize");
    }

    // ── both key types present ─────────────────────────────────────────────────

    #[test]
    fn both_key_types_present_each_extracted_independently() {
        let raw_ed = [0x11u8; 32];
        let raw_x25 = [0x22u8; 32];
        let enc_ed = multibase::encode(multibase::Base::Base58Btc, &raw_ed);
        let enc_x25 = multibase::encode(multibase::Base::Base58Btc, &raw_x25);

        let mut doc = base_doc("did:key:zBoth");
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zBoth#ed".to_string(),
            key_type: ED25519_KEY_TYPE_2020.to_string(),
            controller: "did:key:zBoth".to_string(),
            public_key_multibase: enc_ed,
        });
        doc.verification_method.push(VerificationMethod {
            id: "did:key:zBoth#x25519".to_string(),
            key_type: X25519_KEY_TYPE.to_string(),
            controller: "did:key:zBoth".to_string(),
            public_key_multibase: enc_x25,
        });

        assert_eq!(doc.ed25519_public_key().unwrap(), raw_ed);
        assert_eq!(doc.x25519_public_key().unwrap(), raw_x25);
    }
}
