//! DIDComm v2 message envelope model for Kotoba.
//!
//! The crate intentionally models the plaintext envelope and storage
//! projection.  Encryption/packing can sit above this boundary while Datom
//! remains the internal SSoT.

use kotoba_core::cid::KotobaCid;
use kotoba_datomic::Datom;
use kotoba_edn::EdnValue;
use serde::{Deserialize, Serialize};

pub const DIDCOMM_MESSAGING_SERVICE: &str = "DIDCommMessaging";

pub const ATTR_DIDCOMM_ID: &str = "didcomm/id";
pub const ATTR_DIDCOMM_TYPE: &str = "didcomm/type";
pub const ATTR_DIDCOMM_FROM: &str = "didcomm/from";
pub const ATTR_DIDCOMM_TO: &str = "didcomm/to";
pub const ATTR_DIDCOMM_THREAD: &str = "didcomm/thread";
pub const ATTR_DIDCOMM_PARENT_THREAD: &str = "didcomm/parentThread";
pub const ATTR_DIDCOMM_CREATED_TIME: &str = "didcomm/createdTime";
pub const ATTR_DIDCOMM_EXPIRES_TIME: &str = "didcomm/expiresTime";
pub const ATTR_DIDCOMM_BODY: &str = "didcomm/body";
pub const ATTR_DIDCOMM_BODY_FIELD_PREFIX: &str = "didcomm/body/";
pub const ATTR_DIDCOMM_ATTACHMENT: &str = "didcomm/attachment";
pub const ATTR_DIDCOMM_WIRE_ID: &str = "id";
pub const ATTR_DIDCOMM_WIRE_TYPE: &str = "type";
pub const ATTR_DIDCOMM_WIRE_FROM: &str = "from";
pub const ATTR_DIDCOMM_WIRE_TO: &str = "to";
pub const ATTR_DIDCOMM_WIRE_THREAD: &str = "thid";
pub const ATTR_DIDCOMM_WIRE_PARENT_THREAD: &str = "pthid";
pub const ATTR_DIDCOMM_WIRE_CREATED_TIME: &str = "created_time";
pub const ATTR_DIDCOMM_WIRE_EXPIRES_TIME: &str = "expires_time";
pub const ATTR_DIDCOMM_WIRE_BODY: &str = "body";
pub const ATTR_DIDCOMM_WIRE_ATTACHMENT: &str = "attachments";

#[derive(Debug, thiserror::Error)]
pub enum DidCommError {
    #[error("json encode: {0}")]
    Json(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidCommMessage {
    pub id: String,
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pthid: Option<String>,
    #[serde(
        rename = "created_time",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub created_time: Option<u64>,
    #[serde(
        rename = "expires_time",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_time: Option<u64>,
    #[serde(default)]
    pub body: serde_json::Value,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

impl DidCommMessage {
    pub fn cid(&self) -> Result<KotobaCid, DidCommError> {
        let bytes = serde_json::to_vec(self).map_err(|e| DidCommError::Json(e.to_string()))?;
        Ok(KotobaCid::from_bytes(&bytes))
    }

    pub fn thread_id(&self) -> &str {
        self.thid.as_deref().unwrap_or(&self.id)
    }

    pub fn to_datoms(&self, tx: KotobaCid) -> Result<Vec<Datom>, DidCommError> {
        let e = self.cid()?;
        let mut out = vec![
            datom(&e, ATTR_DIDCOMM_ID, EdnValue::string(&self.id), &tx),
            datom(&e, ATTR_DIDCOMM_WIRE_ID, EdnValue::string(&self.id), &tx),
            datom(
                &e,
                ATTR_DIDCOMM_TYPE,
                EdnValue::string(&self.message_type),
                &tx,
            ),
            datom(
                &e,
                ATTR_DIDCOMM_WIRE_TYPE,
                EdnValue::string(&self.message_type),
                &tx,
            ),
            datom(
                &e,
                ATTR_DIDCOMM_THREAD,
                EdnValue::string(self.thread_id()),
                &tx,
            ),
            datom(
                &e,
                ATTR_DIDCOMM_WIRE_THREAD,
                EdnValue::string(self.thread_id()),
                &tx,
            ),
            datom(&e, ATTR_DIDCOMM_TO, string_vec(&self.to), &tx),
            datom(&e, ATTR_DIDCOMM_WIRE_TO, string_vec(&self.to), &tx),
            datom(&e, ATTR_DIDCOMM_BODY, json_to_edn(&self.body), &tx),
            datom(&e, ATTR_DIDCOMM_WIRE_BODY, json_to_edn(&self.body), &tx),
        ];
        append_json_field_datoms(
            &mut out,
            &e,
            ATTR_DIDCOMM_BODY_FIELD_PREFIX,
            &self.body,
            &tx,
        );
        if let Some(from) = &self.from {
            out.push(datom(&e, ATTR_DIDCOMM_FROM, EdnValue::string(from), &tx));
            out.push(datom(
                &e,
                ATTR_DIDCOMM_WIRE_FROM,
                EdnValue::string(from),
                &tx,
            ));
        }
        if let Some(pthid) = &self.pthid {
            out.push(datom(
                &e,
                ATTR_DIDCOMM_PARENT_THREAD,
                EdnValue::string(pthid),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_DIDCOMM_WIRE_PARENT_THREAD,
                EdnValue::string(pthid),
                &tx,
            ));
        }
        if let Some(created_time) = self.created_time {
            out.push(datom(
                &e,
                ATTR_DIDCOMM_CREATED_TIME,
                EdnValue::Integer(created_time as i64),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_DIDCOMM_WIRE_CREATED_TIME,
                EdnValue::Integer(created_time as i64),
                &tx,
            ));
        }
        if let Some(expires_time) = self.expires_time {
            out.push(datom(
                &e,
                ATTR_DIDCOMM_EXPIRES_TIME,
                EdnValue::Integer(expires_time as i64),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_DIDCOMM_WIRE_EXPIRES_TIME,
                EdnValue::Integer(expires_time as i64),
                &tx,
            ));
        }
        for attachment in &self.attachments {
            out.push(datom(
                &e,
                ATTR_DIDCOMM_ATTACHMENT,
                attachment_to_edn(attachment),
                &tx,
            ));
            out.push(datom(
                &e,
                ATTR_DIDCOMM_WIRE_ATTACHMENT,
                attachment_to_edn(attachment),
                &tx,
            ));
        }
        out.push(datom(&e, &self.message_type, json_to_edn(&self.body), &tx));
        Ok(out)
    }
}

fn datom(e: &KotobaCid, a: &str, v: EdnValue, tx: &KotobaCid) -> Datom {
    Datom::assert(e.clone(), a.to_string(), v, tx.clone())
}

fn string_vec(xs: &[String]) -> EdnValue {
    EdnValue::vector(xs.iter().cloned().map(EdnValue::string))
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
        let attr = format!("{attr_prefix}{key}");
        out.push(datom(e, &attr, json_to_edn(value), tx));
        append_json_field_datoms(out, e, &format!("{attr}/"), value, tx);
    }
}

fn attachment_to_edn(attachment: &Attachment) -> EdnValue {
    let mut fields = vec![
        (EdnValue::kw_bare("id"), EdnValue::string(&attachment.id)),
        (EdnValue::kw_bare("data"), json_to_edn(&attachment.data)),
    ];
    if let Some(description) = &attachment.description {
        fields.push((
            EdnValue::kw_bare("description"),
            EdnValue::string(description),
        ));
    }
    if let Some(media_type) = &attachment.media_type {
        fields.push((
            EdnValue::kw_bare("media_type"),
            EdnValue::string(media_type),
        ));
    }
    EdnValue::map(fields)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn didcomm_message_projects_to_datoms() {
        let msg = DidCommMessage {
            id: "msg-1".into(),
            message_type: "https://didcomm.org/basicmessage/2.0/message".into(),
            from: Some("did:key:zAlice".into()),
            to: vec!["did:key:zBob".into()],
            thid: Some("thread-1".into()),
            pthid: None,
            created_time: Some(1),
            expires_time: None,
            body: json!({"content": "hello", "meta": {"lang": "en"}, "tags": ["chat"]}),
            attachments: vec![Attachment {
                id: "att-1".into(),
                description: Some("profile".into()),
                media_type: Some("application/json".into()),
                data: json!({"json": {"name": "Alice"}}),
            }],
        };
        let datoms = msg.to_datoms(KotobaCid::from_bytes(b"tx")).unwrap();
        assert!(datoms.iter().any(|d| d.a == ATTR_DIDCOMM_TYPE));
        assert!(datoms.iter().any(|d| d.a == ATTR_DIDCOMM_THREAD));
        assert!(datoms.iter().any(|d| d.a == ATTR_DIDCOMM_BODY));
        assert!(datoms.iter().any(|d| d.a == ATTR_DIDCOMM_WIRE_TYPE));
        assert!(datoms
            .iter()
            .any(|d| d.a == ATTR_DIDCOMM_WIRE_THREAD && d.v == EdnValue::string("thread-1")));
        let body_edn = datoms
            .iter()
            .find(|d| d.a == ATTR_DIDCOMM_BODY)
            .map(|d| kotoba_edn::to_string(&d.v))
            .unwrap();
        assert!(body_edn.contains(":meta {:lang \"en\""));
        assert!(body_edn.contains(":tags [\"chat\"]"));
        assert!(datoms
            .iter()
            .any(|d| d.a == "didcomm/body/content" && d.v == EdnValue::string("hello")));
        assert!(datoms
            .iter()
            .any(|d| d.a == "didcomm/body/meta"
                && kotoba_edn::to_string(&d.v).contains(":lang \"en\"")));
        assert!(datoms
            .iter()
            .any(|d| d.a == "didcomm/body/meta/lang" && d.v == EdnValue::string("en")));
        assert!(datoms
            .iter()
            .any(|d| d.a == "didcomm/body/tags"
                && kotoba_edn::to_string(&d.v).contains("[\"chat\"]")));
        let attachment_edn = datoms
            .iter()
            .find(|d| d.a == ATTR_DIDCOMM_ATTACHMENT)
            .map(|d| kotoba_edn::to_string(&d.v))
            .unwrap();
        assert!(attachment_edn.contains(":description \"profile\""));
        assert!(attachment_edn.contains(":media_type \"application/json\""));
        assert!(attachment_edn.contains(":json {:name \"Alice\""));
        assert!(datoms
            .iter()
            .any(|d| d.a == "https://didcomm.org/basicmessage/2.0/message"));
    }
}
