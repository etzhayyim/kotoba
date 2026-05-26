/// Application-layer message schema: thread, reply, reaction.
use serde::{Deserialize, Serialize};

pub const SIGNAL_CONTENT_TYPE: &str = "application/x-signal-envelope";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MessageType {
    /// 1:1 Double Ratchet message.
    DirectMessage,
    /// Group Sender Key message.
    GroupMessage,
    /// Delivery receipt.
    Receipt,
}

/// Wire-format message envelope for `ai.gftd.signal.sendMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignalMessage {
    pub message_type:   MessageType,
    pub sender_did:     String,
    pub recipient_did:  String,
    pub device_id:      String,
    /// Optional group ID for GroupMessage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id:       Option<String>,
    /// Serialised `RatchetMessage` or `SenderKeyMessage` (JSON).
    pub ciphertext_envelope: String,
    /// RFC 3339 timestamp.
    pub timestamp:      String,
    /// For initial X3DH messages: sender's ephemeral public key (base64url).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_key:  Option<String>,
    /// For initial X3DH messages: consumed one-time pre-key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_prekey_id: Option<u32>,
}

/// Application-level thread message (plaintext, nested inside ciphertext_envelope).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadMessage {
    /// Message ID (CID or UUID).
    pub id:          String,
    pub sender_did:  String,
    pub text:        String,
    /// Reply-to message ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to:    Option<String>,
    /// Inline reactions at creation time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reactions:   Vec<Reaction>,
    pub timestamp:   String,
}

/// Emoji reaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reaction {
    pub sender_did: String,
    pub emoji:      String,
    pub message_id: String,
}

/// Delivery / read receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryReceipt {
    pub message_ids: Vec<String>,
    pub status:      ReceiptStatus,
    pub timestamp:   String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReceiptStatus {
    Delivered,
    Read,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_content_type_constant() {
        assert_eq!(SIGNAL_CONTENT_TYPE, "application/x-signal-envelope");
    }

    #[test]
    fn message_type_json_is_camel_case() {
        assert_eq!(serde_json::to_string(&MessageType::DirectMessage).unwrap(),  "\"directMessage\"");
        assert_eq!(serde_json::to_string(&MessageType::GroupMessage).unwrap(),   "\"groupMessage\"");
        assert_eq!(serde_json::to_string(&MessageType::Receipt).unwrap(),        "\"receipt\"");
    }

    #[test]
    fn receipt_status_json_is_camel_case() {
        assert_eq!(serde_json::to_string(&ReceiptStatus::Delivered).unwrap(), "\"delivered\"");
        assert_eq!(serde_json::to_string(&ReceiptStatus::Read).unwrap(),      "\"read\"");
    }

    #[test]
    fn signal_message_json_roundtrip() {
        let msg = SignalMessage {
            message_type:       MessageType::DirectMessage,
            sender_did:         "did:key:zSender".to_string(),
            recipient_did:      "did:key:zRecip".to_string(),
            device_id:          "device-1".to_string(),
            group_id:           None,
            ciphertext_envelope: "base64ciphertext==".to_string(),
            timestamp:          "2026-01-01T00:00:00Z".to_string(),
            ephemeral_key:      None,
            one_time_prekey_id: None,
        };
        let json  = serde_json::to_string(&msg).unwrap();
        let back: SignalMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.sender_did,    msg.sender_did);
        assert_eq!(back.recipient_did, msg.recipient_did);
        // Optional None fields should be absent from JSON
        assert!(!json.contains("groupId"));
        assert!(!json.contains("ephemeralKey"));
        assert!(!json.contains("oneTimePrekeyId"));
    }

    #[test]
    fn thread_message_reactions_omitted_when_empty() {
        let m = ThreadMessage {
            id:         "msg-1".to_string(),
            sender_did: "did:key:z1".to_string(),
            text:       "hello".to_string(),
            reply_to:   None,
            reactions:  vec![],
            timestamp:  "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("reactions"), "empty reactions must be omitted");
    }

    #[test]
    fn reaction_json_roundtrip() {
        let r = Reaction {
            sender_did: "did:key:zA".to_string(),
            emoji:      "👍".to_string(),
            message_id: "msg-42".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: Reaction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.emoji, "👍");
        assert_eq!(back.message_id, "msg-42");
    }
}
