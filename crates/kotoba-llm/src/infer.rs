use super::kvcache::KvCache;
use kotoba_core::cid::KotobaCid;
use kotoba_core::foreign::{ForeignBridge, ForeignCall, ForeignCallType};

/// InferenceRequest — maps to Invoke ChainEntry + CALL_FOREIGN(LlmInfer)
/// Each token generation = one Pregel superstep
/// Bonsai ADR-2605092500: Reasoning as Sap-Flow Walk in Vector Space
pub struct InferenceRequest {
    pub model_cid: KotobaCid,
    pub adapter_cid: Option<KotobaCid>, // LoRA
    pub input_tokens: Vec<u32>,
    pub max_tokens: u32,
    pub call_id: u64,
    pub ucan_cid: KotobaCid,
}

pub struct InferenceSession {
    pub request: InferenceRequest,
    pub kv_cache: KvCache,
    pub output: Vec<u32>,
}

impl InferenceSession {
    pub fn new(request: InferenceRequest, session_cid: KotobaCid) -> Self {
        Self {
            kv_cache: KvCache::new(session_cid),
            output: Vec::new(),
            request,
        }
    }

    /// Delegate to AgentGateway → Vultr A16 pool (ADR-2605211000)
    pub async fn run(&mut self, bridge: &ForeignBridge) -> Result<Vec<u32>, InferError> {
        let call = ForeignCall {
            call_id: self.request.call_id,
            ucan_cid: self.request.ucan_cid.clone(),
            call_type: ForeignCallType::LlmInfer {
                model_cid: self.request.model_cid.clone(),
                adapter_cid: self.request.adapter_cid.clone(),
                session_cid: Some(self.kv_cache.session_cid.clone()),
                max_tokens: self.request.max_tokens,
            },
        };
        let _result = bridge
            .call(call)
            .await
            .map_err(|e| InferError::Bridge(e.to_string()))?;
        Ok(vec![]) // token stream in full impl
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InferError {
    #[error("bridge error: {0}")]
    Bridge(String),
    #[error("context length exceeded")]
    ContextExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;

    fn make_request() -> InferenceRequest {
        InferenceRequest {
            model_cid: KotobaCid::from_bytes(b"model"),
            adapter_cid: None,
            input_tokens: vec![1, 2, 3],
            max_tokens: 64,
            call_id: 42,
            ucan_cid: KotobaCid::from_bytes(b"ucan"),
        }
    }

    #[test]
    fn new_session_output_is_empty() {
        let session_cid = KotobaCid::from_bytes(b"session");
        let session = InferenceSession::new(make_request(), session_cid);
        assert!(session.output.is_empty());
    }

    #[test]
    fn new_session_kvcache_has_correct_cid() {
        let session_cid = KotobaCid::from_bytes(b"my-session");
        let session = InferenceSession::new(make_request(), session_cid.clone());
        assert_eq!(session.kv_cache.session_cid, session_cid);
    }

    #[test]
    fn new_session_preserves_request_fields() {
        let session_cid = KotobaCid::from_bytes(b"sess");
        let session = InferenceSession::new(make_request(), session_cid);
        assert_eq!(session.request.call_id, 42);
        assert_eq!(session.request.max_tokens, 64);
        assert_eq!(session.request.input_tokens, vec![1, 2, 3]);
        assert!(session.request.adapter_cid.is_none());
    }

    #[test]
    fn infer_error_bridge_display() {
        let e = InferError::Bridge("timeout".to_string());
        assert_eq!(e.to_string(), "bridge error: timeout");
    }

    #[test]
    fn infer_error_context_exceeded_display() {
        let e = InferError::ContextExceeded;
        assert_eq!(e.to_string(), "context length exceeded");
    }

    // ── additional InferenceSession / InferenceRequest tests ──────────────────

    #[test]
    fn new_session_kvcache_is_empty() {
        let session_cid = KotobaCid::from_bytes(b"session");
        let session = InferenceSession::new(make_request(), session_cid);
        // KvCache starts with an empty Arrangement (no quads stored)
        let quads = session
            .kv_cache
            .arrangement
            .get_by_attribute("kv/layer/0/seq/0");
        assert!(quads.is_empty(), "new session KV cache should be empty");
    }

    #[test]
    fn inference_request_with_adapter_cid() {
        let req = InferenceRequest {
            model_cid: KotobaCid::from_bytes(b"model"),
            adapter_cid: Some(KotobaCid::from_bytes(b"lora")),
            input_tokens: vec![10, 20],
            max_tokens: 32,
            call_id: 99,
            ucan_cid: KotobaCid::from_bytes(b"ucan"),
        };
        assert!(req.adapter_cid.is_some());
        assert_eq!(req.adapter_cid.unwrap(), KotobaCid::from_bytes(b"lora"));
    }

    #[test]
    fn inference_request_model_cid_stable() {
        let cid = KotobaCid::from_bytes(b"gemma4-2b");
        let req = InferenceRequest {
            model_cid: cid.clone(),
            adapter_cid: None,
            input_tokens: vec![],
            max_tokens: 0,
            call_id: 0,
            ucan_cid: KotobaCid::from_bytes(b"u"),
        };
        assert_eq!(req.model_cid, cid);
    }

    #[test]
    fn infer_error_bridge_with_empty_message() {
        let e = InferError::Bridge(String::new());
        assert_eq!(e.to_string(), "bridge error: ");
    }

    #[test]
    fn infer_error_bridge_with_long_message() {
        let msg = "timeout after 120s while waiting for GPU response";
        let e = InferError::Bridge(msg.to_string());
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn two_sessions_with_different_cids_have_different_kvcache_cids() {
        let s1 = InferenceSession::new(make_request(), KotobaCid::from_bytes(b"session-a"));
        let s2 = InferenceSession::new(make_request(), KotobaCid::from_bytes(b"session-b"));
        assert_ne!(s1.kv_cache.session_cid, s2.kv_cache.session_cid);
    }
}
