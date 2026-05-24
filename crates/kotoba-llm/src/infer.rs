use kotoba_core::cid::KotobaCid;
use kotoba_vm::foreign::{ForeignBridge, ForeignCall, ForeignCallType};
use super::kvcache::KvCache;

/// InferenceRequest — maps to Invoke ChainEntry + CALL_FOREIGN(LlmInfer)
/// Each token generation = one Pregel superstep
/// Bonsai ADR-2605092500: Reasoning as Sap-Flow Walk in Vector Space
pub struct InferenceRequest {
    pub model_cid:    KotobaCid,
    pub adapter_cid:  Option<KotobaCid>,   // LoRA
    pub input_tokens: Vec<u32>,
    pub max_tokens:   u32,
    pub call_id:      u64,
    pub ucan_cid:     KotobaCid,
}

pub struct InferenceSession {
    pub request:  InferenceRequest,
    pub kv_cache: KvCache,
    pub output:   Vec<u32>,
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
                model_cid:   self.request.model_cid.clone(),
                adapter_cid: self.request.adapter_cid.clone(),
                session_cid: Some(self.kv_cache.session_cid.clone()),
                max_tokens:  self.request.max_tokens,
            },
        };
        let _result = bridge.call(call).await
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
