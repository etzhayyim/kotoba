use kotoba_core::cid::KotobaCid;

/// CALL_FOREIGN (0xF) subtypes
#[derive(Debug, Clone)]
pub enum ForeignCallType {
    /// LLM text inference → Vultr A16 pool via AgentGateway MCP
    LlmInfer {
        model_cid:   KotobaCid,
        adapter_cid: Option<KotobaCid>,
        session_cid: Option<KotobaCid>,
        max_tokens:  u32,
    },
    /// Compute embedding → vector<f32> QuadObject
    Embed {
        model_cid: KotobaCid,
        text:      String,
    },
    /// Load FP8 weight tensor from Vault
    WeightLoad {
        blob_cid: KotobaCid,
        shape:    Vec<u32>,
    },
}

#[derive(Debug, Clone)]
pub struct ForeignCall {
    pub call_id:   u64,
    pub call_type: ForeignCallType,
    pub ucan_cid:  KotobaCid, // CACAO authorization
}

/// ForeignBridge — delegates CALL_FOREIGN to AgentGateway MCP
/// Full implementation: HTTP to AgentGateway → LangServer pod → Vultr A16
pub struct ForeignBridge {
    pub gateway_url: String,
}

impl ForeignBridge {
    pub fn new(gateway_url: impl Into<String>) -> Self {
        Self { gateway_url: gateway_url.into() }
    }

    pub async fn call(&self, _call: ForeignCall) -> Result<Vec<u8>, ForeignError> {
        // Phase 6 implementation: HTTP POST to AgentGateway
        Err(ForeignError::NotImplemented)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ForeignError {
    #[error("not implemented")]
    NotImplemented,
    #[error("gateway error: {0}")]
    Gateway(String),
    #[error("unauthorized")]
    Unauthorized,
}
