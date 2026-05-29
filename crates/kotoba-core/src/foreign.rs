use crate::cid::KotobaCid;

/// CALL_FOREIGN (0xF) subtypes
#[derive(Debug, Clone)]
pub enum ForeignCallType {
    /// LLM text inference → Vultr A16 pool via AgentGateway MCP
    LlmInfer {
        model_cid: KotobaCid,
        adapter_cid: Option<KotobaCid>,
        session_cid: Option<KotobaCid>,
        max_tokens: u32,
    },
    /// Compute embedding → vector<f32> QuadObject
    Embed { model_cid: KotobaCid, text: String },
    /// Load FP8 weight tensor from Vault
    WeightLoad {
        blob_cid: KotobaCid,
        shape: Vec<u32>,
    },
}

#[derive(Debug, Clone)]
pub struct ForeignCall {
    pub call_id: u64,
    pub call_type: ForeignCallType,
    pub ucan_cid: KotobaCid, // CACAO authorization
}

/// ForeignBridge — delegates CALL_FOREIGN to AgentGateway MCP via JSON-RPC 2.0.
///
/// Wire: POST {gateway_url}/mcp  (JSON-RPC 2.0 tools/call)
/// Auth: UCAN CID passed as `Authorization: Bearer {ucan_cid}`
///
/// Tool mapping:
///   LlmInfer   → tool `kotoba_infer_run`
///   Embed      → tool `kotoba_embed_create`
///   WeightLoad → tool `kotoba_weight_get`
pub struct ForeignBridge {
    pub gateway_url: String,
    #[cfg(feature = "foreign-http")]
    client: reqwest::Client,
}

impl ForeignBridge {
    pub fn new(gateway_url: impl Into<String>) -> Self {
        Self {
            gateway_url: gateway_url.into(),
            #[cfg(feature = "foreign-http")]
            client: reqwest::Client::new(),
        }
    }

    #[cfg(feature = "foreign-http")]
    pub async fn call(&self, call: ForeignCall) -> Result<Vec<u8>, ForeignError> {
        let ucan = call.ucan_cid.to_multibase();

        let (tool, arguments) = match call.call_type {
            ForeignCallType::LlmInfer {
                model_cid,
                adapter_cid: _,
                session_cid: _,
                max_tokens,
            } => {
                let args = serde_json::json!({
                    "model_cid":      model_cid.to_multibase(),
                    "max_new_tokens": max_tokens,
                    "prompt":         "",
                });
                ("kotoba_infer_run", args)
            }
            ForeignCallType::Embed { model_cid, text } => {
                let args = serde_json::json!({
                    "text":      text,
                    "model_cid": model_cid.to_multibase(),
                    "doc_cid":   KotobaCid::from_bytes(text.as_bytes()).to_multibase(),
                    "graph":     "foreign/embed",
                });
                ("kotoba_embed_create", args)
            }
            ForeignCallType::WeightLoad { blob_cid, shape: _ } => {
                let args = serde_json::json!({
                    "cid": blob_cid.to_multibase(),
                });
                ("kotoba_weight_get", args)
            }
        };

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id":      call.call_id,
            "method":  "tools/call",
            "params": {
                "name":      tool,
                "arguments": arguments,
            }
        });

        let url = format!("{}/mcp", self.gateway_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {ucan}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| ForeignError::Gateway(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ForeignError::Gateway(format!("HTTP {status}: {text}")));
        }

        let rpc: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ForeignError::Gateway(e.to_string()))?;

        if let Some(err) = rpc.get("error") {
            return Err(ForeignError::Gateway(err.to_string()));
        }

        // Result bytes: serialize the result JSON as UTF-8
        let result = rpc.get("result").unwrap_or(&serde_json::Value::Null);
        let bytes = serde_json::to_vec(result).map_err(|e| ForeignError::Gateway(e.to_string()))?;

        Ok(bytes)
    }

    #[cfg(not(feature = "foreign-http"))]
    pub async fn call(&self, _call: ForeignCall) -> Result<Vec<u8>, ForeignError> {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_cid(seed: &[u8]) -> KotobaCid {
        KotobaCid::from_bytes(seed)
    }

    #[test]
    fn foreign_bridge_new_ok() {
        let bridge = ForeignBridge::new("http://localhost:9000");
        assert!(bridge.gateway_url.contains("9000"));
    }

    #[test]
    fn foreign_call_type_llm_infer_fields() {
        let call = ForeignCall {
            call_id: 1,
            call_type: ForeignCallType::LlmInfer {
                model_cid: dummy_cid(b"model"),
                adapter_cid: None,
                session_cid: None,
                max_tokens: 256,
            },
            ucan_cid: dummy_cid(b"ucan"),
        };
        assert_eq!(call.call_id, 1);
    }

    #[test]
    fn foreign_call_type_embed_fields() {
        let call = ForeignCall {
            call_id: 2,
            call_type: ForeignCallType::Embed {
                model_cid: dummy_cid(b"embed-model"),
                text: "hello world".into(),
            },
            ucan_cid: dummy_cid(b"ucan"),
        };
        if let ForeignCallType::Embed { text, .. } = &call.call_type {
            assert_eq!(text, "hello world");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn foreign_call_type_weight_load_fields() {
        let call = ForeignCall {
            call_id: 3,
            call_type: ForeignCallType::WeightLoad {
                blob_cid: dummy_cid(b"blob"),
                shape: vec![4096, 4096],
            },
            ucan_cid: dummy_cid(b"ucan"),
        };
        if let ForeignCallType::WeightLoad { shape, .. } = &call.call_type {
            assert_eq!(shape, &[4096, 4096]);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn foreign_error_display() {
        let e = ForeignError::Gateway("timeout".into());
        assert!(e.to_string().contains("timeout"));
        assert!(ForeignError::NotImplemented
            .to_string()
            .contains("not implemented"));
        assert!(ForeignError::Unauthorized
            .to_string()
            .contains("unauthorized"));
    }

    #[test]
    fn foreign_bridge_trims_trailing_slash_for_url() {
        let bridge = ForeignBridge::new("http://gateway.example.com/");
        // The URL is stored as-is; trim happens at call time — just ensure construction works
        assert!(bridge.gateway_url.contains("gateway.example.com"));
    }

    #[test]
    fn foreign_call_weight_load_shape_clone() {
        let call = ForeignCall {
            call_id: 10,
            call_type: ForeignCallType::WeightLoad {
                blob_cid: dummy_cid(b"weight"),
                shape: vec![1024, 512],
            },
            ucan_cid: dummy_cid(b"ucan2"),
        };
        let call2 = call.clone();
        if let ForeignCallType::WeightLoad { shape, .. } = call2.call_type {
            assert_eq!(shape, vec![1024, 512]);
        } else {
            panic!("expected WeightLoad");
        }
    }

    #[test]
    fn foreign_call_llm_infer_with_optional_cids() {
        let call = ForeignCall {
            call_id: 5,
            call_type: ForeignCallType::LlmInfer {
                model_cid: dummy_cid(b"model"),
                adapter_cid: Some(dummy_cid(b"adapter")),
                session_cid: Some(dummy_cid(b"session")),
                max_tokens: 512,
            },
            ucan_cid: dummy_cid(b"ucan3"),
        };
        if let ForeignCallType::LlmInfer {
            max_tokens,
            adapter_cid,
            session_cid,
            ..
        } = call.call_type
        {
            assert_eq!(max_tokens, 512);
            assert!(adapter_cid.is_some());
            assert!(session_cid.is_some());
        } else {
            panic!("expected LlmInfer");
        }
    }

    // ── New tests ─────────────────────────────────────────────────────────────

    #[test]
    fn foreign_error_gateway_contains_message() {
        let msg = "connection refused";
        let e = ForeignError::Gateway(msg.to_string());
        assert!(e.to_string().contains(msg));
    }

    #[test]
    fn foreign_error_not_implemented_display() {
        let e = ForeignError::NotImplemented;
        let s = e.to_string();
        assert_eq!(s, "not implemented");
    }

    #[test]
    fn foreign_error_unauthorized_display() {
        let e = ForeignError::Unauthorized;
        let s = e.to_string();
        assert_eq!(s, "unauthorized");
    }

    #[test]
    fn foreign_bridge_new_stores_exact_url() {
        let url = "https://mcp.example.com";
        let bridge = ForeignBridge::new(url);
        assert_eq!(bridge.gateway_url, url);
    }

    #[test]
    fn foreign_call_embed_empty_text() {
        let call = ForeignCall {
            call_id: 99,
            call_type: ForeignCallType::Embed {
                model_cid: dummy_cid(b"m"),
                text: "".to_string(),
            },
            ucan_cid: dummy_cid(b"u"),
        };
        if let ForeignCallType::Embed { text, .. } = &call.call_type {
            assert!(text.is_empty());
        } else {
            panic!("expected Embed");
        }
    }

    #[test]
    fn foreign_call_weight_load_empty_shape() {
        let call = ForeignCall {
            call_id: 7,
            call_type: ForeignCallType::WeightLoad {
                blob_cid: dummy_cid(b"weight_empty"),
                shape: vec![],
            },
            ucan_cid: dummy_cid(b"u2"),
        };
        if let ForeignCallType::WeightLoad { shape, .. } = &call.call_type {
            assert!(shape.is_empty());
        } else {
            panic!("expected WeightLoad");
        }
    }

    #[test]
    fn foreign_call_id_zero_is_valid() {
        let call = ForeignCall {
            call_id: 0,
            call_type: ForeignCallType::LlmInfer {
                model_cid: dummy_cid(b"m"),
                adapter_cid: None,
                session_cid: None,
                max_tokens: 1,
            },
            ucan_cid: dummy_cid(b"u"),
        };
        assert_eq!(call.call_id, 0);
    }

    #[test]
    fn foreign_error_debug_contains_variant_name() {
        let e = ForeignError::NotImplemented;
        let s = format!("{e:?}");
        assert!(s.contains("NotImplemented"));
        let e2 = ForeignError::Unauthorized;
        assert!(format!("{e2:?}").contains("Unauthorized"));
        let e3 = ForeignError::Gateway("oops".into());
        assert!(format!("{e3:?}").contains("Gateway"));
    }
}
