use anyhow::Result;
use std::sync::Arc;
use wasmtime::{Config, Engine, Store};
use wasmtime::component::{Component, ComponentType, Lift, Linker, Lower};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView, ResourceTable};
use kotoba_auth::delegation::DelegationChain;

/// Type alias for a synchronous local inference function.
///
/// Signature: `(prompt: &str, max_new_tokens: usize) -> Result<String>`
///
/// The concrete implementation (e.g. `GemmaRunner::generate`) is provided by
/// `kotoba-llm --features local-inference` and wired in by `kotoba-server`.
/// Using a trait object here breaks the circular dependency:
///   kotoba-llm → kotoba-vm → kotoba-runtime
/// by removing the direct kotoba-runtime → kotoba-llm edge.
pub type InferenceFn = Arc<dyn Fn(&str, usize) -> anyhow::Result<String> + Send + Sync>;

/// Type alias for a synchronous dense embedding function.
///
/// Signature: `(text: &str) -> Result<Vec<f32>>`
///
/// Wired in from `kotoba-ingest::embed_client::EmbedClient` by `kotoba-server`.
/// Type-erased to avoid kotoba-runtime → kotoba-ingest dependency.
pub type EmbedFn = Arc<dyn Fn(&str) -> anyhow::Result<Vec<f32>> + Send + Sync>;

/// WIT record type for kotoba:kais/kqe.quad.
///
/// `func_wrap` requires an exact Rust type that mirrors the WIT record layout.
/// Field names must match WIT field names (kebab-case via `#[component(name)]`).
#[derive(Debug, Clone, ComponentType, Lift, Lower)]
#[component(record)]
pub struct WitQuad {
    pub graph: String,
    pub subject: String,
    pub predicate: String,
    #[component(name = "object-cbor")]
    pub object_cbor: Vec<u8>,
}

/// Host-side state injected into every WASM Store.
/// Carries the capabilities that host functions need plus WASI context.
pub struct HostState {
    /// DID of the agent executing this invocation
    pub agent_did: String,
    /// Gas counter (decrements per host call)
    pub gas_remaining: u64,
    /// Accumulated output quads (asserted by guest via kqe.assert-quad)
    pub pending_asserts: Vec<PendingQuad>,
    pub pending_retracts: Vec<PendingQuad>,
    /// Snapshot of the named graph's quads — pre-populated before execution
    /// so that `kqe.query` can do synchronous predicate-filter lookups.
    pub quad_snapshot: Vec<WitQuad>,
    /// kse.publish calls buffered during WASM execution.
    /// Applied to the KSE Journal by the caller after execute() returns.
    pub pending_publishes: Vec<(String, Vec<u8>)>,
    /// chain.append-infer calls buffered during WASM execution.
    /// Each entry: (model_cid, prompt_cid, output_cid).
    pub pending_chain_entries: Vec<(String, String, String)>,
    /// WASI preview2 context (required by wasm32-wasip2 components)
    pub wasi_ctx: WasiCtx,
    pub wasi_table: ResourceTable,
    /// Local CPU inference callable.
    ///
    /// `None` by default — pass a concrete function via `HostState::with_inference()`
    /// to wire in real inference (e.g. from `kotoba-llm --features local-inference`).
    ///
    /// Type-erased as `InferenceFn` to avoid a direct kotoba-runtime → kotoba-llm
    /// dependency (which would create a cycle through kotoba-vm).
    pub inference_engine: Option<InferenceFn>,
    /// LoRA loads buffered during WASM execution — (base_model_cid, lora_cid) pairs.
    /// Applied by the caller after execute() returns.
    pub pending_lora_loads: Vec<(String, String)>,
    /// Head commit map (graph multibase → commit multibase) — pre-populated before execution
    /// so that `kqe.get-head` can do synchronous lookups.
    pub head_commits: std::collections::HashMap<String, String>,
    /// Inbox for `kse.drain` — pre-populated by the caller with (topic, payload) entries.
    pub kse_inbox: Vec<(String, Vec<u8>)>,
    /// Head CID of the current agent's Source Chain — pre-populated before execution
    /// so that `chain.head-cid` can return it synchronously.
    pub source_chain_head: Option<String>,
    /// Dense embedding function — routes to HttpEmbedClient when configured.
    /// Type-erased to avoid kotoba-runtime → kotoba-ingest dependency.
    pub embed_fn: Option<EmbedFn>,
}

#[derive(Debug, Clone)]
pub struct PendingQuad {
    pub graph:       String,
    pub subject:     String,
    pub predicate:   String,
    pub object_cbor: Vec<u8>,
}

impl HostState {
    pub fn new(agent_did: impl Into<String>, gas_limit: u64) -> Self {
        let wasi_ctx = WasiCtxBuilder::new().inherit_stderr().build();
        Self {
            agent_did: agent_did.into(),
            gas_remaining: gas_limit,
            pending_asserts: Vec::new(),
            pending_retracts: Vec::new(),
            quad_snapshot: Vec::new(),
            pending_publishes: Vec::new(),
            pending_chain_entries: Vec::new(),
            wasi_ctx,
            wasi_table: ResourceTable::new(),
            inference_engine: None,
            pending_lora_loads: Vec::new(),
            head_commits: std::collections::HashMap::new(),
            kse_inbox: Vec::new(),
            source_chain_head: None,
            embed_fn: None,
        }
    }

    /// Set the Source Chain head CID for `chain.head-cid` lookups.
    pub fn with_source_chain_head(mut self, head: Option<String>) -> Self {
        self.source_chain_head = head;
        self
    }

    /// Wire in a real embedding function (e.g. from HttpEmbedClient).
    pub fn with_embed_fn(mut self, f: EmbedFn) -> Self {
        self.embed_fn = Some(f);
        self
    }

    /// Pre-populate the quad snapshot for `kqe.query` lookups during WASM execution.
    pub fn with_snapshot(mut self, snapshot: Vec<WitQuad>) -> Self {
        self.quad_snapshot = snapshot;
        self
    }

    /// Pre-populate the head commits map for `kqe.get-head` lookups during WASM execution.
    pub fn with_head_commits(mut self, head_commits: std::collections::HashMap<String, String>) -> Self {
        self.head_commits = head_commits;
        self
    }

    /// Construct a HostState with a pre-loaded local inference engine.
    ///
    /// The caller provides any callable matching `(prompt, max_tokens) → Result<String>`.
    /// Typically this is a closure wrapping `GemmaRunner::generate` from
    /// `kotoba-llm --features local-inference`:
    ///
    /// ```rust,ignore
    /// let runner = Arc::new(std::sync::Mutex::new(GemmaRunner::load().await?));
    /// let engine: InferenceFn = Arc::new(move |prompt, max| {
    ///     runner.lock().unwrap().generate(prompt, max)
    /// });
    /// let state = HostState::with_inference("did:example:1", 10_000_000, engine);
    /// ```
    pub fn with_inference(
        agent_did: impl Into<String>,
        gas_limit: u64,
        engine: InferenceFn,
    ) -> Self {
        let mut s = Self::new(agent_did, gas_limit);
        s.inference_engine = Some(engine);
        s
    }

    pub fn with_inference_and_snapshot(
        agent_did: impl Into<String>,
        gas_limit: u64,
        engine: InferenceFn,
        snapshot: Vec<WitQuad>,
    ) -> Self {
        let mut s = Self::with_inference(agent_did, gas_limit, engine);
        s.quad_snapshot = snapshot;
        s
    }

    pub fn charge_gas(&mut self, cost: u64) -> Result<()> {
        if self.gas_remaining < cost {
            anyhow::bail!("gas exhausted");
        }
        self.gas_remaining -= cost;
        Ok(())
    }
}

impl WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable { &mut self.wasi_table }
    fn ctx(&mut self) -> &mut WasiCtx { &mut self.wasi_ctx }
}

/// Central wasmtime Engine shared across all invocations (thread-safe, clone is cheap).
#[derive(Clone)]
pub struct KotobaEngine(Engine);

impl KotobaEngine {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        // TODO(wasmtime-upgrade): componentize-py 0.23 emits extended-const expressions
        // (i32.add in global initializers). wasmtime 22 disables this proposal by default
        // and has no public Config API to re-enable it. Upgrade the wasmtime pin in
        // Cargo.toml to "24" or later and add `config.wasm_extended_const(true)` here.
        // Until then, Python-compiled WASM agents fail with CompileFailed on first load.
        let engine = Engine::new(&config)?;
        Ok(Self(engine))
    }

    pub fn inner(&self) -> &Engine {
        &self.0
    }

    pub fn compile(&self, wasm_bytes: &[u8]) -> Result<Component> {
        Component::new(&self.0, wasm_bytes)
    }

    pub fn new_store(&self, state: HostState) -> Store<HostState> {
        Store::new(&self.0, state)
    }

    pub fn new_linker(&self) -> KotobaLinker {
        KotobaLinker(Linker::new(&self.0))
    }
}

pub struct KotobaLinker(pub(crate) Linker<HostState>);

impl KotobaLinker {
    /// Bind all KOTOBA WIT host interfaces:
    ///   kotoba:kais/kqe, kotoba:kais/kse, kotoba:kais/auth,
    ///   kotoba:kais/llm, kotoba:kais/chain
    /// Also binds WASI preview2 interfaces (required by wasm32-wasip2 components).
    pub fn bind_kotoba_interfaces(&mut self) -> Result<()> {
        // WASI preview2 — needed by all wasm32-wasip2 components
        wasmtime_wasi::add_to_linker_sync(&mut self.0)?;
        // Kotoba host interfaces
        bind_kqe(&mut self.0)?;
        bind_kse(&mut self.0)?;
        bind_auth(&mut self.0)?;
        bind_llm(&mut self.0)?;
        bind_chain(&mut self.0)?;
        bind_evm(&mut self.0)?;
        Ok(())
    }
}

// ── kotoba:kais/kqe ────────────────────────────────────────────────────────

fn bind_kqe(linker: &mut Linker<HostState>) -> Result<()> {
    let mut inst = linker.instance("kotoba:kais/kqe@0.1.0")?;

    // assert-quad: func(q: quad) -> result<_, string>
    // WIT record → Rust WitQuad (ComponentType/Lift/Lower).
    inst.func_wrap(
        "assert-quad",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (q,): (WitQuad,)|
         -> Result<(Result<(), String>,)> {
            ctx.data_mut().charge_gas(10)?;
            ctx.data_mut().pending_asserts.push(PendingQuad {
                graph:       q.graph,
                subject:     q.subject,
                predicate:   q.predicate,
                object_cbor: q.object_cbor,
            });
            Ok((Ok(()),))
        },
    )?;

    // retract-quad: func(q: quad) -> result<_, string>
    inst.func_wrap(
        "retract-quad",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (q,): (WitQuad,)|
         -> Result<(Result<(), String>,)> {
            ctx.data_mut().charge_gas(10)?;
            ctx.data_mut().pending_retracts.push(PendingQuad {
                graph:       q.graph,
                subject:     q.subject,
                predicate:   q.predicate,
                object_cbor: q.object_cbor,
            });
            Ok((Ok(()),))
        },
    )?;

    // query: func(datalog-src: string) -> result<list<quad>, string>
    // `datalog_src` is treated as a predicate/relation filter:
    //   - empty string  → return all quads in the snapshot
    //   - non-empty     → return quads whose predicate == datalog_src
    inst.func_wrap(
        "query",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (predicate_filter,): (String,)|
         -> Result<(Result<Vec<WitQuad>, String>,)> {
            ctx.data_mut().charge_gas(100)?;
            let matches: Vec<WitQuad> = ctx
                .data()
                .quad_snapshot
                .iter()
                .filter(|q| predicate_filter.is_empty() || q.predicate == predicate_filter)
                .cloned()
                .collect();
            Ok((Ok(matches),))
        },
    )?;

    // get-objects: func(graph: string, subject: string, predicate: string) -> list<list<u8>>
    inst.func_wrap(
        "get-objects",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (graph, subject, predicate): (String, String, String)|
         -> Result<(Vec<Vec<u8>>,)> {
            ctx.data_mut().charge_gas(5)?;
            let matches: Vec<Vec<u8>> = ctx.data().quad_snapshot.iter()
                .filter(|q| q.graph == graph && q.subject == subject && q.predicate == predicate)
                .map(|q| q.object_cbor.clone())
                .collect();
            Ok((matches,))
        },
    )?;

    // get-head: func(graph-name: string) -> option<string>
    inst.func_wrap(
        "get-head",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (graph_name,): (String,)|
         -> Result<(Option<String>,)> {
            ctx.data_mut().charge_gas(1)?;
            Ok((ctx.data().head_commits.get(&graph_name).cloned(),))
        },
    )?;

    // evaluate-rules: func(rules-cbor: list<u8>) -> result<list<quad>, string>
    // CBOR-decode Vec<DatalogRule>, seed fact_base from quad_snapshot, run evaluate_delta.
    inst.func_wrap(
        "evaluate-rules",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (rules_cbor,): (Vec<u8>,)|
         -> Result<(Result<Vec<WitQuad>, String>,)> {
            ctx.data_mut().charge_gas(500)?;
            let result = (|| -> anyhow::Result<Vec<WitQuad>> {
                use kotoba_kqe::{DatalogProgram, DatalogRule, Delta};
                use kotoba_kqe::quad::{Quad, QuadObject};
                use kotoba_core::cid::KotobaCid;

                // Deserialize rules from CBOR
                let rules: Vec<DatalogRule> = ciborium::de::from_reader(rules_cbor.as_slice())
                    .map_err(|e| anyhow::anyhow!("rule deserialize: {e}"))?;

                let mut program = DatalogProgram::new();
                for rule in rules { program.add_rule(rule); }

                // Build input deltas from quad_snapshot (all treated as assert facts)
                let snapshot = ctx.data().quad_snapshot.clone();
                let mut input_deltas: Vec<Delta> = Vec::with_capacity(snapshot.len());
                for wit_q in &snapshot {
                    let object: QuadObject = ciborium::de::from_reader(wit_q.object_cbor.as_slice())
                        .unwrap_or(QuadObject::Text(wit_q.predicate.clone()));
                    input_deltas.push(Delta::assert(Quad {
                        subject:   KotobaCid::from_bytes(wit_q.subject.as_bytes()),
                        predicate: wit_q.predicate.clone(),
                        object,
                        graph:     KotobaCid::from_bytes(wit_q.graph.as_bytes()),
                    }));
                }

                // Run semi-naive bottom-up derivation
                let derived = program.evaluate_delta(&input_deltas);

                // Convert derived deltas to WitQuad (only asserts)
                let mut out = Vec::new();
                for d in derived {
                    if !d.is_assert() { continue; }
                    let mut obj_cbor = Vec::new();
                    ciborium::ser::into_writer(&d.quad.object, &mut obj_cbor)
                        .map_err(|e| anyhow::anyhow!("object serialize: {e}"))?;
                    out.push(WitQuad {
                        graph:       d.quad.graph.to_multibase(),
                        subject:     d.quad.subject.to_multibase(),
                        predicate:   d.quad.predicate,
                        object_cbor: obj_cbor,
                    });
                }
                Ok(out)
            })();
            Ok((result.map_err(|e| e.to_string()),))
        },
    )?;

    Ok(())
}

// ── kotoba:kais/kse ────────────────────────────────────────────────────────

fn bind_kse(linker: &mut Linker<HostState>) -> Result<()> {
    let mut inst = linker.instance("kotoba:kais/kse@0.1.0")?;

    inst.func_wrap(
        "publish",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (topic, payload): (String, Vec<u8>)|
         -> Result<(Result<String, String>,)> {
            ctx.data_mut().charge_gas(20)?;
            // Buffer the publish; the caller applies it to the KSE Journal after execute().
            let synthetic_cid = format!("pending/{}/{}", topic, ctx.data().pending_publishes.len());
            ctx.data_mut().pending_publishes.push((topic, payload));
            Ok((Ok(synthetic_cid),))
        },
    )?;

    inst.func_wrap(
        "drain",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (topic_pattern, max_items): (String, u32)|
         -> Result<(Result<Vec<(String, Vec<u8>)>, String>,)> {
            ctx.data_mut().charge_gas(20)?;
            let matches: Vec<(String, Vec<u8>)> = ctx.data().kse_inbox.iter()
                .filter(|(t, _)| topic_pattern.is_empty() || t.starts_with(&topic_pattern))
                .take(max_items as usize)
                .cloned()
                .collect();
            Ok((Ok(matches),))
        },
    )?;

    Ok(())
}

// ── kotoba:kais/auth ───────────────────────────────────────────────────────

fn bind_auth(linker: &mut Linker<HostState>) -> Result<()> {
    let mut inst = linker.instance("kotoba:kais/auth@0.1.0")?;

    inst.func_wrap(
        "current-did",
        |ctx: wasmtime::StoreContextMut<HostState>, (): ()| -> Result<(String,)> {
            Ok((ctx.data().agent_did.clone(),))
        },
    )?;

    inst.func_wrap(
        "verify-cacao",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (cacao_cbor,): (Vec<u8>,)|
         -> Result<(Result<String, String>,)> {
            ctx.data_mut().charge_gas(50)?;
            let result = (|| -> anyhow::Result<String> {
                let chain = DelegationChain::from_cbor(&cacao_cbor)
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let did = chain.verify("", "")
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(did)
            })();
            Ok((result.map_err(|e| e.to_string()),))
        },
    )?;

    inst.func_wrap(
        "has-capability",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (resource_uri, ability): (String, String)|
         -> Result<(bool,)> {
            ctx.data_mut().charge_gas(10)?;
            let agent_did = ctx.data().agent_did.clone();
            // Convention: subject=agent_did, predicate="auth/capability/{resource_uri}/{ability}"
            let predicate = format!("auth/capability/{resource_uri}/{ability}");
            let has = ctx.data().quad_snapshot.iter()
                .any(|q| q.subject == agent_did && q.predicate == predicate);
            Ok((has,))
        },
    )?;

    Ok(())
}

// ── kotoba:kais/llm ────────────────────────────────────────────────────────

fn bind_llm(linker: &mut Linker<HostState>) -> Result<()> {
    let mut inst = linker.instance("kotoba:kais/llm@0.1.0")?;

    inst.func_wrap(
        "infer",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_model_cid, prompt_bytes): (String, Vec<u8>)|
         -> Result<(Result<Vec<u8>, String>,)> {
            // CALL_FOREIGN(0xF): gas is high — each token = one Pregel superstep
            ctx.data_mut().charge_gas(1000)?;

            // Clone the Arc so the closure doesn't hold a borrow on ctx.
            let engine_opt = ctx.data().inference_engine.clone();
            if let Some(engine_fn) = engine_opt {
                let prompt = String::from_utf8_lossy(&prompt_bytes).to_string();
                return match engine_fn(&prompt, 256) {
                    Ok(text) => Ok((Ok(text.into_bytes()),)),
                    Err(e)   => Ok((Err(e.to_string()),)),
                };
            }

            // No engine loaded at runtime.
            let _ = prompt_bytes;
            Ok((Err(
                "no local inference engine loaded — call HostState::with_inference() \
                 before executing WASM guests that call llm.infer"
                .to_string(),
            ),))
        },
    )?;

    inst.func_wrap(
        "embed",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_model_cid, text): (String, String)|
         -> Result<(Result<Vec<u8>, String>,)> {
            ctx.data_mut().charge_gas(200)?;
            // Prefer real embed_fn (HttpEmbedClient) when available
            let embed_fn_opt = ctx.data().embed_fn.clone();
            if let Some(embed_fn) = embed_fn_opt {
                return match embed_fn(&text) {
                    Ok(floats) => {
                        let bytes: Vec<u8> = floats.iter()
                            .flat_map(|f| f.to_le_bytes())
                            .collect();
                        Ok((Ok(bytes),))
                    }
                    Err(e) => Ok((Err(e.to_string()),)),
                };
            }
            Ok((Err("no embed function configured — call HostState::with_embed_fn()".to_string()),))
        },
    )?;

    inst.func_wrap(
        "load-lora",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (base_model_cid, lora_cid): (String, String)|
         -> Result<(Result<(), String>,)> {
            ctx.data_mut().charge_gas(500)?;
            ctx.data_mut().pending_lora_loads.push((base_model_cid, lora_cid));
            Ok((Ok(()),))
        },
    )?;

    Ok(())
}

// ── kotoba:kais/chain ──────────────────────────────────────────────────────

fn bind_chain(linker: &mut Linker<HostState>) -> Result<()> {
    let mut inst = linker.instance("kotoba:kais/chain@0.1.0")?;

    inst.func_wrap(
        "append-infer",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (model_cid, prompt_cid, output_cid): (String, String, String)|
         -> Result<(Result<String, String>,)> {
            ctx.data_mut().charge_gas(30)?;
            // Buffer the chain entry; caller appends to SourceChain after execute().
            let idx = ctx.data().pending_chain_entries.len();
            let synthetic_cid = format!("chain/pending/{idx}");
            ctx.data_mut().pending_chain_entries.push((model_cid, prompt_cid, output_cid));
            Ok((Ok(synthetic_cid),))
        },
    )?;

    inst.func_wrap(
        "head-cid",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (): ()| -> Result<(Option<String>,)> {
            ctx.data_mut().charge_gas(1)?;
            Ok((ctx.data().source_chain_head.clone(),))
        },
    )?;

    Ok(())
}

// ── kotoba:kais/evm ────────────────────────────────────────────────────────
// EVM JSON-RPC bridge — CALL_FOREIGN class (gas = 1000 per call)
// All calls use a shared ureq Agent with 5-second timeout.

fn bind_evm(linker: &mut Linker<HostState>) -> Result<()> {
    use std::time::Duration;

    // Build a reusable agent with 5-second timeout per spec requirement
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build();

    let agent1 = agent.clone();
    let agent2 = agent.clone();
    let agent3 = agent;

    let mut inst = linker.instance("kotoba:kais/evm@0.1.0")?;

    // eth-call: ABI-encoded view call
    inst.func_wrap(
        "eth-call",
        move |mut ctx: wasmtime::StoreContextMut<HostState>,
              (rpc_url, to, calldata, block_tag): (String, String, Vec<u8>, Option<String>)|
              -> Result<(Result<Vec<u8>, String>,)> {
            ctx.data_mut().charge_gas(1000)?;
            let block = block_tag.as_deref().unwrap_or("latest");
            let data_hex = format!("0x{}", hex::encode(&calldata));
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "eth_call",
                "params": [{"to": to, "data": data_hex}, block]
            });
            let result = (|| -> Result<Vec<u8>, String> {
                let resp: serde_json::Value = agent1.post(&rpc_url)
                    .set("Content-Type", "application/json")
                    .send_json(body)
                    .map_err(|e| e.to_string())?
                    .into_json()
                    .map_err(|e| e.to_string())?;
                if let Some(err) = resp.get("error") {
                    return Err(err.to_string());
                }
                hex::decode(resp["result"].as_str().unwrap_or("0x").trim_start_matches("0x"))
                    .map_err(|e| e.to_string())
            })();
            Ok((result,))
        },
    )?;

    // eth-get-storage-at: read raw storage slot
    inst.func_wrap(
        "eth-get-storage-at",
        move |mut ctx: wasmtime::StoreContextMut<HostState>,
              (rpc_url, address, slot): (String, String, String)|
              -> Result<(Result<Vec<u8>, String>,)> {
            ctx.data_mut().charge_gas(1000)?;
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "eth_getStorageAt",
                "params": [address, slot, "latest"]
            });
            let result = (|| -> Result<Vec<u8>, String> {
                let resp: serde_json::Value = agent2.post(&rpc_url)
                    .set("Content-Type", "application/json")
                    .send_json(body)
                    .map_err(|e| e.to_string())?
                    .into_json()
                    .map_err(|e| e.to_string())?;
                if let Some(err) = resp.get("error") {
                    return Err(err.to_string());
                }
                hex::decode(resp["result"].as_str().unwrap_or("0x").trim_start_matches("0x"))
                    .map_err(|e| e.to_string())
            })();
            Ok((result,))
        },
    )?;

    // eth-get-balance: get ETH balance as hex wei string
    inst.func_wrap(
        "eth-get-balance",
        move |mut ctx: wasmtime::StoreContextMut<HostState>,
              (rpc_url, address): (String, String)|
              -> Result<(Result<String, String>,)> {
            ctx.data_mut().charge_gas(1000)?;
            let body = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "method": "eth_getBalance",
                "params": [address, "latest"]
            });
            let result = (|| -> Result<String, String> {
                let resp: serde_json::Value = agent3.post(&rpc_url)
                    .set("Content-Type", "application/json")
                    .send_json(body)
                    .map_err(|e| e.to_string())?
                    .into_json()
                    .map_err(|e| e.to_string())?;
                if let Some(err) = resp.get("error") {
                    return Err(err.to_string());
                }
                Ok(resp["result"].as_str().unwrap_or("0x0").to_string())
            })();
            Ok((result,))
        },
    )?;

    Ok(())
}
