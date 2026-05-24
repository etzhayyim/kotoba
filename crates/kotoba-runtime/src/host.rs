use anyhow::Result;
use wasmtime::{Config, Engine, Store};
use wasmtime::component::{Component, ComponentType, Lift, Linker, Lower};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView, ResourceTable};

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
    /// WASI preview2 context (required by wasm32-wasip2 components)
    pub wasi_ctx: WasiCtx,
    pub wasi_table: ResourceTable,
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
            wasi_ctx,
            wasi_table: ResourceTable::new(),
        }
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
        // Cranelift optimizing compiler (default)
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
    // Return type uses WitQuad for the list element.
    inst.func_wrap(
        "query",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (datalog_src,): (String,)|
         -> Result<(Result<Vec<WitQuad>, String>,)> {
            ctx.data_mut().charge_gas(100)?;
            // TODO(Phase 4): delegate to KQE DatalogProgram evaluation
            let _ = datalog_src;
            Ok((Ok(vec![]),))
        },
    )?;

    // get-objects: func(graph: string, subject: string, predicate: string) -> list<list<u8>>
    inst.func_wrap(
        "get-objects",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_graph, _subject, _predicate): (String, String, String)|
         -> Result<(Vec<Vec<u8>>,)> {
            ctx.data_mut().charge_gas(5)?;
            Ok((vec![],))
        },
    )?;

    // get-head: func(graph-name: string) -> option<string>
    inst.func_wrap(
        "get-head",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_graph_name,): (String,)|
         -> Result<(Option<String>,)> {
            ctx.data_mut().charge_gas(1)?;
            Ok((None,))
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
            // TODO(Phase 4): route to KSE Journal
            let _ = (topic, payload);
            Ok((Ok("bplaceholder_cid".to_string()),))
        },
    )?;

    inst.func_wrap(
        "drain",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_topic_pattern, _max_items): (String, u32)|
         -> Result<(Result<Vec<(String, Vec<u8>)>, String>,)> {
            ctx.data_mut().charge_gas(20)?;
            Ok((Ok(vec![]),))
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
         (_cacao_cbor,): (Vec<u8>,)|
         -> Result<(Result<String, String>,)> {
            ctx.data_mut().charge_gas(50)?;
            // TODO(Phase 3): delegate to kotoba-auth DelegationChain::verify
            Ok((Err("not implemented".to_string()),))
        },
    )?;

    inst.func_wrap(
        "has-capability",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_resource_uri, _ability): (String, String)|
         -> Result<(bool,)> {
            ctx.data_mut().charge_gas(10)?;
            Ok((false,))
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
         (_model_cid, _prompt_bytes): (String, Vec<u8>)|
         -> Result<(Result<Vec<u8>, String>,)> {
            // CALL_FOREIGN(0xF): gas is high — each token = one Pregel superstep
            ctx.data_mut().charge_gas(1000)?;
            // TODO(Phase 4): delegate to kotoba-llm InferenceSession via AgentGateway MCP
            Ok((Err("foreign bridge not yet wired".to_string()),))
        },
    )?;

    inst.func_wrap(
        "embed",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_model_cid, _text): (String, String)|
         -> Result<(Result<Vec<u8>, String>,)> {
            ctx.data_mut().charge_gas(200)?;
            Ok((Err("foreign bridge not yet wired".to_string()),))
        },
    )?;

    inst.func_wrap(
        "load-lora",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_base_model_cid, _lora_cid): (String, String)|
         -> Result<(Result<(), String>,)> {
            ctx.data_mut().charge_gas(500)?;
            Ok((Err("foreign bridge not yet wired".to_string()),))
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
         (_model_cid, _prompt_cid, _output_cid): (String, String, String)|
         -> Result<(Result<String, String>,)> {
            ctx.data_mut().charge_gas(30)?;
            // TODO(Phase 4): append Infer ChainEntry to SourceChain
            Ok((Err("chain append not yet wired".to_string()),))
        },
    )?;

    inst.func_wrap(
        "head-cid",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (): ()| -> Result<(Option<String>,)> {
            ctx.data_mut().charge_gas(1)?;
            Ok((None,))
        },
    )?;

    Ok(())
}
