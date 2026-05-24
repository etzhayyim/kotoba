use anyhow::Result;
use wasmtime::{Config, Engine, Store};
use wasmtime::component::{Component, Linker};

/// Host-side state injected into every WASM Store.
/// Carries the capabilities that host functions need.
pub struct HostState {
    /// DID of the agent executing this invocation
    pub agent_did: String,
    /// Gas counter (decrements per host call)
    pub gas_remaining: u64,
    /// Accumulated output quads (asserted by guest via kqe.assert-quad)
    pub pending_asserts: Vec<PendingQuad>,
    pub pending_retracts: Vec<PendingQuad>,
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
        Self {
            agent_did: agent_did.into(),
            gas_remaining: gas_limit,
            pending_asserts: Vec::new(),
            pending_retracts: Vec::new(),
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
    pub fn bind_kotoba_interfaces(&mut self) -> Result<()> {
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
    let mut inst = linker.instance("kotoba:kais/kqe")?;

    inst.func_wrap(
        "assert-quad",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (graph, subject, predicate, object_cbor): (String, String, String, Vec<u8>)|
         -> Result<(Result<(), String>,)> {
            ctx.data_mut().charge_gas(10)?;
            ctx.data_mut().pending_asserts.push(PendingQuad {
                graph,
                subject,
                predicate,
                object_cbor,
            });
            Ok((Ok(()),))
        },
    )?;

    inst.func_wrap(
        "retract-quad",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (graph, subject, predicate, object_cbor): (String, String, String, Vec<u8>)|
         -> Result<(Result<(), String>,)> {
            ctx.data_mut().charge_gas(10)?;
            ctx.data_mut().pending_retracts.push(PendingQuad {
                graph,
                subject,
                predicate,
                object_cbor,
            });
            Ok((Ok(()),))
        },
    )?;

    inst.func_wrap(
        "query",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (datalog_src,): (String,)|
         -> Result<(Result<Vec<Vec<u8>>, String>,)> {
            ctx.data_mut().charge_gas(100)?;
            // TODO(Phase 4): delegate to KQE DatalogProgram evaluation
            let _ = datalog_src;
            Ok((Ok(vec![]),))
        },
    )?;

    inst.func_wrap(
        "get-objects",
        |mut ctx: wasmtime::StoreContextMut<HostState>,
         (_graph, _subject, _predicate): (String, String, String)|
         -> Result<(Vec<Vec<u8>>,)> {
            ctx.data_mut().charge_gas(5)?;
            Ok((vec![],))
        },
    )?;

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
    let mut inst = linker.instance("kotoba:kais/kse")?;

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
    let mut inst = linker.instance("kotoba:kais/auth")?;

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
    let mut inst = linker.instance("kotoba:kais/llm")?;

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
    let mut inst = linker.instance("kotoba:kais/chain")?;

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
