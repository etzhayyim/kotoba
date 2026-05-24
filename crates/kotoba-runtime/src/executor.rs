use anyhow::Result;
use tracing::instrument;
use wasmtime::component::Func;

use crate::error::RuntimeError;
use crate::host::{HostState, KotobaEngine, PendingQuad};
use crate::program::ProgramStore;

/// InvokeContext is CBOR-decoded from the Invoke ChainEntry input field.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct InvokeContext {
    /// Named graph CID this invocation operates on
    pub graph:       String,
    /// Session CID (for stateful invocations; None for UDF-style)
    pub session_cid: Option<String>,
    /// CBOR-encoded arguments
    pub args_cbor:   Vec<u8>,
}

/// InvokeResult is written back as the Result ChainEntry output field.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct InvokeResult {
    pub output_cbor:  Vec<u8>,
    pub gas_used:     u64,
    /// Quads to apply to Arrangement after successful execution
    pub assert_quads: Vec<SerializedQuad>,
    pub retract_quads: Vec<SerializedQuad>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SerializedQuad {
    pub graph:       String,
    pub subject:     String,
    pub predicate:   String,
    pub object_cbor: Vec<u8>,
}

impl From<PendingQuad> for SerializedQuad {
    fn from(q: PendingQuad) -> Self {
        Self {
            graph:       q.graph,
            subject:     q.subject,
            predicate:   q.predicate,
            object_cbor: q.object_cbor,
        }
    }
}

/// Executor: takes an Invoke ChainEntry and runs the WASM component.
///
/// Execution model (Kotoba Superstep):
///   1. Decode InvokeContext from Invoke.input (CBOR)
///   2. Load / compile program_cid → Component (via ProgramStore)
///   3. Create Store<HostState> + bind all KOTOBA WIT host interfaces
///   4. Instantiate Component → call guest export `run(ctx_cbor)`
///   5. Collect pending_asserts + pending_retracts from HostState
///   6. Return InvokeResult (caller appends to SourceChain + applies to Arrangement)
pub struct WasmExecutor {
    engine:  KotobaEngine,
    programs: ProgramStore,
    gas_limit: u64,
}

impl WasmExecutor {
    pub fn new(gas_limit: u64) -> Result<Self> {
        let engine = KotobaEngine::new()?;
        let programs = ProgramStore::new(engine.clone());
        Ok(Self { engine, programs, gas_limit })
    }

    #[instrument(skip(self, agent_did, wasm_bytes, ctx_cbor), fields(program_cid))]
    pub fn execute(
        &self,
        program_cid: &str,
        wasm_bytes:  &[u8],
        agent_did:   &str,
        ctx_cbor:    Vec<u8>,
    ) -> Result<InvokeResult, RuntimeError> {
        let component = self.programs
            .get_or_compile(program_cid, wasm_bytes)
            .map_err(RuntimeError::CompileFailed)?;

        let state = HostState::new(agent_did, self.gas_limit);
        let mut store = self.engine.new_store(state);

        let mut linker = self.engine.new_linker();
        linker
            .bind_kotoba_interfaces()
            .map_err(RuntimeError::HostCall)?;

        let instance = linker
            .0
            .instantiate(&mut store, &component)
            .map_err(RuntimeError::InstantiateFailed)?;

        // Locate the `run` export (kotoba-node world)
        let run_func: Func = instance
            .get_func(&mut store, "run")
            .ok_or_else(|| RuntimeError::GuestError("missing `run` export".into()))?;

        // Call via dynamic Val dispatch (avoids wit-bindgen dependency at call site)
        use wasmtime::component::Val;
        let args = [Val::List(
            ctx_cbor
                .iter()
                .map(|b| Val::U8(*b))
                .collect::<Vec<_>>(),
        )];
        let mut results = vec![Val::Bool(false)];

        run_func
            .call(&mut store, &args, &mut results)
            .map_err(|e| RuntimeError::Trap(e.to_string()))?;

        // Parse result<list<u8>, string> from Val
        let output_cbor = match &results[0] {
            Val::Result(Ok(Some(inner))) => match inner.as_ref() {
                Val::List(bytes) => bytes
                    .iter()
                    .filter_map(|v| if let Val::U8(b) = v { Some(*b) } else { None })
                    .collect::<Vec<u8>>(),
                _ => return Err(RuntimeError::GuestError("unexpected output type".into())),
            },
            Val::Result(Err(Some(inner))) => {
                let msg = match inner.as_ref() {
                    Val::String(s) => s.to_string(),
                    _ => "unknown guest error".into(),
                };
                return Err(RuntimeError::GuestError(msg));
            }
            _ => return Err(RuntimeError::GuestError("unexpected result variant".into())),
        };

        let gas_used = self.gas_limit - store.data().gas_remaining;
        let assert_quads = store
            .data()
            .pending_asserts
            .iter()
            .cloned()
            .map(SerializedQuad::from)
            .collect();
        let retract_quads = store
            .data()
            .pending_retracts
            .iter()
            .cloned()
            .map(SerializedQuad::from)
            .collect();

        Ok(InvokeResult {
            output_cbor,
            gas_used,
            assert_quads,
            retract_quads,
        })
    }
}
