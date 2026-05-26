use anyhow::Result;
use kotoba_dht::source_chain::ProgramType;
use kotoba_kqe::{arrangement::Arrangement, datalog::DatalogProgram, delta::Delta};
use kotoba_runtime::{host::{InferenceFn, WitQuad}, InvokeResult, UdfExecutor, WasmExecutor};
use thiserror::Error;

use crate::executor::{ExecResult, ExecStatus, KotobaVm};
use crate::foreign::ForeignBridge;

/// InvokeRouter: unified dispatch for Invoke ChainEntry.
///
/// Routing table:
///   ProgramType::Datalog  → KotobaVm::execute()  (Datalog semi-naive evaluation)
///   ProgramType::WasmNode → WasmExecutor::execute() (kotoba-node world)
///   ProgramType::WasmUdf  → UdfExecutor::eval()     (kotoba-udf world, stateless)
pub struct InvokeRouter {
    wasm:    WasmExecutor,
    udf:     UdfExecutor,
    _bridge: ForeignBridge,
}

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("wasm execution failed: {0}")]
    Wasm(#[from] kotoba_runtime::RuntimeError),

    #[error("program bytes not provided for wasm program_type")]
    MissingWasmBytes,

    #[error("datalog execution exceeded step limit")]
    StepsExceeded,

    #[error("datalog execution error")]
    DatalogError,
}

/// Unified result across all dispatch paths
#[derive(Debug)]
pub enum DispatchResult {
    /// Datalog path: out-deltas to apply to Arrangement
    Datalog(ExecResult),
    /// WASM node path: assert/retract quads + opaque output bytes
    Wasm(InvokeResult),
}

impl InvokeRouter {
    pub fn new(gas_limit: u64, gateway_url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            wasm:    WasmExecutor::new(gas_limit)?,
            udf:     UdfExecutor::new()?,
            _bridge: ForeignBridge::new(gateway_url),
        })
    }

    /// Construct an `InvokeRouter` where the WASM executor is pre-loaded with a
    /// local inference engine (e.g. Gemma 4 E2B).  Datalog and UDF paths are
    /// unaffected.
    pub fn with_inference(
        gas_limit:   u64,
        gateway_url: impl Into<String>,
        engine:      InferenceFn,
    ) -> Result<Self> {
        Ok(Self {
            wasm:    WasmExecutor::with_inference(gas_limit, engine)?,
            udf:     UdfExecutor::new()?,
            _bridge: ForeignBridge::new(gateway_url),
        })
    }

    /// Dispatch an Invoke ChainEntry to the correct executor.
    ///
    /// `program_bytes` must be supplied for WasmNode / WasmUdf program types.
    /// For Datalog, pass `None`; `program` and `arrangement` must be Some.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch(
        &self,
        program_cid:    &str,
        program_type:   ProgramType,
        agent_did:      &str,
        call_id:        u64,
        // WASM path
        program_bytes:  Option<&[u8]>,
        ctx_cbor:       Vec<u8>,
        // Datalog path
        program:        Option<&DatalogProgram>,
        arrangement:    Option<&Arrangement>,
        input_deltas:   &[Delta],
        max_steps:      u32,
    ) -> Result<DispatchResult, RouterError> {
        self.dispatch_with_snapshot(
            program_cid, program_type, agent_did, call_id,
            program_bytes, ctx_cbor,
            program, arrangement, input_deltas, max_steps,
            vec![],
            std::collections::HashMap::new(),
        )
    }

    /// Like `dispatch` but supplies a quad snapshot for `kqe.query` in WASM guests.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_with_snapshot(
        &self,
        program_cid:    &str,
        program_type:   ProgramType,
        agent_did:      &str,
        call_id:        u64,
        program_bytes:  Option<&[u8]>,
        ctx_cbor:       Vec<u8>,
        program:        Option<&DatalogProgram>,
        arrangement:    Option<&Arrangement>,
        input_deltas:   &[Delta],
        max_steps:      u32,
        quad_snapshot:  Vec<WitQuad>,
        head_commits:   std::collections::HashMap<String, String>,
    ) -> Result<DispatchResult, RouterError> {
        match program_type {
            ProgramType::WasmNode => {
                let bytes = program_bytes.ok_or(RouterError::MissingWasmBytes)?;
                let result = self.wasm.execute(program_cid, bytes, agent_did, ctx_cbor, quad_snapshot, head_commits)?;
                Ok(DispatchResult::Wasm(result))
            }

            ProgramType::WasmUdf => {
                let bytes = program_bytes.ok_or(RouterError::MissingWasmBytes)?;
                let rows = vec![ctx_cbor];
                let out_rows = self.udf.eval(program_cid, bytes, rows)?;
                let output_cbor = out_rows.into_iter().flatten().collect();
                Ok(DispatchResult::Wasm(InvokeResult {
                    output_cbor,
                    gas_used: 0,
                    assert_quads: vec![],
                    retract_quads: vec![],
                    pending_publishes: vec![],
                    pending_chain_entries: vec![],
                    pending_lora_loads: vec![],
                }))
            }

            ProgramType::Datalog => {
                let prog = program.expect("Datalog dispatch requires program");
                let arr  = arrangement.expect("Datalog dispatch requires arrangement");
                use kotoba_core::cid::KotobaCid;
                let cid = KotobaCid::from_bytes(program_cid.as_bytes());
                let result = KotobaVm::execute(&cid, prog, arr, input_deltas, max_steps, call_id, None);
                match result.status {
                    ExecStatus::Ok | ExecStatus::Halt => Ok(DispatchResult::Datalog(result)),
                    ExecStatus::StepsExceeded         => Err(RouterError::StepsExceeded),
                    ExecStatus::Error                 => Err(RouterError::DatalogError),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_kqe::{arrangement::Arrangement, datalog::DatalogProgram};

    fn router() -> InvokeRouter {
        InvokeRouter::new(10_000, "http://localhost:9999").unwrap()
    }

    #[test]
    fn error_display_missing_wasm_bytes() {
        let msg = RouterError::MissingWasmBytes.to_string();
        assert!(msg.contains("wasm"));
    }

    #[test]
    fn error_display_steps_exceeded() {
        let msg = RouterError::StepsExceeded.to_string();
        assert!(msg.contains("step"));
    }

    #[test]
    fn datalog_empty_program_returns_dispatch_result() {
        let r   = router();
        let prog = DatalogProgram::new();
        let arr  = Arrangement::default();
        let result = r.dispatch(
            "prog-cid", ProgramType::Datalog, "did:test:agent",
            1, None, vec![], Some(&prog), Some(&arr), &[], 100,
        );
        assert!(result.is_ok(), "empty datalog program should succeed: {result:?}");
        assert!(matches!(result.unwrap(), DispatchResult::Datalog(_)));
    }

    #[test]
    fn wasm_node_without_bytes_returns_missing_bytes_error() {
        let r = router();
        let result = r.dispatch(
            "prog-cid", ProgramType::WasmNode, "did:test:agent",
            1, None, vec![], None, None, &[], 0,
        );
        assert!(matches!(result, Err(RouterError::MissingWasmBytes)));
    }

    #[test]
    fn wasm_udf_without_bytes_returns_missing_bytes_error() {
        let r = router();
        let result = r.dispatch(
            "prog-cid", ProgramType::WasmUdf, "did:test:agent",
            1, None, vec![], None, None, &[], 0,
        );
        assert!(matches!(result, Err(RouterError::MissingWasmBytes)));
    }

    #[test]
    fn error_display_datalog_error() {
        let msg = RouterError::DatalogError.to_string();
        assert!(msg.contains("datalog"), "got: {msg}");
    }

    #[test]
    fn error_display_wasm_from_runtime_error() {
        let re = kotoba_runtime::RuntimeError::GasExceeded { limit: 42 };
        let re_msg = re.to_string();
        let router_err = RouterError::Wasm(kotoba_runtime::RuntimeError::GasExceeded { limit: 42 });
        let msg = router_err.to_string();
        assert!(msg.contains("wasm") || msg.contains(&re_msg), "got: {msg}");
    }

    #[test]
    fn dispatch_result_datalog_debug() {
        let r    = router();
        let prog = DatalogProgram::new();
        let arr  = Arrangement::default();
        let result = r.dispatch(
            "prog-cid", ProgramType::Datalog, "did:test:agent",
            1, None, vec![], Some(&prog), Some(&arr), &[], 10,
        ).unwrap();
        let dbg = format!("{result:?}");
        assert!(dbg.contains("Datalog"), "debug output should contain 'Datalog': {dbg}");
    }

    #[test]
    fn router_new_with_zero_gas_fails() {
        // WasmExecutor::new requires gas_limit > 0; passing 0 should fail
        let result = InvokeRouter::new(0, "http://localhost:9999");
        assert!(result.is_err(), "gas_limit=0 should fail InvokeRouter::new");
    }
}
