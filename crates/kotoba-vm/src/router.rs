use anyhow::Result;
use kotoba_dht::source_chain::ProgramType;
use kotoba_kqe::{arrangement::Arrangement, datalog::DatalogProgram, delta::Delta};
use kotoba_runtime::{InvokeResult, UdfExecutor, WasmExecutor};
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

    /// Dispatch an Invoke ChainEntry to the correct executor.
    ///
    /// `program_bytes` must be supplied for WasmNode / WasmUdf program types.
    /// For Datalog, pass `None`; `program` and `arrangement` must be Some.
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
        match program_type {
            ProgramType::WasmNode => {
                let bytes = program_bytes.ok_or(RouterError::MissingWasmBytes)?;
                let result = self.wasm.execute(program_cid, bytes, agent_did, ctx_cbor)?;
                Ok(DispatchResult::Wasm(result))
            }

            ProgramType::WasmUdf => {
                let bytes = program_bytes.ok_or(RouterError::MissingWasmBytes)?;
                // UDF: ctx_cbor treated as a single row; returns list of rows
                let rows = vec![ctx_cbor];
                let out_rows = self.udf.eval(program_cid, bytes, rows)?;
                // Wrap output as a simple InvokeResult
                let output_cbor = out_rows.into_iter().flatten().collect();
                Ok(DispatchResult::Wasm(InvokeResult {
                    output_cbor,
                    gas_used: 0,
                    assert_quads: vec![],
                    retract_quads: vec![],
                }))
            }

            ProgramType::Datalog => {
                let prog = program.expect("Datalog dispatch requires program");
                let arr  = arrangement.expect("Datalog dispatch requires arrangement");
                use kotoba_core::cid::KotobaCid;
                let cid = KotobaCid::from_bytes(program_cid.as_bytes());
                let result = KotobaVm::execute(&cid, prog, arr, input_deltas, max_steps, call_id);
                match result.status {
                    ExecStatus::Ok | ExecStatus::Halt => Ok(DispatchResult::Datalog(result)),
                    ExecStatus::StepsExceeded         => Err(RouterError::StepsExceeded),
                    ExecStatus::Error                 => Err(RouterError::DatalogError),
                }
            }
        }
    }
}
