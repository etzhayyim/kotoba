use anyhow::Result;
use wasmtime::component::Func;

use crate::error::RuntimeError;
use crate::host::{HostState, KotobaEngine};
use crate::program::ProgramStore;

/// UdfExecutor: stateless WASM UDF mirroring RisingWave Python UDF contract.
///
/// World: kotoba-udf (exports `eval`, imports only kqe read methods)
///
/// Usage in KQE: Datalog rule can call a UDF program_cid to transform rows,
/// analogous to RisingWave UDF written in Python/Java.
///
/// Multi-language WASM UDF examples (built with WIT SDK):
///   Rust   — cargo build --target wasm32-wasip2 --features kotoba-udf
///   Python — componentize-py build --world kotoba-udf
///   JS/TS  — jco componentize --world kotoba-udf
///   Go     — TinyGo + wit-bindgen-go
pub struct UdfExecutor {
    engine: KotobaEngine,
    programs: ProgramStore,
}

impl UdfExecutor {
    pub fn new() -> Result<Self> {
        let engine = KotobaEngine::new()?;
        let programs = ProgramStore::new(engine.clone());
        Ok(Self { engine, programs })
    }

    /// Evaluate a UDF: input rows (CBOR list<list<u8>>) → output rows
    pub fn eval(
        &self,
        program_cid: &str,
        wasm_bytes: &[u8],
        rows_cbor: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, RuntimeError> {
        let component = self
            .programs
            .get_or_compile(program_cid, wasm_bytes)
            .map_err(RuntimeError::CompileFailed)?;

        let state = HostState::new("udf:anonymous", u64::MAX);
        let mut store = self.engine.new_store(state);

        let mut linker = self.engine.new_linker();
        linker
            .bind_kotoba_interfaces()
            .map_err(RuntimeError::HostCall)?;

        let instance = linker
            .0
            .instantiate(&mut store, &component)
            .map_err(RuntimeError::InstantiateFailed)?;

        let eval_func: Func = instance
            .get_func(&mut store, "eval")
            .ok_or_else(|| RuntimeError::GuestError("missing `eval` export".into()))?;

        use wasmtime::component::Val;

        // Encode rows as Val::List<Val::List<Val::U8>>
        let val_rows = Val::List(
            rows_cbor
                .into_iter()
                .map(|row| Val::List(row.into_iter().map(Val::U8).collect::<Vec<_>>()))
                .collect::<Vec<_>>(),
        );

        let args = [val_rows];
        let mut results = vec![Val::Bool(false)];

        eval_func
            .call(&mut store, &args, &mut results)
            .map_err(|e| RuntimeError::Trap(e.to_string()))?;

        // Decode result<list<list<u8>>, string>
        match &results[0] {
            Val::Result(Ok(Some(inner))) => {
                if let Val::List(outer) = inner.as_ref() {
                    let rows = outer
                        .iter()
                        .map(|row_val| {
                            if let Val::List(bytes) = row_val {
                                bytes
                                    .iter()
                                    .filter_map(
                                        |v| if let Val::U8(b) = v { Some(*b) } else { None },
                                    )
                                    .collect::<Vec<u8>>()
                            } else {
                                vec![]
                            }
                        })
                        .collect();
                    Ok(rows)
                } else {
                    Err(RuntimeError::GuestError(
                        "unexpected eval output type".into(),
                    ))
                }
            }
            Val::Result(Err(Some(inner))) => {
                let msg = match inner.as_ref() {
                    Val::String(s) => s.to_string(),
                    _ => "unknown eval error".into(),
                };
                Err(RuntimeError::GuestError(msg))
            }
            _ => Err(RuntimeError::GuestError("unexpected result variant".into())),
        }
    }
}
