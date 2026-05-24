//! kotoba-runtime — WASM Component Model host for Kotoba node programs.
//!
//! Architecture:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │  KotobaRuntime (wasmtime Engine + ProgramStore)                  │
//! │                                                                  │
//! │  Invoke ChainEntry ──► WasmExecutor::execute()                  │
//! │       program_cid  ──► ProgramStore::get_or_compile()           │
//! │       ctx_cbor     ──► guest export run(ctx)                    │
//! │                                                                  │
//! │  WIT Host Interfaces (bound to every WASM Store):               │
//! │    kotoba:kais/kqe   assert/retract/query (ASSERT 0x1)          │
//! │    kotoba:kais/kse   publish/drain (SEND 0x3 / RECV 0x4)       │
//! │    kotoba:kais/auth  current-did / verify-cacao                 │
//! │    kotoba:kais/llm   infer/embed → CALL_FOREIGN(0xF) bridge     │
//! │    kotoba:kais/chain append-infer / head-cid                    │
//! │                                                                  │
//! │  WASM Guest (any language via WIT Component Model):             │
//! │    Rust  — wit-bindgen 0.28 + wasm32-wasip2                     │
//! │    Python — componentize-py 0.5                                 │
//! │    JS/TS  — jco ComponentizeJS                                   │
//! │    Go     — TinyGo + wit-bindgen-go                             │
//! │    C/C++  — clang --target=wasm32-wasi                         │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! WIT world definition: `wit/world.wit`
//! ADR: `90-docs/adr/2605240001-kotoba-cleanroom-architecture.md` §16

pub mod error;
pub mod executor;
pub mod host;
pub mod program;
pub mod sdk;
pub mod udf;

pub use error::RuntimeError;
pub use executor::{InvokeContext, InvokeResult, WasmExecutor};
pub use host::{HostState, KotobaEngine, KotobaLinker};
pub use program::ProgramStore;
pub use udf::UdfExecutor;
