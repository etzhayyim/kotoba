/// kotoba-runtime/src/sdk.rs
///
/// Multi-language WASM guest SDK guide (documentation module, no runtime code).
///
/// Developers writing Kotoba node programs in other languages use the WIT file
/// at `crates/kotoba-runtime/wit/world.wit` with their language's WIT binding generator.
///
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │  Language  │ Tool                │ Target                               │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │  Rust      │ wit-bindgen 0.28    │ wasm32-wasip2 (--target wasm32-wasip2)│
/// │  Python    │ componentize-py 0.5 │ wasm32-wasi (via CPython WASM port)  │
/// │  JS / TS   │ jco / ComponentizeJS│ wasm32-wasi (via SpiderMonkey embed) │
/// │  Go        │ TinyGo + wit-bindgen│ wasm32-wasi                          │
/// │  C / C++   │ clang + wit-bindgen │ wasm32-wasi                          │
/// └─────────────────────────────────────────────────────────────────────────┘
///
/// Rust example (guest side):
///
/// ```rust,ignore
/// wit_bindgen::generate!({
///     path: "path/to/world.wit",
///     world: "kotoba-node",
/// });
///
/// struct KotobaProgram;
///
/// impl Guest for KotobaProgram {
///     fn run(ctx_cbor: Vec<u8>) -> Result<Vec<u8>, String> {
///         let q = kqe::Quad {
///             graph:       "g:my-graph".into(),
///             subject:     "did:plc:alice".into(),
///             predicate:   "knows".into(),
///             object_cbor: b"\"did:plc:bob\"".to_vec(), // CBOR text
///         };
///         kqe::assert_quad(q)?;
///         Ok(b"done".to_vec())
///     }
/// }
///
/// export!(KotobaProgram);
/// ```
///
/// Python example (componentize-py):
///
/// ```python
/// # app.py
/// from kotoba_kais import exports
///
/// class KotobaProgram(exports.KotobaNode):
///     def run(self, ctx_cbor: bytes) -> bytes:
///         from kotoba_kais.imports import kqe
///         kqe.assert_quad(kqe.Quad(
///             graph="g:my-graph",
///             subject="did:plc:alice",
///             predicate="knows",
///             object_cbor=b'"did:plc:bob"'
///         ))
///         return b"done"
/// ```
///
/// TypeScript example (jco):
///
/// ```typescript
/// // main.ts
/// import { assertQuad } from 'kotoba:kais/kqe';
///
/// export const run = (ctxCbor: Uint8Array): Uint8Array => {
///   assertQuad({ graph: 'g:my-graph', subject: 'did:plc:alice',
///                predicate: 'knows', objectCbor: new TextEncoder().encode('"did:plc:bob"') });
///   return new TextEncoder().encode('done');
/// };
/// ```

/// No runtime code in this module; documentation only.
#[allow(dead_code)]
const _SDK_DOCS: () = ();
