//! kotoba-hello — minimal Kotoba node program (WASM Component Model guest)
//!
//! Implements the `kotoba-node` WIT world:
//!   - imports: kqe / kse / auth / llm / chain
//!   - exports: run(ctx-cbor) → result<list<u8>, string>
//!
//! What it does:
//!   1. Read current agent DID from auth.current-did
//!   2. Assert a "greeted" quad into the graph
//!   3. Return b"hello from kotoba-wasm" as output

wit_bindgen::generate!({
    path: "../../crates/kotoba-runtime/wit/world.wit",
    world: "kotoba-node",
});

struct KotobaHello;

impl Guest for KotobaHello {
    fn run(ctx_cbor: Vec<u8>) -> Result<Vec<u8>, String> {
        // 1. Get current agent DID
        let did = auth::current_did();

        // 2. Assert a greeting quad
        let q = kqe::Quad {
            graph:       "g:hello-world".to_string(),
            subject:     did.clone(),
            predicate:   "greeted".to_string(),
            // CBOR-encoded boolean `true` = 0xF5
            object_cbor: vec![0xF5],
        };
        kqe::assert_quad(q).map_err(|e| format!("assert failed: {e}"))?;

        // 3. Publish to KSE journal
        kse::publish(
            "kotoba/hello/greet".to_string(),
            format!("hello from {did}").into_bytes(),
        )
        .map_err(|e| format!("publish failed: {e}"))?;

        // ctx_cbor echoed back + greeting suffix
        let mut out = b"hello from kotoba-wasm | did=".to_vec();
        out.extend_from_slice(did.as_bytes());
        out.extend_from_slice(b" | ctx_len=");
        out.extend_from_slice(ctx_cbor.len().to_string().as_bytes());

        Ok(out)
    }
}

export!(KotobaHello);
