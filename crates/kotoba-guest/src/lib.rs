/// kotoba-guest — reference WASM Component guest for the kotoba-node world.
///
/// When built with `cargo component build --target wasm32-wasip2`, this produces
/// a WASM Component that the KotobaRuntime WasmExecutor can execute.
///
/// The guest demonstrates the full KOTOBA host ABI:
///   kqe.assert-quad  — persist a quad into the Arrangement
///   kse.publish      — emit an event into the KSE Journal
///   auth.current-did — read the executing agent DID
///   chain.append-infer (skipped — no model loaded in tests)
///
/// InvokeContext wire format (CBOR map):
///   { "graph": string, "session_cid": string|null, "args_cbor": bytes }
///
/// Output CBOR: `{"status": "ok", "quads_asserted": u32, "agent_did": string}`

// On native targets the wit-bindgen macro can't expand (no WIT resolver at compile
// time for non-component builds), so we gate the whole impl behind wasm32.
#[cfg(target_arch = "wasm32")]
mod bindings {
    wit_bindgen::generate!({
        world: "kotoba-node",
        path: "wit",
    });
}

#[cfg(target_arch = "wasm32")]
use bindings::{
    kotoba::kais::{
        auth,
        kqe::{self, Quad},
        kse,
    },
    Guest,
};

/// InvokeContext — mirrors the host-side struct for CBOR decode.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct InvokeContext {
    graph: String,
    #[allow(dead_code)]
    session_cid: Option<String>,
    args_cbor: Vec<u8>,
}

/// InvokeOutput — CBOR-encoded return value.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
struct InvokeOutput {
    status: String,
    quads_asserted: u32,
    agent_did: String,
    topic_cid: String,
}

#[cfg(target_arch = "wasm32")]
struct EchoAssertComponent;

#[cfg(target_arch = "wasm32")]
impl Guest for EchoAssertComponent {
    /// Entry point called by KotobaRuntime for each Invoke ChainEntry.
    fn run(ctx_cbor: Vec<u8>) -> Result<Vec<u8>, String> {
        // Decode InvokeContext from CBOR.
        let ctx: InvokeContext =
            ciborium::from_reader(ctx_cbor.as_slice()).map_err(|e| format!("cbor decode: {e}"))?;

        // Read executing agent DID.
        let agent_did = auth::current_did();

        // Assert one quad: (graph, subject="self", predicate="task", object=args_cbor).
        // object-cbor is passed through as raw bytes (CBOR or any payload).
        kqe::assert_quad(&Quad {
            graph: ctx.graph.clone(),
            subject: agent_did.clone(),
            predicate: "kotoba/task".to_string(),
            object_cbor: ctx.args_cbor.clone(),
        })
        .map_err(|e| format!("assert-quad: {e}"))?;

        // Publish a KSE event.
        let topic_cid = kse::publish(&format!("kotoba/{}/invoked", ctx.graph), &ctx.args_cbor)
            .map_err(|e| format!("kse.publish: {e}"))?;

        // Encode output as CBOR.
        let out = InvokeOutput {
            status: "ok".to_string(),
            quads_asserted: 1,
            agent_did,
            topic_cid,
        };
        let mut output_cbor = Vec::new();
        ciborium::into_writer(&out, &mut output_cbor).map_err(|e| format!("cbor encode: {e}"))?;

        Ok(output_cbor)
    }
}

#[cfg(target_arch = "wasm32")]
bindings::export!(EchoAssertComponent with_types_in bindings);

// ── Native stub (IDE + `cargo test --workspace` compatibility) ────────────────

/// Native shim so `cargo test --workspace` (aarch64-apple-darwin) compiles cleanly.
/// The real implementation is the wasm32 path above.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_native(ctx_cbor: &[u8]) -> Result<Vec<u8>, String> {
    let ctx: InvokeContext =
        ciborium::from_reader(ctx_cbor).map_err(|e| format!("cbor decode: {e}"))?;

    let out = InvokeOutput {
        status: "ok (native stub)".to_string(),
        quads_asserted: 0,
        agent_did: "did:stub:native".to_string(),
        topic_cid: format!("stub/{}", ctx.graph),
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&out, &mut buf).map_err(|e| format!("cbor encode: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_stub_runs() {
        // Encode a minimal InvokeContext.
        let ctx = InvokeContext {
            graph: "test-graph".to_string(),
            session_cid: None,
            args_cbor: b"hello kotoba".to_vec(),
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&ctx, &mut cbor).unwrap();

        let result = run_native(&cbor).unwrap();
        assert!(!result.is_empty());

        // Decode and check the output.
        let out: InvokeOutput = ciborium::from_reader(result.as_slice()).unwrap();
        assert_eq!(out.status, "ok (native stub)");
        assert!(out.topic_cid.contains("test-graph"));
    }
}
