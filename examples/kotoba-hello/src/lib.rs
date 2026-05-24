//! kotoba-hello — Kotoba node program demonstrating EVM compatibility (WASM Component Model guest)
//!
//! Implements the `kotoba-node` WIT world:
//!   - imports: kqe / kse / auth / llm / chain / evm
//!   - exports: run(ctx-cbor) → result<list<u8>, string>
//!
//! What it does:
//!   1. Read current agent DID from auth.current-did
//!   2. Assert an EVM-address quad into the graph
//!   3. Publish to KSE journal
//!   4. Fetch ETH balance from public RPC via evm.eth-get-balance
//!   5. Return output including the balance

wit_bindgen::generate!({
    path: "../../crates/kotoba-runtime/wit/world.wit",
    world: "kotoba-node",
});

use kotoba::kais::{auth, evm, kqe, kse};

struct KotobaHello;

impl Guest for KotobaHello {
    fn run(ctx_cbor: Vec<u8>) -> Result<Vec<u8>, String> {
        let did = auth::current_did();

        // Assert a quad representing an EVM address linked to this agent
        let evm_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"; // vitalik.eth
        let addr_cbor = evm_address.as_bytes().to_vec();
        kqe::assert_quad(&kqe::Quad {
            graph:       "eip155:1".into(),
            subject:     evm_address.into(),
            predicate:   "erc20/holder".into(),
            object_cbor: addr_cbor,
        })?;

        // Publish to KSE Journal
        kse::publish("kotoba/evm/hello", did.as_bytes())
            .map_err(|e| format!("publish failed: {e}"))?;

        // Fetch ETH balance from public RPC
        let rpc_url = "https://ethereum-rpc.publicnode.com";
        let balance = match evm::eth_get_balance(rpc_url, evm_address) {
            Ok(bal) => bal,
            Err(e)  => format!("rpc_err:{e}"),
        };

        let output = format!(
            "hello from kotoba-wasm | did={did} | ctx_len={} | eth_balance={balance}",
            ctx_cbor.len()
        );
        Ok(output.into_bytes())
    }
}

export!(KotobaHello);
