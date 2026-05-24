# kotoba-hello

Minimal Kotoba WASM guest component implementing the `kotoba-node` WIT world.

## Build

```bash
# 1. Install wasm32-wasip2 target (once)
rustup target add wasm32-wasip2

# 2. Build
cargo build --target wasm32-wasip2 --release

# Output
ls -lh target/wasm32-wasip2/release/kotoba_hello.wasm
```

## Test via kotoba-server

```bash
# 1. Start server
cd ../..
cargo run --bin kotoba

# 2. Encode the WASM as base64
WASM_B64=$(base64 -i examples/kotoba-hello/target/wasm32-wasip2/release/kotoba_hello.wasm)

# 3. Invoke via XRPC
curl -s -X POST http://localhost:8080/xrpc/ai.gftd.apps.kotoba.invoke.run \
  -H 'Content-Type: application/json' \
  -d "{
    \"program_cid\":  \"btest_hello_cid\",
    \"program_type\": \"wasm-node\",
    \"agent_did\":    \"did:plc:hello-tester\",
    \"wasm_b64\":     \"$WASM_B64\",
    \"ctx_b64\":      \"$(echo -n '{}' | base64)\"
  }" | jq .
```

Expected response:
```json
{
  "status": "ok",
  "gas_used": 42,
  "output_b64": "aGVsbG8gZnJvbSBrb3RvYmEtd2FzbSB8IGRpZD1kaWQ6cGxjOmhlbGxvLXRlc3Rlcg==",
  "assert_count": 1,
  "retract_count": 0
}
```

Decoded output: `hello from kotoba-wasm | did=did:plc:hello-tester | ctx_len=2`

## Multi-language equivalents

| Language | Tool | Command |
|---|---|---|
| Python | componentize-py | `componentize-py build --wit-path ../../crates/kotoba-runtime/wit/ --world kotoba-node -p app.py -o hello.wasm` |
| JS/TS | jco | `jco componentize src/main.js --wit-path ../../crates/kotoba-runtime/wit/ --world kotoba-node -o hello.wasm` |
| Go | TinyGo | `tinygo build -target wasm32-wasi -o hello.wasm .` |
