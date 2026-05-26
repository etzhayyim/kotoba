#!/usr/bin/env bash
# build-pywasm.sh — Compile a Python LangGraph agent to a kotoba WASM component
#
# Usage:
#   ./scripts/build-pywasm.sh <agent_module.py> [-o output.wasm]
#
# The agent module must:
#   1. Build a compiled LangGraph (StateGraph.compile())
#   2. Declare a WitWorld class that calls handle_invoke:
#
#     import wit_world
#     from kotoba_langgraph import handle_invoke
#     compiled = ...   # your StateGraph.compile()
#
#     class WitWorld(wit_world.WitWorld):
#         def run(self, ctx_cbor: bytes) -> bytes:
#             return handle_invoke(ctx_cbor, compiled)
#
# Requirements (auto-installed if missing):
#   pip install componentize-py>=0.23 cbor2 langgraph langchain-core
#
# Environment:
#   KOTOBA_WIT_PATH — override path to world.wit (default: auto-detected)
#   KOTOBA_SITE_PKG — override Python site-packages path

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KOTOBA_DIR="$(dirname "$SCRIPT_DIR")"

# ── Args ────────────────────────────────────────────────────────────────────
AGENT_FILE="${1:-}"
OUTPUT="${2:-}"

if [[ -z "$AGENT_FILE" ]]; then
    echo "Usage: $0 <agent_module.py> [output.wasm]" >&2
    exit 1
fi
if [[ ! -f "$AGENT_FILE" ]]; then
    echo "Error: file not found: $AGENT_FILE" >&2
    exit 1
fi

AGENT_DIR="$(cd "$(dirname "$AGENT_FILE")" && pwd)"
AGENT_MODULE="$(basename "$AGENT_FILE" .py)"
OUTPUT="${OUTPUT:-${AGENT_DIR}/${AGENT_MODULE}.wasm}"

# ── Paths ───────────────────────────────────────────────────────────────────
WIT_PATH="${KOTOBA_WIT_PATH:-${KOTOBA_DIR}/crates/kotoba-runtime/wit/world.wit}"
BINDINGS_DIR="${KOTOBA_DIR}/target/pywasm-bindings"
PY_PKG_DIR="${KOTOBA_DIR}/py"

if [[ ! -f "$WIT_PATH" ]]; then
    echo "Error: world.wit not found at $WIT_PATH" >&2
    echo "Set KOTOBA_WIT_PATH to override." >&2
    exit 1
fi

# ── Site-packages detection ──────────────────────────────────────────────────
if [[ -n "${KOTOBA_SITE_PKG:-}" ]]; then
    SITE_PKG="$KOTOBA_SITE_PKG"
else
    SITE_PKG="$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null || true)"
    if [[ -z "$SITE_PKG" ]]; then
        SITE_PKG="$(python3 -m site --user-site 2>/dev/null || true)"
    fi
fi

# ── Ensure componentize-py is available ─────────────────────────────────────
if ! command -v componentize-py &>/dev/null; then
    echo "Installing componentize-py..." >&2
    pip install "componentize-py>=0.23" cbor2
fi

# ── Generate WIT bindings (cached) ──────────────────────────────────────────
BINDINGS_STAMP="${BINDINGS_DIR}/.stamp"
WIT_MTIME="$(stat -f "%m" "$WIT_PATH" 2>/dev/null || stat -c "%Y" "$WIT_PATH" 2>/dev/null)"

if [[ ! -f "$BINDINGS_STAMP" ]] || [[ "$(cat "$BINDINGS_STAMP" 2>/dev/null)" != "$WIT_MTIME" ]]; then
    echo "Generating WIT bindings → $BINDINGS_DIR" >&2
    mkdir -p "$BINDINGS_DIR"
    componentize-py \
        -d "$WIT_PATH" \
        -w kotoba-node \
        bindings "$BINDINGS_DIR"
    echo "$WIT_MTIME" > "$BINDINGS_STAMP"
fi

# ── Build WASM component ─────────────────────────────────────────────────────
echo "Building $AGENT_MODULE → $OUTPUT" >&2

componentize-py \
    -d "$WIT_PATH" \
    -w kotoba-node \
    componentize "$AGENT_MODULE" \
    -p "$AGENT_DIR" \
    -p "$BINDINGS_DIR" \
    -p "$PY_PKG_DIR" \
    ${SITE_PKG:+-p "$SITE_PKG"} \
    -o "$OUTPUT"

SIZE_MB="$(du -sh "$OUTPUT" | cut -f1)"
echo "Built: $OUTPUT ($SIZE_MB)" >&2
