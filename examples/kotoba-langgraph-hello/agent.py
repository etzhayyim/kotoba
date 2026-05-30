"""kotoba-langgraph-hello — minimal LangGraph-compatible chatbot compiled to WASM.

This is a self-contained kotoba WASM component.  Build with:

    ../../scripts/build-pywasm.sh agent.py -o agent.wasm

Then load agent.wasm with kotoba-runtime's WasmExecutor as any other
kotoba-node component.

The code below is standard LangGraph syntax — the only kotoba-specific
additions are:
  • ``KotobaLLM``         — routes .invoke() through kotoba:kais/llm WIT
  • ``KotobaCheckpointer``— persists state to kotoba:kais/kqe (in-memory fallback)
  • ``handle_invoke``     — bridges the WIT run() export to compiled.invoke()
  • ``WitWorld`` class    — required boilerplate for componentize-py 0.23+
"""

import wit_world

from typing import Annotated, TypedDict

from kotoba_langgraph import (
    StateGraph,
    KotobaLLM,
    KotobaCheckpointer,
    START,
    END,
    handle_invoke,
)
from kotoba_langgraph.messages import add_messages

# componentize-py static analysis does not follow the lazy `from kotoba_langgraph._cbor
# import loads` inside _entry.handle_invoke; import the submodules explicitly at module
# scope so they are bundled (otherwise the component traps at call time with
# ModuleNotFoundError). Mirrors aria_kotoba.py (ADR-2605301625 follow-up).
import kotoba_langgraph._cbor  # noqa: F401
import kotoba_langgraph._entry  # noqa: F401
# Same reason: kotoba_langgraph.llm._wit_infer does `from wit_world.imports import llm`
# lazily inside a function, so componentize-py does not bundle the host llm import.
# Pull it to module scope so the kotoba:kais/llm WIT import is available at call time.
import wit_world.imports.llm  # noqa: F401

# ── State ────────────────────────────────────────────────────────────────────

class State(TypedDict):
    messages: Annotated[list, add_messages]

# ── LLM (routed through kotoba:kais/llm WIT import) ─────────────────────────

# model_cid: Kotoba Vault CID of the GGUF model.
# Leave empty to use MURAKUMO_DEFAULT_MODEL configured on the host.
llm = KotobaLLM(model_cid="")

# ── Nodes ────────────────────────────────────────────────────────────────────

def chatbot(state: State) -> dict:
    return {"messages": [llm.invoke(state["messages"])]}

# ── Graph (identical LangGraph builder syntax) ───────────────────────────────

graph_builder = StateGraph(State)
graph_builder.add_node("chatbot", chatbot)
graph_builder.add_edge(START, "chatbot")
graph_builder.add_edge("chatbot", END)

compiled = graph_builder.compile(checkpointer=KotobaCheckpointer())

# ── kotoba-node WIT export (boilerplate, always the same) ────────────────────

class WitWorld(wit_world.WitWorld):
    def run(self, ctx_cbor: bytes) -> bytes:
        return handle_invoke(ctx_cbor, compiled)
