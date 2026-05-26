"""kotoba_langgraph — LangGraph-compatible graph engine for kotoba WASM components.

Pure Python (no pydantic, no C extensions) so it compiles cleanly to a WASM
Component Model binary via componentize-py.

API is intentionally identical to ``langgraph`` so that user code is
drop-in compatible — only the import path changes.

Typical usage
-------------
    # my_agent.py — compiled to .wasm with:
    #   componentize-py -d world.wit -w kotoba-node componentize my_agent \\
    #       -p . -p bindings -p site-packages -o my_agent.wasm

    import wit_world
    from typing import Annotated, TypedDict
    from kotoba_langgraph import StateGraph, START, END
    from kotoba_langgraph.messages import add_messages, human_message
    from kotoba_langgraph import KotobaLLM, KotobaCheckpointer, handle_invoke

    llm = KotobaLLM(model_cid="")          # routes through kotoba:kais/llm WIT

    class State(TypedDict):
        messages: Annotated[list, add_messages]

    def chatbot(state: State) -> dict:
        return {"messages": [llm.invoke(state["messages"])]}

    graph = StateGraph(State)
    graph.add_node("chatbot", chatbot)
    graph.add_edge(START, "chatbot")
    graph.add_edge("chatbot", END)
    compiled = graph.compile(checkpointer=KotobaCheckpointer())

    class WitWorld(wit_world.WitWorld):
        def run(self, ctx_cbor: bytes) -> bytes:
            return handle_invoke(ctx_cbor, compiled)

Build
-----
    ./scripts/build-pywasm.sh my_agent.py -o my_agent.wasm
"""

from .graph import StateGraph, CompiledGraph, MessagesState, START, END
from .llm import KotobaLLM
from .checkpointer import KotobaCheckpointer
from ._entry import handle_invoke

__all__ = [
    # Graph API (same as langgraph.graph)
    "StateGraph",
    "CompiledGraph",
    "MessagesState",
    "START",
    "END",
    # kotoba-specific
    "KotobaLLM",
    "KotobaCheckpointer",
    "handle_invoke",
]
