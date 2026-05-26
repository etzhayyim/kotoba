"""Tests for kotoba_langgraph._entry — handle_invoke CBOR bridge."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
from typing import Annotated, TypedDict

from kotoba_langgraph._cbor import dumps, loads
from kotoba_langgraph._entry import handle_invoke
from kotoba_langgraph.graph import StateGraph, START, END
from kotoba_langgraph.messages import add_messages, human_message


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _echo_graph():
    """Graph that echoes input messages with a prefix."""
    class State(TypedDict):
        messages: Annotated[list, add_messages]

    def echo(state):
        last = state["messages"][-1]["content"]
        return {"messages": [{"type": "ai", "content": f"echo:{last}"}]}

    g = StateGraph(State)
    g.add_node("echo", echo)
    g.add_edge(START, "echo")
    g.add_edge("echo", END)
    return g.compile()


def _make_ctx(input_state: dict, thread_id: str = "t1", session_cid: str = "sess-1") -> bytes:
    """Build a CBOR-encoded InvokeContext matching the kotoba-runtime wire format."""
    ctx = {
        "graph": "test-graph-cid",
        "session_cid": session_cid,
        "args": {
            "thread_id": thread_id,
            "input": input_state,
        },
    }
    return dumps(ctx)


# ── handle_invoke tests ───────────────────────────────────────────────────────

class TestHandleInvoke:
    def test_ok_response(self):
        compiled = _echo_graph()
        ctx_cbor = _make_ctx({"messages": [human_message("hello")]})
        result_cbor = handle_invoke(ctx_cbor, compiled)
        result = loads(result_cbor)
        assert "ok" in result
        assert "err" not in result

    def test_ok_contains_json_string(self):
        compiled = _echo_graph()
        ctx_cbor = _make_ctx({"messages": [human_message("hi")]})
        result = loads(handle_invoke(ctx_cbor, compiled))
        state = json.loads(result["ok"])
        assert "messages" in state
        assert state["messages"][-1]["content"] == "echo:hi"

    def test_thread_id_from_args(self):
        from kotoba_langgraph.checkpointer import KotobaCheckpointer
        ckpt = KotobaCheckpointer()

        class State(TypedDict):
            messages: Annotated[list, add_messages]

        def bot(state):
            return {"messages": [{"type": "ai", "content": "pong"}]}

        g = StateGraph(State)
        g.add_node("bot", bot)
        g.add_edge(START, "bot")
        g.add_edge("bot", END)
        compiled = g.compile(checkpointer=ckpt)

        ctx1 = _make_ctx({"messages": [human_message("ping")]}, thread_id="session-A")
        loads(handle_invoke(ctx1, compiled))

        ctx2 = _make_ctx({"messages": [human_message("ping2")]}, thread_id="session-A")
        result2 = loads(handle_invoke(ctx2, compiled))
        state2 = json.loads(result2["ok"])
        # second call should have prior messages (2 from turn1 + 2 from turn2 = 4)
        assert len(state2["messages"]) == 4

    def test_thread_id_falls_back_to_session_cid(self):
        """When args has no thread_id, session_cid is used."""
        compiled = _echo_graph()
        ctx = {
            "graph": "g",
            "session_cid": "my-session",
            "args": {"input": {"messages": [human_message("x")]}},
        }
        result = loads(handle_invoke(dumps(ctx), compiled))
        assert "ok" in result

    def test_malformed_cbor_returns_err(self):
        compiled = _echo_graph()
        result = loads(handle_invoke(b"\xff\xfe\xfd", compiled))
        assert "err" in result
        assert "cbor" in result["err"].lower()

    def test_graph_exception_returns_err(self):
        class State(TypedDict):
            x: int

        def boom(state):
            raise RuntimeError("intentional failure")

        g = StateGraph(State)
        g.add_node("boom", boom)
        g.add_edge(START, "boom")
        g.add_edge("boom", END)
        compiled = g.compile()

        ctx_cbor = _make_ctx({"x": 1})
        result = loads(handle_invoke(ctx_cbor, compiled))
        assert "err" in result
        assert "intentional failure" in result["err"]

    def test_empty_args_uses_full_ctx_as_input(self):
        """If args has no 'input' key, entire args dict is used as input."""
        class State(TypedDict):
            count: int

        def inc(state): return {"count": state.get("count", 0) + 1}

        g = StateGraph(State)
        g.add_node("inc", inc)
        g.add_edge(START, "inc")
        g.add_edge("inc", END)
        compiled = g.compile()

        ctx = {
            "graph": "g",
            "session_cid": "s",
            "args": {"count": 5},  # no "input" key — args itself is the input
        }
        result = loads(handle_invoke(dumps(ctx), compiled))
        assert "ok" in result
        state = json.loads(result["ok"])
        assert state["count"] == 6
