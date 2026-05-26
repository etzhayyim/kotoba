"""Tests for kotoba_langgraph.graph — StateGraph builder + CompiledGraph executor."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import operator
from typing import Annotated, TypedDict

from kotoba_langgraph.graph import StateGraph, CompiledGraph, MessagesState, START, END
from kotoba_langgraph.messages import add_messages


# ── Shared state schemas ──────────────────────────────────────────────────────

class CountState(TypedDict):
    count: int


class MsgState(TypedDict):
    messages: Annotated[list, add_messages]


class AccState(TypedDict):
    items: Annotated[list, operator.add]
    label: str


# ── Builder tests ─────────────────────────────────────────────────────────────

class TestStateGraphBuilder:
    def test_add_node_returns_self(self):
        g = StateGraph(CountState)
        assert g.add_node("a", lambda s: s) is g

    def test_add_edge_returns_self(self):
        g = StateGraph(CountState)
        assert g.add_edge(START, END) is g

    def test_compile_returns_compiled_graph(self):
        g = StateGraph(CountState)
        g.add_node("n", lambda s: {})
        g.add_edge(START, "n")
        g.add_edge("n", END)
        compiled = g.compile()
        assert isinstance(compiled, CompiledGraph)

    def test_set_entry_point(self):
        g = StateGraph(CountState)
        g.add_node("first", lambda s: {})
        g.set_entry_point("first")
        assert g._edges[START] == "first"

    def test_add_conditional_edges_with_path_map(self):
        g = StateGraph(CountState)
        g.add_conditional_edges("a", lambda s: "x", {"x": "b", "y": "c"})
        edge_fn = g._edges["a"]
        assert callable(edge_fn)
        assert edge_fn({"count": 0}) == "b"

    def test_add_conditional_edges_unknown_key_goes_to_end(self):
        g = StateGraph(CountState)
        g.add_conditional_edges("a", lambda s: "z", {"x": "b"})
        edge_fn = g._edges["a"]
        assert edge_fn({"count": 0}) == END

    def test_add_conditional_edges_no_path_map(self):
        g = StateGraph(CountState)
        router = lambda s: "b"
        g.add_conditional_edges("a", router)
        assert g._edges["a"] is router


# ── invoke() tests ────────────────────────────────────────────────────────────

class TestInvoke:
    def _simple_graph(self):
        def increment(state):
            return {"count": state["count"] + 1}

        g = StateGraph(CountState)
        g.add_node("inc", increment)
        g.add_edge(START, "inc")
        g.add_edge("inc", END)
        return g.compile()

    def test_basic_invoke(self):
        c = self._simple_graph()
        result = c.invoke({"count": 0})
        assert result["count"] == 1

    def test_invoke_returns_full_state(self):
        c = self._simple_graph()
        result = c.invoke({"count": 5})
        assert result["count"] == 6

    def test_multi_node_chain(self):
        def add1(s): return {"count": s["count"] + 1}
        def mul2(s): return {"count": s["count"] * 2}

        g = StateGraph(CountState)
        g.add_node("add", add1)
        g.add_node("mul", mul2)
        g.add_edge(START, "add")
        g.add_edge("add", "mul")
        g.add_edge("mul", END)

        result = g.compile().invoke({"count": 3})
        assert result["count"] == 8  # (3+1)*2

    def test_conditional_routing(self):
        def route(state): return "big" if state["count"] > 5 else "small"
        def set_big(s): return {"label": "BIG"}
        def set_small(s): return {"label": "SMALL"}

        class S(TypedDict):
            count: int
            label: str

        g = StateGraph(S)
        g.add_node("big", set_big)
        g.add_node("small", set_small)
        g.add_edge(START, "router")
        g.add_node("router", lambda s: {})
        g.add_conditional_edges("router", route, {"big": "big", "small": "small"})
        g.add_edge("big", END)
        g.add_edge("small", END)

        assert g.compile().invoke({"count": 10, "label": ""})["label"] == "BIG"
        assert g.compile().invoke({"count": 2, "label": ""})["label"] == "SMALL"

    def test_invoke_with_config(self):
        c = self._simple_graph()
        result = c.invoke({"count": 0}, config={"configurable": {"thread_id": "t1"}})
        assert result["count"] == 1

    def test_messages_reducer(self):
        def echo(state):
            msgs = state["messages"]
            return {"messages": [{"type": "ai", "content": f"echo:{msgs[-1]['content']}"}]}

        g = StateGraph(MsgState)
        g.add_node("echo", echo)
        g.add_edge(START, "echo")
        g.add_edge("echo", END)

        result = g.compile().invoke({"messages": [{"type": "human", "content": "hi"}]})
        assert len(result["messages"]) == 2
        assert result["messages"][1]["content"] == "echo:hi"

    def test_operator_add_reducer(self):
        def append_x(s): return {"items": ["x"]}

        g = StateGraph(AccState)
        g.add_node("n", append_x)
        g.add_edge(START, "n")
        g.add_edge("n", END)

        result = g.compile().invoke({"items": ["a", "b"], "label": "test"})
        assert result["items"] == ["a", "b", "x"]

    def test_node_returns_none_is_safe(self):
        def noop(s): pass  # returns None

        g = StateGraph(CountState)
        g.add_node("noop", noop)
        g.add_edge(START, "noop")
        g.add_edge("noop", END)

        result = g.compile().invoke({"count": 7})
        assert result["count"] == 7

    def test_missing_edge_stops_execution(self):
        g = StateGraph(CountState)
        g.add_node("orphan", lambda s: {"count": 99})
        g.add_edge(START, "orphan")
        # no edge from "orphan" → should stop after one step

        result = g.compile().invoke({"count": 0})
        assert result["count"] == 99

    def test_max_steps_guard(self):
        def cycle(s): return {"count": s["count"] + 1}

        g = StateGraph(CountState)
        g.add_node("n", cycle)
        g.add_edge(START, "n")
        g.add_edge("n", "n")  # infinite loop

        compiled = g.compile()
        compiled.MAX_STEPS = 10
        result = compiled.invoke({"count": 0})
        assert result["count"] == 10


# ── stream() tests ────────────────────────────────────────────────────────────

class TestStream:
    def test_stream_values_yields_per_node(self):
        def inc(s): return {"count": s["count"] + 1}

        g = StateGraph(CountState)
        g.add_node("a", inc)
        g.add_node("b", inc)
        g.add_edge(START, "a")
        g.add_edge("a", "b")
        g.add_edge("b", END)

        snapshots = list(g.compile().stream({"count": 0}))
        assert len(snapshots) == 2
        assert snapshots[0]["count"] == 1
        assert snapshots[1]["count"] == 2


# ── MessagesState convenience ─────────────────────────────────────────────────

class TestMessagesState:
    def test_messages_state_reducer(self):
        def respond(s):
            return {"messages": [{"type": "ai", "content": "hello"}]}

        g = StateGraph(MessagesState)
        g.add_node("bot", respond)
        g.add_edge(START, "bot")
        g.add_edge("bot", END)

        result = g.compile().invoke({"messages": [{"type": "human", "content": "hi"}]})
        assert len(result["messages"]) == 2
