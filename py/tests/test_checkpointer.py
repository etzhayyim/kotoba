"""Tests for kotoba_langgraph.checkpointer — in-memory KotobaCheckpointer."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kotoba_langgraph.checkpointer import KotobaCheckpointer
from kotoba_langgraph.graph import StateGraph, START, END
from kotoba_langgraph.messages import add_messages, human_message, ai_message
from typing import Annotated, TypedDict


class TestKotobaCheckpointerMemory:
    def setup_method(self):
        self.ckpt = KotobaCheckpointer()

    def test_save_and_load(self):
        state = {"messages": [{"content": "hello"}], "count": 1}
        self.ckpt.save("t1", state)
        loaded = self.ckpt.load("t1")
        assert loaded == state

    def test_load_missing_returns_none(self):
        assert self.ckpt.load("nonexistent") is None

    def test_save_overwrites(self):
        self.ckpt.save("t1", {"count": 1})
        self.ckpt.save("t1", {"count": 2})
        assert self.ckpt.load("t1") == {"count": 2}

    def test_clear_removes_state(self):
        self.ckpt.save("t1", {"x": 1})
        self.ckpt.clear("t1")
        assert self.ckpt.load("t1") is None

    def test_clear_nonexistent_is_safe(self):
        self.ckpt.clear("does-not-exist")

    def test_isolates_threads(self):
        self.ckpt.save("thread-a", {"val": "A"})
        self.ckpt.save("thread-b", {"val": "B"})
        a = self.ckpt.load("thread-a")
        b = self.ckpt.load("thread-b")
        assert a is not None and a["val"] == "A"
        assert b is not None and b["val"] == "B"

    def test_save_makes_copy(self):
        original = {"x": [1, 2, 3]}
        self.ckpt.save("t1", original)
        original["x"].append(4)  # mutate original
        loaded = self.ckpt.load("t1")
        assert loaded is not None and loaded["x"] == [1, 2, 3]


class TestMultiTurnThread:
    """Verify that checkpointer correctly accumulates messages across invoke() calls."""

    def _build_graph(self, ckpt):
        class State(TypedDict):
            messages: Annotated[list, add_messages]

        def respond(state):
            last = state["messages"][-1]["content"]
            return {"messages": [ai_message(f"reply:{last}")]}

        g = StateGraph(State)
        g.add_node("bot", respond)
        g.add_edge(START, "bot")
        g.add_edge("bot", END)
        return g.compile(checkpointer=ckpt)

    def test_multi_turn_accumulates(self):
        ckpt = KotobaCheckpointer()
        compiled = self._build_graph(ckpt)
        cfg = {"configurable": {"thread_id": "session-1"}}

        r1 = compiled.invoke({"messages": [human_message("turn1")]}, config=cfg)
        assert len(r1["messages"]) == 2

        r2 = compiled.invoke({"messages": [human_message("turn2")]}, config=cfg)
        # 2 from turn1 + 1 new human + 1 new ai = 4
        assert len(r2["messages"]) == 4

        r3 = compiled.invoke({"messages": [human_message("turn3")]}, config=cfg)
        assert len(r3["messages"]) == 6

    def test_different_threads_are_isolated(self):
        ckpt = KotobaCheckpointer()
        compiled = self._build_graph(ckpt)

        compiled.invoke(
            {"messages": [human_message("a"), human_message("b"), human_message("c")]},
            config={"configurable": {"thread_id": "thread-X"}},
        )
        r = compiled.invoke(
            {"messages": [human_message("fresh")]},
            config={"configurable": {"thread_id": "thread-Y"}},
        )
        # thread-Y has no prior history — only 1 human + 1 ai
        assert len(r["messages"]) == 2
