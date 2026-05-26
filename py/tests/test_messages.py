"""Tests for kotoba_langgraph.messages — message constructors and add_messages reducer."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from kotoba_langgraph.messages import (
    human_message, ai_message, tool_message, system_message,
    add_messages, message_content, message_type,
)


class TestConstructors:
    def test_human_message(self):
        m = human_message("hello")
        assert m["type"] == "human"
        assert m["role"] == "user"
        assert m["content"] == "hello"

    def test_ai_message(self):
        m = ai_message("hi there")
        assert m["type"] == "ai"
        assert m["role"] == "assistant"
        assert m["content"] == "hi there"
        assert "tool_calls" not in m

    def test_ai_message_with_tool_calls(self):
        tc = [{"name": "search", "arguments": {"q": "test"}}]
        m = ai_message("ok", tool_calls=tc)
        assert m["tool_calls"] == tc

    def test_tool_message(self):
        m = tool_message("result", "call-123")
        assert m["type"] == "tool"
        assert m["tool_call_id"] == "call-123"
        assert m["content"] == "result"

    def test_system_message(self):
        m = system_message("You are helpful.")
        assert m["type"] == "system"
        assert m["role"] == "system"

    def test_extra_kwargs_propagated(self):
        m = human_message("hi", id="msg-1", name="Alice")
        assert m["id"] == "msg-1"
        assert m["name"] == "Alice"


class TestAddMessages:
    def test_append_single_dict(self):
        left = [human_message("a")]
        right = ai_message("b")
        result = add_messages(left, right)
        assert len(result) == 2
        assert result[1]["content"] == "b"

    def test_append_list(self):
        left = [human_message("a")]
        right = [ai_message("b"), human_message("c")]
        result = add_messages(left, right)
        assert len(result) == 3

    def test_dedup_by_id_upserts(self):
        left = [{"id": "1", "content": "old"}, {"id": "2", "content": "keep"}]
        right = [{"id": "1", "content": "new"}]
        result = add_messages(left, right)
        assert len(result) == 2
        assert result[0]["content"] == "new"
        assert result[1]["content"] == "keep"

    def test_no_id_always_appends(self):
        left = [{"content": "a"}]
        right = [{"content": "a"}]  # same content, no id
        result = add_messages(left, right)
        assert len(result) == 2

    def test_left_none_treated_as_empty(self):
        result = add_messages(None, [human_message("hi")])
        assert len(result) == 1

    def test_empty_left_empty_right(self):
        assert add_messages([], []) == []

    def test_preserves_order(self):
        left = [{"content": str(i)} for i in range(5)]
        right = [{"content": "new"}]
        result = add_messages(left, right)
        assert [m["content"] for m in result] == ["0", "1", "2", "3", "4", "new"]


class TestHelpers:
    def test_message_content_from_dict(self):
        assert message_content({"content": "hello"}) == "hello"

    def test_message_content_missing_key(self):
        assert message_content({}) == ""

    def test_message_content_non_dict(self):
        class Fake:
            content = "fake content"
        assert message_content(Fake()) == "fake content"

    def test_message_type_from_dict(self):
        assert message_type({"type": "human"}) == "human"

    def test_message_type_fallback_to_role(self):
        assert message_type({"role": "assistant"}) == "assistant"

    def test_message_type_default_human(self):
        assert message_type({}) == "human"
