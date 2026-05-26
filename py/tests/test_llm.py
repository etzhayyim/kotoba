"""Tests for kotoba_langgraph.llm — KotobaLLM normalisation and dev-mode behaviour."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import pytest
from unittest.mock import patch
from kotoba_langgraph.llm import KotobaLLM
from kotoba_langgraph.messages import human_message, ai_message


class TestNormalise:
    def test_dict_messages_role(self):
        llm = KotobaLLM()
        msgs = [{"role": "user", "content": "hello"}]
        norm = llm._normalise(msgs)
        assert norm[0] == {"role": "user", "content": "hello"}

    def test_dict_messages_type_fallback(self):
        llm = KotobaLLM()
        msgs = [human_message("hi"), ai_message("hey")]
        norm = llm._normalise(msgs)
        assert norm[0]["role"] == "user"
        assert norm[1]["role"] == "assistant"

    def test_system_prompt_prepended(self):
        llm = KotobaLLM(system_prompt="You are helpful.")
        msgs = [human_message("hi")]
        norm = llm._normalise(msgs)
        assert norm[0] == {"role": "system", "content": "You are helpful."}
        assert norm[1]["content"] == "hi"

    def test_no_system_prompt(self):
        llm = KotobaLLM()
        msgs = [human_message("hi")]
        norm = llm._normalise(msgs)
        assert len(norm) == 1
        assert norm[0]["role"] == "user"

    def test_langchain_like_object(self):
        """LangChain BaseMessage-like objects are handled via getattr fallback."""
        class FakeHuman:
            type = "human"
            content = "hello from langchain"

        llm = KotobaLLM()
        norm = llm._normalise([FakeHuman()])
        assert norm[0]["role"] == "human"
        assert norm[0]["content"] == "hello from langchain"

    def test_missing_content_defaults_empty(self):
        llm = KotobaLLM()
        msgs = [{"role": "user"}]
        norm = llm._normalise(msgs)
        assert norm[0]["content"] == ""

    def test_empty_messages_no_system(self):
        llm = KotobaLLM()
        assert llm._normalise([]) == []

    def test_empty_messages_with_system(self):
        llm = KotobaLLM(system_prompt="sys")
        norm = llm._normalise([])
        assert len(norm) == 1
        assert norm[0]["role"] == "system"


class TestInvokeMocked:
    """Test invoke/ainvoke/stream with a mocked WIT infer function."""

    def _response_bytes(self, text: str) -> bytes:
        return text.encode("utf-8")

    def test_invoke_returns_ai_message_dict(self):
        llm = KotobaLLM(model_cid="test-cid")
        with patch("kotoba_langgraph.llm._wit_infer", return_value=b"Hello!"):
            result = llm.invoke([human_message("hi")])
        assert result["type"] == "ai"
        assert result["role"] == "assistant"
        assert result["content"] == "Hello!"

    def test_invoke_passes_correct_prompt_json(self):
        llm = KotobaLLM(model_cid="m")
        captured = {}

        def mock_infer(model_cid, prompt_bytes):
            captured["model_cid"] = model_cid
            captured["prompt"] = json.loads(prompt_bytes)
            return b"ok"

        with patch("kotoba_langgraph.llm._wit_infer", side_effect=mock_infer):
            llm.invoke([human_message("test input")])

        assert captured["model_cid"] == "m"
        assert captured["prompt"][0]["role"] == "user"
        assert captured["prompt"][0]["content"] == "test input"

    def test_invoke_outside_wasm_raises_runtime_error(self):
        llm = KotobaLLM()
        with pytest.raises(RuntimeError, match="kotoba:kais/llm"):
            llm.invoke([human_message("hi")])

    def test_stream_yields_one_chunk(self):
        llm = KotobaLLM()
        with patch("kotoba_langgraph.llm._wit_infer", return_value=b"chunk"):
            chunks = list(llm.stream([human_message("hi")]))
        assert len(chunks) == 1
        assert chunks[0]["content"] == "chunk"

    @pytest.mark.asyncio
    async def test_ainvoke_delegates_to_invoke(self):
        llm = KotobaLLM()
        with patch("kotoba_langgraph.llm._wit_infer", return_value=b"async-reply"):
            result = await llm.ainvoke([human_message("hello")])
        assert result["content"] == "async-reply"

    def test_invoke_unicode_content(self):
        llm = KotobaLLM()
        with patch("kotoba_langgraph.llm._wit_infer", return_value="日本語の返答".encode("utf-8")):
            result = llm.invoke([human_message("こんにちは")])
        assert result["content"] == "日本語の返答"


class TestEmbed:
    def test_embed_parses_float32_bytes(self):
        import struct
        floats = [0.1, 0.5, 0.9, -0.3]
        raw = struct.pack("<4f", *floats)
        llm = KotobaLLM()
        with patch("kotoba_langgraph.llm._wit_embed", return_value=raw):
            result = llm.embed("hello")
        assert len(result) == 4
        assert result == pytest.approx(floats, abs=1e-5)

    def test_embed_outside_wasm_raises(self):
        llm = KotobaLLM()
        with pytest.raises(RuntimeError, match="kotoba:kais/llm"):
            llm.embed("hello")

    def test_embed_empty_bytes(self):
        llm = KotobaLLM()
        with patch("kotoba_langgraph.llm._wit_embed", return_value=b""):
            result = llm.embed("x")
        assert result == []
