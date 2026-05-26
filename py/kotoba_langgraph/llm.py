"""KotobaLLM — pure-Python LLM interface backed by kotoba:kais/llm WIT import.

No pydantic / langchain-core dependency.  Provides the same ``invoke`` /
``stream`` call shape as LangChain ``BaseChatModel`` so user code is
drop-in compatible:

    llm = KotobaLLM(model_cid="bafkrei...")
    response = llm.invoke(messages)          # returns a message dict
    for chunk in llm.stream(messages): ...   # yields message dicts

Messages are plain Python dicts with ``"role"`` and ``"content"`` keys,
matching the standard OpenAI / Anthropic wire format.
"""

from __future__ import annotations

import json
from typing import Any, Iterator, Optional


def _wit_infer(model_cid: str, prompt: bytes) -> bytes:
    """Call kotoba:kais/llm.infer WIT import.  ImportError outside WASM."""
    from wit_world.imports import llm
    return llm.infer(model_cid, prompt)


def _wit_embed(model_cid: str, text: str) -> bytes:
    """Call kotoba:kais/llm.embed WIT import."""
    from wit_world.imports import llm
    return llm.embed(model_cid, text)


class KotobaLLM:
    """Pure-Python ChatModel that routes through kotoba:kais/llm WIT import.

    Parameters
    ----------
    model_cid:
        Kotoba Vault CID of the GGUF/GGML model blob.  Leave empty string to
        use ``MURAKUMO_DEFAULT_MODEL`` configured on the host.
    system_prompt:
        Optional system message prepended to every invoke call.
    """

    def __init__(
        self,
        model_cid: str = "",
        system_prompt: Optional[str] = None,
    ) -> None:
        self.model_cid = model_cid
        self.system_prompt = system_prompt

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _normalise(self, messages: list) -> list[dict]:
        """Normalise a mixed list of dicts / LangChain message objects."""
        out = []
        if self.system_prompt:
            out.append({"role": "system", "content": self.system_prompt})
        for m in messages:
            if isinstance(m, dict):
                out.append({"role": m.get("role", m.get("type", "user")), "content": m.get("content", "")})
            else:
                # Compat with LangChain BaseMessage objects (graceful fallback)
                role = getattr(m, "type", "user")
                content = getattr(m, "content", str(m))
                out.append({"role": role, "content": content})
        return out

    def _call(self, messages: list) -> str:
        prompt = json.dumps(self._normalise(messages), ensure_ascii=False).encode()
        try:
            result_bytes = _wit_infer(self.model_cid, prompt)
        except ImportError:
            raise RuntimeError(
                "KotobaLLM requires kotoba:kais/llm WIT import.  "
                "Compile your agent with componentize-py targeting kotoba-node.  "
                "For local dev/test, use a real LangChain provider instead."
            )
        return result_bytes.decode("utf-8", errors="replace")

    # ── Public API (same shape as LangChain BaseChatModel) ───────────────────

    def invoke(
        self,
        messages: list,
        **kwargs: Any,  # noqa: ARG002
    ) -> dict:
        """Invoke the LLM and return an assistant message dict."""
        text = self._call(messages)
        return {"role": "assistant", "type": "ai", "content": text}

    def stream(
        self,
        messages: list,
        **kwargs: Any,  # noqa: ARG002
    ) -> Iterator[dict]:
        """Single-shot stream (yields one assistant chunk).

        Phase 2 will yield incremental chunks via kotoba:kais/kse.
        """
        yield self.invoke(messages)

    async def ainvoke(
        self,
        messages: list,
        **kwargs: Any,  # noqa: ARG002
    ) -> dict:
        """Async invoke; delegates to invoke (componentize-py asyncio ok)."""
        return self.invoke(messages)

    def embed(self, text: str) -> list[float]:
        """Return a float embedding vector for ``text``."""
        import struct
        try:
            raw = _wit_embed(self.model_cid, text)
        except ImportError:
            raise RuntimeError("KotobaLLM.embed requires kotoba:kais/llm WIT import.")
        count = len(raw) // 4
        return list(struct.unpack(f"<{count}f", raw[:count * 4]))
