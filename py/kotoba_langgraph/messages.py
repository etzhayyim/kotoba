"""Message helpers — plain-dict equivalents of LangChain message types.

Inside a WASM component, messages are represented as plain Python dicts
rather than pydantic models.  These helpers provide the same constructor
names as LangChain so user code reads identically.

LangGraph ``add_messages`` reducer is also defined here (same semantics as
``langgraph.graph.message.add_messages``).

Example
-------
    from kotoba_langgraph.messages import human_message, ai_message, add_messages
    from typing import Annotated, TypedDict

    class State(TypedDict):
        messages: Annotated[list, add_messages]
"""

from __future__ import annotations

from typing import Any, Optional

# ── Message constructors (returns plain dicts) ────────────────────────────────

def human_message(content: str, **kwargs: Any) -> dict:
    """dict equivalent of ``HumanMessage(content=...)``.

    ``msg["type"]`` == ``"human"`` — same as LangChain's ``m.type``.
    """
    return {"type": "human", "role": "user", "content": content, **kwargs}


def ai_message(content: str, tool_calls: Optional[list] = None, **kwargs: Any) -> dict:
    """dict equivalent of ``AIMessage(content=...)``.

    ``msg["type"]`` == ``"ai"`` — same as LangChain's ``m.type``.
    """
    msg: dict = {"type": "ai", "role": "assistant", "content": content, **kwargs}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return msg


def tool_message(content: str, tool_call_id: str, **kwargs: Any) -> dict:
    """dict equivalent of ``ToolMessage(content=..., tool_call_id=...)``."""
    return {
        "type": "tool",
        "role": "tool",
        "content": content,
        "tool_call_id": tool_call_id,
        **kwargs,
    }


def system_message(content: str, **kwargs: Any) -> dict:
    """dict equivalent of ``SystemMessage(content=...)``."""
    return {"type": "system", "role": "system", "content": content, **kwargs}


# ── LangGraph-compatible reducer ─────────────────────────────────────────────

def add_messages(left: list, right: Any) -> list:
    """Append-style reducer matching LangGraph's ``add_messages`` semantics.

    ``right`` can be a single message dict or a list of message dicts.
    Duplicate message IDs (``msg["id"]``) are deduplicated in favour of the
    newer value, matching LangGraph's upsert behaviour.
    """
    left = list(left) if left is not None else []
    if not isinstance(right, list):
        right = [right]

    # Deduplicate by "id" if present (LangGraph upsert semantics)
    left_ids: dict[str, int] = {}
    for i, msg in enumerate(left):
        if isinstance(msg, dict) and "id" in msg:
            left_ids[msg["id"]] = i

    result = list(left)
    for msg in right:
        if isinstance(msg, dict) and "id" in msg and msg["id"] in left_ids:
            result[left_ids[msg["id"]]] = msg
        else:
            result.append(msg)

    return result


# ── Compatibility shim ─────────────────────────────────────────────────────────

def message_content(msg: Any) -> str:
    """Extract content string from a message (dict or LangChain BaseMessage)."""
    if isinstance(msg, dict):
        return str(msg.get("content", ""))
    return str(getattr(msg, "content", ""))


def message_type(msg: Any) -> str:
    """Extract type string from a message (dict or LangChain BaseMessage)."""
    if isinstance(msg, dict):
        return str(msg.get("type", msg.get("role", "human")))
    return str(getattr(msg, "type", "human"))
