"""handle_invoke — bridges the kotoba-node WIT export to a compiled LangGraph.

The kotoba-runtime executor calls ``run(ctx_cbor: bytes) -> bytes`` on the
WASM guest.  ``handle_invoke`` decodes the CBOR InvokeContext, calls
``compiled_graph.invoke()``, and returns a CBOR-encoded result.

InvokeContext wire format (CBOR map, matches Rust ``InvokeContext``)
--------------------------------------------------------------------
  {
    "graph":       str,   # graph def CID
    "session_cid": str,   # session / thread CID
    "args": {
      "input":     dict,  # LangGraph input state (required)
      "thread_id": str,   # optional, defaults to session_cid
    }
  }

Result wire format (CBOR map)
-----------------------------
  {"ok":  <JSON string of output state>}   # success
  {"err": <error message string>}           # failure
"""

from __future__ import annotations

import json
import traceback
from typing import Any


def _cbor_loads(data: bytes) -> Any:
    import cbor2
    return cbor2.loads(data)


def _cbor_dumps(obj: Any) -> bytes:
    import cbor2
    return cbor2.dumps(obj)


def handle_invoke(ctx_cbor: bytes, compiled_graph: Any) -> bytes:
    """Decode InvokeContext, run compiled_graph.invoke(), return CBOR result.

    Parameters
    ----------
    ctx_cbor:
        Raw CBOR bytes from ``run(ctx_cbor)`` WIT export argument.
    compiled_graph:
        A ``CompiledGraph`` produced by ``StateGraph.compile()``.

    Returns
    -------
    bytes
        CBOR-encoded ``{"ok": json_str}`` or ``{"err": message}``.
    """
    try:
        ctx = _cbor_loads(ctx_cbor)
    except Exception as e:
        return _cbor_dumps({"err": f"cbor decode error: {e}"})

    try:
        args = ctx.get("args", {}) if isinstance(ctx, dict) else {}
        session_cid: str = ctx.get("session_cid", "default") if isinstance(ctx, dict) else "default"

        thread_id: str = args.get("thread_id", session_cid)
        input_state: dict = args.get("input", args)

        config = {"configurable": {"thread_id": thread_id}}
        result = compiled_graph.invoke(input_state, config=config)

        # Serialise result — fall back to str for non-serialisable objects
        result_json = json.dumps(result, default=str)
        return _cbor_dumps({"ok": result_json})

    except Exception:
        return _cbor_dumps({"err": traceback.format_exc()})
