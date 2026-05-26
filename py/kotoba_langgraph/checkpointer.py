"""KotobaCheckpointer — pure-Python checkpointer backed by kotoba:kais/kqe.

No pydantic / langgraph dependency.  Implements a minimal save/load interface
compatible with the ``CompiledGraph`` in ``kotoba_langgraph.graph``.

Storage layout in KQE
---------------------
  graph:     "lgraph/ckpt"
  subject:   "<thread_id>"
  predicate: "state"
  object:    QuadObject::Text( JSON-serialised state dict )

Fallback
--------
In-memory dict when running outside a WASM component (dev/test).
"""

from __future__ import annotations

import json
from typing import Optional


def _try_kqe():
    """Return (kqe module, True) in WASM, (None, False) otherwise."""
    try:
        from wit_world.imports import kqe
        return kqe, True
    except ImportError:
        return None, False


def _cbor_text(text: str) -> bytes:
    """Encode a string as CBOR ``{"Text": text}`` (ciborium map format)."""
    from kotoba_langgraph._cbor import dumps
    return dumps({"Text": text})


def _cbor_text_decode(raw: bytes) -> str:
    from kotoba_langgraph._cbor import loads
    obj = loads(raw)
    if isinstance(obj, dict) and "Text" in obj:
        return obj["Text"]
    return raw.decode("utf-8", errors="replace")


class KotobaCheckpointer:
    """Thread-state checkpointer for ``kotoba_langgraph.graph.CompiledGraph``.

    In WASM (componentize-py environment): persists state to KQE so that
    multi-turn threads survive across ``run()`` invocations.

    Outside WASM (dev / test): keeps state in an in-memory dict.
    """

    def __init__(self) -> None:
        self._memory: dict[str, dict] = {}

    def save(self, thread_id: str, state: dict) -> None:
        """Persist ``state`` for ``thread_id``."""
        self._memory[thread_id] = dict(state)

        kqe, in_wasm = _try_kqe()
        if not (in_wasm and kqe is not None):
            return
        try:
            kqe.assert_quad(
                kqe.Quad(
                    graph="lgraph/ckpt",
                    subject=thread_id,
                    predicate="state",
                    object_cbor=_cbor_text(json.dumps(state, default=str)),
                )
            )
        except Exception:
            pass

    def load(self, thread_id: str) -> Optional[dict]:
        """Return the last persisted state for ``thread_id``, or None."""
        kqe, in_wasm = _try_kqe()
        if in_wasm and kqe is not None:
            try:
                raw_list = kqe.get_objects("lgraph/ckpt", thread_id, "state")
                if raw_list:
                    text = _cbor_text_decode(bytes(raw_list[-1]))
                    loaded = json.loads(text)
                    self._memory[thread_id] = loaded
                    return loaded
            except Exception:
                pass
        return self._memory.get(thread_id)

    def clear(self, thread_id: str) -> None:
        """Remove persisted state for ``thread_id`` (in-memory + KQE)."""
        self._memory.pop(thread_id, None)
        kqe, in_wasm = _try_kqe()
        if in_wasm and kqe is not None:
            try:
                kqe.retract_quad(
                    kqe.Quad(
                        graph="lgraph/ckpt",
                        subject=thread_id,
                        predicate="state",
                        object_cbor=b"",
                    )
                )
            except Exception:
                pass
