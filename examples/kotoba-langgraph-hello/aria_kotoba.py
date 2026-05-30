"""aria (kotoba-native port) — 6-signal parallel ingest + Von Neumann minimax.

Faithful port of magatama's ARIA actor
(`20-actors/magatama/py/src/pymagatama/agents/aria.py`) onto the WASM-native
`kotoba_langgraph` API so it compiles to a kotoba-node component and runs on a
live kotoba server via invoke.run / kotoba_wasm_run.

Graph (identical to upstream):
    START → ingest_all → compute_area → minimax_select → witness → END

The only change vs. upstream: `_ingest_all` reads the six signal dicts directly
from the invocation context (`state["context"]`) instead of calling
`pymagatama.primitives.aria_signal.*`, since those primitives merely project the
six signals out of the same context.  The decision logic
(compute_area / minimax_select / witness) is byte-for-byte the upstream logic.

Build:
    ../../scripts/build-pywasm.sh aria_kotoba.py -o aria_kotoba.wasm
"""

from __future__ import annotations

from typing import Any, TypedDict

import wit_world

from kotoba_langgraph import StateGraph, KotobaCheckpointer, START, END, handle_invoke
# Force-bundle submodules that kotoba_langgraph imports lazily at runtime
# (_entry.handle_invoke does `from kotoba_langgraph._cbor import loads` inside
# the function body, which componentize-py's static analysis does not follow).
import kotoba_langgraph._cbor  # noqa: F401
import kotoba_langgraph._entry  # noqa: F401


# ── State ──────────────────────────────────────────────────────────────────

class AriaState(TypedDict, total=False):
    context: dict
    threadId: str
    budgetMs: int
    emotion: dict
    attention: dict
    request: dict
    market: dict
    money: dict
    influence: dict
    area_integral: float
    eta_global: float
    minimax_result: dict
    witnessed: bool
    audit_cid: str


_SIGNAL_KEYS = ("emotion", "attention", "request", "market", "money", "influence")


# ── Nodes (decision logic identical to upstream aria.py) ────────────────────

def _ingest_all(state: AriaState) -> dict:
    """Project the six signals out of the invocation context.

    Upstream calls aria_signal.task_aria_*_ingest(ctx); each primitive returns
    ctx[<signal>] (a {"intensity": float, ...} dict). We inline that here so the
    component is self-contained — no pymagatama dependency in the WASM bundle.
    """
    ctx = state.get("context", {}) or {}
    return {k: ctx.get(k, {}) for k in _SIGNAL_KEYS}


def _compute_area(state: AriaState) -> dict:
    """Information-area integral + global decay (eta) — upstream logic."""
    signals = [state.get(k, {}) for k in _SIGNAL_KEYS]
    area = 0.0
    for s in signals:
        v = s.get("intensity", 0.0) if isinstance(s, dict) else 0.0
        area += float(v)
    eta = area / (len(signals) or 1)
    return {"area_integral": area, "eta_global": eta}


def _minimax_select(state: AriaState) -> dict:
    """Von Neumann minimax over the signal payoff vector — upstream logic."""
    signals = {k: state.get(k, {}) for k in _SIGNAL_KEYS}
    scored = {
        k: float(v.get("intensity", 0.0)) if isinstance(v, dict) else 0.0
        for k, v in signals.items()
    }
    best = max(scored, key=scored.get) if scored else None
    worst = min(scored, key=scored.get) if scored else None
    return {"minimax_result": {"action": best, "hedge": worst, "scores": scored}}


def _witness(state: AriaState) -> dict:
    """Witness attestation — emit audit record — upstream logic."""
    mr = state.get("minimax_result", {})
    return {"witnessed": True, "audit_cid": "aria:" + str(mr.get("action", "none"))}


# ── Graph (identical topology to upstream) ──────────────────────────────────

_g = StateGraph(AriaState)
_g.add_node("ingest_all", _ingest_all)
_g.add_node("compute_area", _compute_area)
_g.add_node("minimax_select", _minimax_select)
_g.add_node("witness", _witness)
_g.add_edge(START, "ingest_all")
_g.add_edge("ingest_all", "compute_area")
_g.add_edge("compute_area", "minimax_select")
_g.add_edge("minimax_select", "witness")
_g.add_edge("witness", END)

compiled = _g.compile(checkpointer=KotobaCheckpointer())


# ── kotoba-node WIT export (boilerplate) ────────────────────────────────────

class WitWorld(wit_world.WitWorld):
    def run(self, ctx_cbor: bytes) -> bytes:
        return handle_invoke(ctx_cbor, compiled)
