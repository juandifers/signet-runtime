"""Bind ([D]): what a capability commits to, its lifecycle, and the freshness/TOCTOU re-check at
execution time.

`recheck` is the load-bearing hook — the gate that re-binds the capability to the runtime context
immediately before the door fires (the kernel context-bind for the effect-key rails). The BINDING
FIELDS are rail-specific (merge binds recipient/head_sha/base/diff; egress binds host+port and the
token's chain_hash), so the predicate content is INJECTED, exactly as `role_b` injects its gate
predicates. The framework owns the contract (recheck gates the door, and a raising predicate fails
CLOSED); the rail supplies which fields bind.

Variants:
  * EffectKeyOneShot — consume-once on chain_hash (the kernel mints + consumes); recheck == the
    kernel context-bind. Used by BOTH merge and egress.
  * InlineCapability — a capability consumed inline with no standing bearer token (no TOCTOU
    window); recheck defaults to pass-through unless a predicate is injected.
  * MeteredLedger — debit against an atomic aggregate (STUB: named, not built; the multi-instance
    atomic check-and-set is the production swap, see CLAUDE.md).
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .types import Capability, METERED, ONE_SHOT


class EffectKeyOneShot:
    """Consume-once binding keyed on the effect (chain_hash). `recheck_fn(cap, runtime_context)`
    is the kernel context-bind the rail supplies; it is called with the kernel token as `cap` and
    the ExecutionRequest as `runtime_context`. A raising predicate is caught -> False (FAIL-CLOSED)."""

    def __init__(self, recheck_fn: Callable[[Any, Any], bool],
                 commit_fn: Optional[Callable[[Any], Capability]] = None):
        self._recheck_fn = recheck_fn
        self._commit_fn = commit_fn

    def lifecycle(self) -> str:
        return ONE_SHOT

    def commit(self, effect) -> Capability:
        if self._commit_fn is not None:
            return self._commit_fn(effect)
        return Capability(effect=effect, lifecycle=ONE_SHOT)

    def recheck(self, cap, runtime_context) -> bool:
        try:
            return bool(self._recheck_fn(cap, runtime_context))
        except Exception:
            return False                                    # FAIL-CLOSED on a broken predicate


class InlineCapability:
    """A capability consumed inline (no standing bearer token to leak). One-shot lifecycle; recheck
    is a pass-through unless a freshness predicate is injected (then it fails closed on a raise)."""

    def __init__(self, recheck_fn: Optional[Callable[[Any, Any], bool]] = None):
        self._recheck_fn = recheck_fn

    def lifecycle(self) -> str:
        return ONE_SHOT

    def commit(self, effect) -> Capability:
        return Capability(effect=effect, lifecycle=ONE_SHOT, handle=None)

    def recheck(self, cap, runtime_context) -> bool:
        if self._recheck_fn is None:
            return True
        try:
            return bool(self._recheck_fn(cap, runtime_context))
        except Exception:
            return False


class MeteredLedger:
    """METERED binding: each commit debits an atomic aggregate ledger. STUB — the atomic
    multi-instance check-and-set is named, not built (the Redis/Postgres swap in CLAUDE.md). Safe to
    CONSTRUCT (so a Composition can name it); calling commit/recheck raises until the ledger exists."""

    def __init__(self, *, ledger: str = "metered-ledger(unbuilt)"):
        self._ledger = ledger

    def lifecycle(self) -> str:
        return METERED

    def commit(self, effect) -> Capability:                # pragma: no cover - stub
        raise NotImplementedError(
            "MeteredLedger.commit needs the atomic multi-instance ledger (named, not built)")

    def recheck(self, cap, runtime_context) -> bool:       # pragma: no cover - stub
        raise NotImplementedError(
            "MeteredLedger.recheck needs the atomic multi-instance ledger (named, not built)")
