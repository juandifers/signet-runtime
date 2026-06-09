"""Independently-verifiable, tamper-evident audit records for the GitHub MERGE rail.

The whole RFC-6962 Merkle machinery (DecisionRecord shape, signed tree head, inclusion proof,
the independent verifier, the anchor sink, the reasoning-trace hash-link) is rail-AGNOSTIC and
lives in `evals/_rail_core/transparency.py` — reused unchanged by every rail. What is
GitHub-shaped, and stays here, is exactly ONE knob: which (effect_class, tier) pairs count as
"sensitive" (protected merges + non-auto tiers). This module binds that knob and keeps the
GitHub-namespaced schema strings so merge-rail records stay self-describing.

No kernel edits: the kernel `Receipt` schema is frozen.
"""
from __future__ import annotations

from typing import Optional, Tuple

# Re-export the rail-agnostic core surface (the tests + mandate import these by name).
from evals._rail_core.transparency import (  # noqa: F401
    AnchorSink, ConsideredRejected, DecisionRecord, EffectDescriptor, InclusionProof, LogEntry,
    LocalAppendOnlyAnchor, ReasoningTraceStore, SignedTreeHead, TransparencyLog as _CoreLog,
    VERDICT_APPROVED, VERDICT_BLOCKED, VERDICT_REVIEW, audit_path, is_sensitive as _core_sensitive,
    leaf_hash, merkle_root, reasoning_trace_hash, verify_inclusion, verify_receipt_binding,
    build_decision_record as _core_build_record)

from .domain import EFFECT_MERGE_PROTECTED
from .policy import TIER_APPROVE, TIER_COSIGN, TIER_DENY

# GitHub-namespaced schema identities (keep the merge rail's record/STH namespace stable).
RECORD_SCHEMA = "signet.github.decision_record.v1"
STH_SCHEMA = "signet.github.signed_tree_head.v1"

# The merge rail's "sensitive" knob: a protected effect class, or any non-auto tier.
_PROTECTED_CLASSES = (EFFECT_MERGE_PROTECTED,)
_SENSITIVE_TIERS = (TIER_APPROVE, TIER_COSIGN, TIER_DENY)


def is_sensitive(effect_class: str, tier: str) -> bool:
    """Reuse the policy tier to decide what gets a proactively-surfaced proof, with the merge
    rail's protected/sensitive sets bound in."""
    return _core_sensitive(effect_class, tier, protected_classes=_PROTECTED_CLASSES,
                           sensitive_tiers=_SENSITIVE_TIERS)


def build_decision_record(receipt, *, repo_id: str, open_mandate_id: str, verdict: str,
                          cause: str, tier: str, effect_class: str,
                          resolved_target: Optional[str] = None,
                          effect: Optional[EffectDescriptor] = None,
                          considered_rejected: Tuple[ConsideredRejected, ...] = (),
                          reasoning_trace_hash: Optional[str] = None) -> DecisionRecord:
    """Assemble a merge-rail DecisionRecord — computes `sensitive` with the merge rail's sets and
    stamps the GitHub-namespaced schema, then delegates to the shared core builder."""
    return _core_build_record(
        receipt, repo_id=repo_id, open_mandate_id=open_mandate_id, verdict=verdict, cause=cause,
        tier=tier, effect_class=effect_class, sensitive=is_sensitive(effect_class, tier),
        resolved_target=resolved_target, effect=effect, considered_rejected=considered_rejected,
        reasoning_trace_hash=reasoning_trace_hash, schema=RECORD_SCHEMA)


class TransparencyLog(_CoreLog):
    """The merge rail's Merkle log — defaults the log id + STH schema to GitHub's namespace."""

    def __init__(self, enforcer_sk: str, enforcer_vk: str, *, log_id: str = "github-rail",
                 anchor_sink: Optional[AnchorSink] = None, anchor_every: Optional[int] = None,
                 clock=None) -> None:
        super().__init__(enforcer_sk, enforcer_vk, log_id=log_id, anchor_sink=anchor_sink,
                         anchor_every=anchor_every, clock=clock, sth_schema=STH_SCHEMA)
