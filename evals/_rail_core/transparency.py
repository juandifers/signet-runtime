"""Rail-AGNOSTIC, independently-verifiable, tamper-evident audit records — Step 3 promoted out of
the GitHub merge rail. Turn a per-decision receipt into an audit artifact an outside party can
verify WITHOUT trusting (or even reaching) the runtime. The structure is borrowed from RFC 6962
(Certificate Transparency) — a Merkle tree of leaves, a signed tree head, and audit-path
inclusion proofs — applied to enforcement decisions instead of certificates.

This whole module is rail-agnostic. The ONLY rail-specific input is which (effect_class, tier)
pairs count as "sensitive" (worth a proactively-surfaced proof) — supplied via `is_sensitive`'s
`protected_classes`/`sensitive_tiers` (a rail passes its own). The schema strings are
parameterized too, so a rail can keep a stable, namespaced record identity. Everything else —
the DecisionRecord shape, the Merkle primitives, the signed tree head, the inclusion proof, the
independent verifier, the anchor sink — is shared verbatim.

No kernel edits: the kernel `Receipt` schema is frozen. The structured record is bound into the
Merkle leaf alongside the receipt hash, so the receipt is certified without changing it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from signet import crypto
from signet.canonical import canonical_json, hash_obj, sha256_hex

RECORD_SCHEMA = "signet.decision_record.v1"
STH_SCHEMA = "signet.signed_tree_head.v1"

# Verdict vocabulary (mirrors the receipt decisions).
VERDICT_APPROVED = "approved"
VERDICT_BLOCKED = "blocked"
VERDICT_REVIEW = "review"


# ============================================================================
# A. The structured, enforcement-bound DecisionRecord
# ============================================================================
@dataclass(frozen=True)
class EffectDescriptor:
    """The concrete effect, as fields (not a jammed string). Field names read git-ish for legacy
    reasons but are loose: a rail maps its own binding fields onto them (deploy:
    target=service@env:digest/config, base=environment, head_sha=artifact_digest,
    touched_paths=(config_hash,) etc.)."""
    effect_class: str
    target: str
    base: str
    head_sha: str
    touched_paths: Tuple[str, ...]


@dataclass(frozen=True)
class ConsideredRejected:
    """A candidate considered and rejected (e.g. an injection attempt)."""
    pr: Optional[int]
    target: str
    cause: str                  # off-scope / protected / off-allowlist / ambiguous ...
    channel: str                # "resolver" | "injection"


@dataclass(frozen=True)
class DecisionRecord:
    """A canonical, enforcement-bound audit record. Hashed via `record_hash`; the hash is bound
    into a Merkle leaf and certified by the signed tree head."""
    schema: str
    repo_id: str
    open_mandate_id: str
    effect_class: str
    verdict: str                                  # approved | blocked | review
    cause: str
    tier: str
    sensitive: bool
    resolved_target: Optional[str]
    effect: Optional[EffectDescriptor]
    considered_rejected: Tuple[ConsideredRejected, ...]
    # --- binding to the ENFORCEMENT (the differentiator vs a passive audit log) ---
    chain_hash: str                               # the authorizer decision's chain_hash
    execution_id: str                             # the ExecutionToken's execution_id
    receipt_id: str
    # --- the (optional) hash-link to Role B's UNTRUSTED reasoning trace ---
    reasoning_trace_hash: Optional[str] = None

    def to_canonical(self) -> dict:
        d = asdict(self)
        if self.reasoning_trace_hash is None:
            d.pop("reasoning_trace_hash")
        return d

    def record_hash(self) -> str:
        return hash_obj(self.to_canonical())


def is_sensitive(effect_class: str, tier: str, *, protected_classes=(), sensitive_tiers=()) -> bool:
    """Reuse the rail's policy tier to decide what gets a proactively-surfaced proof: a protected
    effect class, or any tier in the rail's sensitive set (e.g. approve/cosign/deny). The rail
    supplies both sets; this is the ONLY rail-specific knob in the whole module."""
    return (effect_class in set(protected_classes)
            or tier in set(sensitive_tiers))


def build_decision_record(receipt, *, repo_id: str, open_mandate_id: str, verdict: str,
                          cause: str, tier: str, effect_class: str, sensitive: bool,
                          resolved_target: Optional[str] = None,
                          effect: Optional[EffectDescriptor] = None,
                          considered_rejected: Tuple[ConsideredRejected, ...] = (),
                          reasoning_trace_hash: Optional[str] = None,
                          schema: str = RECORD_SCHEMA) -> DecisionRecord:
    """Assemble a DecisionRecord from a signed kernel Receipt (the enforcement artifact) plus the
    decision context. chain_hash/execution_id/receipt_id come from the receipt, so the record
    certifies an ENFORCED decision (not a passive observation). The rail computes `sensitive`
    (via `is_sensitive` with its own sets) and may pass a namespaced `schema`."""
    return DecisionRecord(
        schema=schema, repo_id=repo_id, open_mandate_id=open_mandate_id,
        effect_class=effect_class, verdict=verdict, cause=cause, tier=tier,
        sensitive=sensitive,
        resolved_target=resolved_target, effect=effect,
        considered_rejected=tuple(considered_rejected),
        chain_hash=receipt.chain_hash, execution_id=receipt.execution_id,
        receipt_id=receipt.receipt_id, reasoning_trace_hash=reasoning_trace_hash)


def verify_receipt_binding(receipt, record: DecisionRecord) -> Tuple[bool, str]:
    """The intrinsic, in-receipt half of the binding: the signed kernel Receipt backlinks to THIS
    record via `decision_record_hash`, and identifies the same enforcement (receipt_id /
    chain_hash / execution_id). Tampering either side breaks it."""
    if getattr(receipt, "decision_record_hash", None) is None:
        return False, "receipt carries no decision_record_hash backlink"
    if receipt.decision_record_hash != record.record_hash():
        return False, "receipt backlink != record hash (record or receipt tampered)"
    if (receipt.receipt_id != record.receipt_id
            or receipt.chain_hash != record.chain_hash
            or receipt.execution_id != record.execution_id):
        return False, "receipt/record identify different enforcement"
    return True, "receipt intrinsically backlinks this record"


# ============================================================================
# A (cont). The reasoning-trace hash-link — commit to the HASH, store the content apart
# ============================================================================
TRACE_SCHEMA = "signet.reasoning_trace.v1"


def reasoning_trace_hash(trace: str) -> str:
    """Stable hash of Role B's reasoning narrative. The DecisionRecord commits to THIS value; the
    narrative text itself never enters the record, the Merkle leaf, or the anchor."""
    return hash_obj({"schema": TRACE_SCHEMA, "trace": str(trace or "")})


class ReasoningTraceStore:
    """A SEPARATE, mutable, deletable store of UNTRUSTED Role-B agent narrative.

    Deliberately NOT append-only and NOT in the Merkle tree: the trace is an aid to a human
    reviewer, not evidence. The tamper-EVIDENCE lives in the hash-link — the anchored
    DecisionRecord commits to `reasoning_trace_hash(trace)`, so if the stored text is later edited
    or deleted, `verify(h)` no longer matches the committed hash and the discrepancy is
    detectable."""

    def __init__(self) -> None:
        self._traces: Dict[str, str] = {}

    def put(self, trace: str) -> str:
        h = reasoning_trace_hash(trace)
        self._traces[h] = str(trace or "")
        return h

    def get(self, h: str) -> Optional[str]:
        return self._traces.get(h)

    def delete(self, h: str) -> None:
        self._traces.pop(h, None)

    def verify(self, h: str) -> Tuple[bool, str]:
        t = self._traces.get(h)
        if t is None:
            return False, "no trace stored under this hash (deleted or never stored)"
        if reasoning_trace_hash(t) != h:
            return False, "stored trace does not match its committed hash (tampered)"
        return True, "stored trace matches the committed hash"

    def __contains__(self, h: str) -> bool:
        return h in self._traces


# ============================================================================
# B. RFC 6962 Merkle primitives (domain-separated leaf/interior hashing)
# ============================================================================
def leaf_hash(receipt_hash: str, record_hash: str) -> str:
    """RFC 6962 leaf hash: SHA-256(0x00 || entry). The entry commits over BOTH the signed receipt
    hash (the enforcement) and the structured decision-record hash (the audit)."""
    entry = canonical_json({"receipt_hash": receipt_hash, "record_hash": record_hash})
    return sha256_hex(b"\x00" + entry)


def _node_hash(left_hex: str, right_hex: str) -> str:
    return sha256_hex(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def _largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: List[str]) -> str:
    n = len(leaves)
    if n == 0:
        return sha256_hex(b"")
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(m: int, leaves: List[str]) -> List[str]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        return audit_path(m, leaves[:k]) + [merkle_root(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [merkle_root(leaves[:k])]


def _root_from_path(m: int, n: int, leaf: str, path: List[str]) -> Optional[str]:
    if n <= 0 or m < 0 or m >= n:
        return None
    if n == 1:
        return leaf if not path else None
    if not path:
        return None
    k = _largest_pow2_below(n)
    sibling = path[-1]
    if m < k:
        left = _root_from_path(m, k, leaf, path[:-1])
        return _node_hash(left, sibling) if left is not None else None
    right = _root_from_path(m - k, n - k, leaf, path[:-1])
    return _node_hash(sibling, right) if right is not None else None


# ============================================================================
# B (cont). Signed tree head + inclusion proof + the INDEPENDENT verifier
# ============================================================================
@dataclass(frozen=True)
class SignedTreeHead:
    schema: str
    tree_size: int
    root_hash: str
    timestamp: str
    log_id: str
    signature: Optional[str] = None

    def signing_payload(self) -> bytes:
        return canonical_json({"schema": self.schema, "tree_size": self.tree_size,
                               "root_hash": self.root_hash, "timestamp": self.timestamp,
                               "log_id": self.log_id})


@dataclass(frozen=True)
class InclusionProof:
    leaf_index: int
    tree_size: int
    receipt_hash: str
    leaf_hash: str
    audit_path: Tuple[str, ...]


def verify_inclusion(record: DecisionRecord, proof: InclusionProof,
                     sth: SignedTreeHead, enforcer_vk: str) -> Tuple[bool, str]:
    """The function an auditor runs. Given ONLY (record, proof, signed tree head) and a pinned
    enforcer public key — no log, no live system, no trust in the runtime — confirm that `record`
    is committed under the signed root."""
    if proof.tree_size != sth.tree_size:
        return False, "proof tree_size != signed tree head tree_size"
    recomputed_leaf = leaf_hash(proof.receipt_hash, record.record_hash())
    if recomputed_leaf != proof.leaf_hash:
        return False, "leaf hash does not match the record (record tampered or wrong proof)"
    root = _root_from_path(proof.leaf_index, proof.tree_size, recomputed_leaf,
                           list(proof.audit_path))
    if root is None:
        return False, "audit path malformed for this (index, size)"
    if root != sth.root_hash:
        return False, "recomputed root != signed root (not included, or path forged)"
    if not sth.signature or not crypto.verify(enforcer_vk, sth.signing_payload(),
                                              sth.signature):
        return False, "signed tree head signature invalid"
    return True, "included: record is committed under the signed, enforcer-anchored root"


# ============================================================================
# C. AnchorSink — the swap seam for an external immutable anchor
# ============================================================================
class AnchorSink(ABC):
    @abstractmethod
    def anchor(self, sth: SignedTreeHead) -> str:
        ...

    @abstractmethod
    def latest(self) -> Optional[SignedTreeHead]:
        ...


class LocalAppendOnlyAnchor(AnchorSink):
    """Offline stub for an immutable external anchor: an append-only, monotonic store of signed
    roots. Refuses to anchor a tree SMALLER than the last (no rewinding history) and exposes no
    mutation — modelling WORM semantics without a network."""

    def __init__(self) -> None:
        self._roots: List[SignedTreeHead] = []
        self.locators: List[str] = []

    def anchor(self, sth: SignedTreeHead) -> str:
        if self._roots and sth.tree_size < self._roots[-1].tree_size:
            raise PermissionError(
                "anchor is append-only: refusing to anchor a smaller tree than the last")
        self._roots.append(sth)
        loc = f"anchor://local/{len(self._roots) - 1}"
        self.locators.append(loc)
        return loc

    def latest(self) -> Optional[SignedTreeHead]:
        return self._roots[-1] if self._roots else None

    def get(self, index: int) -> SignedTreeHead:
        return self._roots[index]

    def all(self) -> List[SignedTreeHead]:
        return list(self._roots)


# ============================================================================
# The rail-side transparency log (stores records keyed by execution_id / chain_hash)
# ============================================================================
@dataclass
class LogEntry:
    index: int
    record: DecisionRecord
    receipt_hash: str
    leaf_hash: str
    sensitive: bool


class TransparencyLog:
    """An append-only Merkle log of DecisionRecords, signed-headed by the enforcer key. Records
    are stored rail-side and indexed by execution_id and chain_hash. The whole root is anchored
    (per N entries and/or on demand) so every action is in the tree; sensitive actions
    additionally get a proactively-surfaced inclusion proof."""

    def __init__(self, enforcer_sk: str, enforcer_vk: str, *, log_id: str = "rail",
                 anchor_sink: Optional[AnchorSink] = None, anchor_every: Optional[int] = None,
                 clock=None, sth_schema: str = STH_SCHEMA) -> None:
        self._sk = enforcer_sk
        self._vk = enforcer_vk
        self.log_id = log_id
        self._sink = anchor_sink
        self._anchor_every = anchor_every
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._sth_schema = sth_schema
        self._entries: List[LogEntry] = []
        self._leaves: List[str] = []
        self._by_exec: Dict[str, int] = {}
        self._by_chain: Dict[str, int] = {}

    def append(self, record: DecisionRecord, *, receipt_hash: str) -> LogEntry:
        idx = len(self._entries)
        lh = leaf_hash(receipt_hash, record.record_hash())
        entry = LogEntry(idx, record, receipt_hash, lh, record.sensitive)
        self._entries.append(entry)
        self._leaves.append(lh)
        if record.execution_id:
            self._by_exec[record.execution_id] = idx
        if record.chain_hash:
            self._by_chain[record.chain_hash] = idx
        if self._anchor_every and self._sink and len(self._entries) % self._anchor_every == 0:
            self.seal_and_anchor()
        return entry

    def root_hash(self) -> str:
        return merkle_root(self._leaves)

    def size(self) -> int:
        return len(self._entries)

    def sign_root(self) -> SignedTreeHead:
        sth = SignedTreeHead(
            schema=self._sth_schema, tree_size=len(self._leaves), root_hash=self.root_hash(),
            timestamp=self._clock().isoformat(), log_id=self.log_id)
        sig = crypto.sign(self._sk, sth.signing_payload())
        return SignedTreeHead(schema=sth.schema, tree_size=sth.tree_size,
                              root_hash=sth.root_hash, timestamp=sth.timestamp,
                              log_id=sth.log_id, signature=sig)

    def inclusion_proof(self, index: int) -> InclusionProof:
        if not (0 <= index < len(self._leaves)):
            raise IndexError(f"no entry at index {index}")
        return InclusionProof(
            leaf_index=index, tree_size=len(self._leaves),
            receipt_hash=self._entries[index].receipt_hash, leaf_hash=self._leaves[index],
            audit_path=tuple(audit_path(index, self._leaves)))

    def proof_for_execution(self, execution_id: str) -> InclusionProof:
        return self.inclusion_proof(self._by_exec[execution_id])

    def proof_for_chain(self, chain_hash: str) -> InclusionProof:
        return self.inclusion_proof(self._by_chain[chain_hash])

    def surface_sensitive_proofs(self) -> Dict[int, InclusionProof]:
        return {e.index: self.inclusion_proof(e.index)
                for e in self._entries if e.sensitive}

    def seal_and_anchor(self) -> Tuple[SignedTreeHead, Optional[str]]:
        sth = self.sign_root()
        loc = self._sink.anchor(sth) if self._sink else None
        return sth, loc

    def entries(self) -> List[LogEntry]:
        return list(self._entries)
