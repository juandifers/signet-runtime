"""Independently-verifiable, tamper-evident audit records for the GitHub merge rail.

This is Step 3: turn the per-decision receipt into an audit artifact an outside party can
verify WITHOUT trusting (or even reaching) the runtime. The structure is borrowed from
RFC 6962 (Certificate Transparency) — a Merkle tree of leaves, a signed tree head, and
audit-path inclusion proofs — applied to enforcement decisions instead of certificates.

Three layers, agentdojo-free + offline + deterministic:

  A. DecisionRecord  — the audit semantics as REAL canonical fields (effect, mandate,
       resolved target, verdict, cause, considered-and-rejected). It is bound to the
       ENFORCEMENT, not just an observation: it references the ExecutionToken's chain_hash
       + execution_id and the signed kernel Receipt's hash. A record certifies a decision
       that was *enforced*, which is what distinguishes this from a passive audit log.

  B. Merkle layer    — each leaf commits over (receipt_hash, decision_record_hash) with the
       RFC 6962 leaf prefix 0x00; interior nodes use 0x01 || left || right; the tree split
       is the RFC 6962 shape (largest power of two below n on the left). The tree head is
       signed with the existing enforcer key (no new key). `verify_inclusion(record, proof,
       signed_root, enforcer_vk)` recomputes the leaf from the record alone and walks the
       audit path to the root — it needs nothing but its three arguments and a pinned key.

  C. Anchoring + tiering — `AnchorSink` is the swap seam for an external immutable anchor;
       `LocalAppendOnlyAnchor` is an offline stub (append-only, monotonic signed roots) that
       simulates S3-Object-Lock / a ledger / Rekor. The whole root is anchored on a cadence,
       so every action is in the tree. Sensitive actions (protected effect class, or a
       cosign/deny/approve tier — reusing the policy tier) get a proactively-surfaced
       inclusion proof + a `sensitive` flag; ordinary actions get the tree entry without a
       surfaced proof.

No kernel edits: the kernel `Receipt` schema is frozen. The structured record is bound into
the Merkle leaf alongside the receipt hash, so the receipt is certified without changing it.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from signet import crypto
from signet.canonical import canonical_json, hash_obj, sha256_hex

from .domain import EFFECT_MERGE_PROTECTED
from .policy import TIER_APPROVE, TIER_COSIGN, TIER_DENY

RECORD_SCHEMA = "signet.github.decision_record.v1"
STH_SCHEMA = "signet.github.signed_tree_head.v1"

# Verdict vocabulary (mirrors the receipt decisions).
VERDICT_APPROVED = "approved"
VERDICT_BLOCKED = "blocked"
VERDICT_REVIEW = "review"


# ============================================================================
# A. The structured, enforcement-bound DecisionRecord
# ============================================================================
@dataclass(frozen=True)
class EffectDescriptor:
    """The concrete merge effect, as fields (not a jammed string)."""
    effect_class: str
    target: str                 # repo#pr->base@head_sha
    base: str
    head_sha: str
    touched_paths: Tuple[str, ...]


@dataclass(frozen=True)
class ConsideredRejected:
    """A candidate considered and rejected (e.g. the #99 injection attempt)."""
    pr: Optional[int]
    target: str
    cause: str                  # off-scope / protected / off-allowlist / ambiguous ...
    channel: str                # "resolver" | "injection"


@dataclass(frozen=True)
class DecisionRecord:
    """A canonical, enforcement-bound audit record. Hashed via `record_hash`; the hash is
    bound into a Merkle leaf and certified by the signed tree head."""
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
    # The record identifies the signed kernel Receipt by its STABLE ids (receipt_id +
    # chain_hash + execution_id), NOT by the receipt's hash. That is deliberate: the receipt
    # now carries a backlink (`decision_record_hash`) to THIS record, so embedding the
    # receipt_hash here too would make the two hashes mutually recursive. The receipt_hash
    # used to build the Merkle leaf travels in the InclusionProof instead.
    chain_hash: str                               # the authorizer decision's chain_hash
    execution_id: str                             # the ExecutionToken's execution_id
    receipt_id: str
    # --- the (optional) hash-link to Role B's UNTRUSTED reasoning trace (Q3) ---
    # When a real-LLM resolver picked the target, this commits to the HASH of its reasoning
    # narrative. The trace CONTENT lives in a separate, mutable/deletable store
    # (`ReasoningTraceStore`); only this hash enters the record -> the Merkle leaf -> the
    # anchor. Optional + dropped from the canonical form when None, so deterministic-resolver
    # records (no trace) hash byte-identically to before — existing proofs are unchanged.
    reasoning_trace_hash: Optional[str] = None

    def to_canonical(self) -> dict:
        d = asdict(self)
        if self.reasoning_trace_hash is None:
            d.pop("reasoning_trace_hash")
        return d

    def record_hash(self) -> str:
        return hash_obj(self.to_canonical())


def is_sensitive(effect_class: str, tier: str) -> bool:
    """Reuse the policy tier to decide what gets a proactively-surfaced proof: a protected
    effect class, or any non-auto tier (approve/cosign/deny)."""
    return (effect_class == EFFECT_MERGE_PROTECTED
            or tier in (TIER_APPROVE, TIER_COSIGN, TIER_DENY))


def build_decision_record(receipt, *, repo_id: str, open_mandate_id: str, verdict: str,
                          cause: str, tier: str, effect_class: str,
                          resolved_target: Optional[str] = None,
                          effect: Optional[EffectDescriptor] = None,
                          considered_rejected: Tuple[ConsideredRejected, ...] = (),
                          reasoning_trace_hash: Optional[str] = None) -> DecisionRecord:
    """Assemble a DecisionRecord from a signed kernel Receipt (the enforcement artifact) plus
    the decision context. chain_hash/execution_id/receipt_id come from the receipt — for an
    approved merge the receipt carries the ExecutionToken's chain_hash + execution_id, so the
    record certifies an ENFORCED decision (not a passive observation).

    `reasoning_trace_hash` (optional) hash-links Role B's untrusted narrative WITHOUT putting
    its content in the record/leaf/anchor; omit it (None) for the deterministic resolver and
    the record hashes exactly as before."""
    return DecisionRecord(
        schema=RECORD_SCHEMA, repo_id=repo_id, open_mandate_id=open_mandate_id,
        effect_class=effect_class, verdict=verdict, cause=cause, tier=tier,
        sensitive=is_sensitive(effect_class, tier),
        resolved_target=resolved_target, effect=effect,
        considered_rejected=tuple(considered_rejected),
        chain_hash=receipt.chain_hash, execution_id=receipt.execution_id,
        receipt_id=receipt.receipt_id, reasoning_trace_hash=reasoning_trace_hash)


def verify_receipt_binding(receipt, record: DecisionRecord) -> Tuple[bool, str]:
    """The intrinsic, in-receipt half of the binding (Task 0): the signed kernel Receipt
    backlinks to THIS record via `decision_record_hash`, and identifies the same enforcement
    (receipt_id / chain_hash / execution_id). Tampering either side breaks it."""
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
# A (cont). The reasoning-trace hash-link (Q3) — commit to the HASH, store the content apart
# ============================================================================
TRACE_SCHEMA = "signet.github.reasoning_trace.v1"


def reasoning_trace_hash(trace: str) -> str:
    """Stable hash of Role B's reasoning narrative. The DecisionRecord commits to THIS value;
    the narrative text itself never enters the record, the Merkle leaf, or the anchor."""
    return hash_obj({"schema": TRACE_SCHEMA, "trace": str(trace or "")})


class ReasoningTraceStore:
    """A SEPARATE, mutable, deletable store of UNTRUSTED Role-B agent narrative.

    Deliberately NOT append-only and NOT in the Merkle tree: the trace is an aid to a human
    reviewer, not evidence. The tamper-EVIDENCE lives in the hash-link — the anchored
    DecisionRecord commits to `reasoning_trace_hash(trace)`, so if the stored text is later
    edited or deleted, `verify(h)` no longer matches the committed hash and the discrepancy is
    detectable. You can redact/delete a trace here freely without disturbing any inclusion
    proof; you simply lose the ability to re-derive the committed hash from the stored text.
    """

    def __init__(self) -> None:
        self._traces: Dict[str, str] = {}

    def put(self, trace: str) -> str:
        """Store a trace under its content hash; return the hash (the value the record commits
        to). Idempotent for identical content."""
        h = reasoning_trace_hash(trace)
        self._traces[h] = str(trace or "")
        return h

    def get(self, h: str) -> Optional[str]:
        return self._traces.get(h)

    def delete(self, h: str) -> None:
        self._traces.pop(h, None)

    def verify(self, h: str) -> Tuple[bool, str]:
        """True iff a trace is stored under `h` AND it still hashes to `h`. Editing the stored
        content (tampering) or deleting it breaks the match — the hash-link is tamper-evident."""
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
    """RFC 6962 leaf hash: SHA-256(0x00 || entry). The entry commits over BOTH the signed
    receipt hash (the enforcement) and the structured decision-record hash (the audit)."""
    entry = canonical_json({"receipt_hash": receipt_hash, "record_hash": record_hash})
    return sha256_hex(b"\x00" + entry)


def _node_hash(left_hex: str, right_hex: str) -> str:
    """RFC 6962 interior node: SHA-256(0x01 || left || right)."""
    return sha256_hex(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def _largest_pow2_below(n: int) -> int:
    """Largest power of two strictly less than n (n > 1). The RFC 6962 split point."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def merkle_root(leaves: List[str]) -> str:
    """RFC 6962 Merkle Tree Hash over a list of leaf hashes."""
    n = len(leaves)
    if n == 0:
        return sha256_hex(b"")          # MTH({}) = SHA-256() of the empty string
    if n == 1:
        return leaves[0]
    k = _largest_pow2_below(n)
    return _node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(m: int, leaves: List[str]) -> List[str]:
    """RFC 6962 PATH(m, D[n]): the sibling hashes from the leaf's level up to the root,
    deepest sibling first. Reveals only sibling hashes — nothing about other entries."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        return audit_path(m, leaves[:k]) + [merkle_root(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [merkle_root(leaves[:k])]


def _root_from_path(m: int, n: int, leaf: str, path: List[str]) -> Optional[str]:
    """Recompute the root from a leaf hash + its audit path (the verifier's half). Mirrors
    `audit_path` exactly; needs only (m, n, leaf, path) — no tree, no other leaves."""
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
    """An RFC-6962-style signed tree head (STH): the root over `tree_size` leaves, signed by
    the enforcer. This is the only thing an auditor must trust (against a pinned public key)."""
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
    """Minimal disclosure: a leaf index, the tree size, the receipt hash + leaf hash for the
    proven entry, and the sibling-hash audit path. Carries no OTHER records — only hashes.
    `receipt_hash` is the one the leaf commits over (alongside the record hash); it lets the
    verifier recompute the leaf from the record without the record embedding it (which would
    be recursive with the receipt's backlink)."""
    leaf_index: int
    tree_size: int
    receipt_hash: str
    leaf_hash: str
    audit_path: Tuple[str, ...]


def verify_inclusion(record: DecisionRecord, proof: InclusionProof,
                     sth: SignedTreeHead, enforcer_vk: str) -> Tuple[bool, str]:
    """The function an auditor runs. Given ONLY (record, proof, signed tree head) and a
    pinned enforcer public key — no log, no live system, no trust in the runtime — confirm
    that `record` is committed under the signed root.

    Recomputes the leaf from the record itself (so tampering any field breaks it), walks the
    audit path to a root, checks it equals the STH root, and verifies the STH signature.
    """
    # 1. The proof's tree size must match the signed tree head it's offered against.
    if proof.tree_size != sth.tree_size:
        return False, "proof tree_size != signed tree head tree_size"
    # 2. Recompute the leaf from the record's own hash + the proof's receipt_hash (do not
    #    trust the proof's stated leaf_hash). Tampering ANY record field changes record_hash
    #    -> the leaf no longer matches -> the path will not reach the signed root.
    recomputed_leaf = leaf_hash(proof.receipt_hash, record.record_hash())
    if recomputed_leaf != proof.leaf_hash:
        return False, "leaf hash does not match the record (record tampered or wrong proof)"
    # 3. Walk the audit path to a candidate root.
    root = _root_from_path(proof.leaf_index, proof.tree_size, recomputed_leaf,
                           list(proof.audit_path))
    if root is None:
        return False, "audit path malformed for this (index, size)"
    if root != sth.root_hash:
        return False, "recomputed root != signed root (not included, or path forged)"
    # 4. The signed tree head must carry a valid enforcer signature.
    if not sth.signature or not crypto.verify(enforcer_vk, sth.signing_payload(),
                                              sth.signature):
        return False, "signed tree head signature invalid"
    return True, "included: record is committed under the signed, enforcer-anchored root"


# ============================================================================
# C. AnchorSink — the swap seam for an external immutable anchor
# ============================================================================
class AnchorSink(ABC):
    """Where a signed tree head is anchored so it cannot later be disavowed. Production
    targets: S3 Object Lock (WORM), a public ledger, or a Rekor transparency log — each a
    drop-in replacement for the local stub below."""

    @abstractmethod
    def anchor(self, sth: SignedTreeHead) -> str:
        """Persist the STH immutably; return an external locator. MUST be append-only."""

    @abstractmethod
    def latest(self) -> Optional[SignedTreeHead]:
        ...


class LocalAppendOnlyAnchor(AnchorSink):
    """Offline stub for an immutable external anchor: an append-only, monotonic store of
    signed roots. Refuses to anchor a tree SMALLER than the last (no rewinding history) and
    exposes no mutation — modelling WORM semantics without a network."""

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
    """An append-only Merkle log of DecisionRecords, signed-headed by the enforcer key.

    Records are stored rail-side and indexed by execution_id and chain_hash. The whole root
    is anchored (per N entries and/or on demand) so every action is in the tree; sensitive
    actions additionally get a proactively-surfaced inclusion proof.
    """

    def __init__(self, enforcer_sk: str, enforcer_vk: str, *, log_id: str = "github-rail",
                 anchor_sink: Optional[AnchorSink] = None, anchor_every: Optional[int] = None,
                 clock=None) -> None:
        self._sk = enforcer_sk
        self._vk = enforcer_vk
        self.log_id = log_id
        self._sink = anchor_sink
        self._anchor_every = anchor_every
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._entries: List[LogEntry] = []
        self._leaves: List[str] = []
        self._by_exec: Dict[str, int] = {}
        self._by_chain: Dict[str, int] = {}

    # -- append --
    def append(self, record: DecisionRecord, *, receipt_hash: str) -> LogEntry:
        """Append a DecisionRecord. `receipt_hash` is the signed kernel Receipt's hash that
        the leaf commits over alongside the record hash (binds the enforcement artifact)."""
        idx = len(self._entries)
        lh = leaf_hash(receipt_hash, record.record_hash())
        entry = LogEntry(idx, record, receipt_hash, lh, record.sensitive)
        self._entries.append(entry)
        self._leaves.append(lh)
        if record.execution_id:
            self._by_exec[record.execution_id] = idx
        if record.chain_hash:
            self._by_chain[record.chain_hash] = idx
        # Anchor on a per-N-entries cadence if configured.
        if self._anchor_every and self._sink and len(self._entries) % self._anchor_every == 0:
            self.seal_and_anchor()
        return entry

    # -- tree head --
    def root_hash(self) -> str:
        return merkle_root(self._leaves)

    def size(self) -> int:
        return len(self._entries)

    def sign_root(self) -> SignedTreeHead:
        sth = SignedTreeHead(
            schema=STH_SCHEMA, tree_size=len(self._leaves), root_hash=self.root_hash(),
            timestamp=self._clock().isoformat(), log_id=self.log_id)
        sig = crypto.sign(self._sk, sth.signing_payload())
        return SignedTreeHead(schema=sth.schema, tree_size=sth.tree_size,
                              root_hash=sth.root_hash, timestamp=sth.timestamp,
                              log_id=sth.log_id, signature=sig)

    # -- proofs --
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
        """Proactively emit inclusion proofs for sensitive entries (protected effect class /
        non-auto tier). Ordinary entries are in the tree but get no surfaced proof."""
        return {e.index: self.inclusion_proof(e.index)
                for e in self._entries if e.sensitive}

    # -- anchoring --
    def seal_and_anchor(self) -> Tuple[SignedTreeHead, Optional[str]]:
        """Sign the current root and anchor it immutably (whole tree -> every action covered).
        Returns the STH and the anchor locator (None if no sink is configured)."""
        sth = self.sign_root()
        loc = self._sink.anchor(sth) if self._sink else None
        return sth, loc

    def entries(self) -> List[LogEntry]:
        return list(self._entries)
