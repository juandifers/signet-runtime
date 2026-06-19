# Egress log anchor

This directory holds the **published Merkle root** of the egress decision log — and only the
root. Receipts and leaf contents are never published here (leaf contents stay private; see
`verify/RECEIPT_FORMAT.md`). A verifier is handed `root.txt` out of band and checks a receipt's
inclusion against it (`python verify/verify.py <receipt.json> --anchor anchor/root.txt`).

## What `root.txt` is

`root.txt` is the RFC-6962 Merkle root over all egress decision leaves recorded in one run,
computed by `evals/egress_receipts/anchor_publish.publish_root` after the run completes.

## Anchoring strength (v1 — public git commit)

The anchor is the **git commit that adds/updates `root.txt`, plus its timestamp, in a public
repository**. Concretely:

> The root is committed to a public repo at time *T*. Forging a receipt's membership in the log
> after *T* would require rewriting already-pushed git history (and convincing every clone/mirror
> of the rewrite). The commit is a cheap, human-auditable timestamped commitment to the root.

Limits, stated honestly: this is only as strong as the hosting platform's resistance to history
rewriting, and the timestamp is the platform's, not a trustless one. It defends against
*post-hoc* equivocation (changing what the log said after publishing), not against an operator who
publishes a dishonest root in the first place.

The actual `git push` is a **human last-mile** — `publish_root` writes the file and prints the
exact commit command; it does not push (pushing is outward-facing and not auto-run).

## Upgrade (unimplemented): OpenTimestamps / Bitcoin

`anchor_publish.opentimestamps_hook` is a marked, unimplemented hook. The upgrade submits the root
to an OpenTimestamps calendar, yielding a `.ots` receipt that anchors the root in the Bitcoin
blockchain — a **trustless** timestamp that replaces "trust the git host not to rewrite history"
with a chain-backed proof. No code path depends on it; it is a documented future swap.

## Independence from the egress path

Anchoring runs strictly **after** a run. The egress decision and its leaf commitment are final
before this step exists, and egress never waits on or fails because of an anchor target
(see `evals/egress_receipts/chokepoint.py`).
