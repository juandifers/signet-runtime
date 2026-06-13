# Signet egress receipt — wire format contract (v1)

This document specifies, byte-for-byte, the receipt the standalone verifier
(`verify/verify.py`) consumes. It is the **only** coupling between the verifier and
Signet: the verifier imports no Signet code, it reimplements every check from this
document. A second person should be able to write an independent verifier from this
file alone and reach the same VERIFIED / FAILED verdict on the same inputs.

The hashing and proof conventions are taken verbatim from Signet's Merkle log
(`evals/_rail_core/transparency.py`) and its canonical serializer
(`signet/canonical.py`). The receipt *content* schema (the egress effect, the
`payload_commitment`, the structured `policy_basis`) is new — it is the part this
verifier pins down, because the existing egress decision path records only a free-text
cause in a non-anchored local log (see the PR's Stage-0 findings).

---

## 1. Hashing conventions (RFC 6962 style)

All Merkle-layer hashes are SHA-256, hex-encoded lowercase, 64 chars.

```
canonical_bytes(obj) = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8")

leaf_hash      = SHA-256( 0x00 || canonical_bytes(leaf_contents) )
node_hash(L,R) = SHA-256( 0x01 || L || R )          # L, R are raw 32-byte digests
```

- **Domain separation is mandatory.** Leaves are prefixed with the single byte `0x00`,
  interior nodes with `0x01`. This is RFC 6962 §2.1 and defends against
  second-preimage confusion between a leaf and an interior node.
- **Canonicalization** is sorted-key, comma/colon-tight JSON, UTF-8, `ensure_ascii=False`.
  Receipt content is restricted to JSON strings, integers, and `null` — no floats, no
  NaN/Infinity, no map-ordering ambiguity. This is what makes independent re-hashing of
  the leaf contents reproducible.

## 2. Merkle tree shape and the inclusion proof

The tree is the RFC 6962 binary Merkle tree over an ordered list of `n` leaf hashes:

```
MTH([d0])            = d0                                  # single leaf: root == leaf
MTH(leaves), n > 1   = node_hash( MTH(leaves[:k]), MTH(leaves[k:]) )
                       where k = largest power of two strictly less than n
```

An **inclusion proof** for the leaf at index `m` in a tree of size `n` is the ordered
list of sibling hashes, **bottom-up** (the sibling closest to the leaf first, the
top-most sibling last). The side of each sibling is **not** stored — it is recomputed
from `(m, n)` by the same largest-power-of-two split. The reference walk:

```
root_from_proof(leaf, m, n, path):
    if n <= 0 or m < 0 or m >= n: FAIL          # index out of range
    if n == 1: return leaf if path == [] else FAIL
    if path == []: FAIL                          # ran out of siblings before the root
    k = largest power of two < n
    sibling = path[-1]                           # top-most sibling consumed first
    if m < k:  return node_hash( root_from_proof(leaf,   m,     k,   path[:-1]), sibling )
    else:      return node_hash( sibling, root_from_proof(leaf, m-k, n-k, path[:-1]) )
```

The implementation in `verify.py` is validated against known-answer test vectors before
it is trusted (`tests/test_receipt_verifier.py::test_root_from_proof_known_answer_vectors`).

## 3. Receipt JSON schema

A receipt is a single self-contained JSON object. **Every** field below is required;
a missing, extra, or wrong-typed field is a loud FAILED, never a silent pass.

```json
{
  "decision": "DENY",
  "effect": {
    "class": "egress",
    "destination": "attacker.example:443",
    "payload_commitment": "sha256:9f3c…(64 hex)",
    "session_id": "run_2026_06_13_001",
    "timestamp": "2026-06-13T00:00:00Z"
  },
  "policy_basis": {
    "layer": "standing",
    "axis": "egress_destination",
    "rule": "destination not in operator standing allow-set",
    "learned_rule_id": null
  },
  "leaf":  { "leaf_hash": "<64 hex>" },
  "inclusion_proof": {
    "leaf_index": 4,
    "tree_size": 6,
    "audit_path": ["<64 hex>", "<64 hex>", "<64 hex>"]
  },
  "claimed_root": "<64 hex>"
}
```

Field rules:

| field | type | rule |
|---|---|---|
| `decision` | string | `"DENY"` or `"ALLOW"`. Must equal the verifier's expected mode. |
| `effect.class` | string | must be `"egress"`. |
| `effect.destination` | string | non-empty; the bound destination (`host:port`) or attempted URL. |
| `effect.payload_commitment` | string | **must** match `^sha256:[0-9a-f]{64}$`. A value that looks like raw data is refused — the receipt commits to a hash of the payload, never the payload. |
| `effect.session_id` | string | non-empty. |
| `effect.timestamp` | string | non-empty (ISO-8601 by convention; not parsed). |
| `policy_basis.layer` | string | `"standing"` or `"learned"`. |
| `policy_basis.axis` | string | the fence axis (e.g. `"egress_destination"`). |
| `policy_basis.rule` | string | human-readable rule description. |
| `policy_basis.learned_rule_id` | string or null | `null` ⟺ `layer == "standing"`. A non-null id ⟺ `layer == "learned"`. |
| `leaf.leaf_hash` | hex string | recomputed and cross-checked; see §4. |
| `inclusion_proof.leaf_index` | int | `0 ≤ leaf_index < tree_size`. |
| `inclusion_proof.tree_size` | int | `≥ 1`. |
| `inclusion_proof.audit_path` | list of hex strings | bottom-up siblings (§2). |
| `claimed_root` | hex string | the root the receipt claims; checked against the supplied anchor. |

Hash strings: Merkle-layer fields (`leaf_hash`, `audit_path[]`, `claimed_root`, and the
anchor argument) are bare 64-char lowercase hex; an optional `sha256:` prefix is
tolerated and stripped. `payload_commitment` **must** carry the `sha256:` prefix (it is
the marker that distinguishes a commitment from raw data).

## 4. The leaf contents (what the leaf commits to)

The leaf is hashed over exactly this object, with keys in this order *before*
canonicalization (canonicalization re-sorts them, so the order here is informative):

```
leaf_contents = { "decision": <decision>,
                  "effect": <the entire effect object, verbatim>,
                  "policy_basis": <the entire policy_basis object, verbatim> }
leaf_hash     = SHA-256( 0x00 || canonical_bytes(leaf_contents) )
```

The verifier rebuilds `leaf_contents` from the receipt's own `decision`, `effect`, and
`policy_basis` fields, recomputes `leaf_hash`, and requires it to equal the stored
`leaf.leaf_hash`. This is the binding: it proves the receipt is not lying about *what*
was committed (changing the destination, the payload commitment, or the basis changes
the leaf hash). `session_id` and `timestamp` live inside `effect`, so they are bound too.

## 5. Verdict (what is attested, and what is not)

The verifier prints **VERIFIED** (exit 0) only if, in order, all hold:

1. structural parse (§3),
2. `decision` equals the expected mode (DENY by default, ALLOW with `--allow`),
3. `effect.class == "egress"` and `destination` present,
4. `payload_commitment` is a commitment, not raw data,
5. recomputed `leaf_hash` == stored `leaf.leaf_hash`,
6. `root_from_proof(leaf_hash, proof)` == `claimed_root`,
7. `claimed_root` == supplied anchor root.

The **strong operator-ceiling attestation** ("denied by the part of the fence no
approval could move") is printed only when additionally `policy_basis.layer == "standing"`
and `learned_rule_id is null`. When the basis is a learned rule, inclusion still
VERIFIES, but the verdict states the weaker fact: the decision rests on a learned rule
and could be moved by an approval — it is **not** the operator ceiling.

The verdict attests only the bounded fact: *this effect, this decision, on this basis,
is present and unaltered in a tree whose root equals the supplied anchor.* It never
claims "Signet is secure" or "the attack was contained" — that story is assembled by a
human from this fact plus the observed compromise plus the allowed-legitimate control.
```
