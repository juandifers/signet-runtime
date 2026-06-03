"""Deterministic serialization and hashing.

For a production AP2 deployment you would use RFC 8785 JCS for canonical JSON.
For this PoC, sorted-keys + compact separators is deterministic and sufficient,
and we keep the seam (`canonical_json`) isolated so JCS can be swapped in later.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Produce a deterministic byte representation of a JSON-able object."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj: Any) -> str:
    """sha256 of the canonical JSON of an object, hex-encoded."""
    return sha256_hex(canonical_json(obj))
