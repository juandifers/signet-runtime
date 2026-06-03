"""Ed25519 signing primitives and an in-memory key registry.

PoC note: AP2's specification mandates ECDSA P-256 as the minimum curve for
mandate Verifiable Credentials. We use Ed25519 here because it is simple and
because XRPL wallets are Ed25519 by default, which keeps the two halves of the
demo consistent. The `sign`/`verify` seam is the only thing that would change
to become spec-faithful.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder


def generate_keypair() -> Tuple[str, str]:
    """Return (signing_key_hex, verify_key_hex)."""
    sk = SigningKey.generate()
    return (
        sk.encode(HexEncoder).decode(),
        sk.verify_key.encode(HexEncoder).decode(),
    )


def sign(signing_key_hex: str, message: bytes) -> str:
    sk = SigningKey(signing_key_hex.encode(), encoder=HexEncoder)
    return sk.sign(message).signature.hex()


def verify(verify_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        vk = VerifyKey(verify_key_hex.encode(), encoder=HexEncoder)
        vk.verify(message, bytes.fromhex(signature_hex))
        return True
    except Exception:
        return False


@dataclass
class KeyStore:
    """Maps an identity (e.g. principal_id) to its public verify key."""

    _keys: Dict[str, str] = field(default_factory=dict)

    def register(self, identity: str, verify_key_hex: str) -> None:
        self._keys[identity] = verify_key_hex

    def verify_key_for(self, identity: str) -> str | None:
        return self._keys.get(identity)
