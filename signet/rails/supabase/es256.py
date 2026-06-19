"""ES256 (ECDSA P-256) JWT minting + verification for the Supabase rail.

Supabase verifies asymmetric JWTs with ES256: a private signing key mints the JWT, a JWKS
public key verifies it. This module is the rail's crypto seam — deliberately OUTSIDE the
kernel `signet/crypto.py` (which is Ed25519 and frozen). Wiring the broker to a real project
means configuring `Es256Key` from the project's JWT signing key.

Determinism note: `verify_jwt` takes an explicit `now` and checks `exp` MANUALLY (PyJWT's
own exp check reads wall-clock and can't be injected). This lets the expiry test (#5) be
deterministic and offline while still doing a REAL ES256 signature verification.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ...canonical import sha256_hex

ALG = "ES256"


class Es256Error(Exception):
    """Verification failed (bad signature, expired, malformed, wrong key)."""


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


@dataclass
class Es256Key:
    """A broker-held EC P-256 signing key. The PRIVATE key never leaves the broker; callers
    that verify receive only `jwks()` (the public half) — echoing the receipt property:
    a capability is verifiable without the issuer online."""

    _private: ec.EllipticCurvePrivateKey

    # -- construction --
    @classmethod
    def generate(cls) -> "Es256Key":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_pem(cls, pem: bytes, password: Optional[bytes] = None) -> "Es256Key":
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise Es256Error("PEM is not an EC private key")
        return cls(key)

    def private_pem(self) -> bytes:
        return self._private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    # -- a stable key id over the public point (so JWKS rotation is expressible) --
    def kid(self) -> str:
        raw = self._private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return sha256_hex(raw)[:16]

    # -- mint --
    def mint_jwt(self, claims: dict, *, now: Optional[_dt.datetime] = None,
                 ttl_seconds: int = 60) -> str:
        """Mint a short-lived ES256 JWT. `iat`/`exp` are stamped from `now` (the broker's
        verifier-authoritative clock), not the caller's word."""
        now = now or _utcnow()
        iat = int(now.timestamp())
        payload = dict(claims)
        payload.setdefault("iat", iat)
        payload.setdefault("exp", iat + ttl_seconds)
        return jwt.encode(payload, self.private_pem(), algorithm=ALG,
                          headers={"kid": self.kid()})

    # -- public material for verification --
    def public_jwk(self) -> dict:
        nums = self._private.public_key().public_numbers()
        import base64

        def b64u(i: int) -> str:
            b = i.to_bytes(32, "big")
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

        return {"kty": "EC", "crv": "P-256", "alg": ALG, "use": "sig",
                "kid": self.kid(), "x": b64u(nums.x), "y": b64u(nums.y)}

    def jwks(self) -> dict:
        return {"keys": [self.public_jwk()]}


def _pubkey_from_jwk(jwk: dict) -> ec.EllipticCurvePublicKey:
    import base64

    def b64u_int(s: str) -> int:
        pad = "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")

    nums = ec.EllipticCurvePublicNumbers(b64u_int(jwk["x"]), b64u_int(jwk["y"]),
                                         ec.SECP256R1())
    return nums.public_key()


def verify_jwt(token: str, jwks: dict, *, now: Optional[_dt.datetime] = None) -> dict:
    """Verify an ES256 JWT against a JWKS and check exp against `now`. Returns the claims.
    Raises `Es256Error` on bad signature, unknown kid, or expiry. No network, no issuer."""
    now = now or _utcnow()
    try:
        header = jwt.get_unverified_header(token)
    except Exception as e:  # malformed token
        raise Es256Error(f"malformed token: {e}") from e

    kid = header.get("kid")
    candidates = [k for k in jwks.get("keys", []) if k.get("kid") == kid] or jwks.get("keys", [])
    if not candidates:
        raise Es256Error("no verification key available")

    last_err: Optional[Exception] = None
    for jwk in candidates:
        try:
            # verify signature only; exp is checked manually below for determinism.
            claims = jwt.decode(token, _pubkey_from_jwk(jwk), algorithms=[ALG],
                                options={"verify_exp": False})
            exp = claims.get("exp")
            if exp is None:
                raise Es256Error("token has no exp (refusing unbounded capability)")
            if int(now.timestamp()) >= int(exp):
                raise Es256Error("token expired")
            return claims
        except Es256Error:
            raise
        except Exception as e:  # signature mismatch against this candidate
            last_err = e
    raise Es256Error(f"signature verification failed: {last_err}")
