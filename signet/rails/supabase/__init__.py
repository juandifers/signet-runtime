"""Supabase Postgres credential rail — the first keyholder vertical slice.

Zero-standing-ELEVATED-credentials: the agent never holds the secret/service_role
key, the JWT signing key, or a direct Postgres DSN. To touch the database it must
ask the broker for a short-lived, effect-bound ES256 JWT scoped to a restricted
Postgres role. See DESIGN.md "Self-hosted agent adapter — the credential/effect
broker" and the CLAUDE.md invariants (ZERO-STANDING-ELEVATED-CRED, CAP-BOUND,
BROKER-SEPARATE-PRINCIPAL, ONLY-DOOR-OR-DECLARE).
"""
