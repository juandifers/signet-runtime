"""A FAITHFUL offline stand-in for the Supabase API gateway + PostgREST + RLS.

The battery runs with no network and no real project, but exercises the REAL crypto (ES256
verify) and the REAL scope logic (role -> GRANT), so the properties it proves transfer to a
live project. Two paths model the two ways to reach the database:

  * `SupabaseGateway` — the brokered path. Requires BOTH headers: `apikey` (a publishable-class
    key, RLS-neutered) AND `Authorization: Bearer <minted-JWT>`. It rejects a secret/service_role
    key presented as apikey (mirroring Supabase's browser-block guardrail), verifies the JWT
    against the broker JWKS (real ES256, with exp), extracts the `role` claim, and enforces the
    role's GRANTs. A query outside the role's grants is REJECTED AT THE RESOURCE — this is what
    defeats the search_path/rephrase trick regardless of how the SQL is phrased.

  * `PostgresDirect` — the AMBIENT path. A raw Postgres connection from a DSN (or a secret key)
    bypasses PostgREST/RLS/roles entirely (BYPASSRLS, like service_role). It exists ONLY if such
    a standing credential is in the environment. With zero-standing-elevated-creds there is no
    DSN, so this path cannot be constructed (nothing to go around). The P8 negative test
    deliberately injects a DSN to show the broker is only advisory once that invariant is broken.

Opt-in live mode (`SIGNET_SUPABASE_LIVE=1`) routes the same brokered path at a real project;
its results are MEASUREMENTS, never invariants, and CI never depends on them.
"""
from __future__ import annotations

import datetime as _dt
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .es256 import Es256Error, verify_jwt
from .roles import Grant, role_permits

PUBLISHABLE_PREFIX = "sb_publishable_"
SECRET_PREFIX = "sb_secret_"
LEGACY_SERVICE_ROLE = "service_role"


class SupabaseResourceError(Exception):
    """The resource refused the operation (bad key class, bad/expired JWT, or no GRANT)."""


def _matches(predicate: Optional[str], row: dict) -> bool:
    """Minimal predicate support: `col=value` (and bare None = all rows)."""
    if not predicate:
        return True
    if "=" not in predicate:
        return True
    col, _, val = predicate.partition("=")
    return str(row.get(col.strip())) == val.strip()


@dataclass
class Store:
    """In-memory tables: {(schema, table): [rows]}."""
    tables: Dict[Tuple[str, str], List[dict]] = field(default_factory=dict)

    def rows(self, schema: str, table: str) -> List[dict]:
        return self.tables.setdefault((schema, table), [])

    def apply(self, schema: str, table: str, op: str, predicate: Optional[str]) -> dict:
        rows = self.rows(schema, table)
        if op == "select":
            return {"op": "select", "rows": [r for r in rows if _matches(predicate, r)]}
        if op == "delete":
            keep = [r for r in rows if not _matches(predicate, r)]
            n = len(rows) - len(keep)
            self.tables[(schema, table)] = keep
            return {"op": "delete", "deleted": n}
        if op == "insert":
            return {"op": "insert", "inserted": 1}
        if op == "update":
            n = sum(1 for r in rows if _matches(predicate, r))
            return {"op": "update", "updated": n}
        raise SupabaseResourceError(f"unknown op {op!r}")


@dataclass
class SupabaseGateway:
    """The brokered path: apikey gate + ES256 JWT verify + role->GRANT enforcement."""
    jwks: dict
    grants: Dict[str, List[Grant]]
    store: Store
    clock: Callable[[], _dt.datetime] = lambda: _dt.datetime.now(_dt.timezone.utc)

    def request(self, *, apikey: str, bearer_jwt: str, schema: str, table: str, op: str,
                predicate: Optional[str] = None, now: Optional[_dt.datetime] = None) -> dict:
        now = now or self.clock()
        # 1. apikey must be a publishable-class key. A secret/service_role key in the apikey
        #    header is blocked (you cannot use elevated creds from the gateway).
        if apikey.startswith(SECRET_PREFIX) or apikey == LEGACY_SERVICE_ROLE:
            raise SupabaseResourceError("secret/service_role key blocked in apikey header")
        if not apikey.startswith(PUBLISHABLE_PREFIX):
            raise SupabaseResourceError("apikey must be a publishable-class key")
        # 2. verify the minted JWT against the JWKS (real ES256, exp checked vs `now`).
        try:
            claims = verify_jwt(bearer_jwt, self.jwks, now=now)
        except Es256Error as e:
            raise SupabaseResourceError(f"jwt rejected: {e}") from e
        role = claims.get("role")
        if not role:
            raise SupabaseResourceError("jwt has no role claim")
        # 3. role -> GRANT: the (schema, table, op) must be granted to this role, however the
        #    request is phrased. A staging role has no GRANT on prod.* -> rejected here.
        if not role_permits(self.grants, role, schema, table, op):
            raise SupabaseResourceError(
                f"role {role} has no GRANT on {schema}.{table} [{op}]")
        # 4. apply (RLS predicate, if any, is part of `predicate`).
        result = self.store.apply(schema, table, op, predicate)
        result["role"] = role
        result["via"] = "gateway"
        return result


@dataclass
class PostgresDirect:
    """The ambient/bypass path: a raw connection that ignores RLS/roles (BYPASSRLS)."""
    store: Store

    @classmethod
    def from_env(cls, env: Dict[str, str], store: Store) -> "PostgresDirect":
        """Construct ONLY if a standing elevated credential is present. With
        zero-standing-elevated-creds this raises — there is nothing to go around."""
        dsn = (env.get("SUPABASE_DB_URL") or env.get("DATABASE_URL")
               or env.get("SUPABASE_SECRET_KEY"))
        if not dsn:
            raise ConnectionRefusedError(
                "no Postgres DSN / secret key in environment (nothing to go around)")
        return cls(store=store)

    def query(self, schema: str, table: str, op: str,
              predicate: Optional[str] = None) -> dict:
        result = self.store.apply(schema, table, op, predicate)
        result["via"] = "postgres-direct (BYPASSRLS)"
        return result


# --- opt-in live mode (MEASUREMENT, never an invariant) ---

def live_enabled() -> bool:
    return os.environ.get("SIGNET_SUPABASE_LIVE") == "1"


def live_request(*, project_url: str, apikey: str, bearer_jwt: str, schema: str,
                 table: str, op: str, predicate: Optional[str] = None) -> dict:
    """Run the brokered path against a REAL Supabase project (PostgREST). Opt-in only; needs
    `requests`. Returns a MEASUREMENT dict (status + body), never used as a CI invariant."""
    import requests  # lazy: live-only dependency
    headers = {"apikey": apikey, "Authorization": f"Bearer {bearer_jwt}"}
    url = f"{project_url.rstrip('/')}/rest/v1/{table}"
    params = {}
    if predicate and "=" in predicate:
        col, _, val = predicate.partition("=")
        params[col.strip()] = f"eq.{val.strip()}"
    if op == "select":
        r = requests.get(url, headers={**headers, "Accept-Profile": schema}, params=params)
    elif op == "delete":
        r = requests.delete(url, headers={**headers, "Content-Profile": schema}, params=params)
    else:
        raise NotImplementedError(f"live mode supports select/delete only, not {op}")
    return {"measurement": True, "status": r.status_code,
            "body": r.text[:500], "via": "live-supabase"}
