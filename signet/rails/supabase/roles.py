"""Restricted Postgres role granularity (FORK F: one role per (schema, op-class) for v0).

The broker never mints a JWT for the elevated role (BYPASSRLS / service_role). It maps the
granted scope to a RESTRICTED role pre-provisioned in Postgres with GRANTs only on the
permitted tables. The JWT `role` claim selects which role PostgREST switches to; RLS + that
role's GRANTs enforce scope AT THE DATABASE — this is what defeats the search_path / rephrase
trick (Phase 4 #6): a staging-scoped role simply has no GRANT on prod.users, however the SQL
is phrased.

Per-table roles are a later refinement; v0 collapses to (schema, op-class):
    select            -> signet_<schema>_ro
    insert/update/del -> signet_<schema>_rw
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from .effect import DbEffect


def role_for(schema: str, op_class: str) -> str:
    return f"signet_{schema}_{op_class}"


def role_for_effect(effect: DbEffect) -> str:
    return role_for(effect.schema, effect.op_class())


# A GRANT entry: (schema, table_glob, ops) — what a restricted role may do, enforced by the
# resource (PostgREST/RLS) independently of any string inspection. "*" table_glob = whole schema.
Grant = Tuple[str, str, Tuple[str, ...]]


def default_grants(schemas_rw: List[str], schemas_ro: List[str]) -> Dict[str, List[Grant]]:
    """Build the role->GRANT map the resource enforces. RW roles get all four ops on their
    schema; RO roles get only select. NO role is ever granted anything on a schema not listed
    here — so unlisted schemas (e.g. prod) are unreachable by any minted credential."""
    grants: Dict[str, List[Grant]] = {}
    for s in schemas_rw:
        grants[role_for(s, "rw")] = [(s, "*", ("select", "insert", "update", "delete"))]
    for s in schemas_ro:
        grants[role_for(s, "ro")] = [(s, "*", ("select",))]
    return grants


def role_permits(grants: Dict[str, List[Grant]], role: str,
                 schema: str, table: str, op: str) -> bool:
    """Does `role` hold a GRANT covering (schema, table, op)? Used by the resource simulator
    (and, in live mode, the real Postgres GRANT table does this)."""
    from ...fence import matches_any  # reuse the rail's exact glob semantics
    for g_schema, g_table, g_ops in grants.get(role, ()):
        if g_schema == schema and op in g_ops and (
            g_table == "*" or g_table == table or matches_any(table, (g_table,))
        ):
            return True
    return False
