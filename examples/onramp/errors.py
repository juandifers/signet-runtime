"""Teaching errors for the Signet on-ramp (spec §0.5: "Errors that teach").

Every on-ramp failure names the PROBLEM and the FIX — never a stack trace into the kernel, the seam,
or a rail module. A stranger who mistypes a target, forgets a rail extra, or asks for a rail that
does not exist should read the message and know exactly what to change.
"""
from __future__ import annotations


class SignetOnRampError(Exception):
    """Base for every on-ramp facade error. Catch this to handle any misuse of `guard()`/`Mandate`."""


class MalformedTargetError(SignetOnRampError):
    """A grant/guard target was not in the shape the door binds at (e.g. a DB target without a
    `schema.table`, or an egress host carrying a URL scheme)."""

    @classmethod
    def db(cls, target) -> "MalformedTargetError":
        return cls(
            f"db target {target!r} is malformed: expected 'schema.table' "
            f"(e.g. 'public.credits'). The supabase door binds at (schema, table, op) — "
            f"pass the schema and table, not a URL or a bare table name.")

    @classmethod
    def egress(cls, host) -> "MalformedTargetError":
        return cls(
            f"egress host {host!r} is malformed: expected a bare hostname "
            f"(e.g. 'payments.internal'), not a URL. Drop the scheme/path: "
            f"use 'payments.internal', not 'https://payments.internal/...'.")


class UnknownRailError(SignetOnRampError):
    """A rail was requested that the on-ramp does not wire."""

    def __init__(self, rail, known) -> None:
        super().__init__(
            f"unknown rail {rail!r}: the on-ramp wires {sorted(known)}. "
            f"To add a rail, give it a binding (mirror examples/refund_triage's "
            f"SupabaseBinding / EgressProxyBinding) and teach guard() to dispatch it — "
            f"the kernel/seam stay unchanged (CLAUDE.md 'the one rule').")
        self.rail = rail
        self.known = known


class MissingRailExtraError(SignetOnRampError):
    """A rail's optional dependency is not installed."""

    def __init__(self, rail: str, module: str, extra: str) -> None:
        super().__init__(
            f"the {rail!r} rail needs the optional dependency {module!r}, which is not installed. "
            f"Fix: pip install -e \".[{extra}]\"  (the {extra!r} extra in pyproject.toml).")
        self.rail = rail
        self.module = module
        self.extra = extra


def require(module: str, *, rail: str, extra: str):
    """Import `module` or raise a teaching MissingRailExtraError naming the pip fix. Used by guard()
    before it wires a rail whose binding pulls an optional dependency (langgraph, pyjwt, ...)."""
    from importlib import import_module
    try:
        return import_module(module)
    except ImportError as e:           # not installed -> name the extra, not the traceback
        raise MissingRailExtraError(rail, module, extra) from e
