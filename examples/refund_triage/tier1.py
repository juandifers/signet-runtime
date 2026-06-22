"""Tier-1 (OS-separated) transport for the refund-triage demo.

Tier 0 (agent.py default) runs the supabase composition IN-PROCESS via `SupabaseBinding` — the
signing key lives in the same process; the containment is *advisory*. Tier 1 moves the broker to
a SEPARATE OS principal reached over a Unix socket (`UnixSocketBrokerServer` + `BrokerClient`,
signet/broker/server.py:163 / client.py:14), so "a fooled agent cannot obtain a DB signing key"
is true at the OS level (peer-credential refusal + key file owned by uid_broker, unreadable by
uid_agent). Verdicts do NOT change — only the credential mechanism and the honesty of the label.

This module is DEMO WIRING ONLY. It reuses the existing Tier-1 classes verbatim and the unchanged
seam; it edits no kernel, no `effective_permits`/`DbGrant.permits`, no `roles.py`, and no broker
transport. `RemoteSupabaseBinding` is a seam `RailBinding` (shape="admission") that, instead of
holding the minter, sends a `CapabilityRequest` over `BrokerClient` and maps the
`CapabilityResponse` back to a seam `Decision` — so `signet_guarded_tool` -> `EffectInterceptor`
-> BrokerClient -> socket -> broker, exactly the spec §3 diagram.
"""
from __future__ import annotations

import os
import socket as _socket
from dataclasses import dataclass
from typing import Optional

from signet import crypto
from signet.broker.client import BrokerClient
from signet.canonical import hash_obj
from signet.rails.supabase.chain_adapter import POLICY_ID
from signet.rails.supabase.effect import OPS

from integrations.effect_gateway.seam import Decision, Outcome, ProposedEffect

# Same tool set the in-process SupabaseBinding handles (rails_supabase.py:58).
_DB_TOOLS = frozenset({"db_write", "db_execute", "db_query", "sql_insert", "sql_update",
                       "sql_delete", "sql_select", "supabase_write"})


def _synth_hash(*parts) -> str:
    return hash_obj(["refund-tier1", *[str(p) for p in parts]])


def _effect_args(args: dict) -> Optional[dict]:
    """Validate + normalize the self-describing db op (mirrors rails_supabase._effect_from_args:127
    — same fail-closed rules; NOT a re-implementation of any permit logic)."""
    if not isinstance(args, dict):
        return None
    database, schema, table, op = (args.get("database"), args.get("schema"),
                                   args.get("table"), args.get("op"))
    predicate = args.get("predicate")
    if database is None or schema is None or table is None or op is None:
        return None
    if op not in OPS:                       # out-of-band op -> fail closed
        return None
    out = {"database": str(database), "schema": str(schema), "table": str(table), "op": str(op)}
    if predicate is not None:
        out["predicate"] = str(predicate)
    return out


class RemoteSupabaseBinding:
    """Binds the OS-separated broker to the seam. `submit` issues a CapabilityRequest over the
    socket and maps the response to a Decision. Fail-closed: a malformed op, a refused peer, or an
    unreachable broker is a BLOCK — never a silent execute."""

    name = "supabase"
    shape = "admission"

    def __init__(self, *, client: BrokerClient, agent_id: str = "support-bot",
                 receipt_log=None, db_tools=None):
        self._client = client
        self._agent_id = agent_id
        self._receipts = receipt_log        # demo-local audit ReceiptLog (trace parity)
        self._db_tools = frozenset(db_tools) if db_tools else _DB_TOOLS

    # -- seam protocol --
    def handles(self, eff: ProposedEffect) -> bool:
        return eff.tool in self._db_tools

    def proposal_for(self, proposal):
        return proposal                     # admission identity-prepare (no candidate set)

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               proposal) -> Decision:
        task_id = getattr(mandate, "task_id", None)
        if task_id is None:
            return self._block("no frozen task mandate (fail closed)", "gate_contained",
                               None, mandate)
        op = _effect_args(eff.args)
        if op is None:
            return self._block(f"malformed or missing db operation in {eff.args!r}",
                               "gate_contained", None, mandate)
        # The broker is ONE long-lived process with ONE consume-once registry; a request_nonce
        # derived from the FULL proposed args lets two logically-distinct rows that share a DB
        # effect-key (e.g. clean amount=50 vs a3 amount=5000, both `insert credits`) each mint a
        # capability instead of false-colliding as a replay. This is the protocol's documented
        # "legitimately re-request the same logical effect" knob (protocol.py:8) — NOT a permit edit.
        request_nonce = hash_obj(dict(eff.args))[:24]
        try:
            resp = self._client.request_db(
                database=op["database"], schema=op["schema"], table=op["table"], op=op["op"],
                predicate=op.get("predicate"), task_id=task_id, agent_id=self._agent_id,
                request_nonce=request_nonce)
        except (ConnectionRefusedError, FileNotFoundError, OSError, _socket.timeout) as e:
            # The broker is unreachable (killed / never started / wrong path). FAIL CLOSED — a
            # missing broker must NEVER degrade to a silent write.
            return self._block(f"broker-unreachable ({type(e).__name__}: {e})",
                               "gate_contained", op, mandate)
        bound = f"{op['schema']}.{op['table']}.{op['op']}"
        if resp.granted:
            return self._allow(resp, bound, op, mandate)
        # refusal classification for the trace's escalation_source (verdict is BLOCK either way)
        src = "transport" if ("uid" in (resp.cause or "") or "peer" in (resp.cause or "")) \
            else "admission_denied"
        return self._block(resp.cause, src, op, mandate, broker_receipt=resp.receipt_id)

    # -- verdict -> Decision (+ one demo-local signed receipt for trace parity) --
    def _allow(self, resp, bound, op, mandate) -> Decision:
        receipt = self._append(resp.extra.get("chain_hash") if resp.extra else None, mandate,
                               decision="approved", payment_status="capability_issued",
                               payment_ref=resp.capability, bound=bound)
        return Decision(Outcome.ALLOW, resp.cause, receipt=receipt, escalation_source="resolved",
                        tier="auto", bound_target=bound, check_ref=resp.capability)

    def _block(self, cause: str, source: str, op: Optional[dict], mandate,
               broker_receipt: Optional[str] = None) -> Decision:
        bound = f"{op['schema']}.{op['table']}.{op['op']}" if op else ""
        receipt = self._append(None, mandate, decision="blocked",
                               payment_status=f"contained:{source}", payment_ref=None, bound=bound,
                               extra_seed=broker_receipt or cause)
        return Decision(Outcome.BLOCK, cause, receipt=receipt, escalation_source=source,
                        bound_target=bound)

    def _append(self, chain_hash, mandate, *, decision, payment_status, payment_ref, bound,
                extra_seed=""):
        if self._receipts is None:
            return None
        ch = chain_hash or _synth_hash(decision, bound, extra_seed)
        mid = mandate.mandate_hash() if mandate is not None else "refund:tier1"
        return self._receipts.append(
            execution_id="exec_" + _synth_hash(decision, bound, extra_seed)[:16],
            mandate_id=mid, chain_hash=ch, policy_id=POLICY_ID, decision=decision,
            payment_status=payment_status, payment_ref=payment_ref, rail="supabase")


# --------------------------------------------------------------------------------------------
# Separation detection — the honest label gate (spec §0.4). A run is "structural" ONLY if the
# OS peer-credential boundary is genuinely in force at runtime: the platform supports SO_PEERCRED
# AND the broker socket is owned by a DIFFERENT uid than this (agent) process. The agent verifies
# this itself by stat()-ing the socket — it does not trust an env var.
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Separation:
    structural: bool
    reason: str
    agent_uid: int
    broker_uid: Optional[int] = None
    peercred: bool = False

    @property
    def label(self) -> str:
        return "1 (structural)" if self.structural else "0 (advisory)"


def detect_separation(socket_path: str) -> Separation:
    agent_uid = os.getuid()
    peercred = hasattr(_socket, "SO_PEERCRED")          # Linux only (server.py:56)
    try:
        broker_uid = os.stat(socket_path).st_uid        # the uid that bound the socket
    except OSError:
        return Separation(False, "broker socket not present (no Tier-1 broker reachable)",
                          agent_uid, None, peercred)
    if not peercred:
        return Separation(False, "platform has no SO_PEERCRED (peer-credential check unavailable; "
                          "Tier-1 structural separation requires Linux)", agent_uid, broker_uid,
                          peercred)
    if broker_uid == agent_uid:
        return Separation(False, "broker socket owned by the agent's own uid (no OS separation)",
                          agent_uid, broker_uid, peercred)
    return Separation(True, f"broker uid {broker_uid} != agent uid {agent_uid}; SO_PEERCRED active",
                      agent_uid, broker_uid, peercred)


def make_audit_log():
    """A demo-local signed receipt log (Ed25519 via the kernel crypto library) so the trace's
    RECEIPT line works identically in Tier 1. This is the demo's audit record; the AUTHORITATIVE
    signed receipt is the broker's own (server-side LocalReceiptLog, returned as receipt_id)."""
    from signet.receipts import ReceiptLog
    sk, vk = crypto.generate_keypair()
    return ReceiptLog(sk, vk)
