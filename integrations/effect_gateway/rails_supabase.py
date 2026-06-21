"""Supabase db-write `RailBinding` — adapts the EXISTING Supabase credential-broker pipeline to
the seam. This is the seam's SECOND admission rail, and the DECIDING vote on the two over-fits the
first admission rail (egress) surfaced (SEAM_CONTRACT.register.md `SEAM-SHAPE-OVERFIT`).

Where `rails_github.py` is a RESOLUTION rail (pick one owned candidate out of a `world`, then
authorize the bound effect), Supabase — like egress — is an ADMISSION rail: the operation is
self-describing `(database, schema, table, op, predicate)`, and the only question is admit-or-deny.
The seam now declares `shape ∈ {resolution, admission}` (the reshape this rail cast the deciding vote
for, SUPABASE_BINDING.md / `SEAM-SHAPE-OVERFIT`); supabase declares `shape = "admission"`:

  * `proposal_for` is an honest IDENTITY-PREPARE — admission has no candidate set, so it returns
    the self-describing effect unchanged (no longer a vestigial resolver-shaped pass-through).
  * the `proposal` and `world` params of `submit` are IGNORED — the operation is read from
    `eff.args`, not picked out of a world.
  * there is NO `resume` / ESCALATE in v0 — admission is binary, and the seam REFUSES a resume on
    an admission binding structurally (RESUME-SHAPE-GATED, NO-ESCALATE-V0 is seam-level).

The binding REWRITES no rail logic and adds NO gate: it drives the unchanged Supabase composition
(DbBrokerCore.mint_token -> kernel verify -> SupabaseAuthorizer.authorize), exactly the admission
the broker server runs, and maps the result to a seam `Decision`. Containment lives entirely in the
authorizer (Bind + MandateFreshness + Policy + Door); the binding only translates a verdict and
appends one signed receipt (A6).

NOTE on the kernel verifier (face 2, vote 2/2): Supabase's kernel policy is EFFECT-SCOPED
(`DbBrokerCore._verifier_for(effect)` mints a per-request verifier whose `allowed_recipients ==
[effect.target()]` and `allowed_actions == ["db.<op>"]`), so it cannot share the seam's single
`env.verifier` the way merge does — the binding mints through that per-effect verifier instead. This
is the SAME second face of the over-fit egress recorded; two independent admission rails now confirm
it (SUPABASE_BINDING.md §2).

ALLOW means a SCOPED CAPABILITY WAS ISSUED (a least-privilege, effect-bound, short-TTL ES256 JWT) —
NOT that the write executed. The downstream PEP (`resource_sim.SupabaseGateway` / a real PostgREST)
performs + enforces it. The JWT handle rides in `receipt.payment_ref`. The capability's scope is
enforced AT THE RESOURCE at ROLE granularity (role -> GRANT); the finer `signet_effect_hash` carried
in the JWT is bound at MINT (Bind/consume-once) but not re-checked at the resource PEP in v0 — the
third face, SUPABASE_BINDING.md §4/§8 and `SEAM-EFFECT-PHASE`.

Outcome mapping (the acceptance spec, §6):
  kernel verify rejects (decision not approved / no token)    -> BLOCK  (kernel_blocked)
  Bind.recheck fails (unbound-token / effect-context-mismatch)-> BLOCK  (admission_denied)
  MandateFreshness fails (no-frozen-mandate / mandate-expired)-> BLOCK  (admission_denied)
  Policy denies (op outside frozen mandate ∩ standing)        -> BLOCK  (admission_denied)
  Door: scoped ES256 JWT minted                               -> ALLOW
  malformed / missing / out-of-band operation args            -> BLOCK  (gate_contained, fail-closed)
"""
from __future__ import annotations

from typing import Optional

from signet.canonical import hash_obj
from signet.rails.supabase.authorizer import SupabaseAuthorizer
from signet.rails.supabase.chain_adapter import DbBrokerCore
from signet.rails.supabase.effect import OPS, DbEffect

from .seam import Decision, Outcome, ProposedEffect

# Tools whose call IS a "write to / query the database" effect.
_DB_TOOLS = frozenset({"db_write", "db_execute", "db_query", "sql_insert", "sql_update",
                       "sql_delete", "sql_select", "supabase_write"})


def _synth_hash(*parts) -> str:
    return hash_obj(["effect-gateway-supabase", *[str(p) for p in parts]])


class SupabaseBinding:
    """Binds the Supabase credential-broker admission rail to the orchestrator-agnostic seam."""

    name = "supabase"
    shape = "admission"         # self-describing db op, admit-or-deny; per-effect verifier, no resume

    def __init__(self, *, broker_core: DbBrokerCore, mandate_provider, standing_policy,
                 minter, ttl_seconds: int = 60, env=None, agent_id: str = "agent",
                 db_tools=None):
        self._broker = broker_core              # the db "env": per-effect kernel verifier + keys
        self._mandates = mandate_provider       # task_id -> frozen TaskMandate (Role A)
        self._standing = standing_policy        # the standing ceiling (agent can't widen it)
        self._minter = minter                   # the broker-held ES256 key (signs the JWT; never leaves)
        self._ttl = ttl_seconds
        self._env = env                         # accepted for signature parity; UNUSED (see module doc)
        self._agent_id = agent_id
        self._db_tools = frozenset(db_tools) if db_tools else _DB_TOOLS

    # -- seam protocol --------------------------------------------------------
    def handles(self, eff: ProposedEffect) -> bool:
        return eff.tool in self._db_tools

    def proposal_for(self, proposal):
        """Admission identity-prepare: the operation is SELF-DESCRIBING, so there is no candidate
        set to coerce. Return the proposal unchanged — the seam routes admission rails straight to
        `submit`, which reads the operation from `eff.args`."""
        return proposal

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               proposal) -> Decision:
        # `proposal`, `world`, `env`, `bridge` are IGNORED — admission reads the operation from
        # eff.args and drives the supabase composition. The task is selected by the FROZEN Role-A
        # mandate (its task_id), which the authorizer's recheck re-fetches from the provider.
        task_id = getattr(mandate, "task_id", None)
        if task_id is None:
            return self._block(receipts, "no frozen task mandate (fail closed)", "gate_contained",
                               None, None, None)

        effect = self._effect_from_args(eff.args)
        if effect is None:
            return self._block(receipts, f"malformed or missing db operation in {eff.args!r}",
                               "gate_contained", None, None, None)

        # kernel verify + token via the broker core's PER-EFFECT verifier (the real pipeline).
        decision, token, req, verifier = self._broker.mint_token(effect, task_id, self._agent_id)
        if not decision.approved or token is None:
            cause = "replay" if "Replay" in (decision.reason or "") else decision.reason
            return self._block(receipts, cause, "kernel_blocked", effect, req, None)

        # the composition: Bind -> MandateFreshness -> Policy -> Door (unchanged authorizer hooks).
        authorizer = SupabaseAuthorizer(
            verifier, self._broker.enforcer_vk, mandate_provider=self._mandates,
            standing_policy=self._standing, minter=self._minter, ttl_seconds=self._ttl,
            clock=self._broker.clock)
        auth = authorizer.authorize(token, req)
        if auth.executed:
            return self._allow(receipts, auth, effect, req, token)
        return self._block(receipts, auth.reason, "admission_denied", effect, req, token,
                           payment_ref=auth.payment_ref)

    # -- operation from the proposed args (structured {database,schema,table,op,predicate?}) -----
    def _effect_from_args(self, args: dict) -> Optional[DbEffect]:
        if not isinstance(args, dict):
            return None
        database = args.get("database")
        schema = args.get("schema")
        table = args.get("table")
        op = args.get("op")
        predicate = args.get("predicate")
        if database is None or schema is None or table is None or op is None:
            return None
        if op not in OPS:                         # out-of-band op -> fail closed (no default-allow)
            return None
        try:
            return DbEffect(str(database), str(schema), str(table), str(op),
                            None if predicate is None else str(predicate))
        except (ValueError, TypeError):           # DbEffect.__post_init__ rejects unknown ops
            return None

    # -- verdict -> Decision (+ one signed receipt) --------------------------------------------
    def _allow(self, receipts, auth, effect: DbEffect, req, token) -> Decision:
        receipt = receipts.append(
            execution_id=token.execution_id, mandate_id=token.mandate_id,
            chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
            decision="approved", payment_status="capability_issued",
            payment_ref=auth.payment_ref, rail="supabase")
        return Decision(Outcome.ALLOW, auth.reason, receipt=receipt,
                        escalation_source="resolved", tier="auto",
                        bound_target=f"{effect.target()}.{effect.op}", check_ref=auth.payment_ref)

    def _block(self, receipts, cause: str, source: str, effect: Optional[DbEffect],
               req, token, payment_ref: Optional[str] = None) -> Decision:
        bound = f"{effect.target()}.{effect.op}" if effect is not None else ""
        chain_hash = (token.chain_hash if token is not None
                      else _synth_hash(source, bound, cause))
        mandate_id = req.intent.mandate_id if req is not None else f"supabase:{source}"
        policy_id = req.intent.policy_id if req is not None else "db_broker_policy_v1"
        receipt = receipts.append(
            execution_id="exec_" + _synth_hash(source, bound, cause)[:16],
            mandate_id=mandate_id, chain_hash=chain_hash, policy_id=policy_id,
            decision="blocked", payment_status=f"contained:{source}",
            payment_ref=payment_ref, rail="supabase")
        return Decision(Outcome.BLOCK, cause, receipt=receipt, escalation_source=source,
                        bound_target=bound)
