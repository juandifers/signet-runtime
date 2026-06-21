"""Egress `RailBinding` — adapts the EXISTING egress admission pipeline to the seam.

This is the seam's FIRST admission rail. Where `rails_github.py` is a RESOLUTION rail (pick one
owned candidate out of a `world`, then authorize the bound effect), egress is an ADMISSION rail:
the destination is self-describing (host, port, protocol), and the only question is admit-or-deny.
The seam now declares `shape ∈ {resolution, admission}` (the reshape SEAM-SHAPE-OVERFIT earned, and
this rail confirmed); egress declares `shape = "admission"`, and the seam routes accordingly:

  * `proposal_for` is an honest IDENTITY-PREPARE — admission has no candidate set, so it returns
    the self-describing effect unchanged (no longer a vestigial resolver-shaped pass-through).
  * the `proposal` and `world` params of `submit` are IGNORED — the destination is read from
    `eff.args`, not picked out of a world.
  * there is NO `resume` / ESCALATE in v0 — admission is binary, and the seam REFUSES a resume on
    an admission binding structurally (RESUME-SHAPE-GATED, NO-ESCALATE-V0 is seam-level).

The binding REWRITES no rail logic and adds NO gate: it drives the unchanged egress composition
(EgressBrokerCore.mint_token -> kernel verify -> EgressAuthorizer.authorize @ ADMIT), exactly the
admission `signet/broker/proxy.py:EgressBroker.admit` runs, and maps the result to a seam
`Decision`. Containment lives entirely in the composition (Bind + MandateFreshness + Policy +
Door); the binding only translates a verdict and appends one signed receipt (A6).

NOTE on the kernel verifier: egress's kernel policy is EFFECT-SCOPED (allowed_recipients ==
[this destination]), so it cannot share the seam's single `env.verifier` the way merge does — the
binding mints the token through the egress core's per-effect verifier instead (EGRESS_BINDING.md
§4.8). This is a second face of the same over-fit the bend records.

Outcome mapping (the acceptance spec, §6):
  kernel verify rejects (decision not approved / no token)   -> BLOCK  (kernel_blocked)
  Bind.recheck fails (TOCTOU: context dest != signed Cart)   -> BLOCK  (admission_denied)
  MandateFreshness fails (no-frozen-mandate / mandate-expired)-> BLOCK (admission_denied)
  Policy.decide denies (off-allowlist / off mandate ∩ standing /
          raw-IP not a trusted-resolved allowlisted host)    -> BLOCK  (admission_denied)
  Door.enforce admits                                        -> ALLOW
  malformed / missing destination args                       -> BLOCK  (gate_contained, fail-closed)
"""
from __future__ import annotations

from typing import Optional
from urllib.parse import urlsplit

from signet.canonical import hash_obj
from signet.rails.egress.authorizer import EgressAuthorizer
from signet.rails.egress.chain_adapter import EgressBrokerCore
from signet.rails.egress.effect import EgressEffect

from .seam import Decision, Outcome, ProposedEffect

# Tools whose call IS an "open an outbound connection" effect.
_EGRESS_TOOLS = frozenset({"egress", "http_connect", "fetch_url", "post_webpage",
                           "requests_get", "requests_post", "http_get"})

_DEFAULT_PORTS = {"https": 443, "http": 80}


def _synth_hash(*parts) -> str:
    return hash_obj(["effect-gateway-egress", *[str(p) for p in parts]])


class EgressBinding:
    """Binds the egress admission rail to the orchestrator-agnostic seam."""

    name = "egress"
    shape = "admission"         # self-describing destination, admit-or-deny; per-effect verifier, no resume

    def __init__(self, *, broker_core: EgressBrokerCore, mandate_provider, standing_policy,
                 resolver, env=None, agent_id: str = "agent", egress_tools=None):
        self._broker = broker_core                 # the egress "env": per-effect kernel verifier + keys
        self._mandates = mandate_provider          # task_id -> frozen EgressMandate (Role A)
        self._standing = standing_policy           # the standing ceiling (agent can't write)
        self._resolver = resolver                  # the TRUSTED host->ip resolver (raw-IP defense)
        self._env = env                            # accepted for signature parity; UNUSED (see module doc)
        self._agent_id = agent_id
        self._egress_tools = frozenset(egress_tools) if egress_tools else _EGRESS_TOOLS

    # -- seam protocol --------------------------------------------------------
    def handles(self, eff: ProposedEffect) -> bool:
        return eff.tool in self._egress_tools

    def proposal_for(self, proposal):
        """Admission identity-prepare: the destination is SELF-DESCRIBING, so there is no
        candidate set to coerce. Return the proposal unchanged — the seam routes admission rails
        straight to `submit`, which reads the destination from `eff.args`."""
        return proposal

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               proposal) -> Decision:
        # `proposal`, `world`, `env`, `bridge` are IGNORED — admission reads the destination from
        # eff.args and drives the egress composition. The task is selected by the FROZEN Role-A
        # mandate (its task_id), which MandateFreshness then re-fetches inside the composition.
        task_id = getattr(mandate, "task_id", None)
        if task_id is None:
            return self._block(receipts, "no frozen task mandate (fail closed)", "gate_contained",
                               None, None, None)

        effect = self._effect_from_args(eff.args)
        if effect is None:
            return self._block(receipts, f"malformed or missing egress destination in {eff.args!r}",
                               "gate_contained", None, None, None)

        # kernel verify + token via the egress core's PER-EFFECT verifier (the real pipeline).
        decision, token, req, verifier = self._broker.mint_token(effect, task_id, self._agent_id)
        if not decision.approved or token is None:
            cause = "replay" if "Replay" in (decision.reason or "") else decision.reason
            return self._block(receipts, cause, "kernel_blocked", effect, req, None)

        # the composition @ ADMIT: Bind -> MandateFreshness -> Policy -> Door (unchanged authorizer).
        authorizer = EgressAuthorizer(
            verifier, self._broker.enforcer_vk, mandate_provider=self._mandates,
            standing_policy=self._standing, resolver=self._resolver, clock=self._broker.clock)
        auth = authorizer.authorize(token, req)
        if auth.executed:
            return self._allow(receipts, auth, effect, req, token)
        return self._block(receipts, auth.reason, "admission_denied", effect, req, token,
                           payment_ref=auth.payment_ref)

    # -- destination from the proposed args (structured {host,port,protocol} OR {url}) ----------
    def _effect_from_args(self, args: dict) -> Optional[EgressEffect]:
        if not isinstance(args, dict):
            return None
        host = args.get("host")
        port = args.get("port")
        protocol = args.get("protocol", "http_connect")
        if host is None and args.get("url"):
            parsed = self._parse_url(args["url"])
            if parsed is None:
                return None
            host, port, protocol = parsed
        if host is None or port is None:
            return None
        try:
            return EgressEffect(str(host), int(port), str(protocol))
        except (ValueError, TypeError):           # bad port / unknown protocol -> fail closed
            return None

    @staticmethod
    def _parse_url(url) -> Optional[tuple]:
        try:
            u = urlsplit(str(url))
        except (ValueError, TypeError):
            return None
        if not u.hostname:
            return None
        try:
            port = u.port
        except ValueError:                        # malformed authority (e.g. host:notaport)
            return None
        if port is None:
            port = _DEFAULT_PORTS.get(u.scheme.lower())
        if port is None:
            return None
        return u.hostname, port, "http_connect"   # an outbound call is a CONNECT tunnel

    # -- verdict -> Decision (+ one signed receipt) --------------------------------------------
    def _allow(self, receipts, auth, effect: EgressEffect, req, token) -> Decision:
        receipt = receipts.append(
            execution_id=token.execution_id, mandate_id=token.mandate_id,
            chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
            decision="approved", payment_status="admitted",
            payment_ref=auth.payment_ref, rail="egress")
        return Decision(Outcome.ALLOW, auth.reason, receipt=receipt,
                        escalation_source="resolved", tier="auto",
                        bound_target=effect.target(), check_ref=auth.payment_ref)

    def _block(self, receipts, cause: str, source: str, effect: Optional[EgressEffect],
               req, token, payment_ref: Optional[str] = None) -> Decision:
        bound = effect.target() if effect is not None else ""
        chain_hash = (token.chain_hash if token is not None
                      else _synth_hash(source, bound, cause))
        mandate_id = req.intent.mandate_id if req is not None else f"egress:{source}"
        policy_id = req.intent.policy_id if req is not None else "egress_broker_policy_v1"
        receipt = receipts.append(
            execution_id="exec_" + _synth_hash(source, bound, cause)[:16],
            mandate_id=mandate_id, chain_hash=chain_hash, policy_id=policy_id,
            decision="blocked", payment_status=f"contained:{source}",
            payment_ref=payment_ref, rail="egress")
        return Decision(Outcome.BLOCK, cause, receipt=receipt, escalation_source=source,
                        bound_target=bound)
