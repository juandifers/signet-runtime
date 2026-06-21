"""GitHub merge `RailBinding` — adapts the EXISTING merge pipeline to the seam.

This is a THIN wrapper over `resolve_task_mandate(...)` + `authorize_closed_mandate(...)`. It
rewrites NO rail logic, adds NO gate, and ships NO fence: the containment that matters
(bounded-to-own -> allow-list -> scope/protected fence, fail-closed) happens INSIDE
`run_role_b_stages` regardless of what the agent proposed (A1). The binding only maps a
`MandateResolution` -> a seam `Decision`/`Outcome`, carrying `escalation_source`.

Outcome mapping (the acceptance spec, §7):
  RESOLVED + tier==auto + authorizer success           -> ALLOW   (Check Run `success`)
  RESOLVED + tier==auto + kernel/authorizer refused     -> BLOCK   (contained; no merge)
  RESOLVED + tier!=auto (approve/cosign/deny)           -> ESCALATE (a human-approval tier)
  UNRESOLVED, source in {gate_contained, no_match}      -> BLOCK   (off-fence / nothing matched)
  UNRESOLVED, source in {layer_a_structural, cardinality} -> ESCALATE (genuine ambiguity)

On a BLOCK we ALSO conclude the rail's required Check Run as `failure` (a rail-native record
that the merge demonstrably did NOT proceed — the offline analogue of l3_run's fail-closed
failure post). On an ESCALATE/BLOCK a single signed receipt is appended for the decision (A6).
"""
from __future__ import annotations

from typing import Optional

from signet.canonical import hash_obj

from evals.github_railbridge.domain import target_id
from evals.github_railbridge.enforce import resolve_effective_policy
from evals.github_railbridge.mandate import (RESOLVED, authorize_closed_mandate,
                                             resolve_task_mandate)
from evals.github_railbridge.merge_chain import PRINCIPAL, build_merge_chain
from evals.github_railbridge.policy import TIER_AUTO, InMemoryPolicySource
from evals.github_railbridge.resolver import FixedChoiceResolver, FixedSetResolver
from evals._rail_core.role_b import ESC_CARDINALITY, ESC_GATE, ESC_LAYER_A

from .seam import Decision, Outcome, ProposedEffect

# Tools whose call IS a "merge a PR to a protected branch" effect.
_MERGE_TOOLS = frozenset({"merge_pr", "merge_pull_request"})
# UNRESOLVED escalation_sources that mean "genuine ambiguity a human must resolve" (ESCALATE);
# everything else under UNRESOLVED is containment (BLOCK).
_AMBIGUOUS = frozenset({ESC_LAYER_A, ESC_CARDINALITY})


def _synth_hash(*parts) -> str:
    return hash_obj(["effect-gateway", *[str(p) for p in parts]])


class GitHubMergeBinding:
    """Binds the GitHub merge rail to the orchestrator-agnostic seam."""

    name = "github_merge"
    shape = "resolution"        # pick one owned candidate out of a world, then authorize the bound effect

    def __init__(self, *, repo_id: str, source: Optional[InMemoryPolicySource] = None,
                 principal: str = PRINCIPAL, author: str = "alice"):
        self.repo_id = repo_id
        self.source = source or InMemoryPolicySource()   # the standing fence (agent can't write)
        self.principal = principal
        self.author = author

    # -- seam protocol --------------------------------------------------------
    def handles(self, eff: ProposedEffect) -> bool:
        return eff.tool in _MERGE_TOOLS

    def proposal_for(self, proposal):
        """A raw agent pick -> the merge rail's Role-B resolver. A single owned id is a
        one-element set (passes the cardinality rule, so the fence is what contains it); an
        iterable of ids is a set (cardinality>=2 escalates); None/empty means the model
        proposed nothing (no_match -> BLOCK)."""
        if proposal is None:
            return FixedChoiceResolver(None, reason="orchestrator proposed nothing")
        if isinstance(proposal, (list, tuple, set, frozenset)):
            ids = [int(x) for x in proposal]
            if len(ids) == 1:
                return FixedChoiceResolver(ids[0], reason="orchestrator tool-call pick")
            return FixedSetResolver(ids, reason="orchestrator proposed a set")
        return FixedChoiceResolver(int(proposal), reason="orchestrator tool-call pick")

    def submit(self, eff: ProposedEffect, *, mandate, world, env, bridge, receipts,
               proposal) -> Decision:
        if world is None:
            return Decision(Outcome.BLOCK, "no runtime world supplied (fail closed)",
                            escalation_source="gate_contained")
        # effective fence = standing PolicySource INTERSECT the frozen mandate (monotonic; only
        # tightens). The mandate is Role A; the proposal (Role-B resolver)/world are the only
        # runtime channel. `env.verifier` is THIS rail's verifier (resolution shape, face 2).
        effective = resolve_effective_policy(self.source, self.repo_id, self.principal,
                                             mandate.as_task_policy())
        resolution = resolve_task_mandate(mandate, world, effective, resolver=proposal)
        return self._to_decision(resolution, effective, world, env, bridge, receipts)

    # -- MandateResolution -> Decision ---------------------------------------
    def _to_decision(self, resolution, effective, world, env, bridge, receipts) -> Decision:
        if resolution.kind == RESOLVED:
            return self._resolved(resolution, effective, env, bridge, receipts)

        src = resolution.escalation_source or ESC_GATE   # deterministic path -> treat as contained
        if src in _AMBIGUOUS:
            # genuine ambiguity: surface ONLY owned ids (the gate never lets an attacker id here).
            cands = tuple(c.pr for c in resolution.considered if c.pr is not None)
            receipt = receipts.append(
                execution_id="exec_" + _synth_hash(resolution.cause, "escalate")[:16],
                mandate_id=f"open:{self.repo_id}",
                chain_hash=_synth_hash(self.repo_id, "escalate", *sorted(cands)),
                policy_id=f"effective:{self.repo_id}", decision="review",
                payment_status=f"escalated:{src}", payment_ref=None, rail="github")
            return Decision(Outcome.ESCALATE, resolution.cause, candidates=cands,
                            receipt=receipt, escalation_source=src)

        # containment: off-fence / not-owned / no-match. Conclude a fail-closed failure Check Run
        # (rail-native record) for the contained candidate(s), then append ONE blocked receipt.
        check_ref = self._conclude_failures(resolution, world, bridge)
        contained = ", ".join(f"#{c.pr}" for c in resolution.considered if c.pr is not None)
        receipt = receipts.append(
            execution_id="exec_" + _synth_hash(resolution.cause, "block")[:16],
            mandate_id=f"open:{self.repo_id}",
            chain_hash=_synth_hash(self.repo_id, "contained", contained),
            policy_id=f"effective:{self.repo_id}", decision="blocked",
            payment_status=f"contained:{src}", payment_ref=check_ref, rail="github")
        return Decision(Outcome.BLOCK, resolution.cause, receipt=receipt,
                        escalation_source=src, check_ref=check_ref)

    def _resolved(self, resolution, effective, env, bridge, receipts) -> Decision:
        closed = resolution.closed
        outcome = authorize_closed_mandate(env, bridge, receipts, repo_id=self.repo_id,
                                           closed=closed, effective=effective,
                                           principal_id=self.principal, author=self.author)
        if outcome.tier != TIER_AUTO:
            # a protected/human-approval tier: not autonomously authorizable -> ESCALATE.
            return Decision(Outcome.ESCALATE, outcome.reason, candidates=(closed.pr,),
                            receipt=outcome.receipt, escalation_source="human_approval_tier",
                            tier=outcome.tier, bound_target=closed.bound_target)
        if outcome.approved:
            return Decision(Outcome.ALLOW, outcome.reason, receipt=outcome.receipt,
                            escalation_source="resolved", tier=outcome.tier,
                            bound_target=closed.bound_target, check_ref=outcome.check_ref)
        # kernel-blocked (context-bind / consume-once / velocity) or authorizer-refused.
        return Decision(Outcome.BLOCK, outcome.reason, receipt=outcome.receipt,
                        escalation_source="kernel_blocked", tier=outcome.tier,
                        bound_target=closed.bound_target, check_ref=outcome.check_ref)

    # -- rail-native containment record (conclude required Check Run as failure) ----
    def _conclude_failures(self, resolution, world, bridge) -> Optional[str]:
        ref = None
        for c in resolution.considered:
            rec = world.open_prs.get(c.pr) if c.pr is not None else None
            if rec is None:
                continue
            ref = self._fail_check(bridge, rec) or ref
        return ref

    @staticmethod
    def _fail_check(bridge, rec) -> Optional[str]:
        """Conclude the required Check Run as `failure` for one contained candidate — the
        rail-native record that the merge demonstrably did NOT proceed. Only the enforcer's
        rail can conclude a check; the agent never can."""
        rail = getattr(bridge, "_rail", None)
        if rail is None:
            return None
        tgt = target_id(rec.repo, rec.number, rec.base, rec.head_sha)
        ch = _synth_hash("contained-check", tgt)
        try:
            check_run_id = rail.open_check(ch, rec.head_sha)
            return rail.conclude(check_run_id, ch, "failure")
        except Exception:                      # a rail that refuses is still fail-closed (no merge)
            return None

    # -- ESCALATE -> human approval -> resume (the TOCTOU re-check lives in the kernel) ------
    def resume(self, eff: ProposedEffect, decision: Decision, approval, *, mandate,
               frozen_world, current_world, env, bridge, receipts) -> Decision:
        """A human resumed an ESCALATE. The approval names ONE owned candidate (or denies). The
        chosen id is RE-GATED on the world the human saw (`frozen_world`), then authorized with
        the Cart bound to that FROZEN effect while the RuntimeContext reads the CURRENT world —
        so a force-push / base swap between approval and authorize changes the effect-key and is
        BLOCKED by the UNMODIFIED kernel (A4). Approval is NEVER a license to widen: a chosen id
        outside the offered owned candidates, or one that fails the gate, is contained."""
        choice = self._approval_choice(approval, decision)
        if choice is None:
            return self._resume_block(receipts, "human declined or named no candidate",
                                      "human_denied")
        if decision.candidates and choice not in decision.candidates:
            return self._resume_block(receipts, f"chosen #{choice} is not an offered owned "
                                      f"candidate (no widening on resume)", "gate_contained")

        effective = resolve_effective_policy(self.source, self.repo_id, self.principal,
                                             mandate.as_task_policy())
        # Re-gate the human's choice on the world they approved (bounded-to-own -> allow-list ->
        # fence, fail-closed). An off-fence choice is contained even after approval.
        regate = resolve_task_mandate(mandate, frozen_world, effective,
                                      resolver=FixedChoiceResolver(int(choice)))
        if regate.kind != RESOLVED:
            ref = None
            rec = frozen_world.open_prs.get(int(choice))
            if rec is not None:
                ref = self._fail_check(bridge, rec)
            return self._resume_block(receipts, f"chosen #{choice} failed the gate: "
                                      f"{regate.cause}", regate.escalation_source or ESC_GATE,
                                      check_ref=ref)

        current = (current_world or frozen_world).open_prs.get(int(choice))
        if current is None:                    # the PR vanished between approval and authorize
            return self._resume_block(receipts, f"chosen #{choice} no longer exists "
                                      "(fail closed)", "gate_contained")
        return self._authorize_bound(regate.closed, current, effective, env, bridge, receipts)

    @staticmethod
    def _approval_choice(approval, decision: Decision):
        """Interpret a human resume value -> the chosen owned id, or None (deny / abstain). Accepts
        an int, {"choice": id} / {"approved": True}, or a bare True/"approve"/"yes" when exactly one
        candidate was offered. Anything falsey or ambiguous fails closed to None (deny)."""
        if isinstance(approval, bool):
            return decision.candidates[0] if (approval and len(decision.candidates) == 1) else None
        if isinstance(approval, int):
            return int(approval)
        if isinstance(approval, str):
            if approval.strip().lower() in ("approve", "yes", "ok", "y") \
                    and len(decision.candidates) == 1:
                return decision.candidates[0]
            try:
                return int(approval.strip().lstrip("#"))
            except ValueError:
                return None
        if isinstance(approval, dict):
            if "choice" in approval and approval["choice"] is not None:
                try:
                    return int(approval["choice"])
                except (TypeError, ValueError):
                    return None
            if approval.get("approved") or approval.get("approve"):
                return decision.candidates[0] if len(decision.candidates) == 1 else None
        return None

    def _resume_block(self, receipts, cause: str, source: str,
                      check_ref: Optional[str] = None) -> Decision:
        receipt = receipts.append(
            execution_id="exec_" + _synth_hash(cause, "resume-block")[:16],
            mandate_id=f"open:{self.repo_id}", chain_hash=_synth_hash(self.repo_id, "resume", cause),
            policy_id=f"effective:{self.repo_id}", decision="blocked",
            payment_status=f"resume-contained:{source}", payment_ref=check_ref, rail="github")
        return Decision(Outcome.BLOCK, cause, receipt=receipt, escalation_source=source,
                        check_ref=check_ref)

    def _authorize_bound(self, frozen_closed, current_rec, effective, env, bridge,
                         receipts) -> Decision:
        """Authorize a FROZEN bound effect (the Cart commits to the approved head/base/paths)
        against the CURRENT runtime record. If they match, the kernel approves and the enforcer
        concludes the Check Run -> ALLOW. If a bound field was mutated after approval, the
        runtime context diverges from the signed Cart and the kernel's context-binding (step 7)
        BLOCKS before any side effect — the same mechanism the merge rail's bound-effect probe
        exercises."""
        bound_target = target_id(frozen_closed.repo, frozen_closed.pr,
                                 frozen_closed.base, frozen_closed.head_sha)
        req = build_merge_chain(
            env, repo=frozen_closed.repo, pr=frozen_closed.pr, base=frozen_closed.base,
            head_sha=frozen_closed.head_sha, touched_paths=tuple(frozen_closed.touched_paths),
            author=self.author, policy=effective,
            ctx_base=current_rec.base, ctx_head_sha=current_rec.head_sha,
            ctx_paths=tuple(current_rec.files))
        decision, token = env.verifier.evaluate(req)
        if not decision.approved:
            ref = self._fail_check(bridge, current_rec)
            receipt = receipts.append(
                execution_id="exec_" + _synth_hash(bound_target, "resume-kblock")[:16],
                mandate_id=req.intent.mandate_id,
                chain_hash=decision.chain_hash or _synth_hash(bound_target),
                policy_id=req.intent.policy_id, decision="blocked",
                payment_status="kernel-blocked-on-resume", payment_ref=ref, rail="github")
            return Decision(Outcome.BLOCK, decision.reason, receipt=receipt,
                            escalation_source="kernel_blocked", bound_target=bound_target,
                            check_ref=ref)
        auth = bridge.authorize(token, req)
        receipt = receipts.append(
            execution_id=token.execution_id, mandate_id=token.mandate_id,
            chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
            decision="approved" if auth.executed else "blocked",
            payment_status="executed" if auth.executed else "authorizer-refused",
            payment_ref=auth.payment_ref, rail=auth.rail or "github")
        outcome = Outcome.ALLOW if auth.executed else Outcome.BLOCK
        return Decision(outcome, auth.reason, receipt=receipt,
                        escalation_source="resolved" if auth.executed else "kernel_blocked",
                        tier=TIER_AUTO, bound_target=bound_target, check_ref=auth.payment_ref)
