"""Pipeline tracer — runs the REAL, unmodified Signet kernel across THREE rails
(github / deploy / infra) and emits one structured JSON trace for the storytelling
visualizer.

Nothing here re-implements kernel logic. Each scenario builds a signed AP2 chain with the
existing per-rail chain builders, routes it through the UNMODIFIED
`signet.verifier.Verifier.evaluate`, and (on approval) through the rail's real authorizer
(`*RailBridge.authorize`). Per-step PASS/BLOCK state is derived from the kernel's own
`Decision.reason`: an early-returning pipeline, so a blocked run is green up to the firing
step, red at it, and grey ("not reached") after.

This is the "truth layer." The visual demo is a projection of this file's output — every
verdict and every reason string shown there is produced here, by the real kernel.

Run:  python -m demos.trace_pipeline               # all three rails -> stdout JSON
      python -m demos.trace_pipeline > trace.json
"""
from __future__ import annotations

import json
from datetime import timedelta

from signet import chain as chainmod

# --- github rail ---
from signet.authorizers.github_railbridge import GitHubRailBridge, MockGitHubRail
from evals.github_railbridge.merge_chain import build_merge_chain, make_github_env
# --- deploy rail ---
from signet.authorizers.deploy_railbridge import DeployRailBridge, MockDeployGate
from evals.deploy_railbridge.deploy_chain import build_deploy_chain, make_deploy_env
# --- infra rail ---
from signet.authorizers.infra_railbridge import InfraRailBridge, MockInfraApplyGate
from evals.infra_railbridge.infra_chain import build_infra_chain, make_infra_env


# The 11 ordered kernel checks (signet/verifier.py), named for the story. step = i+1.
STEPS = [
    ("Signatures", "Principal signed the Intent and the Cart (Ed25519). The agent's word is irrelevant."),
    ("Chain linkage", "Recompute every hash link: Cart->Intent, Payment->Cart. Catches Cart substitution."),
    ("Agent identity", "intent.agent == cart.agent == runtime.agent. Catches confused-deputy reuse."),
    ("Action allowed", "Cart action is in the Intent's allowed set; runtime action/scope match the Cart."),
    ("Freshness / TTL", "valid_from <= now <= valid_until, on the verifier's own clock."),
    ("Revocation", "Mandate not revoked — checked at execution time, not only at issuance."),
    ("Context binding", "Runtime context hash == the context the Cart committed to. Where substitution dies."),
    ("Exactness", "Runtime amount/currency == Cart; within Intent cap; recipient on the Intent allowlist."),
    ("Enterprise policy", "Caps, allowlist, currency, velocity, human-approval threshold."),
    ("Consume-once", "Atomic INSERT of chain_hash. Replaying the exact transaction is rejected here."),
    ("Issue token", "Record velocity spend and mint the enforcer-signed, one-time ExecutionToken."),
]


def _step_for_reason(reason: str) -> int:
    """Map the kernel's own reason string to the 1-based step that produced it."""
    r = reason.lower()
    table = [
        (1, ["intent mandate signature", "cart mandate signature"]),
        (2, ["chain linkage", "different intent mandate_id", "intent_hash does not match",
             "references a different cart", "cart_hash does not match", "linkage intact",
             "payment amount/currency does not match the cart"]),
        (3, ["agent identity mismatch", "confused deputy"]),
        (4, ["not in intent.allowed_actions", "runtime action/scope"]),
        (5, ["not yet valid", "expired"]),
        (6, ["revoked"]),
        (7, ["execution context does not match"]),
        (8, ["runtime amount/currency does not match", "exceeds intent amount/currency",
             "recipient not in intent allowlist"]),
        (9, ["policy", "velocity", "cap", "allowlist", "human"]),
        (10, ["replay detected"]),
    ]
    for step, needles in table:
        if any(n in r for n in needles):
            return step
    return 9


def _run(env, bridge, *, scenario, narrative, attack, builder, builder_kwargs, replay_first=False):
    req = builder(env, **builder_kwargs)
    if replay_first:
        env.verifier.evaluate(req)  # the first, legitimate use consumes this exact chain_hash

    decision, token = env.verifier.evaluate(req)
    approved = decision.approved
    blocked_step = None if approved else _step_for_reason(decision.reason)

    steps = []
    for i, (name, desc) in enumerate(STEPS, start=1):
        if approved:
            state = "pass"
        elif i < blocked_step:
            state = "pass"
        elif i == blocked_step:
            state = "block"
        else:
            state = "skip"
        steps.append({"n": i, "name": name, "desc": desc, "state": state})

    gate = None
    if approved and token is not None:
        result = bridge.authorize(token, req)
        gate = {"executed": result.executed, "reason": result.reason,
                "rail": result.rail, "ref": result.payment_ref}

    return {
        "scenario": scenario,
        "narrative": narrative,
        "attack": attack,
        "outcome": "approved" if approved else "blocked",
        "reason": decision.reason,
        "blocked_step": blocked_step,
        "chain_hash": (decision.chain_hash
                       or chainmod.chain_hash(req.intent, req.cart, req.payment))[:28],
        "recipient_cart": req.cart.recipient,
        "recipient_runtime": req.context.recipient,
        "steps": steps,
        "gate": gate,
    }


def _scenarios(make_env, make_bridge, builder, base_kwargs, *, attacks):
    """Run a fresh env per scenario (clean state for replay/expiry), return the scenario list.
    `attacks` is a list of (scenario, narrative, attack, extra_kwargs, replay_first) tuples;
    the first entry is conventionally the clean/authorized run."""
    out = []
    for scenario, narrative, attack, extra, replay_first in attacks:
        env = make_env()
        bridge = make_bridge(env)
        kw = dict(base_kwargs)
        kw.update(extra)
        out.append(_run(env, bridge, scenario=scenario, narrative=narrative, attack=attack,
                        builder=builder, builder_kwargs=kw, replay_first=replay_first))
    return out


def github_rail():
    base = dict(repo="octo/payments-service", pr=2, base="main",
                head_sha="sha02aaaaaa", touched_paths=("src/app/payments.py",))
    attacks = [
        ("Authorized merge",
         "The agent merges exactly the PR the operator authorized: PR #2, a fix in "
         "src/app/payments.py, at the signed head SHA.",
         None, {}, False),
        ("Force-push swap",
         "Between approval and execution the agent force-pushes a new commit, so the head SHA "
         "at runtime differs from the SHA the operator signed.",
         "Same PR number, different code. The runtime head_sha no longer matches the Cart's.",
         dict(ctx_head_sha="evil99deadbeef"), False),
        ("Protected-path smuggle",
         "The runtime merge quietly includes a change to .github/workflows, which the policy "
         "fences as protected (human review only).",
         "Runtime effect escalates to merge_pr_protected; no longer the ordinary merge authorized.",
         dict(ctx_paths=("src/app/payments.py", ".github/workflows/deploy.yml")), False),
        ("Replay",
         "The agent captures a fully valid, already-executed merge and resubmits the identical "
         "transaction a second time.",
         "Same Intent/Cart/Payment -> identical chain_hash. The first use already consumed it.",
         {}, True),
        ("Expired mandate",
         "The agent presents a real, signed authorization — but the validity window has closed.",
         "now > valid_until, on the verifier's own clock (the agent cannot supply time).",
         dict(_expire=True), False),
        ("Cart tamper",
         "The agent edits the signed Cart after signing — repointing the merge — without "
         "re-signing it.",
         "The Cart's bytes no longer verify against the principal's Ed25519 signature.",
         dict(tamper_cart_recipient="merge_pr:octo/payments-service#2->main@evil"), False),
        ("Cart substitution",
         "Every signature is individually valid, but the Payment credential is presented "
         "alongside a Cart it was never assembled for.",
         "Payment.cart_hash no longer matches the supplied Cart — the chain links don't close.",
         dict(break_linkage=True), False),
    ]
    # Resolve the _expire sentinel against a concrete env clock.
    def builder(env, **kw):
        if kw.pop("_expire", False):
            now = env.clock()
            kw["valid_from"] = now - timedelta(days=2)
            kw["valid_until"] = now - timedelta(days=1)
        return build_merge_chain(env, **kw)

    return {
        "id": "github", "label": "GitHub merge",
        "gate_label": "Required Check Run", "gate_open": "concluded success",
        "bind": "head_sha", "effect": "merge a PR to a protected branch",
        "scenarios": _scenarios(make_github_env, lambda e: GitHubRailBridge(
            e.verifier, e.enforcer_vk, github_rail=MockGitHubRail()),
            builder, base, attacks=attacks),
    }


def deploy_rail():
    base = dict(service="payments-api", environment="staging",
                artifact_digest="sha256:aaaa1111")
    attacks = [
        ("Authorized promotion",
         "The agent promotes exactly the build the operator authorized: payments-api, the signed "
         "artifact digest, to staging.",
         None, {}, False),
        ("Artifact swap",
         "Between approval and execution the agent points the promotion at a different image "
         "digest than the one that was scanned and signed.",
         "Runtime artifact_digest no longer matches the Cart's — a different build entirely.",
         dict(ctx_artifact_digest="sha256:beefbeef"), False),
        ("Environment escalation",
         "The agent reuses a staging approval to promote straight to prod, a protected "
         "environment.",
         "Runtime effect escalates to deploy_protected; no longer the staging deploy authorized.",
         dict(ctx_environment="prod"), False),
        ("Replay",
         "The agent resubmits an identical, already-executed promotion a second time.",
         "Same Intent/Cart/Payment -> identical chain_hash. The first use already consumed it.",
         {}, True),
        ("Expired mandate",
         "The agent presents a real, signed promotion — but the validity window has closed.",
         "now > valid_until, on the verifier's own clock.",
         dict(_expire=True), False),
        ("Cart tamper",
         "The agent edits the signed Cart after signing without re-signing it.",
         "The Cart's bytes no longer verify against the principal's Ed25519 signature.",
         dict(tamper_cart_recipient="deploy:payments-api@staging#sha256:evil/cfg"), False),
        ("Cart substitution",
         "Every signature is valid, but the Payment is presented with a Cart it was never built "
         "for.",
         "Payment.cart_hash no longer matches the supplied Cart — the chain links don't close.",
         dict(break_linkage=True), False),
    ]
    def builder(env, **kw):
        if kw.pop("_expire", False):
            now = env.clock()
            kw["valid_from"] = now - timedelta(days=2)
            kw["valid_until"] = now - timedelta(days=1)
        return build_deploy_chain(env, **kw)

    return {
        "id": "deploy", "label": "Deploy / promote",
        "gate_label": "Promotion gate", "gate_open": "concluded success",
        "bind": "artifact_digest", "effect": "promote an artifact to an environment",
        "scenarios": _scenarios(make_deploy_env, lambda e: DeployRailBridge(
            e.verifier, e.enforcer_vk, deploy_gate=MockDeployGate()),
            builder, base, attacks=attacks),
    }


def infra_rail():
    base = dict(account="acct-main", cluster="cluster-blue",
                resource_set=("aws_s3_bucket.assets",), plan_hash="plan-001",
                effect_class="infra_apply")
    attacks = [
        ("Authorized apply",
         "The agent applies exactly the change-set the operator authorized: one resource in "
         "acct-main / cluster-blue, at the signed plan hash.",
         None, {}, False),
        ("Plan swap",
         "Between approval and execution the agent applies a different plan than the one that was "
         "reviewed.",
         "Runtime plan_hash no longer matches the Cart's — a different change-set entirely.",
         dict(ctx_plan_hash="plan-666"), False),
        ("Resource slip-in",
         "The agent slips an extra resource into the apply that was not in the approved set "
         "(classic TOCTOU).",
         "Runtime resource set differs from the Cart's — the recipient binding no longer matches.",
         dict(ctx_resource_set=("aws_s3_bucket.assets", "aws_iam_role.admin")), False),
        ("Replay",
         "The agent resubmits an identical, already-executed apply a second time.",
         "Same Intent/Cart/Payment -> identical chain_hash. The first use already consumed it.",
         {}, True),
        ("Expired mandate",
         "The agent presents a real, signed apply — but the validity window has closed.",
         "now > valid_until, on the verifier's own clock.",
         dict(_expire=True), False),
        ("Cart tamper",
         "The agent edits the signed Cart after signing without re-signing it.",
         "The Cart's bytes no longer verify against the principal's Ed25519 signature.",
         dict(tamper_cart_recipient="infra_apply:acct-main@cluster-blue#evil/plan-001"), False),
        ("Cart substitution",
         "Every signature is valid, but the Payment is presented with a Cart it was never built "
         "for.",
         "Payment.cart_hash no longer matches the supplied Cart — the chain links don't close.",
         dict(break_linkage=True), False),
    ]
    def builder(env, **kw):
        if kw.pop("_expire", False):
            now = env.clock()
            kw["valid_from"] = now - timedelta(days=2)
            kw["valid_until"] = now - timedelta(days=1)
        return build_infra_chain(env, **kw)

    return {
        "id": "infra", "label": "Infra apply",
        "gate_label": "Apply gate", "gate_open": "concluded success",
        "bind": "plan_hash", "effect": "apply an IaC change-set to a cluster",
        "scenarios": _scenarios(make_infra_env, lambda e: InfraRailBridge(
            e.verifier, e.enforcer_vk, apply_gate=MockInfraApplyGate()),
            builder, base, attacks=attacks),
    }


def build_trace():
    return {
        "title": "Signet enforcement gauntlet",
        "subtitle": "One authorized action, six attacks, the unmodified kernel — across three rails.",
        "steps_legend": [{"n": i, "name": n, "desc": d}
                         for i, (n, d) in enumerate(STEPS, start=1)],
        "rails": [github_rail(), deploy_rail(), infra_rail()],
    }


if __name__ == "__main__":
    print(json.dumps(build_trace(), indent=2, default=str))