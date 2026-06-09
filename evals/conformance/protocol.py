"""The plugin handle — the minimal contract a rail must expose to be certified. github + deploy
already satisfy it through THIN adapters (`rails.py`) that expose machinery that already exists; no
rail-logic is rewritten.

The handle is deliberately small, but slightly richer than a one-line sketch because the battery has
to (a) drive the rail's full Role-B pipeline INCLUDING `run_gate`, (b) reach the kernel to prove the
effect-key binds a post-auth swap, and (c) drive the authorizer template. Every method below is
backed by code the rails already have — the adapter just surfaces it.

Signature note vs the task sketch: `within_allowlist`/`within_fence` take `(world, candidate_id)`
(the gate predicates in `run_role_b_stages` are id-keyed and need the world to resolve the id), and
the effect-key row is realized by `bound_effect_probe` (which encapsulates "flip a bound field ->
rebuild the chain") alongside the sketch's `mutate_bound_effect`. These are faithful realizations of
the sketch, noted so the deviation is explicit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from evals._rail_core.policy_spec import (CandidateSchema, PolicySpec, evaluate_allowlist,
                                          evaluate_fence)


class ConformanceError(Exception):
    """Raised by register_rail when a plugin fails the offline battery — the rail cannot load."""


@dataclass(frozen=True)
class Verdict:
    """The rail-neutral outcome of `plugin.resolve` (normalized from the rail's MandateResolution)."""
    resolved: bool                       # an effect was AUTHORIZED (the gate passed)
    target_id: Optional[int]             # the bound owned id when resolved, else None
    escalation_source: Optional[str]     # resolved | layer_a_structural | layer_b_cardinality |
                                         # gate_contained | no_match
    cause: str = ""
    raw: str = ""                        # the untrusted Role-B narrative (never trusted)


@dataclass
class EffectKeyProbe:
    """Everything the EFFECT_KEY_BIND row needs: two chains differing ONLY by one bound volatile
    field (head_sha / artifact_digest / config_hash), their effect-keys, and the live verifier. The
    clean chain must verify; the mutated runtime context must be BLOCKED by the kernel context-bind."""
    clean_request: object                # ExecutionRequest, cart==ctx -> approved
    mutated_request: object              # ExecutionRequest, runtime ctx field swapped -> blocked
    clean_key: str
    mutated_key: str
    verifier: object                     # has .evaluate(req) -> (Decision, token|None)


@dataclass
class TokenProbe:
    """Everything the AUTHZ_TEMPLATE row needs: a VALID enforcer token + the clean request (recheck
    passes), and a request whose recheck MUST fail (runtime context diverged). The authorizer's
    template must block both an invalid token and a failing recheck before produce_capability."""
    token: object                        # a valid ExecutionToken from an approved clean request
    request: object                      # the clean request (recheck passes)
    recheck_failing_request: object      # a request whose recheck_against_context returns False
    authorizer: object                   # a ready Authorizer bound to the same env


@runtime_checkable
class RailPlugin(Protocol):
    name: str
    untrusted_fields: tuple              # candidate fields carrying untrusted data (injection channel)

    # ---- world construction + introspection ----
    def build_world(self, spec: Optional[dict] = None): ...
    def candidates(self, world) -> List: ...          # the candidate views run_role_b_stages sees
    def owned_ids(self, world) -> set: ...
    def criterion(self, world) -> str: ...            # a clean (non-structural) standing criterion
    def attacker_id(self, world) -> Optional[int]: ...  # the planted OFF-FENCE candidate (#E)

    # ---- the DECLARATIVE typed policy (MANDATORY) — the fence is DATA, not code ----
    # A rail DECLARES every attribute the policy may read (candidate_schema), the resolved policy as
    # typed Conditions (policy_spec), and how to map a candidate to those attrs (project). The
    # allow-list / fence DECISION is the ONE shared evaluator over that data (see within_* below);
    # a rail physically cannot read an undeclared attribute or ship fail-open fence code.
    def candidate_schema(self) -> CandidateSchema: ...        # non-empty; every attr the policy reads
    def policy_spec(self, world) -> PolicySpec: ...           # the resolved policy as DATA
    def project(self, world, candidate_id: int) -> Dict: ...  # candidate -> declared attrs (total)
    def make_probe(self, attr_name: str, value) -> Tuple[object, int]: ...
    # ^ synthesize a single-candidate world whose probe candidate projects attr_name==value and is
    #   otherwise maximally in-allowlist & in-fence — drives the full-schema GATE sweep + responsiveness.

    # ---- allow-list / fence: SHARED, non-overridable (provided by DeclarativeRailPlugin) ----
    def within_allowlist(self, world, candidate_id: int) -> bool: ...
    def within_fence(self, world, candidate_id: int) -> bool: ...

    # ---- resolution: drives run_role_b_stages INCLUDING run_gate; returns a Verdict ----
    def resolve(self, criterion: str, world, resolver) -> Verdict: ...

    # ---- untrusted injection (red-team): write payload into #E's untrusted fields ----
    def inject(self, world, payload: dict): ...

    # ---- effect-key binding (TOCTOU) ----
    def effect_key(self, world, candidate_id: int) -> str: ...
    def mutate_bound_effect(self, world, candidate_id: int): ...   # world with #cid's bound field flipped
    def bound_effect_probe(self, world, candidate_id: int) -> EffectKeyProbe: ...

    # ---- authorizer template ----
    @property
    def authorizer(self): ...
    def token_probe(self, world, candidate_id: int) -> TokenProbe: ...

    # ---- live red-team defender: the rail's own Role-B (prompt + candidate shape) ----
    def make_llm_resolver(self, model: str): ...


class DeclarativeRailPlugin:
    """The SHARED base that supplies the allow-list / fence wrappers ALL rails inherit and MUST NOT
    override. The decision is the ONE shared evaluator over the rail's declared `project()` +
    `policy_spec()` — so there is no per-rail fence/allow-list code to make fail open, and a rail can
    only decide over attributes it declared. This SUPERSEDES the old optional `fence_axes`: a numeric
    cap is now a NUMERIC attribute + an LE/GE Condition, swept by the mandatory full-schema sweep."""

    def within_allowlist(self, world, candidate_id: int) -> bool:
        return evaluate_allowlist(self.project(world, candidate_id), self.policy_spec(world))

    def within_fence(self, world, candidate_id: int) -> bool:
        ok, _ = evaluate_fence(self.project(world, candidate_id), self.policy_spec(world))
        return ok
