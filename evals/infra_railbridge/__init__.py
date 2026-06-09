"""Infra-as-code rail (#3) — "apply a change-set to a target account/cluster".

Rail #3 is the FIRST plugin BORN CERTIFIED: it must pass `evals.conformance.register_rail` to
load. It exists to stress the conformance protocol on two axes the first two rails (boolean fence /
scalar effect-key) never exercised:

  * a QUANTITATIVE fence — `within_fence` is a CONJUNCTION that includes blast-radius <= cap AND
    destroy-count <= cap (not just a protected-flag membership test);
  * a SET-VALUED effect-key — `target_id` binds a HASH of the SORTED resource-address SET, so a
    post-auth ADD/REMOVE of a single resource (not a scalar swap) changes the bound recipient and
    the unmodified kernel context-bind blocks it.

The apply gate is MOCK (offline-property discipline, like XRPL / the DeployGate): the enforcer
concludes a `MockInfraApplyGate`; no real terraform/k8s/cloud apply is implemented.
"""
