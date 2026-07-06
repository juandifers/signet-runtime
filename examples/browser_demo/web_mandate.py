"""`WebMandate` — a FROZEN two-tier web mandate: a ceiling + a menu of named scopes.

Spec 02 makes the mandate two-tier (it was a single flat allowlist in Spec 01):

  * CEILING — the maximum authority this mandate could ever exercise. Frozen.
  * MENU of named SCOPES — each a declared *subset* of the ceiling. Frozen.
  * ACTIVE — the single mutable thing: which scope name is live right now.

`.build()` validates that every scope ⊆ ceiling (domains within the ceiling's domains,
actions ⊆ ceiling actions, click_policy no more permissive than the ceiling's) and freezes
the ceiling + the whole menu. At runtime ONLY `mandate.active` may change (via its validated
setter — `select_scope` flips it to another *menu key*, never to an authored permission).
This is what keeps the planner contained: it can pick a frozen scope, it cannot widen one.

Builder ergonomics (tiered):

    WebMandate("demo-agent", task_id="browse-demo-001")
      .ceiling(domains=["wikipedia.org", "ycombinator.com"], actions=["navigate","click","extract"])
      .scope("tour",       domains=["wikipedia.org"],                  actions=["navigate","extract","click"], click_policy="in_domain_only")
      .scope("learn_more", domains=["wikipedia.org","ycombinator.com"], actions=["navigate","extract","click"], click_policy="in_domain_only")
      .default_scope("tour")
      .build()

Spec 01 ergonomics still work (kept green): `.allow_domains([...]).allow_actions([...]).build()`
produces a single frozen scope named "default" that equals the ceiling.

PROVENANCE-MONOTONICITY / FROZEN-BEFORE-INPUT are unchanged: the ceiling and menu are frozen
before `agent.run(...)`; nothing observed at runtime can add a domain, an action, or a scope.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable, Optional

# The only action types this spine knows. Anything else is default-denied by the gate.
ACTION_TYPES = frozenset({"navigate", "click", "type", "extract"})

# Click policies, ordered by permissiveness for the ⊆ check. `in_domain_only` denies a click
# whose destination cannot be statically resolved (default-deny); `allow_unresolved` permits
# such a click with a receipt note. In BOTH, an off-domain destination is always blocked.
CLICK_POLICIES = ("in_domain_only", "allow_unresolved")
_CLICK_RANK = {p: i for i, p in enumerate(CLICK_POLICIES)}

DEFAULT_PRINCIPAL = "demo-agent"
DEFAULT_TASK_ID = "browse-demo-001"


def _normalize_domain(d: str) -> str:
    """Lower-case bare host, no scheme/port/path. `https://Example.com/x` -> `example.com`."""
    if not isinstance(d, str) or not d.strip():
        raise ValueError(f"domain must be a non-empty string, got {d!r}")
    s = d.strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]          # drop any path
    s = s.split("@", 1)[-1]         # drop any userinfo
    s = s.split(":", 1)[0]          # drop any port
    if not s:
        raise ValueError(f"could not normalize domain from {d!r}")
    return s


def _domain_within(domain: str, allowed: frozenset[str]) -> bool:
    """Exact host match or a subdomain of an allowed registrable domain. (Same matching the
    gate uses; duplicated here so web_mandate imports nothing from gate — gate imports it.)"""
    return any(domain == a or domain.endswith("." + a) for a in allowed)


@dataclass(frozen=True)
class Scope:
    """One named subset of the ceiling. The gate decides against the ACTIVE scope.

    `path_allow` (Spec 06): fnmatch-style globs over the URL PATH within an allowed domain
    (e.g. `/inventory*`, `/cart.html`). The default `("/*",)` matches every path, so a mandate
    that never sets paths behaves exactly as Spec 01-05 did. There is NO build-time glob-subset
    proof against the ceiling: the gate checks the ceiling's `path_allow` AND the active scope's
    on every decision, so a scope can never reach a path the ceiling forbids (the dual-check IS
    the structural guarantee)."""

    name: str
    allowed_actions: frozenset[str]
    allowed_domains: frozenset[str]
    click_policy: str = "in_domain_only"
    path_allow: frozenset[str] = frozenset({"/*"})

    def granted_scope(self) -> list[dict]:
        """Flat (rail, action, target) allow-list for the session viewer header."""
        ops = "|".join(a for a in ("navigate", "click", "type", "extract")
                       if a in self.allowed_actions)
        return [{"rail": "browser", "action": ops, "target": d}
                for d in sorted(self.allowed_domains)]

    def summary(self) -> dict:
        return {"name": self.name, "domains": sorted(self.allowed_domains),
                "actions": sorted(self.allowed_actions), "click_policy": self.click_policy,
                "paths": sorted(self.path_allow)}


class FrozenWebMandate:
    """Immutable ceiling + frozen scope menu; only `active` (a menu key) mutates at runtime."""

    __slots__ = ("principal", "task_id", "_ceiling", "_menu", "_active")

    def __init__(self, principal: str, task_id: str, ceiling: Scope,
                 menu: dict[str, Scope], active: str) -> None:
        self.principal = principal
        self.task_id = task_id
        self._ceiling = ceiling
        self._menu = dict(menu)            # logically frozen: no public mutator exposed
        if active not in self._menu:
            raise ValueError(f"default scope {active!r} not in menu {list(self._menu)}")
        self._active = active

    # -- the one runtime-mutable thing -----------------------------------------------------
    @property
    def active(self) -> str:
        return self._active

    @active.setter
    def active(self, name: str) -> None:
        """Deterministic activation: the name MUST be a frozen menu key (⊆ ceiling by build)."""
        if name not in self._menu:
            raise ValueError(f"unknown scope {name!r}; menu is {list(self._menu)}")
        self._active = name

    @property
    def active_scope(self) -> Scope:
        return self._menu[self._active]

    @property
    def ceiling(self) -> Scope:
        return self._ceiling

    @property
    def menu(self) -> dict[str, Scope]:
        return dict(self._menu)            # copy; callers cannot mutate the frozen menu

    def menu_summaries(self) -> list[dict]:
        return [s.summary() for s in self._menu.values()]

    # -- back-compat shims so Spec 01 callers + the gate read the ACTIVE scope -------------
    @property
    def allowed_domains(self) -> frozenset[str]:
        return self.active_scope.allowed_domains

    @property
    def allowed_actions(self) -> frozenset[str]:
        return self.active_scope.allowed_actions

    @property
    def click_policy(self) -> str:
        return self.active_scope.click_policy

    @property
    def name(self) -> str:
        return self.active_scope.name

    def granted_scope(self) -> list[dict]:
        return self.active_scope.granted_scope()


class WebMandate:
    """Fluent builder. Supports the Spec 01 flat API and the Spec 02 tiered (ceiling+scopes) API."""

    def __init__(self, principal: str = DEFAULT_PRINCIPAL, *,
                 task_id: str = DEFAULT_TASK_ID) -> None:
        self.principal = principal
        self.task_id = task_id
        # flat (Spec 01) accumulation
        self._flat_domains: set[str] = set()
        self._flat_actions: set[str] = set()
        # tiered (Spec 02) accumulation
        self._ceiling: Optional[Scope] = None
        self._scopes: dict[str, Scope] = {}
        self._default: Optional[str] = None

    # -- Spec 01 flat API (kept green) -----------------------------------------------------
    def allow_domains(self, domains: Iterable[str]) -> "WebMandate":
        for d in domains:
            self._flat_domains.add(_normalize_domain(d))
        return self

    def allow_actions(self, actions: Iterable[str]) -> "WebMandate":
        for a in actions:
            self._flat_actions.add(_check_action(a))
        return self

    # -- Spec 02 tiered API ----------------------------------------------------------------
    def ceiling(self, *, domains: Iterable[str], actions: Iterable[str],
                click_policy: str = "allow_unresolved",
                path_allow: Iterable[str] = ("/*",)) -> "WebMandate":
        """Declare the maximum authority. Scopes are validated ⊆ this at build() for domains and
        actions; `path_allow` is NOT subset-validated here — the gate's dual-check (ceiling AND
        scope) is the runtime guarantee (Spec 06)."""
        self._ceiling = Scope(
            name="__ceiling__",
            allowed_actions=frozenset(_check_action(a) for a in actions),
            allowed_domains=frozenset(_normalize_domain(d) for d in domains),
            click_policy=_check_click_policy(click_policy),
            path_allow=frozenset(_check_path(p) for p in path_allow),
        )
        return self

    def scope(self, name: str, *, domains: Iterable[str], actions: Iterable[str],
              click_policy: str = "in_domain_only",
              path_allow: Iterable[str] = ("/*",)) -> "WebMandate":
        """Add a named scope (a declared subset of the ceiling — domains/actions validated at
        build(); `path_allow` is enforced by the gate's dual-check, not validated here)."""
        if not name or name == "__ceiling__":
            raise ValueError(f"invalid scope name {name!r}")
        if name in self._scopes:
            raise ValueError(f"duplicate scope {name!r}")
        self._scopes[name] = Scope(
            name=name,
            allowed_actions=frozenset(_check_action(a) for a in actions),
            allowed_domains=frozenset(_normalize_domain(d) for d in domains),
            click_policy=_check_click_policy(click_policy),
            path_allow=frozenset(_check_path(p) for p in path_allow),
        )
        return self

    def default_scope(self, name: str) -> "WebMandate":
        self._default = name
        return self

    # -- validate / freeze -----------------------------------------------------------------
    def build(self) -> FrozenWebMandate:
        if self._scopes or self._ceiling is not None:
            return self._build_tiered()
        return self._build_flat()

    def _build_flat(self) -> FrozenWebMandate:
        if not self._flat_domains:
            raise ValueError("empty scope: call .allow_domains([...]) (or use the tiered .ceiling/.scope API)")
        if not self._flat_actions:
            raise ValueError("empty scope: call .allow_actions([...])")
        ceiling = Scope(name="__ceiling__",
                        allowed_actions=frozenset(self._flat_actions),
                        allowed_domains=frozenset(self._flat_domains),
                        click_policy="allow_unresolved")
        default = replace(ceiling, name="default")
        return FrozenWebMandate(self.principal, self.task_id, ceiling,
                                {"default": default}, "default")

    def _build_tiered(self) -> FrozenWebMandate:
        if self._ceiling is None:
            raise ValueError("tiered mandate needs a .ceiling(domains=..., actions=...)")
        if not self._scopes:
            raise ValueError("tiered mandate needs at least one .scope(...)")
        for s in self._scopes.values():
            self._validate_subset(s)
        default = self._default or next(iter(self._scopes))
        if default not in self._scopes:
            raise ValueError(f"default_scope {default!r} not among scopes {list(self._scopes)}")
        return FrozenWebMandate(self.principal, self.task_id, self._ceiling,
                                self._scopes, default)

    def _validate_subset(self, s: Scope) -> None:
        c = self._ceiling
        assert c is not None
        bad_actions = s.allowed_actions - c.allowed_actions
        if bad_actions:
            raise ValueError(
                f"scope {s.name!r} actions {sorted(bad_actions)} exceed the ceiling "
                f"{sorted(c.allowed_actions)}")
        bad_domains = [d for d in s.allowed_domains if not _domain_within(d, c.allowed_domains)]
        if bad_domains:
            raise ValueError(
                f"scope {s.name!r} domains {sorted(bad_domains)} are outside the ceiling "
                f"{sorted(c.allowed_domains)}")
        if _CLICK_RANK[s.click_policy] > _CLICK_RANK[c.click_policy]:
            raise ValueError(
                f"scope {s.name!r} click_policy {s.click_policy!r} is more permissive than the "
                f"ceiling {c.click_policy!r}")


def _check_action(a: str) -> str:
    a = str(a).strip().lower()
    if a not in ACTION_TYPES:
        raise ValueError(f"unknown action type {a!r}; allowed: {sorted(ACTION_TYPES)}")
    return a


def _check_path(p: str) -> str:
    """A path-allow entry is an fnmatch glob over the URL path; it MUST be rooted at '/'. We do
    not lower-case it (URL paths are case-sensitive) and we keep the glob verbatim."""
    if not isinstance(p, str) or not p.strip():
        raise ValueError(f"path_allow entry must be a non-empty string, got {p!r}")
    s = p.strip()
    if not s.startswith("/"):
        raise ValueError(f"path_allow entry {p!r} must start with '/' (it globs the URL path)")
    return s


def _check_click_policy(p: str) -> str:
    if p not in _CLICK_RANK:
        raise ValueError(f"unknown click_policy {p!r}; allowed: {list(CLICK_POLICIES)}")
    return p
