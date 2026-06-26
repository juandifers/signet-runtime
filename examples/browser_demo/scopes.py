"""`select_scope(mandate, request)` — the interactive scope switch (Spec 02 Part C).

Two stages, deliberately separated so the UNTRUSTED step can never author authority:

  1. UNTRUSTED PLANNER — map a free-text `request` to exactly ONE frozen menu key, or
     "none". A small constrained LLM classification (reuses the OpenAI key; system prompt
     forces a single menu name or "none") with a DETERMINISTIC keyword-match fallback so it
     still works with no network / no key. The planner can ONLY return a key that already
     exists in the frozen menu — it never invents a scope or widens one.
  2. DETERMINISTIC ACTIVATION — if the key is in the frozen menu, set `mandate.active = key`
     (the menu guarantees ⊆ ceiling by build-time validation) and write a `scope_switch`
     ALLOW receipt. If "none"/unknown, write a REFUSE receipt and leave `active` unchanged.

The gate reads `mandate.active` fresh on every decision, so flipping it changes the next
decision with no agent restart. Containment is structural: even a fully adversarial planner
output is clamped to "a frozen menu key or nothing" before it can affect any decision.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from typing import Optional

from .gate import Decision
from .web_mandate import FrozenWebMandate


def select_scope(mandate: FrozenWebMandate, request: str, *, session=None,
                 use_llm: bool = True, model: Optional[str] = None) -> Decision:
    """Map `request` -> a frozen menu key (or none), then deterministically activate it."""
    key = _llm_classify(request, mandate, model) if use_llm else None
    if key is None:                                  # LLM unavailable/unparseable -> fallback
        key = _keyword_classify(request, mandate)

    if key in mandate.menu:
        mandate.active = key                         # validated setter; ⊆ ceiling by build
        reason = f"request mapped to menu scope {key!r}; activated (frozen, ⊆ ceiling)"
        if session is not None:
            session.record_scope_switch(request, key, "allow", reason=reason)
        return Decision("allow", reason)

    reason = (f"request mapped to {key!r}: no matching frozen menu scope; "
              f"active scope {mandate.active!r} unchanged")
    if session is not None:
        session.record_scope_switch(request, None, "block", reason=reason)
    return Decision("block", reason)


# ---- stage 1a: deterministic keyword fallback --------------------------------------------
def _reg_label(domain: str) -> str:
    """Registrable-ish label: wikipedia.org -> 'wikipedia', www.ycombinator.com -> 'ycombinator'."""
    parts = domain.split(".")
    return parts[-2] if len(parts) >= 2 else parts[0]


def _keyword_classify(request: str, mandate: FrozenWebMandate) -> str:
    """Score each scope by scope-name hits (strong) + rarity-weighted domain-label hits.
    A label shared by every scope is non-discriminating (low weight); a unique label
    (e.g. 'ycombinator' only in learn_more) is decisive. Returns a menu key or 'none'."""
    req = request.lower()
    squashed = re.sub(r"[^a-z0-9]", "", req)         # "Y Combinator's" -> "ycombinators"
    labels = {name: {_reg_label(d) for d in s.allowed_domains}
              for name, s in mandate.menu.items()}
    freq = Counter(l for ls in labels.values() for l in ls)
    best, best_score = "none", 0.0
    for name in mandate.menu:
        score = 0.0
        if name.lower() in req or name.replace("_", " ").lower() in req:
            score += 3.0
        for l in labels[name]:
            if l and (l in req or l in squashed):    # match despaced too ("Y Combinator")
                score += 1.0 / freq[l]               # rarer label -> more discriminating
        if score > best_score:
            best, best_score = name, score
    return best if best_score > 0 else "none"


# ---- stage 1b: constrained LLM classification (primary; falls back on any failure) -------
def _llm_classify(request: str, mandate: FrozenWebMandate,
                  model: Optional[str]) -> Optional[str]:
    """Return a menu key, 'none', or None (None => caller uses the keyword fallback)."""
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    model = (model or os.environ.get("SIGNET_SCOPE_MODEL")
             or os.environ.get("SIGNET_DEMO_MODEL", "gpt-5.4"))
    names = list(mandate.menu.keys())
    menu_desc = "\n".join(
        f"- {s.name}: domains={sorted(s.allowed_domains)} actions={sorted(s.allowed_actions)}"
        for s in mandate.menu.values())
    system = (
        "You map a user request to EXACTLY ONE scope name from a fixed menu, or 'none'. "
        "Return ONLY the scope name (or the literal word none) — no punctuation, no explanation. "
        "You may NOT invent names or widen scope.\n"
        f"Menu:\n{menu_desc}\n"
        f"Valid answers: {names + ['none']}")
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        # Minimal params (no temperature/max_tokens) so newer reasoning models don't reject them.
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": request}])
        ans = (resp.choices[0].message.content or "").strip().strip("\"'.`").lower()
    except Exception:
        return None                                  # any failure -> keyword fallback
    for n in names:
        if ans == n.lower():
            return n
    if ans == "none":
        return "none"
    return None                                      # unparseable -> keyword fallback
