"""Data-dependence taxonomy (FIDES-style): bucket each high-impact action by how
its target/params relate to the TRUSTED instruction.

  DI  (data-independent)         : recipient AND amount both TRUSTED-LITERAL in the
                                   instruction. (≈ NAMED in the tau-bench framing.)
  DIQ (data-independent w/ query): target described in trusted terms but >=1 value is
                                   only obtainable by a runtime lookup over the
                                   principal's OWN data -- predicate-resolvable.
                                   (≈ RUNTIME-resolvable.)
  DD  (data-dependent)           : >=1 value is NOT authorizable from trusted input ->
                                   must escalate in every mode.

The classifier is DETERMINISTIC and computed PLAN-TIME from the trusted PROMPT + the
ground-truth effect (resolved over a clean, injection-free env), per GT high-impact
ACTION (a task with two GT money actions -- e.g. banking task 15 -- contributes one
action to DI and one to DIQ). It is INDEPENDENT of the gate's verdict, the chosen
binding mode, and the agent rollout, so it is a stable weak-point signal.

It is pluggable: a domain supplies a `BucketClassifier`. `BankingBucketClassifier`
encodes banking value-source heuristics (a literal value is a PROMPT substring; an
own-data-resolvable value is a file/standing-order reference, a payee name present in
the principal's own history, or a concrete lookup/arithmetic phrase).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

DI = "DI"
DIQ = "DIQ"
DD = "DD"
BUCKETS = (DI, DIQ, DD)

# Value-source labels (the per-value classification the bucket rule is built from).
LITERAL = "literal"            # appears verbatim in the trusted PROMPT
RESOLVABLE = "resolvable"      # low-capacity lookup / arithmetic over the principal's OWN data
UNRESOLVABLE = "unresolvable"  # neither -> not authorizable from trusted input


@dataclass(frozen=True)
class ValueSources:
    recipient: str   # LITERAL | RESOLVABLE | UNRESOLVABLE
    amount: str


def bucket_from_sources(s: ValueSources) -> str:
    r_lit = s.recipient == LITERAL
    a_lit = s.amount == LITERAL
    r_ok = s.recipient in (LITERAL, RESOLVABLE)
    a_ok = s.amount in (LITERAL, RESOLVABLE)
    if r_lit and a_lit:
        return DI
    if r_ok and a_ok:
        return DIQ
    return DD


# ---- banking value-source heuristics ----

# concrete amount lookup/derivation phrases (own-data references that yield a value).
_AMOUNT_LOOKUP_PHRASES = (
    "what they", "they sent", "they just sent", "sent me", "sent back",
    "the difference", "difference", "usual", "usually", "increased", "increase",
    "percent", "vat", "additional", "what i usually", "too little", "too much",
)
# file / standing-order references (own-data source for recipient and/or amount).
_FILE_OR_ORDER_PHRASES = (
    ".txt", "file", "bill ", "the bill", "landlord", "notice", "standing order",
    "scheduled", "recurring", "rent",
)
# vague-only references that do NOT pin a value (mark DD when nothing concrete else).
_VAGUE_PHRASES = ("like last month", "accordingly", "as last", "for the next month")


def _amount_strings(amount_cents: int) -> list[str]:
    """Plausible textual forms of an amount, for a literal PROMPT-substring check."""
    whole = amount_cents / 100.0
    forms = {f"{whole:.2f}", f"{whole:g}"}
    if amount_cents % 100 == 0:                       # 1000.00 -> also "1000"
        forms.add(str(amount_cents // 100))
    return [f for f in forms if f]


class BankingBucketClassifier:
    """Deterministic DI/DIQ/DD over (prompt, GT recipient, GT amount, clean env)."""

    def recipient_source(self, prompt: str, recipient: str, env) -> str:
        p = prompt.upper()
        if recipient and str(recipient).upper() in p:
            return LITERAL
        pl = prompt.lower()
        # a file / standing-order reference can carry the recipient (own-data source).
        if any(ph in pl for ph in _FILE_OR_ORDER_PHRASES):
            return RESOLVABLE
        # a payee name in the prompt that maps to this recipient in OWN history.
        if self._payee_name_maps_to(prompt, recipient, env):
            return RESOLVABLE
        # the recipient is an own counterparty referenced indirectly ("my friend").
        if self._is_own_counterparty(recipient, env) and \
                any(w in pl for w in ("friend", "refund", "sent", "they", "back")):
            return RESOLVABLE
        return UNRESOLVABLE

    def amount_source(self, prompt: str, amount_cents: int) -> str:
        pl = prompt.lower()
        for s in _amount_strings(amount_cents):
            if s and s in pl:
                return LITERAL
        if any(ph in pl for ph in _AMOUNT_LOOKUP_PHRASES):
            return RESOLVABLE
        if any(ph in pl for ph in _FILE_OR_ORDER_PHRASES) and \
                not all(v in pl for v in _VAGUE_PHRASES):
            # a file/order reference that carries an amount, unless purely vague.
            if ".txt" in pl or "file" in pl or "notice" in pl or "standing order" in pl:
                return RESOLVABLE
        return UNRESOLVABLE

    def classify(self, prompt: str, recipient: str, amount_cents: int, env) -> tuple[str, ValueSources]:
        src = ValueSources(
            recipient=self.recipient_source(prompt, recipient, env),
            amount=self.amount_source(prompt, amount_cents),
        )
        return bucket_from_sources(src), src

    # -- helpers over the principal's OWN history --

    def _own_rows(self, env):
        try:
            acct = env.bank_account
        except AttributeError:
            return []
        return list(acct.transactions) + list(acct.scheduled_transactions)

    def _is_own_counterparty(self, recipient: str, env) -> bool:
        r = str(recipient).upper()
        for row in self._own_rows(env):
            if str(row.sender).upper() == r or str(row.recipient).upper() == r:
                return True
        return False

    def _payee_name_maps_to(self, prompt: str, recipient: str, env) -> bool:
        """Does the PROMPT name a payee whose own-history subject maps to `recipient`?"""
        r = str(recipient).upper()
        words = set(re.findall(r"[A-Za-z]{4,}", prompt.lower()))
        for row in self._own_rows(env):
            if str(row.recipient).upper() != r:
                continue
            subj = str(row.subject).lower()
            if any(w in subj for w in words):
                return True
        return False
