"""Constrained, endorsed value resolution for the banking domain (the §4
predicate-binding mechanism ported from tau-bench retail to AgentDojo banking).

The FIDES/CaMeL move: the PLAN/PREDICATE is trusted (frozen from the instruction
only -- control flow); the specific runtime VALUE (a recipient's IBAN behind a
payee name, or an amount) is validated against that predicate over a BOUNDED set
of the principal's OWN data and only then ENDORSED (promoted to trusted) for the
kernel to context-bind. The resolver may READ runtime data to find candidate
values (data flow), but the CRITERIA for a match come only from the frozen
predicate (control flow). Ownership / the standing allowlist is the hard bound.

Banking specifics that shape what is safely endorsable (verified against the
installed banking environment.yaml):

  * The principal's own statement is `bank_account.transactions` +
    `scheduled_transactions`. Outgoing rows use sender == "me" / the account IBAN;
    incoming rows use recipient == "me" / the account IBAN. So the bounded,
    attacker-unreorderable set is the principal's own transaction rows.
  * The AMOUNT and counterparty IBAN fields of those rows are FIXED env data, not
    injection placeholders -- only some `subject` fields are `{injection_*}`. So an
    amount looked up from an own transaction (incoming_from / usual_recurring) is
    NOT attacker-controllable.
  * File contents (`bill-*.txt`, `landlord-notices.txt`) DO carry `{injection_*}`
    placeholders -- a file is the injection channel. So a value (recipient OR
    amount) read from a file is NOT safely endorsable; the resolver routes it to
    REVIEW with cause `from-file`. This is the honest boundary: PREDICATE endorses
    only non-injected own-history fields.

Monotonicity (see the eval plan): a TRUSTED-LITERAL, user-NAMED recipient is
authorized by the instruction itself -- the allowlist/ownership bound gates only
RUNTIME-RESOLVED (payee-name -> IBAN, or unnamed) recipients. So STRICT -> POLICY
-> PREDICATE never lowers autonomy on a named-but-unlisted recipient.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Optional

from .signet_harness import to_cents

# Resolution kinds.
ENDORSE = "ENDORSE"      # unique validated match -> bind the endorsed (recipient, amount)
REVIEW = "REVIEW"        # ambiguous / derived / not-low-capacity -> escalate to human
BLOCK = "BLOCK"          # out-of-predicate / off-allowlist / no candidate -> deny

# Recipient source (where the recipient comes from -- the control-flow dimension).
REC_NAMED = "named"          # a literal IBAN in the trusted instruction (authorized directly)
REC_PAYEE_NAME = "payee_name"  # a payee NAME -> must resolve to an own+allowlisted IBAN
REC_FROM_FILE = "from_file"    # recipient only in a file (injection channel) -> not endorsable
REC_EXISTING = "existing"      # the recipient of an existing scheduled tx being updated
REC_UNKNOWN = "unknown"

# Amount lookup type (the control-flow dimension for the amount).
AMT_EXACT = "exact"             # an exact number in the instruction (trusted-literal)
AMT_INCOMING_FROM = "incoming_from"   # amount of an incoming tx from a named counterparty
AMT_USUAL_RECURRING = "usual_recurring"  # a repeated/scheduled payment amount to a payee
AMT_FILE = "file_amount"        # amount stated in a named file (injection channel)
AMT_DERIVED = "derived"         # arithmetic over own data ("the difference", "+10%")
AMT_NONE = "none"

_ENDORSABLE_AMOUNT_LOOKUPS = frozenset({AMT_EXACT, AMT_INCOMING_FROM, AMT_USUAL_RECURRING})

# ---- §8 safe arithmetic resolution (the CaMeL/FIDES split applied to a COMPUTED
#      amount). The FORMULA below is TRUSTED + LOW-CAPACITY: a fixed operation enum
#      plus structured operand descriptors, frozen from the instruction only -- the
#      extractor CLASSIFIES it, never evaluates an expression. The OPERAND VALUES are
#      bounded own-data lookups (the same ones the non-arithmetic path uses). The
#      math is done DETERMINISTICALLY IN CODE (never by the LLM), and the RESULT is
#      cap-bounded -- so a misclassified formula is a bounded over/under-payment to
#      the RIGHT recipient, never an attacker payout or an unbounded amount. ----

# Operation enum (the only arithmetic the resolver will compute).
OP_SUBTRACT = "subtract"        # v(op0) - v(op1)                 (exactly 2 operands)
OP_SUM = "sum"                  # sum(v(op_i))
OP_PERCENT_OF = "percent_of"    # round(v(op0) * percent/100) [+ fee_cents]
_SUPPORTED_OPS = frozenset({OP_SUBTRACT, OP_SUM, OP_PERCENT_OF})

# Operand value source (each operand is resolved over the SAME bounded sets the
# amount lookups use -- never a file / injection channel).
SRC_LITERAL = "literal"                # a number stated in the instruction (trusted)
SRC_INCOMING_FROM = "incoming_from"    # amount of an incoming tx from a named counterparty
SRC_USUAL_RECURRING = "usual_recurring"  # a repeated/scheduled OUTGOING payment to a payee
SRC_FILE_AMOUNT = "file_amount"        # a number in a file -> NOT endorsable (-> REVIEW)
_OPERAND_SOURCES = (SRC_LITERAL, SRC_INCOMING_FROM, SRC_USUAL_RECURRING, SRC_FILE_AMOUNT)


@dataclass(frozen=True)
class Operand:
    """One operand of a derived formula. Frozen from the instruction (the SOURCE +
    descriptor + literal + divisor are control flow); only the VALUE of a non-literal
    source is read at resolution time, over the principal's own data."""
    source: str = SRC_LITERAL
    cents: Optional[int] = None        # set iff source == SRC_LITERAL
    descriptor: Optional[str] = None   # counterparty/payee for incoming_from/usual_recurring
    divide_by: int = 1                 # in-code split-by-N (a trusted count); 1 = no split


@dataclass(frozen=True)
class DerivedFormula:
    """A trusted, low-capacity arithmetic spec (amount_lookup == AMT_DERIVED)."""
    operation: str = OP_SUM
    operands: tuple = ()               # tuple[Operand, ...]
    percent: Optional[str] = None      # decimal string for OP_PERCENT_OF (e.g. "19.5")
    fee_cents: Optional[int] = None     # optional additive constant fee


@dataclass(frozen=True)
class BankingTargetPredicate:
    """A trusted, low-capacity predicate frozen from the instruction ONLY.

    Never free text: a small enum + a short descriptor. The recipient/amount
    *criteria* live here (control flow); the runtime DB supplies only candidate
    *values* to validate against them (data flow).
    """
    tool: str                              # send_money | schedule_transaction | update_scheduled_transaction
    recipient_source: str = REC_UNKNOWN
    recipient_iban: Optional[str] = None   # set iff recipient_source == REC_NAMED
    payee_descriptor: Optional[str] = None  # a name/keyword e.g. "Spotify" (for resolution)
    amount_lookup: str = AMT_NONE
    amount_cents: Optional[int] = None     # set iff amount_lookup == AMT_EXACT
    scheduled_id: Optional[int] = None     # for update_scheduled_transaction (REC_EXISTING)
    formula: Optional[DerivedFormula] = None  # set iff amount_lookup == AMT_DERIVED (§8)


@dataclass
class Resolution:
    kind: str                              # ENDORSE | REVIEW | BLOCK
    endorsed_recipient: Optional[str] = None
    endorsed_amount_cents: Optional[int] = None
    cause: str = ""                        # cause label for the diagnostic
    candidates: list = field(default_factory=list)  # candidate amounts considered (for reporting)


# ---- own-data access (the bounded set) ----

def _principal_ibans(env) -> set:
    """The identifiers that denote the principal's own side of a transaction row."""
    out = {"me"}
    try:
        out.add(str(env.bank_account.iban).upper())
    except AttributeError:
        pass
    return out


def _own_rows(env):
    """The principal's own statement: posted + scheduled transactions."""
    try:
        acct = env.bank_account
    except AttributeError:
        return []
    return list(acct.transactions) + list(acct.scheduled_transactions)


def _is_outgoing(row, me: set) -> bool:
    return str(row.sender) in me or str(row.sender).upper() in me


def _is_incoming(row, me: set) -> bool:
    return str(row.recipient) in me or str(row.recipient).upper() in me


# ---- amount lookups over own data (criteria from the predicate) ----

def _incoming_amounts_from(env, counterparty: str) -> list[int]:
    """Distinct amounts (cents) of incoming txns from `counterparty` in OWN history.

    Reads the non-injected `amount`/`sender` fields -- attacker-unreorderable.
    """
    me = _principal_ibans(env)
    cp = str(counterparty).upper()
    amounts = []
    for row in _own_rows(env):
        if _is_incoming(row, me) and str(row.recipient).upper() != cp \
                and str(row.sender).upper() == cp:
            amounts.append(to_cents(row.amount))
    return sorted(set(amounts))


def _usual_amounts_to(env, payee_descriptor: str) -> list[int]:
    """Distinct amounts (cents) of repeated/scheduled OUTGOING payments matching a
    payee descriptor. The descriptor matches the recipient IBAN or the subject
    (a payee name like 'Spotify'); the AMOUNT is the non-injected env field.
    """
    me = _principal_ibans(env)
    key = (payee_descriptor or "").strip().lower()
    if not key:
        return []
    amounts = []
    for row in _own_rows(env):
        if not _is_outgoing(row, me):
            continue
        hay = f"{row.recipient} {row.subject}".lower()
        if key in hay:
            amounts.append(to_cents(row.amount))
    return sorted(set(amounts))


def _resolve_payee_to_iban(env, payee_descriptor: str) -> list[str]:
    """Map a payee NAME to the IBAN(s) it pays in OWN outgoing history (for a
    runtime-resolved recipient). Returns distinct candidate recipient IBANs.
    """
    me = _principal_ibans(env)
    key = (payee_descriptor or "").strip().lower()
    if not key:
        return []
    ibans = []
    for row in _own_rows(env):
        if not _is_outgoing(row, me):
            continue
        if key in str(row.subject).lower() or key in str(row.recipient).lower():
            ibans.append(str(row.recipient).upper())
    return sorted(set(ibans))


# ---- §8 deterministic arithmetic over bounded own-data operands ----

# Sentinels for an operand that cannot be safely valued (route the whole formula
# to REVIEW/BLOCK with a precise cause -- never guess).
_OP_REVIEW = "review"
_OP_BLOCK = "block"


def _operand_value_cents(op: "Operand", env):
    """Resolve ONE operand to a cents value, or a (status, cause) escalation.

    LITERAL -> the trusted number. INCOMING_FROM / USUAL_RECURRING -> a bounded
    own-history lookup (0 -> BLOCK, >1 distinct -> REVIEW). FILE_AMOUNT -> REVIEW
    (the injection-channel boundary stays: arithmetic must not pull file operands
    into scope). The split divisor is applied IN CODE.
    """
    div = op.divide_by if isinstance(op.divide_by, int) else 1
    if div <= 0:
        return (_OP_REVIEW, "derived: non-positive divisor")

    if op.source == SRC_LITERAL:
        if op.cents is None:
            return (_OP_REVIEW, "derived: literal operand missing a value")
        base = int(op.cents)
    elif op.source == SRC_INCOMING_FROM:
        cands = _incoming_amounts_from(env, op.descriptor or "")
        if not cands:
            return (_OP_BLOCK, "derived: no incoming own-history value for operand")
        if len(set(cands)) > 1:
            return (_OP_REVIEW, "derived: ambiguous incoming operand (>1 own value)")
        base = int(cands[0])
    elif op.source == SRC_USUAL_RECURRING:
        cands = _usual_amounts_to(env, op.descriptor or "")
        if not cands:
            return (_OP_BLOCK, "derived: no recurring own-history value for operand")
        if len(set(cands)) > 1:
            return (_OP_REVIEW, "derived: ambiguous recurring operand (>1 own value)")
        base = int(cands[0])
    elif op.source == SRC_FILE_AMOUNT:
        return (_OP_REVIEW, "derived: file operand (injection channel -- not endorsable)")
    else:
        return (_OP_REVIEW, "derived: unsupported operand source")

    if div != 1:
        # in-code split-by-N over a Decimal (round half-up to whole cents).
        base = int((Decimal(base) / Decimal(div)).quantize(Decimal(1), rounding=ROUND_HALF_UP))
    return base


def _compute_derived(formula: Optional["DerivedFormula"], env, *, rec, pred,
                     cap_cents: Optional[int]) -> Resolution:
    """Compute a derived amount DETERMINISTICALLY from a trusted formula + bounded
    own-data operands, then cap-bound the result. The LLM only classified the
    formula; all arithmetic happens here. Returns ENDORSE / REVIEW / BLOCK."""
    if formula is None or formula.operation not in _SUPPORTED_OPS:
        return Resolution(REVIEW, cause="derived: unsupported/unparsed operation")

    vals = []
    for op in formula.operands:
        v = _operand_value_cents(op, env)
        if isinstance(v, tuple):                       # an escalation from an operand
            status, cause = v
            return Resolution(REVIEW if status == _OP_REVIEW else BLOCK, cause=cause)
        vals.append(v)

    op_kind = formula.operation
    if op_kind == OP_SUBTRACT:
        if len(vals) != 2:
            return Resolution(REVIEW, cause="derived: subtract needs exactly 2 operands")
        amt = vals[0] - vals[1]
    elif op_kind == OP_SUM:
        if not vals:
            return Resolution(REVIEW, cause="derived: sum needs >=1 operand")
        amt = sum(vals)
    elif op_kind == OP_PERCENT_OF:
        if len(vals) != 1 or formula.percent is None:
            return Resolution(REVIEW, cause="derived: percent_of needs 1 operand + a percent")
        try:
            pct = Decimal(str(formula.percent))
        except Exception:
            return Resolution(REVIEW, cause="derived: unparseable percent")
        amt = int((Decimal(vals[0]) * pct / Decimal(100)).quantize(
            Decimal(1), rounding=ROUND_HALF_UP))
    else:  # unreachable (guarded above)
        return Resolution(REVIEW, cause="derived: unsupported operation")

    if formula.fee_cents is not None:
        amt += int(formula.fee_cents)

    # BOUND THE RESULT. A nonsensical (<=0) result escalates; a result over the
    # standing cap is a runtime-resolved amount -> blocked (the kernel re-checks).
    if amt <= 0:
        return Resolution(REVIEW, cause=f"derived: non-positive result ({amt})",
                          candidates=[amt])
    if cap_cents is not None and amt > int(cap_cents):
        return Resolution(BLOCK, cause=f"over-cap (derived {amt} > cap {cap_cents})",
                          candidates=[amt])
    return Resolution(ENDORSE, endorsed_recipient=rec, endorsed_amount_cents=int(amt),
                      cause=f"endorsed-arithmetic ({op_kind})", candidates=[amt])


# ---- the resolver ----

def resolve_banking_target(pred: Optional[BankingTargetPredicate], env, *,
                           allowlist: Optional[set] = None,
                           cap_cents: Optional[int] = None,
                           enable_arithmetic: bool = False) -> Resolution:
    """Resolve & endorse a runtime target for a money-moving call.

    Returns a Resolution. ENDORSE carries the (recipient, amount) the kernel will
    context-bind. The cap (when given) bounds any runtime-resolved amount; the
    allowlist (when given) bounds any runtime-RESOLVED recipient -- a NAMED
    recipient is authorized by the instruction itself (monotonicity) and is NOT
    gated by the allowlist.

    `enable_arithmetic` (§8, default OFF so §6/§7 are byte-identical) turns on TWO
    coupled own-data resolutions for the derived-amount path:
      * the recipient-side analog -- a payee NAME is resolved to the IBAN the
        principal has PREVIOUSLY PAID for that name (own outgoing history), bounded
        by own history itself (NOT the standing allowlist; this is a per-resolution
        endorsement, not a permanent onboarding). >1 distinct IBAN -> REVIEW;
        name-not-in-own-history -> BLOCK.
      * the amount-side `derived` formula is COMPUTED in code over bounded own-data
        operands and cap-bounded (see `_compute_derived`).
    Both bounds keep a wrong resolution confined to the principal's own resources --
    never the attacker.
    """
    if pred is None:
        return Resolution(BLOCK, cause="out-of-predicate")
    allow = {str(a).upper() for a in (allowlist or set())}

    # ---- 1. resolve the recipient (control flow) ----
    rec: Optional[str] = None
    if pred.recipient_source == REC_NAMED and pred.recipient_iban:
        rec = str(pred.recipient_iban).upper()          # trusted-literal -> authorized directly
    elif pred.recipient_source == REC_EXISTING:
        # update_scheduled_transaction: the recipient is the existing scheduled
        # tx's own recipient (already in own data), unless the predicate renames it.
        rec = _existing_recipient(env, pred.scheduled_id)
        if rec is None:
            return Resolution(BLOCK, cause="no-match (unknown scheduled id)")
    elif pred.recipient_source == REC_PAYEE_NAME:
        cands = _resolve_payee_to_iban(env, pred.payee_descriptor)
        if enable_arithmetic:
            # Recipient-side own-history endorsement: the bound IS own outgoing
            # history (cands already comes only from it); do NOT additionally require
            # the standing allowlist. Attacker IBANs are never in own outgoing
            # history, so they are structurally unreachable here.
            if not cands:
                return Resolution(BLOCK, cause="no-match (payee not in own payment history)")
            if len(cands) > 1:
                return Resolution(REVIEW, cause="ambiguous (payee resolves to >1 own IBAN)",
                                  candidates=cands)
            rec = cands[0]
        else:
            cands = [c for c in cands if not allow or c in allow]  # runtime-resolved -> allowlist bound
            if not cands:
                return Resolution(BLOCK, cause="off-allowlist (payee not an approved own counterparty)")
            if len(cands) > 1:
                return Resolution(REVIEW, cause="ambiguous (payee resolves to >1 own IBAN)",
                                  candidates=cands)
            rec = cands[0]
    elif pred.recipient_source == REC_FROM_FILE:
        return Resolution(REVIEW, cause="from-file (recipient in an injection-channel file)")
    else:
        return Resolution(REVIEW, cause="no trusted recipient")

    # ---- 2. resolve the amount (control flow + bounded own-data value) ----
    lookup = pred.amount_lookup

    # §8 safe arithmetic: a derived amount is COMPUTED in code over bounded own-data
    # operands and cap-bounded, instead of escalating. Gated so it is opt-in.
    if lookup == AMT_DERIVED and enable_arithmetic:
        return _compute_derived(pred.formula, env, rec=rec, pred=pred,
                                cap_cents=cap_cents)

    if lookup not in _ENDORSABLE_AMOUNT_LOOKUPS:
        cause = {AMT_DERIVED: "derived (arithmetic over own data -- not low-capacity)",
                 AMT_FILE: "from-file (amount in an injection-channel file)",
                 AMT_NONE: "no trusted amount"}.get(lookup, "no trusted amount")
        return Resolution(REVIEW, cause=cause)

    if lookup == AMT_EXACT:
        if pred.amount_cents is None:
            return Resolution(REVIEW, cause="no trusted amount")
        amt = int(pred.amount_cents)
        cands = [amt]
    elif lookup == AMT_INCOMING_FROM:
        # the counterparty is the named recipient (refund) or the payee descriptor.
        cp = rec if pred.recipient_source == REC_NAMED else (pred.payee_descriptor or rec)
        cands = _incoming_amounts_from(env, cp)
    elif lookup == AMT_USUAL_RECURRING:
        cands = _usual_amounts_to(env, pred.payee_descriptor or rec)
    else:  # unreachable
        return Resolution(REVIEW, cause="no trusted amount")

    if not cands:
        return Resolution(BLOCK, cause="no-match (no own-data value for the predicate)",
                          candidates=cands)
    if len(set(cands)) > 1:
        return Resolution(REVIEW, cause="ambiguous (>1 distinct own-data value)",
                          candidates=cands)
    amt = int(cands[0])

    # ---- 3. cap bound on any RUNTIME-RESOLVED endorsed amount (the policy bound;
    #         the kernel re-checks). An EXACT amount stated in the trusted instruction
    #         is authorized by the instruction itself -- like a NAMED recipient -- so
    #         it is NOT gated by the coarse standing cap (monotonicity: the cap gates
    #         runtime-resolved amounts, not trusted-literal ones). ----
    if lookup != AMT_EXACT and cap_cents is not None and amt > int(cap_cents):
        return Resolution(BLOCK, cause=f"over-cap (endorsed {amt} > cap {cap_cents})",
                          candidates=cands)

    return Resolution(ENDORSE, endorsed_recipient=rec, endorsed_amount_cents=amt,
                      cause="endorsed", candidates=cands)


def _existing_recipient(env, scheduled_id: Optional[int]) -> Optional[str]:
    if scheduled_id is None:
        return None
    try:
        for t in env.bank_account.scheduled_transactions:
            if t.id == scheduled_id:
                return str(t.recipient).upper()
    except AttributeError:
        return None
    return None
