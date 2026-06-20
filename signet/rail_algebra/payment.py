"""The payment COMPOSITION stub — names the unexercised variants so the algebra's three axes are
each instantiated by at least one composition (payment is the only one forcing Quantitative +
MeteredLedger + KeyholderBroker).

There is no payment RAIL (DESIGN/CLAUDE.md: a real PSP is out of scope). This is a composition stub:
constructing it is meaningful (it proves the axes compose), but its Bind/Door raise if driven (the
atomic ledger and the live broker minter are named, not built). `test_payment_stub_instantiates`
asserts construction + `describe()` only.
"""
from __future__ import annotations

from .bind import MeteredLedger
from .door import KeyholderBroker
from .policy import Quantitative
from .types import Composition


def payment_composition(*, cap_cents: int = 50_00) -> Composition:
    """Quantitative (threshold over a spend aggregate) × MeteredLedger (atomic debit) × KeyholderBroker
    (the enforcer mints a scoped, effect-bound credential). All three are the STUB ends of their axes."""
    return Composition(
        policy=Quantitative(name="payment_cap", feature="amount_cents", cap=cap_cents),
        bind=MeteredLedger(ledger="spend-ledger(unbuilt)"),
        door=KeyholderBroker(mint=None),
        name="payment",
    )
