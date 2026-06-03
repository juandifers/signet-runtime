"""Role 2 demo -- rail-agnostic guardrail (credential custody).

    python -m demos.role2_demo
"""
from signet.builder import make_env, build_chain
from signet.authorizers.mock_broker import MockCredentialBroker
from signet.receipts import ReceiptLog


def line(c="-"):
    print(c * 68)


def run_case(title, env, broker, log, **overrides):
    line()
    print(f"CASE: {title}")
    req = build_chain(env, **overrides)
    decision, token = env.verifier.evaluate(req)
    print(f"  verifier decision : {decision.decision.upper()}  ({decision.reason})")
    if not decision.approved:
        log.append(execution_id="-", mandate_id=req.intent.mandate_id,
                   chain_hash=decision.chain_hash or "-", policy_id="treasury_policy_v1",
                   decision="blocked", payment_status="not_executed",
                   payment_ref=None, rail=req.context.rail)
        print("  authorizer        : NOT CALLED (no token issued)")
        print("  payment_ref       : none")
        return
    result = broker.authorize(token, req)
    receipt = log.append(execution_id=token.execution_id, mandate_id=token.mandate_id,
                         chain_hash=token.chain_hash, policy_id="treasury_policy_v1",
                         decision="approved",
                         payment_status="executed" if result.executed else "failed",
                         payment_ref=result.payment_ref, rail=result.rail)
    print(f"  authorizer        : {'EXECUTED' if result.executed else 'REFUSED'}  ({result.reason})")
    print(f"  payment_ref       : {result.payment_ref}")
    print(f"  receipt           : {receipt.receipt_id}  hash={receipt.receipt_hash[:16]}...")


def main():
    env = make_env()
    broker = MockCredentialBroker(env.verifier, env.enforcer_vk)
    log = ReceiptLog(env.enforcer_sk, env.enforcer_vk)

    print("\nSIGNET RUNTIME -- Role 2 (rail-agnostic credential custody)\n")
    run_case("Valid invoice payment (vendor_abc, EUR 4,800)", env, broker, log)
    run_case("Over-limit (EUR 7,500 > cap 5,000)", env, broker, log, amount=7500)
    run_case("Recipient/destination substitution (redirect to attacker)",
             env, broker, log, ctx_destination="attacker_account")
    run_case("Cart-substitution (Payment commits to a stale Cart)",
             env, broker, log, break_linkage=True)

    line("=")
    print("RECEIPT LOG (append-only, hash-chained, enforcer-signed)")
    for r in log.all():
        ok, _ = log.verify(r)
        print(f"  {r.receipt_id}  {r.decision:8}  {r.payment_status:13}  "
              f"ref={r.payment_ref or '-':18}  verify={ok}")
    line("=")


if __name__ == "__main__":
    main()
