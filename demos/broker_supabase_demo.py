"""A reproducible transcript of the Supabase keyholder slice (DESIGN.md P7/P8).

Runs the REAL broker against the offline resource simulator and prints, in order:
  honest request -> granted JWT (claims + exp) -> resource accepts -> receipt;
  out-of-mandate request -> refused -> ConsideredRejected receipt;
  forged JWT -> rejected by the resource;
  the search_path/rephrase trick -> rejected at the DB by the credential's role;
  the P8 negative: a leaked standing credential bypasses the broker (advisory-only).

Everything shown is produced by the shipped code at run time; no verdict is authored here.

Run:  python -m demos.broker_supabase_demo
"""
from __future__ import annotations

import datetime as _dt
import os
import tempfile

from signet.broker.mandate import (DbGrant, MandateProvider, StandingPolicy,
                                    TaskMandate)
from signet.broker.protocol import CapabilityRequest
from signet.broker.server import Broker
from signet.cli.local_receipts import LocalReceiptLog
from signet.rails.supabase.es256 import Es256Error, Es256Key, verify_jwt
from signet.rails.supabase.resource_sim import (PostgresDirect, Store,
                                                SupabaseGateway,
                                                SupabaseResourceError)
from signet.rails.supabase.roles import default_grants

T0 = _dt.datetime(2026, 6, 11, 12, 0, 0, tzinfo=_dt.timezone.utc)
PUBLISHABLE = "sb_publishable_demo"
AGENT_UID = os.getuid() + 1   # the agent is a separate OS user than the broker


def _line(s: str = "") -> None:
    print(s)


def main() -> int:
    os.environ.setdefault("SIGNET_HOME", tempfile.mkdtemp(prefix="signet_broker_demo_"))
    clock = lambda: T0

    mandates = MandateProvider()
    mandates.register(TaskMandate(
        task_id="task-001", database="app",
        grants=(DbGrant("staging", "analytics_events", ("select", "delete")),)))
    standing = StandingPolicy(grants=(
        DbGrant("staging", "*", ("select", "insert", "update", "delete")),
        DbGrant("prod", "*", ("select",))))
    minter = Es256Key.generate()
    receipts = LocalReceiptLog("broker:app:demo")
    broker = Broker.create(mandates=mandates, standing=standing, receipts=receipts,
                           minter=minter, clock=clock, ttl_seconds=60)

    store = Store(tables={
        ("staging", "analytics_events"): [{"id": 1, "evt": "click"}, {"id": 2, "evt": "view"}],
        ("prod", "users"): [{"id": 1, "email": "ceo@corp.com", "ssn": "***-**-1234"}]})
    gateway = SupabaseGateway(jwks=minter.jwks(),
                              grants=default_grants(["staging"], ["staging"]),
                              store=store, clock=clock)

    _line("=" * 78)
    _line("SIGNET BROKER — Supabase credential rail (keyholder slice, DESIGN.md P7/P8)")
    _line(f"  broker uid={os.getuid()}  agent uid={AGENT_UID} (separate OS principal)")
    _line("  frozen task mandate task-001: staging.analytics_events {select,delete}")
    _line("  agent holds ONLY the publishable key; no secret key, no signing key, no DSN")
    _line("=" * 78)

    def request(schema, table, op, label):
        r = broker.handle_request(CapabilityRequest(
            "db.query", {"database": "app", "schema": schema, "table": table, "op": op},
            "task-001"), AGENT_UID)
        _line()
        _line(f"[{label}] request: {op} {schema}.{table}")
        _line(f"   granted   : {r.granted}")
        _line(f"   cause     : {r.cause}")
        _line(f"   receipt   : {r.receipt_id}")
        if r.granted:
            _line(f"   capability: {r.capability[:48]}...  (ES256 JWT)")
            _line(f"   expires_at: {r.expires_at}")
            claims = verify_jwt(r.capability, minter.jwks(), now=T0)
            _line(f"   claims    : role={claims['role']} sub={claims['sub']} "
                  f"iss={claims['iss']} exp={claims['exp']}")
        return r

    # 1. honest path
    honest = request("staging", "analytics_events", "delete", "HONEST")
    out = gateway.request(apikey=PUBLISHABLE, bearer_jwt=honest.capability,
                          schema="staging", table="analytics_events", op="delete", now=T0)
    _line(f"   resource  : ACCEPTED via {out['via']} (deleted={out['deleted']}, "
          f"role={out['role']})")

    # 2. out-of-mandate
    request("prod", "users", "select", "OUT-OF-MANDATE")

    # 3. forge
    rogue = Es256Key.generate()
    forged = rogue.mint_jwt({"role": "signet_staging_rw", "sub": "task-001",
                             "iss": "signet-broker"}, now=T0, ttl_seconds=60)
    _line()
    _line("[FORGE] agent fabricates its own JWT (it holds no signing key)")
    try:
        gateway.request(apikey=PUBLISHABLE, bearer_jwt=forged, schema="staging",
                        table="analytics_events", op="select", now=T0)
        _line("   resource  : ACCEPTED  <-- UNEXPECTED")
    except SupabaseResourceError as e:
        _line(f"   resource  : REJECTED ({e})")

    # 4. rephrase / search_path with a valid staging credential
    legit = request("staging", "analytics_events", "select", "REPHRASE/SEARCH_PATH")
    _line("   ... now use that VALID staging JWT to try prod.users:")
    try:
        gateway.request(apikey=PUBLISHABLE, bearer_jwt=legit.capability, schema="prod",
                        table="users", op="select", now=T0)
        _line("   resource  : ACCEPTED  <-- UNEXPECTED")
    except SupabaseResourceError as e:
        _line(f"   resource  : REJECTED at the DB ({e})")

    # 9. P8 negative — leaked standing credential bypasses the broker
    _line()
    _line("[P8 NEGATIVE] a standing elevated credential (DSN) is left in the agent env")
    leaked = {"DATABASE_URL": "postgres://service_role:secret@db.project.supabase.co:5432/postgres"}
    direct = PostgresDirect.from_env(leaked, store)
    pii = direct.query("prod", "users", "select")
    _line(f"   bypass    : SUCCEEDS via {pii['via']} — read {len(pii['rows'])} prod.users row(s) "
          f"with NO broker capability")
    _line("   => the broker is only ADVISORY without an OS only-door (honest containment, P8)")

    _line()
    ok, msg, _ = receipts.verify()
    _line(f"RECEIPTS: {msg} -> verify ok={ok}")
    _line("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
