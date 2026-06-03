# Signet Runtime — Interface Inventory (read-only)

> Read-only audit. No code/config/git changes were made. Signatures and type
> definitions are quoted verbatim (function bodies elided with `...`). Where a
> requested surface is named differently from the prompt, the divergence is noted
> inline and again in **GAPS**. CLAUDE.md is treated as the source of truth for
> naming/invariants; code↔doc disagreements are reported, not reconciled.

---

## 0. REPO MAP & ENVIRONMENT

### Kernel (`signet/`) — 2-level tree
```
signet/
├── __init__.py
├── api.py            FastAPI surface (mock broker only)
├── builder.py        make_env() + build_chain() (tests/demos mint signed chains)
├── canonical.py      sorted-keys JSON + hash_obj
├── chain.py          hashing + linkage + context binding
├── crypto.py         Ed25519 sign/verify + KeyStore
├── models.py         Intent/Cart/Payment + Runtime/Decision/Token/Receipt
├── nonce.py          SQLite atomic consume-once
├── policy.py         caps/allowlist/currency/velocity/human-approval
├── receipts.py       hash-chained signed receipts
├── revocation.py     in-memory revoked-mandate set
├── verifier.py       the 11-step kernel
└── authorizers/
    ├── base.py           Authorizer ABC + AuthorizationResult
    ├── mock_broker.py    Role 2 — credential custody (the ONLY rail wired to api.py)
    ├── xrpl_cosigner.py  Role 1 — XRPL 2-of-2 multisign
    └── mpc_cosigner.py   Role 1b — 2-of-2 threshold Schnorr / MPC
```

### Brain (`evals/`) — 2-level tree
```
evals/
├── __init__.py
├── agentdojo/
│   ├── intent_provider.py    AuthorizedIntentProvider + 4 concrete providers, StandingPolicy
│   ├── resolve.py            BankingTargetPredicate + resolve_banking_target (§4 predicate)
│   ├── effects.py            GENERIC (effect_class,target_id) adapter (docstring calls it §6)
│   ├── domains.py            EffectDomainSpec + Workspace/Slack/Travel specs + DOMAINS registry
│   ├── taxonomy.py           DI/DIQ/DD bucket classifier
│   ├── gate.py               SignetGatedToolsExecutor + MODE_STRICT/POLICY/PREDICATE
│   ├── diagnostic.py         plan-time + lean rollout diagnostic harness
│   ├── signet_harness.py     translates AgentDojo args -> Signet objects (uses real kernel)
│   ├── pipelines.py          build_pipelines / load_dotenv / extractor provider detect
│   ├── run.py                main eval runner
│   ├── extractor_reliability.py, smoke_*.py  reliability + smoke probes
│   └── .runs/, FINDINGS.md, README.md
└── tau_bench/
    ├── retail_intent.py, gate.py, resolve.py, signet_retail_harness.py
    ├── run.py, tau_path.py, smoke_test.py, FINDINGS.md, README.md
    └── __init__.py
```

### Environment / tooling (from `pyproject.toml`)
- **Python**: `requires-python = ">=3.10"`.
- **Pydantic**: `"pydantic>=2"` (models use Pydantic v2: `model_dump(mode="json", exclude=...)`).
- **Test runner**: `pytest>=8` (dev extra). Config: `[tool.pytest.ini_options] pythonpath=["."]`, `testpaths=["tests"]`. Invoke: `pytest -v`.
- **HTTP**: `fastapi>=0.110`, `uvicorn>=0.29` (server `signet/api.py`).
- **GitHub client**: **NOT FOUND** — no `gh`/`requests`/GitHub SDK in dependencies. The only network client is `xrpl-py>=4` (XRPL JSON-RPC, used offline in tests). Eval extractors import `openai` / `anthropic` lazily inside factory functions (not declared in `pyproject.toml`).

---

## 1. `ExecutionRequest` — the full model + `context` structure

`signet/models.py:100-105`
```python
class ExecutionRequest(BaseModel):
    request_id: str
    intent: IntentMandate
    cart: CartMandate
    payment: PaymentMandate
    context: RuntimeContext
```

`context` is a **`RuntimeContext`** — `signet/models.py:81-97`. This is where a new effect type would ride (today it is payment-shaped):
```python
class RuntimeContext(BaseModel):
    """What the agent actually presents at the moment of execution.

    The verifier reconstructs a context hash from these fields and requires it
    to match the context the Cart committed to. This is what catches
    recipient/destination substitution and cross-context replay.
    """
    task_id: str
    agent_id: str
    merchant_id: str
    scope: str
    action: str
    recipient: str
    amount: int
    currency: str
    destination_account: str
    rail: str
```
> Note: the kernel has **no generic effect field**. The eval brain rides new effect
> types over these payment fields by overloading `recipient = "{effect_class}:{target_id}"`
> and `amount = price_or_1` (see §7) — *no kernel edit*.

---

## 2. `Verifier.evaluate()` + `Decision` + `ExecutionToken`

`signet/verifier.py:70-71` (return type is a tuple, declared only in the docstring):
```python
def evaluate(self, req: ExecutionRequest):
    """Return (Decision, ExecutionToken | None)."""
    ...
```
Token verification entry point used by every authorizer — `signet/verifier.py:152-153`:
```python
def verify_token(self, token: ExecutionToken,
                 enforcer_verify_key: str) -> bool:
    """An authorizer calls this before producing any rail capability."""
    ...
```

`Decision` — `signet/models.py:108-118`:
```python
class Decision(BaseModel):
    decision: str                       # "approved" | "blocked"
    reason: str
    chain_hash: Optional[str] = None
    execution_id: Optional[str] = None
    nonce: Optional[str] = None
    expires_at: Optional[datetime] = None

    @property
    def approved(self) -> bool:
        return self.decision == "approved"
```

`ExecutionToken` — `signet/models.py:121-138`:
```python
class ExecutionToken(BaseModel):
    """The enforcer's signed, one-time, intent-bound authorization."""
    execution_id: str
    mandate_id: str
    chain_hash: str
    nonce: str
    expires_at: datetime
    status: str = "approved"
    signature: Optional[str] = None

    def signing_payload(self) -> dict:
        return self.model_dump(mode="json", exclude={"signature"})
```

---

## 3. THE EXACTNESS STEP (priority) — context-binding + exactness vs `req.context`

The "exactness" the prompt asks for is split across **step 7 (context binding)** and
**step 8 (exactness)** of the pipeline. Verbatim, those two steps only — `signet/verifier.py:111-122`:
```python
        # 7. Context binding: runtime context must match what the Cart committed to.
        if chain.context_hash_from_runtime(ctx) != chain.context_hash_from_cart(cart):
            return blocked("Execution context does not match the approved Cart "
                           "(recipient/destination/merchant substitution or context redirect).")

        # 8. Exactness: amount/currency at runtime == cart, and within Intent cap.
        if ctx.amount != cart.amount or ctx.currency != cart.currency:
            return blocked("Runtime amount/currency does not match the Cart.")
        if cart.amount > intent.max_amount or cart.currency != intent.currency:
            return blocked("Cart exceeds Intent amount/currency bound.")
        if cart.recipient not in intent.allowed_recipients:
            return blocked("Recipient not in Intent allowlist.")
```
What is bound: the context hash (`agent_id, merchant_id, action, recipient, amount, currency, destination_account`) of the **runtime** must equal that of the **Cart**; then runtime amount/currency must equal Cart; Cart must be within Intent cap/currency; Cart recipient must be on the Intent allowlist. The two context-hash helpers — `signet/chain.py:23-46`:
```python
def context_hash_from_cart(cart: CartMandate) -> str:
    """The context the Cart commits to."""
    return hash_obj({
        "agent_id": cart.agent_id,
        "merchant_id": cart.merchant_id,
        "scope_action": cart.action,
        "recipient": cart.recipient,
        "amount": cart.amount,
        "currency": cart.currency,
        "destination_account": cart.destination_account,
    })

def context_hash_from_runtime(ctx: RuntimeContext) -> str:
    """The context reconstructed from what the agent presents at execution."""
    return hash_obj({
        "agent_id": ctx.agent_id,
        "merchant_id": ctx.merchant_id,
        "scope_action": ctx.action,
        "recipient": ctx.recipient,
        "amount": ctx.amount,
        "currency": ctx.currency,
        "destination_account": ctx.destination_account,
    })
```

---

## 4. `chain_hash` + the AP2 mandate chain

`chain_hash` — `signet/chain.py:49-58`:
```python
def chain_hash(intent: IntentMandate, cart: CartMandate,
               payment: PaymentMandate) -> str:
    return hash_obj({
        "intent_hash": intent_hash(intent),
        "cart_hash": cart_hash(cart),
        "payment_id": payment.payment_id,
        "amount": payment.amount,
        "currency": payment.currency,
        "rail": payment.funding_instrument.rail,
    })
```
where `intent_hash`/`cart_hash` are `hash_obj(<mandate>.signing_payload())` (`chain.py:15-20`), and `hash_obj` is sorted-keys-JSON SHA-256 (`canonical.py`).

**Mandate types** — `signet/models.py`:

`IntentMandate` (`:24-41`) — *what the principal authorized*:
```python
class IntentMandate(BaseModel):
    mandate_id: str
    principal_id: str
    agent_id: str
    scope: str
    allowed_actions: List[str]
    max_amount: int
    currency: str
    allowed_recipients: List[str]
    valid_from: datetime
    valid_until: datetime
    nonce: str
    policy_id: str
    prompt_playback: Optional[str] = None
    signature: Optional[str] = None
    def signing_payload(self) -> dict: ...   # excludes "signature"
```

`CartMandate` (`:44-59`) — *the assembled transaction, bound to the Intent*:
```python
class CartMandate(BaseModel):
    cart_id: str
    intent_mandate_id: str      # links to IntentMandate.mandate_id
    intent_hash: str            # must equal intent_hash(intent)
    agent_id: str
    merchant_id: str
    action: str
    recipient: str
    amount: int
    currency: str
    destination_account: str
    invoice_id: Optional[str] = None
    signature: Optional[str] = None
    def signing_payload(self) -> dict: ...   # excludes "signature"
```

`PaymentMandate` (`:67-76`) — *the network-facing credential carrying matched hashes*:
```python
class PaymentMandate(BaseModel):
    payment_id: str
    cart_id: str                # links to CartMandate.cart_id
    cart_hash: str              # must equal cart_hash(cart)
    intent_hash: str            # must equal intent_hash(intent)
    amount: int
    currency: str
    funding_instrument: FundingInstrument
    agent_present: str = "HNP"   # "HP" or "HNP"
    signature: Optional[str] = None
```
`FundingInstrument` (`:62-64`): `rail: str`, `token: str`.

**Linkage** is recomputed in `chain.verify_linkage(intent, cart, payment) -> tuple[bool, str]` (`chain.py:61-79`): checks `cart.intent_mandate_id == intent.mandate_id`, `cart.intent_hash == intent_hash`, `payment.cart_id == cart.cart_id`, `payment.cart_hash == cart_hash`, `payment.intent_hash == intent_hash`, `payment.amount/currency == cart.amount/currency`.

**Consume-once key**: the **`chain_hash`** (the exact bound transaction), consumed LAST — `verifier.py:134-137`:
```python
        ch = chain.chain_hash(intent, cart, payment)
        if not self.nonces.consume_once(ch,
                                        ttl_seconds=self.token_ttl_seconds, now=now):
            return blocked("Replay detected: this exact transaction was already executed.")
```

**Velocity aggregation is per PRINCIPAL** (`intent.principal_id`), not per mandate — recorded only after consume-once succeeds — `verifier.py:139-140`:
```python
        self.policy.record_spend(intent.principal_id, cart.amount, now=now)
```
and `PolicyEngine.evaluate` projects `self.spend.day_total(intent.principal_id, now) + cart.amount` against `policy.max_amount_per_day` (`policy.py:97-104`). `SpendLedger` keys on `(subject, day)` (`policy.py:37-66`).

---

## 5. `authorizers/base.py` — the authorizer contract

`signet/authorizers/base.py:19-33`:
```python
@dataclass
class AuthorizationResult:
    executed: bool
    reason: str
    payment_ref: Optional[str] = None
    rail: str = ""


class Authorizer(ABC):
    rail: str = "abstract"

    @abstractmethod
    def authorize(self, token: ExecutionToken,
                  req: ExecutionRequest) -> AuthorizationResult:
        ...
```
> **Discrepancy (code↔CLAUDE.md):** CLAUDE.md says "An authorizer must call
> `verifier.verify_token(...)`" — but the ABC itself does **not** declare or call
> `verify_token`; the contract is enforced only by convention inside each concrete
> authorizer (no `verify_token` is invoked by `base.py`).

The convention each concrete authorizer must follow (re-check vs `req.context` before contributing any capability):

- `MockCredentialBroker.authorize` (`mock_broker.py:65-77`): first line is
  `if not self._verifier.verify_token(token, self._enforcer_vk): return AuthorizationResult(False, ...)`, then mints a one-time credential bound to `token.chain_hash`; the `MockPaymentAdapter.execute` refuses any credential not minted / already used / not bound to the chain_hash.
- `XRPLCosigner.cosign(tx, agent_signed, token, req)` (`xrpl_cosigner.py:68-77`): `verify_token(...)` first, then re-checks `tx.destination != req.context.destination_account` and `tx.amount != str(req.context.amount)` → refuse to co-sign. (Matches CLAUDE.md's "re-check destination/amount against `req.context`".)
- `MPCThresholdCosigner.cosign(tx, R_a, token, req)`: same shape — invalid token / destination / amount mismatch each refuse the share (asserted by tests `test_role1b_*`).

---

## 6. INTENT-PROVIDER INTERFACE (`evals/agentdojo/`)

**Base interface** — `intent_provider.py:150-155`:
```python
class AuthorizedIntentProvider(abc.ABC):
    """Given a user task, produce the envelope Signet enforces."""

    @abc.abstractmethod
    def envelope_for(self, user_task, suite) -> "Envelope":
        ...
```

**The `_extract(self, instruction)` method** the prompt names — `intent_provider.py:342-350` (on `PromptDerivedIntentProvider`; the isolation seam: one `str` parameter, no env/tool channel):
```python
    def _extract(self, instruction: str) -> str:
        # ISOLATION: the only task-derived input is `instruction` (a str). No env,
        # no messages, no suite -- there is no channel for tool output to arrive.
        assert isinstance(instruction, str), "extractor input must be the instruction string"
        self.extractor_inputs.append(instruction)
        try:
            return self._complete(EXTRACTION_SYSTEM, instruction)
        except Exception:
            return ""   # fail closed -> parse_extracted_envelope yields REVIEW/deny
```
> The predicate provider has a parallel `_extract_predicate(self, instruction: str) -> str`
> (`:715-721`) using `EXTRACTION_SYSTEM_PREDICATE`.

**The envelope / capability type it returns:**
```python
Envelope = list                                   # intent_provider.py:113  (a list of...)

@dataclass(frozen=True)
class AuthorizedTransfer:                          # intent_provider.py:103-108
    tool: str
    recipient: str          # IBAN
    amount_cents: int       # EXACT: the exact amount; CAP: the per-tx cap
    mode: str = EXACT
```
The richer predicate "capability" returned by the predicate provider is a
`BankingTargetPredicate` (see §7-adjacent, `resolve.py:108-123`).

**The binding-mode enum (STRICT / POLICY / PREDICATE):** these live in `gate.py:43-46`
as module constants (string values), *not* a Python `Enum`:
```python
MODE_STRICT = "strict"        # literal recipient+amount from the instruction (§2b)
MODE_POLICY = "policy"        # instruction INTERSECT standing operator policy (§2c)
MODE_PREDICATE = "predicate"  # predicate-binding + endorsed value resolution (§4)
```
> A *separate* per-entry binding mode exists on `AuthorizedTransfer.mode`:
> `EXACT = "exact"`, `CAP = "cap"` (`intent_provider.py:61-62`). Don't conflate the two:
> STRICT/POLICY/PREDICATE = which mechanism builds the envelope; EXACT/CAP = how one
> envelope entry binds the amount.

**How a provider is selected:** by binding mode via the domain factory
`_banking_make_mode_provider(mode, model, provider, sp, timed)` (`diagnostic.py:102-119`):
- `MODE_STRICT`  → `PromptDerivedIntentProvider` (instruction-only; `intent_provider.py:324`)
- `MODE_POLICY`  → `PolicyEnrichedIntentProvider(..., allowlist_gates_named=False)` (`intent_provider.py:386`)
- `MODE_PREDICATE` → `PredicateIntentProvider(timed(schema=_BANKING_PREDICATE_SCHEMA), ...)` (`intent_provider.py:698`)
The oracle upper bound is `GroundTruthIntentProvider` (`intent_provider.py:158`). In the CLI runner the string comes from `--intent-provider` (`run.py`: `prompt`/`policy`/oracle) and `--modes` (`diagnostic.py:870`).

**Provenance buckets** (per-task labels, `intent_provider.py:65-71`): `BUCKET_NONE`,
`BUCKET_EXACT`, `BUCKET_CAP`, `BUCKET_REVIEW`, `BUCKET_ALLOWLIST`.

---

## 7. THE GENERIC EFFECT-KEY ADAPTER (HIGHEST PRIORITY — **LOCATED**)

> **⚠ Naming divergence — flag:** the prompt calls this "§7"; the code's own module
> docstring calls it **"§6 predicate-binding mechanism"** (`effects.py:1`), and
> `diagnostic._run_cross_domain` comments "banking uses its **§6** payment path"
> (`diagnostic.py:657`). The arithmetic extension is "§8". The adapter the prompt
> wants is **`evals/agentdojo/effects.py`** (with per-domain hooks in `domains.py`).
> There is no module literally numbered "§7". Treated as the same thing.

It generalizes beyond `(recipient, amount)` to `(effect_class, target_id)`.

**The canonical effect + predicate types** — `effects.py:53-70`:
```python
@dataclass(frozen=True)
class Effect:
    """The canonical side effect (P1: bind the effect, not the tool)."""
    effect_class: str
    target_id: str
    amount_cents: int = 1            # 1 for non-priced effects; the price for travel


@dataclass(frozen=True)
class EffectPredicate:
    """A trusted, low-capacity predicate frozen from the instruction ONLY."""
    effect_class: str
    target_literal: Optional[str] = None   # a target named verbatim in the instruction
    descriptor: Optional[str] = None       # a NAME/keyword to resolve over own data
    selector: str = SEL_NONE               # cheapest/best_rated/computed (travel/aggregate)
    scope: Optional[str] = None            # a bounding scope from the instruction (e.g. a city)
    tiebreak: str = SEL_NONE               # secondary selector ("if multiple, higher price")
```
The kernel-binding key — `effects.py:81-83`:
```python
def effect_key(effect_class: str, target_id: str) -> str:
    """The opaque string the kernel binds as the 'recipient'/destination."""
    return f"{effect_class}:{str(target_id).strip().lower()}"
```

**The resolver / disambiguator** — `resolve_effect_predicate(pred, env, domain, *, allowlist=None, cap_cents=None) -> Resolution` (`effects.py:89-158`). Its branch logic and **where it returns REVIEW**:
1. `pred is None` → `Resolution(BLOCK, "out-of-predicate")`; `effect_class not in domain.authorized_classes` → `BLOCK` "out-of-envelope".
2. **literal** target named in the instruction → `_finish` (ENDORSE, or BLOCK "no-match" if `domain.literal_ok` is false).
3. `selector == SEL_COMPUTED` ("most active user") → **`Resolution(REVIEW, "computed-aggregate (not low-capacity) -> review")`**.
4. `selector in (SEL_CHEAPEST, SEL_BEST_RATED)` over a bounded scope using NON-injectable price/rating; a tie unbroken by `tiebreak` → **`Resolution(REVIEW, "ambiguous (selector tie) -> review")`**.
5. **descriptor** resolved over own data ∩ `domain.target_allowed`: 0 → `BLOCK` "off-allowlist/no-match"; `>1` distinct → **`Resolution(REVIEW, "ambiguous (descriptor -> >1 own target) -> review")`**.
6. fallthrough (no trusted target) → **`Resolution(REVIEW, "no trusted target -> review")`**.
`_finish` also returns `BLOCK` "over-budget" when `amount_for > cap_cents`.

`Resolution` (effect variant) — `effects.py:72-78`: `kind`, `endorsed_target`, `endorsed_amount_cents`, `cause`, `candidates`. Kinds: `ENDORSE`/`REVIEW`/`BLOCK` (`effects.py:43-45`). Selectors: `SEL_NONE/SEL_CHEAPEST/SEL_BEST_RATED/SEL_COMPUTED` (`effects.py:47-50`).

**The gate (executor) that drives the unmodified kernel** — `effects.py:164-292`:
```python
class EffectGatedToolsExecutor(BasePipelineElement):
    def __init__(self, harness: SignetHarness, domain, mode: str = MODE_PREDICATE,
                 output_formatter=tool_result_to_str): ...
    def set_task(self, task_id, predicate, literals=None) -> None: ...
    def begin_episode(self) -> None: ...
    def _decide(self, eff: Effect): ...     # STRICT/POLICY/PREDICATE dispatch
    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}): ...
```
It binds tau-style: `recipient = effect_key(...)`, `amount = price_or_1`, reusing `signet_harness` unchanged.

**Per-domain hooks** — `EffectDomainSpec` (`domains.py:84-161`), concrete specs
`WorkspaceDomain` / `SlackDomain` / `TravelDomain`, registry `DOMAINS` (`domains.py:512`). Hook surface a new domain adapter must implement (defaults shown):
```python
class EffectDomainSpec:
    name = ""; suite_name = ""; version = "v1.1.1"
    high_impact_tools: dict = {}        # tool -> effect_class
    authorized_classes: set = set()
    attacker_ids: set = set()
    standing_policy = EffectPolicy("", None)
    def clean_env(self, suite, user_task): ...
    def canonicalize(self, tool, args, env) -> Optional[Effect]: ...
    def gt_effects(self, user_task, suite) -> list[Effect]: ...
    def _effects_from(self, tool, args, env) -> list[Effect]:  raise NotImplementedError
    def amount_for(self, effect_class, target_id, env) -> Optional[int]: return 1
    def literal_ok(self, effect_class, target, env) -> bool: return True
    def match_descriptor(self, effect_class, descriptor, env) -> list[str]: return []
    def selector_candidates(self, effect_class, scope, env) -> list[tuple]: return []
    def target_allowed(self, effect_class, target, env) -> bool: return False
    def classify(self, prompt, effect_class, target_id, env) -> tuple[str, str]: ...
    def value_source(self, prompt, effect_class, target_id, env) -> str: ...
    def build_extractor(self, model, provider): ...
```
`EffectPolicy` (`domains.py:25-28`): `description: str`, `cap_cents: Optional[int] = None`.

> **Banking's own §4 analogue** (the non-effect, payment version) is
> `resolve_banking_target(...)` in `resolve.py:320-431`, returning a banking
> `Resolution` (`resolve.py:126-132`) over a `BankingTargetPredicate` (`resolve.py:108-123`).

---

## 8. DIAGNOSTIC HARNESS (`evals/agentdojo/diagnostic.py`)

**A task + ground-truth action** are represented as a **`PlanRow`** (one per GT high-impact action) — `diagnostic.py:158-168`:
```python
@dataclass
class PlanRow:
    task_id: str
    tool: str
    gt_recipient: str
    gt_amount_cents: int
    bucket: str
    rec_source: str
    amt_source: str
    # per mode: class, cause, endorsed_recipient, endorsed_amount, bounded
    by_mode: dict = field(default_factory=dict)
```
The GT action set itself comes from an `Envelope` of `AuthorizedTransfer` (banking) or `list[Effect]` (effect domains); the per-mode resolution is classified into `CORRECT / WRONG / ESCALATE` (`diagnostic.py:71-74`).

**Bucketing into DI / DIQ / DD** — `taxonomy.py`. The classifier is deterministic over `(prompt, recipient, amount, clean_env)`:
```python
DI = "DI"; DIQ = "DIQ"; DD = "DD"; BUCKETS = (DI, DIQ, DD)        # taxonomy.py:29-32

@dataclass(frozen=True)
class ValueSources:                                              # taxonomy.py:40-43
    recipient: str   # LITERAL | RESOLVABLE | UNRESOLVABLE
    amount: str

def bucket_from_sources(s: ValueSources) -> str:                 # taxonomy.py:46-55
    r_lit = s.recipient == LITERAL
    a_lit = s.amount == LITERAL
    r_ok = s.recipient in (LITERAL, RESOLVABLE)
    a_ok = s.amount in (LITERAL, RESOLVABLE)
    if r_lit and a_lit:
        return DI
    if r_ok and a_ok:
        return DIQ
    return DD
```
Value-source labels: `LITERAL` (verbatim in prompt), `RESOLVABLE` (low-capacity own-data lookup), `UNRESOLVABLE` (`taxonomy.py:35-37`). `BankingBucketClassifier.classify(prompt, recipient, amount_cents, env) -> (bucket, ValueSources)` (`taxonomy.py:118-123`). Effect domains classify via `EffectDomainSpec.classify` → `{LITERAL:DI, RESOLVABLE:DIQ, UNRESOLVABLE:DD}` (`domains.py:138-146`).

**HITL-load** = escalation rate = GT actions **not** auto-authorized / total; autonomy = 1 − HITL-load. Computed per bucket × per mode by counting `cls == ESCALATE` — `diagnostic.py:337-349`:
```python
        for m in modes:
            esc = sum(1 for r in brows if r.by_mode[m]["cls"] == ESCALATE)
            cells.append(f"{_pct(esc, len(brows))} ({esc}/{len(brows)})")
```

**Wrong-resolution** (the predicate ceiling) = endorsed `!=` GT target / endorsements, computed only on `MODE_PREDICATE` rows — `diagnostic.py:360-366`:
```python
        pwrong = [r for r in rows if r.by_mode[MODE_PREDICATE]["cls"] == WRONG]
        pauth = [r for r in rows if r.by_mode[MODE_PREDICATE]["cls"] in (CORRECT, WRONG)]
        ...
        print(f"  wrong-resolution rate: {_pct(len(pwrong), len(pauth))} ...")
```
plus the **bounded** assertion `all(r.by_mode[MODE_PREDICATE]["bounded"] for r in pwrong)` — every wrong endorsement is bounded to an own/allowlisted target, never the attacker (`diagnostic.py:367`). The CORRECT/WRONG/ESCALATE decision per action is made in `classify_plan_time(...)` (`diagnostic.py:176-219`) for banking and `_classify_effect(...)` (`diagnostic.py:492-537`) for effect domains. Two layers: plan-time (headline, no rollouts) and lean end-to-end rollouts (utility + ASR) via `run_lean_rollouts` (`diagnostic.py:248-301`).

---

## 9. ONE ATTACK TEST (house style) — `tests/test_attacks.py`

> The file contains **21** `test_*` functions (see GAPS re: the prompt's "17-test"
> figure). Representative example pasted IN FULL — `tests/test_attacks.py:103-115`:
```python
def test_split_velocity_blocked():
    # Daily cap 10000. Four 4800 payments = 19200; the third should breach.
    env = make_env()
    approved = 0
    for i in range(4):
        req = build_chain(env, nonce=f"n{i}")
        d, _ = env.verifier.evaluate(req)
        if d.approved:
            approved += 1
        else:
            assert "daily" in d.reason.lower() or "velocity" in d.reason.lower() \
                   or "structuring" in d.reason.lower()
    assert approved == 2   # 4800 + 4800 = 9600 <= 10000; third would exceed
```
House style: fixture `env = make_env()` (`builder.py:36`); request built by `build_chain(env, **override)` (`builder.py:76`); decision via `decision, token = env.verifier.evaluate(req)`; **pass** asserted with `decision.approved` (+ `token`/`verify_token`), **block** asserted with `not decision.approved` and a substring of `decision.reason.lower()`. (Simplest pass/block pair: `test_valid_execution_succeeds` `:18-24` and `test_over_limit_blocked` `:27-32`.)

---

## 10. API ROUTES (`signet/api.py`)

The app trusts only the verifier; the request/response models are minimal. **Request model for both `/intents/evaluate` and `/execute` is `ExecutionRequest`** (§1); responses are plain `dict`s built from `model_dump(mode="json")` (no dedicated response models). `api.py:51-77`:
```python
@app.post("/intents/evaluate")
def evaluate(req: ExecutionRequest):
    decision, token = _env.verifier.evaluate(req)
    return {"decision": decision.model_dump(mode="json"),
            "token": token.model_dump(mode="json") if token else None}


@app.post("/execute")
def execute(req: ExecutionRequest):
    decision, token = _env.verifier.evaluate(req)
    if not decision.approved:
        _receipts.append(execution_id="-", mandate_id=req.intent.mandate_id,
                         chain_hash=decision.chain_hash or "-",
                         policy_id=req.intent.policy_id, decision="blocked",
                         payment_status="not_executed", payment_ref=None,
                         rail=req.context.rail)
        return {"decision": decision.model_dump(mode="json"), "executed": False}
    result = _broker.authorize(token, req)
    receipt = _receipts.append(
        execution_id=token.execution_id, mandate_id=token.mandate_id,
        chain_hash=token.chain_hash, policy_id=req.intent.policy_id,
        decision="approved",
        payment_status="executed" if result.executed else "failed",
        payment_ref=result.payment_ref, rail=result.rail)
    return {"decision": decision.model_dump(mode="json"),
            "executed": result.executed, "payment_ref": result.payment_ref,
            "receipt": receipt.model_dump(mode="json")}
```
Other routes: `GET /info` (`:34`), `POST /mandates/register-key` (body model `RegisterKey{identity:str, verify_key_hex:str}`, `:29-42`), `POST /mandates/{mandate_id}/revoke` (`:45`), `GET /receipts` (`:80`), `POST /receipts/verify` (body model `Receipt`, `:85`). The single in-process env wires **only** the mock broker: `_broker = MockCredentialBroker(_env.verifier, _env.enforcer_vk)` (`:25`) — XRPL/MPC authorizers are **not** reachable over HTTP (consistent with CLAUDE.md "the HTTP surface wires only the mock broker").

---

## 11. REPO-POLICY / ALLOWLIST CONFIG — **NOT FOUND as described (no YAML; no startup-overwrite bug located)**

There is **no YAML allowlist file** in the repo (`find . -name '*.yaml' -o -name '*.yml'`
returns nothing). The only `environment.yaml` mention is a comment in `resolve.py:13`
referring to **AgentDojo's installed banking suite**, not a Signet config file.

**Closest equivalents** (allowlist/policy config is Python, not YAML):
- **Standing operator policy** (the eval allowlist) — a frozen dataclass, `intent_provider.py:74-100`:
  ```python
  @dataclass(frozen=True)
  class StandingPolicy:
      approved_recipients: tuple   # IBAN allowlist of LEGITIMATE vendors only
      per_recipient_cap_cents: int  # coarse, uniform, task-independent per-payment cap
      velocity_cap_cents: int       # cumulative/daily cap across payments (per episode)
      currency: str = CURRENCY

  DEFAULT_STANDING_POLICY = StandingPolicy(
      approved_recipients=_LEGIT_BANKING_VENDORS,
      per_recipient_cap_cents=20000,
      velocity_cap_cents=50000,
  )
  ```
  "Loaded at startup, never from env/tool output" is asserted only in comments/prints
  (`run.py:139-148`); it is a Python literal, not a file load.
- **Kernel policy config** — `signet.policy.Policy` dataclass (`policy.py:19-27`), registered imperatively in `builder.make_env()` (`builder.py:46-65`: `treasury_policy_v1`, `xrpl_treasury_v1`) and per-task in `SignetHarness.register_policy(...)` (`signet_harness.py:115-138`). `PolicyEngine.add` (`policy.py:74`) stores by `policy_id` in a dict (re-adding an id **silently overwrites** — but each eval call uses a fresh incrementing `policy_id`, so no overwrite occurs in practice).
- **Loader present**: `pipelines.load_dotenv(...)` (`pipelines.py:34`) reads `.env` for API keys only — it explicitly "does not overwrite variables already set."

**The "known startup-overwrite bug":** **NOT FOUND.** No code path overwrites an
allowlist/policy at startup. The nearest overwrite *semantics* is `PolicyEngine.add`'s
dict-keyed replace (`policy.py:74-75`), which is not triggered with a duplicate id by
any current caller. (Per the task constraints, nothing was changed; flagging only.)

---

## 12. INVARIANTS FROM CLAUDE.md (a new adapter must not violate)

- **Rail logic stays out of the kernel.** Adding a rail = one new `Authorizer` implementing `authorizers/base.py`; the verifier stays rail-agnostic.
- **Trust only the enforcer token.** Authorizers act on a verified `ExecutionToken`, never the agent's word or the raw mandate; they must call `verifier.verify_token(...)` and refuse unless valid/unexpired/bound to *this* exact transaction, re-checking destination/amount against `req.context`.
- **Signature before nonce.** Verify signatures before touching the consume-once registry (cheap-DoS defense).
- **Verifier-authoritative clock.** TTL/freshness use the verifier's clock, never a client timestamp.
- **Consume-once is keyed on `chain_hash`** and is the LAST gate before issuing the token. Do not move it back to the intent nonce (breaks multi-payment mandates).
- **Velocity aggregates per principal**, not per mandate.
- **Fail closed.** Any unsatisfiable check → block; no best-effort.
- **Pipeline order is deliberate** (`verifier.py`): signatures → linkage → agent identity → action → TTL → revocation → context binding → exactness → policy → atomic consume-once → record spend + sign token.
- **Out-of-scope by design** (do not "fix" in the kernel): a fully self-consistent correctly-signed malicious chain (prompt injection at signing surface), principal key compromise, agent–merchant collusion. The eval-brain echo of this: the predicate/effect resolver endorses values only over the principal's **own** bounded data + standing allowlist, and **escalates (REVIEW) rather than guesses** for computed-aggregate / off-allowlist / ambiguous / injection-channel targets.

---

## GAPS

Requested-but-divergent or not found:

1. **§7 numbering (highest-priority item):** the prompt's "§7 generic effect-key adapter"
   is in the code as **`effects.py`**, whose own docstring labels it **"§6"** (and
   `diagnostic.py:657` calls banking's path "§6"; the arithmetic extension is "§8").
   There is no surface literally numbered §7. Resolved to `effects.py` + `domains.py`.
2. **Attack-suite size:** prompt says "17-test attack suite"; `tests/test_attacks.py`
   actually defines **21** `test_*` functions — matching CLAUDE.md's "21 attack tests",
   not 17. (Count: 11 core/verifier+velocity, 3 Role 2, 2 Role 1 XRPL, 4 Role 1b MPC,
   1 receipts.)
3. **§11 YAML allowlist + "startup-overwrite bug":** **NOT FOUND.** No YAML config
   exists; the allowlist/policy is Python (`StandingPolicy`/`DEFAULT_STANDING_POLICY`
   in `intent_provider.py`; `signet.policy.Policy` via `builder.make_env`). No
   startup-overwrite bug is present in code (closest: `PolicyEngine.add`'s dict-keyed
   replace, not triggered by current callers). Reported, not fixed.
4. **GitHub/HTTP client (§0):** no GitHub SDK or generic HTTP client in dependencies;
   only `fastapi`/`uvicorn` (server) and `xrpl-py` (XRPL). Eval LLM extractors import
   `openai`/`anthropic` lazily and are **not** declared in `pyproject.toml`.
5. **`evaluate()` return type:** not annotated in the signature — declared only in the
   docstring as `(Decision, ExecutionToken | None)` (`verifier.py:70-71`).

Code↔CLAUDE.md divergences:

6. **`base.py` vs the "must call `verify_token`" invariant:** the `Authorizer` ABC
   does not declare or call `verify_token`; the token-check contract is enforced only
   by convention inside each concrete authorizer (`mock_broker`, `xrpl_cosigner`,
   `mpc_cosigner`). A new adapter that forgets the call would still satisfy the ABC.
7. **"Exactness step" naming:** what the prompt calls one exactness step is steps
   **7 (context binding)** and **8 (exactness)** in `verifier.py`; recipient/destination
   substitution is caught at step 7 (context hash), amount/currency at step 8.
8. **Two distinct "binding modes":** `MODE_STRICT/POLICY/PREDICATE` (mechanism, `gate.py`)
   vs `EXACT/CAP` (per-entry amount binding on `AuthorizedTransfer`, `intent_provider.py`).
   The prompt's "STRICT/POLICY/PREDICATE enum" maps to the former. Neither is a Python
   `Enum` — both are module-level string constants.
