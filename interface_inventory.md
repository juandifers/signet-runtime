# Signet Runtime — Interface Inventory

> Signatures and type definitions are quoted verbatim (function bodies elided with
> `...`). CLAUDE.md is treated as the source of truth for naming/invariants;
> code↔doc disagreements are reported, not reconciled.
>
> **Layout:** **Part I (§0–§12)** = the kernel + the AgentDojo/τ-bench eval brain.
> **Part II (§13–§20)** = the **GitHub rail-bridge ("the muscle")** on
> `muscle/github-railbridge` — the `github_railbridge` authorizer plus its
> `evals/github_railbridge/` stack (Open/Closed mandates, the Role A/B LLM resolver +
> quarantine, RFC-6962 transparency). **GAPS** at the end.
>
> _Currency: covers the muscle work through the Role-B quarantine/cassette/corpus layer.
> 94 tests collected; CI makes no live LLM calls._

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
    ├── base.py             Authorizer ABC + AuthorizationResult
    ├── mock_broker.py      Role 2 — credential custody (the ONLY rail wired to api.py)
    ├── xrpl_cosigner.py    Role 1 — XRPL 2-of-2 multisign
    ├── mpc_cosigner.py     Role 1b — 2-of-2 threshold Schnorr / MPC
    └── github_railbridge.py  GitHub merge rail — GitHubRail ABC + MockGitHubRail +
                              GitHubRailBridge (Role-2-style; conclude a Check Run). §13
```
> `models.Receipt` gained ONE additive field — `decision_record_hash: Optional[str] = None`
> (`models.py:157`) — excluded from `hashing_payload()` when None so legacy receipts hash
> identically; when set it is signed-over. This is the **only** kernel edit the muscle made.

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
├── tau_bench/
│   ├── retail_intent.py, gate.py, resolve.py, signet_retail_harness.py
│   ├── run.py, tau_path.py, smoke_test.py, FINDINGS.md, README.md
│   └── __init__.py
└── github_railbridge/                 # the muscle's eval stack (Part II). agentdojo-FREE.
    ├── domain.py            §6 effect-key encoding for merges + GitHubDomain hooks  (§14)
    ├── merge_chain.py       AP2 chain builder for a merge -> kernel (§19)
    ├── policy.py            MergePolicy + PolicySource + intersect (monotonic)      (§15)
    ├── enforce.py           resolve_effective_policy + enforce_merge                (§15)
    ├── mandate.py           AP2 Open/Closed mandate + resolve_task_mandate + gates  (§16)
    ├── resolver.py          Role A/B resolver: SET-valued LLMResolver + _parse_set  (§17)
    ├── ambiguity.py         Layer A structural pre-filter + cardinality abstention  (§17)
    ├── cassette.py          record/replay seam for Role B (CI replay, no key)       (§17)
    ├── record_cassette.py   re-record tool + the 3 recorded scenarios               (§17)
    ├── role_b_corpus.py     opt-in corpus measurement (utility/containment/...)     (§17)
    ├── transparency.py      RFC-6962 DecisionRecord + Merkle + anchor + trace-hash  (§18)
    ├── live_rail.py         real GitHub App rail (read PR ctx; post Check Run)       (§19)
    ├── l3_run.py            live runner CLI (--mandate-file/--resolver/--provider)   (§20)
    ├── tasks.py, corpus.py, diagnostic.py   synthetic task set + plan-time diagnostic
    └── example_mandate.json  a blessed OpenMandate file
```

### Environment / tooling (from `pyproject.toml`)
- **Python**: `requires-python = ">=3.10"`.
- **Pydantic**: `"pydantic>=2"` (models use Pydantic v2: `model_dump(mode="json", exclude=...)`).
- **Test runner**: `pytest>=8` (dev extra). Config: `[tool.pytest.ini_options] pythonpath=["."]`, `testpaths=["tests"]`. Invoke: `pytest -v`.
- **HTTP**: `fastapi>=0.110`, `uvicorn>=0.29` (server `signet/api.py`).
- **GitHub client**: optional extra `l3-github = ["pyjwt[crypto]>=2.8", "requests>=2.31"]` (`pyproject.toml:18`) powers the LIVE rail (`live_rail.py`) — `jwt`/`requests` imported **lazily**, so the offline suite never needs them. The XRPL client is `xrpl-py>=4` (used offline in tests). LLM extractors/resolvers import `openai` / `anthropic` **lazily** inside factory functions (not declared in `pyproject.toml`); the live resolver defaults to OpenAI (`OPENAI_API_KEY`).
- **Agentdojo-free guarantee**: the kernel + the GitHub muscle never import the `agentdojo` package. Enforced by a subprocess probe (`tests/test_github_railbridge_isolation.py`) that imports the production+test modules and asserts no `agentdojo*` leaked.

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

# PART II — the GitHub rail-bridge ("the muscle")

> Enforces **"merge a PR to a protected branch"** as the irreversible action. One new
> `Authorizer`; the kernel is untouched (save the one additive `Receipt` field). The whole
> `evals/github_railbridge/` stack is **agentdojo-free** (§0). The operator's grant is
> **TRUSTED** and frozen BEFORE any runtime (PR/issue) read — same isolation discipline as
> `_extract` (§6).

## 13. GitHub authorizer (`signet/authorizers/github_railbridge.py`)

The irreversible step = the enforcer concluding a required Check Run as `success`. The agent
holds no capability to conclude it; only this authorizer does, and only after `verify_token`
+ an independent effect-vs-Cart re-check. Mirrors `mock_broker` (Role 2).

`GitHubRail` ABC — `:28-37` (the rail capability the enforcer holds):
```python
class GitHubRail(ABC):
    @abstractmethod
    def open_check(self, chain_hash: str, head_sha: str) -> str: ...
    @abstractmethod
    def conclude(self, check_run_id: str, chain_hash: str, conclusion: str) -> str: ...
```
`MockGitHubRail` (`:40-66`) trusts ONLY checks the enforcer opened bound to a `chain_hash`, and refuses to conclude one not so bound or already concluded (consume-once) — the analogue of `MockPaymentAdapter`. The LIVE rail (`live_rail.LiveGitHubRail`, §19) implements the same ABC.

`GitHubRailBridge(Authorizer)` — `:74-135`, `rail = "github"`. `authorize` is the two-step (`:101-135`):
```python
def authorize(self, token: ExecutionToken, req: ExecutionRequest) -> AuthorizationResult:
    if not self._verifier.verify_token(token, self._enforcer_vk):       # FIRST, always
        return AuthorizationResult(False, "Enforcer token invalid/expired.", rail=self.rail)
    head_sha = _parse_head_sha(req.context.recipient)
    recomputed = chain.chain_hash(req.intent, req.cart, req.payment)
    bound = (recomputed == token.chain_hash and self._well_formed(req)
             and self._context_matches_cart(req))                       # independent re-check
    check_run_id = self._rail.open_check(token.chain_hash, head_sha)
    if not bound:
        self._rail.conclude(check_run_id, token.chain_hash, "failure")  # fail closed
        return AuthorizationResult(False, "Effect/context mismatch ...", payment_ref=check_run_id, rail=self.rail)
    ref = self._rail.conclude(check_run_id, recomputed, "success")      # only the enforcer can
    return AuthorizationResult(True, "Check Run concluded success ...", payment_ref=ref, rail=self.rail)
```
`_context_matches_cart` (`:83-91`) re-checks `recipient == ctx.recipient`, `action == ctx.action`, `destination_account == ctx.destination_account` (independent of the kernel's step-7). `_well_formed` (`:93-99`) requires `rail=="github"`, `recipient.startswith(action+":")`, and a `@head_sha`.

## 14. GitHub effect encoding + domain hooks (`evals/github_railbridge/domain.py`)

Reuses the §6/`effect_core` primitives. The encoding (single source of truth, matched by `merge_chain` + the authorizer):
- `effect_class = "merge_pr_protected"` if touched paths hit the protected globs, else `"merge_pr"` (`effect_class_for :108`; `is_protected :95`).
- `target_id(repo, pr, base, head_sha) = f"{repo}#{pr}->{base}@{head_sha}"` (`:85`) — binds base + exact head.
- `diff_hash(touched_paths)` (`:90`) rides as `destination_account`. `effect_key` is re-exported from `effect_core`.
- A post-auth force-push (new head_sha) or base swap changes the bound recipient → the **unchanged kernel** (step 7/8) blocks it.

World types: `PullRequest` (`:60-73`, frozen) carries `repo, number, base, head_sha, files, title, branch, author, injected_body, closes_issue, status, created_order` — `injected_body` is the UNTRUSTED channel the resolver path never reads; `GitHubWorld` (`:76-78`) = `{number -> PullRequest}` (the principal's OWN open PRs).

`GitHubDomain(EffectDomainSpec)` (`:184`) binds its fence to a `MergePolicy` via `__init__(policy=None)` (`:202`). The **two-layer** discrimination (the load-bearing split):
```python
def within_allowlist(self, target, env) -> bool:   # :303  the bounded-to-own UNIVERSE ceiling
    # repo == configured_repo AND base in allowed_bases AND not an attacker id. Repo+base ONLY
    # — NOT protected paths / allow-scope (that is the fence's job). This is what makes a real
    # repo PR an 'own/approved' candidate on the live path exactly as for the synthetic corpus.
def within_fence(self, target, env) -> bool:        # :321  the scope/protected fence
    # not is_protected(rec.files)
def target_allowed(self, effect_class, target, env) -> bool:  # :330
    return self.within_allowlist(target, env) and self.within_fence(target, env)
```
`match_descriptor` (`:263`) resolves a descriptor over OWN PRs only (issue ref / CI status / recency / explicit id / keyword phrase). `canonicalize_literal` (`:239`) keys a literal PR id → its bound `target_id` (escalates protected/off-allowlist). `build_extractor` (`:349`) returns the deterministic instruction-only `extract_merge_predicate` (Role A; §17). Standing constants: `CONFIGURED_REPO="octo/payments-service"` (`:46`), `ALLOWED_BASES=("main","release")` (`:47`), `PROTECTED_GLOBS` (`:50`).

## 15. Layered policy + sources (`policy.py`, `enforce.py`)

`MergePolicy` (`policy.py:67-131`, frozen/hashable) — the typed fence:
```python
allow_paths=("**",); deny_paths=PROTECTED_GLOBS; effect_tiers=DEFAULT_TIERS
merges_per_day=10; freeze=False; allowed_bases=ALLOWED_BASES; repo_id=CONFIGURED_REPO
extra_allow_layers=()    # internal CONJUNCTIVE allow layers (how a task narrows `allow`)
```
- `tier_for(effect_class) -> auto|approve|cosign|deny` (`:87`; unknown → DENY; `freeze` forces ≥cosign). Tiers `TIER_AUTO/APPROVE/COSIGN/DENY` (`:28-31`); `DEFAULT_TIERS = ((merge_pr, auto), (merge_pr_protected, deny))` (`:64`).
- `path_disposition -> in-fence|denied|out-of-allow` (`:102`); `is_fenced` (`:109`).
- `intersect(task)` (`:114`) is **monotonic** — denies union, `merges_per_day` mins, bases intersect, `freeze` ORs, the task's `allow_paths` appends as a conjunctive layer. A task can only ADD restrictions.

`PolicySource` ABC (`:157`) `load_effective_policy(repo_id, principal_id) -> MergePolicy`. Impls: `InMemoryPolicySource` (`:163`, control-plane stub keyed by `(repo,principal)`); `BlessedRefPolicySource` (`:179`, reads a pinned ref and DELIBERATELY ignores the agent-writable `working_tree_policy` — the load-bearing property). `DEFAULT_MERGE_POLICY = MergePolicy()` (`:151`).

`enforce.py`: `resolve_effective_policy(source, repo_id, principal_id, task_policy)` (`:36`) = `standing.intersect(task)` then **stamps `eff.repo_id = repo_id`** (`:49`) so the ownership ceiling keys off the LIVE repo (`SIGNET_GH_REPO`), not the default constant. `enforce_merge(...)` (`:54`) is the standalone decision path (base gate → fence → tier → auto runs the kernel). `MergeDecision` dataclass `:26`.

## 16. AP2 Open/Closed mandate (`evals/github_railbridge/mandate.py`)

`OpenMandate` (`:67-110`, frozen, **TRUSTED**): `criterion, scope_allow=("**",), cap=1, merges_per_day=None, extra_deny=(), repo_id=None`. `as_task_policy()` renders it as a narrowing `MergePolicy`; `predicate()` = Role A interpretation of the criterion string ONLY; `mandate_id()` hashes the grant (no runtime data); `criterion_issue()` parses `issue #N`. Loaded via `load_open_mandate(path)` (`:113`) — the ONLY ingestion point, before any rail read.

`ClosedMandate` (`:138-147`): the resolved, fence-checked, bound effect (`repo, pr, base, head_sha, touched_paths, effect_class, bound_target`). `MandateResolution` (`:160-168`): `kind (RESOLVED|UNRESOLVED), closed, cause, considered, reasoning_trace, reasoning_trace_hash`.

`resolve_task_mandate(om, world, effective, *, resolver=None, trace_store=None)` (`:176`) — the core. Deterministic by default; with a `resolver` it delegates to `_resolve_via_role_b` (`:293`), which proposes ONE owned PR id then runs `_gate_chosen_pr` (`:249`) — the **same gates regardless of proposer**: bounded-to-own membership → `within_allowlist` ceiling → `effective.is_fenced` (scope/protected) → allowed base. Off-scope/off-repo/ambiguous → UNRESOLVED (`unresolved_constraint`) → REVIEW. **Containment never depends on the resolver.**

`run_open_mandate(env, source, bridge, receipts, world, *, repo_id, open_mandate, transparency=None, resolver=None, trace_store=None)` (`:489`) drives one job: resolve → `authorize_closed_mandate` (`:360`, routes through `GitHubRailBridge.authorize` + appends a signed receipt for allow/block/review) → records the injection-channel metric (`injection_targets :327`, the would-have-proceeded rate) → optionally appends a `DecisionRecord` to the Merkle log (re-sealing the receipt with the `decision_record_hash` backlink). `JobResult` (`:421`) carries `proceed_rate`. `explain_pr` (`:451`) prints the one-line per-PR "why" (allow-list ceiling → fence → criterion → verdict).

## 17. Role A / Role B resolver + the quarantine + structural abstention (`resolver.py`, `ambiguity.py`, `cassette.py`, …)

Two strictly-separated roles:
- **Role A (TRUSTED, criterion interpretation)** = the deterministic `domain.extract_merge_predicate` — never sees runtime data (no LLM, so no injectable surface).
- **Role B (EXPOSED, candidate resolution)** = an opt-in real LLM. **SET-VALUED**: it returns EVERY plausible owned id (not one pick), so genuine ambiguity is SURFACED, not guessed past. Quarantined I/O contract:

```python
@dataclass(frozen=True)
class CandidateView:   # resolver.py:64   the EXPOSED runtime view of one owned PR (untrusted)
    pr: int; title=""; body=""; base=""; files=(); closes_issue=None; branch=""
@dataclass(frozen=True)
class ResolverSet:     # :89   the CONSTRAINED set-valued output
    picks: tuple = ()          # tuple of (pr_id, reason); every pr_id is an owned id
    raw: str = ""; unresolved: bool = False
    @property ids -> frozenset # the clamped owned-id set
class Resolver(ABC):   # :116  resolve(criterion, candidates) -> ResolverSet
class FixedSetResolver(Resolver):     # :199  stub: always return a fixed SET (cardinality demos)
class FixedChoiceResolver(Resolver):  # :215  stub: a single id as a one-element set (adversarial)
class LLMResolver(Resolver):          # :273  one completion, clamped by _parse_set
```
`_parse_set(raw, valid_ids)` (`:143`) is the enforcement primitive: parses JSON (robust to prose/fences; tolerates the legacy `{"choice": id}` shape), then **clamps** every element to the owned set — out-of-set ids are **dropped** (never inflate/redirect the set), bools/string-commands/non-lists/extra fields all fail closed; an empty surviving set ⇒ `unresolved`. `_coerce_id` (`:129`) rejects bools + non-`#?N`. `make_complete(provider, model)` / `make_resolver(...)` (`:362`/`:374`) are provider-aware (OpenAI default `gpt-4o-mini` `:55`, Anthropic `claude-sonnet-4-6` `:56`; lazily imported; `make_openai_complete` has a `json_mode` toggle `:293`). `_resolve_provider` (`:349`) auto-detects from the key in env.

**Structural abstention (`ambiguity.py`)** — two deterministic (no-LLM) layers wrap Role B:
- `structural_prefilter(om, world)` (`:36`) = **Layer A**, runs BEFORE any LLM call: if the criterion is a closing-issue reference and ≥2 owned PRs literally close it, escalate (`unresolved_constraint`) — reads only `closes_issue` (low-capacity own field), never bodies.
- `apply_cardinality(resolver_set, owned_ids)` (`:55`) = the **cardinality override** on Role B's clamped set `s`: `|s|==1` → resolve that PR (then the existing gate runs); `|s|>=2` → escalate (ambiguous); `|s|==0` → escalate. Both wired into `mandate._resolve_via_role_b` ahead of the unchanged `_gate_chosen_pr` containment gate.

> **Rail-side invariant (added):** a Role B resolution is endorsed ONLY IF exactly one owned candidate survives the abstention rule. Escalate-on-ambiguity is enforced **structurally on candidate-set cardinality**, never on the model's self-reported confidence or a single pick. This is a CORRECTNESS layer; it does not weaken or replace the containment gate (bounded-to-own → allow-list → scope/protected fence), which still runs independently on the single survivor.

Record/replay seam (`cassette.py`): `cassette_key(criterion, candidates)` (`:31`) hashes the resolver INPUTS (prompt-wording-independent); `Cassette` (`:45`) is the JSON store; `CassetteResolver` (`:83`) replays the recorded raw through the SAME `_parse_set` (REPLAY needs no key/network; RECORD calls a live `CompleteFn`). Fixture: `tests/fixtures/github_railbridge/role_b_cassette.json` (re-recorded under the set schema). Re-record: `python -m evals.github_railbridge.record_cassette --record` (loads `.env`); the 3 scenarios live in `record_cassette.SCENARIOS` (`scenario_fuzzy_legit/ambiguous/poisoned`; only the legit PR structurally closes the issue so Layer A passes through to Role B for the poisoned case).

Opt-in corpus (`role_b_corpus.py`): `build_corpus()` = ~34 labeled cases (clean/fuzzy/ambiguous/injection); `run_corpus`/`report`/`print_report` emit **resolution utility** (correct/escalate/wrong) AND **outcome correctness** (injection→escalate and ambiguous→escalate count as CORRECT), plus containment-when-fooled, bounded-to-own, schema-compliance. Measured live (gpt-4o-mini and gpt-4o, n=34): ambiguous 8/8 escalate (was 2/8), fuzzy 8/8, clean 8/8, injection 10/10 contained (attacker never endorsed), bounded-to-own + schema 100%, zero wrong. CLI: `python -m evals.github_railbridge.role_b_corpus --resolver llm|deterministic`.

## 18. RFC-6962 transparency + reasoning-hash-link (`transparency.py`)

`DecisionRecord` (`:79-124`, frozen) = the audit semantics as canonical fields, bound to the ENFORCEMENT via `chain_hash/execution_id/receipt_id` (not the receipt's hash — that backlink is recursive). Gained `reasoning_trace_hash: Optional[str] = None` (`:108`), **dropped from `to_canonical()` when None** (`:112`) so deterministic-resolver records hash identically. `build_decision_record(...)` `:127`.

The reasoning-trace hash-link: `reasoning_trace_hash(trace)` (`:172`) + `ReasoningTraceStore` (`:178`) — a SEPARATE, mutable/deletable store of UNTRUSTED Role-B narrative; the anchored leaf commits to the HASH only, `verify(h)` is tamper-evident (`:205`). RFC-6962 primitives: `leaf_hash` (`0x00 || entry`, `:222`), `merkle_root` (`:242`), `audit_path`/`_root_from_path`, `SignedTreeHead` (`:287`), `InclusionProof` (`:304`, carries the `receipt_hash`), `verify_inclusion(record, proof, sth, enforcer_vk)` (`:317`, the auditor's function — needs only those 4 args + a pinned key). Anchoring: `AnchorSink` ABC + `LocalAppendOnlyAnchor` (`:366`, WORM stub). `TransparencyLog` (`:406`) stores records, signs the root, surfaces proactive proofs for sensitive (protected/non-auto-tier) entries.

## 19. AP2 chain builder for a merge + the live rail

`merge_chain.build_merge_chain(env, *, repo, pr, base, head_sha, touched_paths, …)` (`merge_chain.py:52`) is the GitHub analogue of `signet_harness`: it maps the merge to Signet objects and routes through the UNMODIFIED `Verifier`. Mapping (`:11-16`): `recipient = effect_key(effect_class, target_id)`, `action = effect_class`, `amount = 1`, `destination_account = diff_hash(touched_paths)`, `rail = "github"`. It exposes `ctx_*` runtime overrides + `tamper_cart_recipient`/`break_linkage` to diverge the RuntimeContext from the signed Cart (the attack hooks). `make_github_env()` (`:46`) reuses `builder.make_env`; `PRINCIPAL="acme_cfo"` (`:40`).

`live_rail.py` — the real GitHub App rail (`LiveGitHubRail(GitHubRail)` `:81`, `from_env` `:102`, creds from `SIGNET_GH_*`, `jwt`/`requests` lazy). `read_pr_context(pr) -> PRContext` (`:183`) reads files/sha/base/title/body/head-ref + closing-issue ids + issue bodies (all UNTRUSTED, fail-closed). `parse_closing_issues(body)` (`:41`) parses `closes/fixes/resolves #N`. `world_from_rail(rail, repo, pr_numbers)` (`:248`) assembles the OWN-PR `GitHubWorld` (body+issues stashed in `injected_body`, never read by resolution).

## 20. L3 runner + demos

`python -m evals.github_railbridge.l3_run --mandate-file <f> [--dry-run] [--repo R] [--env-file .env] [--resolver deterministic|llm|adversarial] [--provider openai|anthropic] [--model M] [--adversarial-pr N]` (`l3_run.py:main`). Loads the TRUSTED OpenMandate FIRST, builds the live rail, assembles the world, resolves (deterministic default; opt-in Role B), routes through the authorizer, posts the `signet/enforced` Check Run, prints per-PR "why" lines + (for LLM) the Role-B reason + `reasoning_trace_hash`. Demos: `demos/github_railbridge_demo.py` (offline, full 7-step story) and `demos/github_railbridge_role_b_demo.py` (`--llm` for a real Role B; offline adversarial stub otherwise).

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
4. **GitHub/HTTP client (§0):** ~~no GitHub SDK~~ **RESOLVED** — the muscle added the
   optional extra `l3-github = ["pyjwt[crypto]>=2.8","requests>=2.31"]` for the live rail
   (`live_rail.py`), imported lazily so the offline suite is unaffected. Eval LLM
   extractors/resolvers still import `openai`/`anthropic` lazily and are **not** declared in
   `pyproject.toml`; the live resolver defaults to OpenAI.
5. **`evaluate()` return type:** not annotated in the signature — declared only in the
   docstring as `(Decision, ExecutionToken | None)` (`verifier.py:70-71`).

Code↔CLAUDE.md divergences:

6. **`base.py` vs the "must call `verify_token`" invariant:** the `Authorizer` ABC
   does not declare or call `verify_token`; the token-check contract is enforced only
   by convention inside each concrete authorizer (`mock_broker`, `xrpl_cosigner`,
   `mpc_cosigner`, and now `github_railbridge` — whose `authorize` calls it as its FIRST
   line, §13). A new adapter that forgets the call would still satisfy the ABC.
7. **"Exactness step" naming:** what the prompt calls one exactness step is steps
   **7 (context binding)** and **8 (exactness)** in `verifier.py`; recipient/destination
   substitution is caught at step 7 (context hash), amount/currency at step 8.
8. **Two distinct "binding modes":** `MODE_STRICT/POLICY/PREDICATE` (mechanism, `gate.py`)
   vs `EXACT/CAP` (per-entry amount binding on `AuthorizedTransfer`, `intent_provider.py`).
   The prompt's "STRICT/POLICY/PREDICATE enum" maps to the former. Neither is a Python
   `Enum` — both are module-level string constants.

Part II currency notes:

9. **Test inventory:** 100 tests collected (`pytest --co`); a full run is **99 passed,
   1 skipped** (the skip = the opt-in empirical breakout). The muscle's GitHub suite =
   `tests/test_github_railbridge_*.py` (attacks 9, corpus 4, e2e 3, isolation 1,
   live_resolution 7, open_mandate 5, policy 6, resolver 13, resolver_quarantine 21,
   resolver_recorded 4, transparency 6 — counts include parametrized cases). CI makes **no
   live LLM calls** (cassette replay + fakes); the empirical breakout (`resolver_quarantine`)
   and `role_b_corpus` are **opt-in** (flag + key). The §9 21-test `test_attacks.py` figure is
   the kernel suite only.
10. **Two corpora in the muscle — don't conflate:** `evals/github_railbridge/corpus.py` +
    `diagnostic.py` are the synthetic ~42-task **plan-time** set (deterministic, offline),
    whereas `role_b_corpus.py` is the opt-in **real-LLM Role-B** corpus (~34 cases, §17).
