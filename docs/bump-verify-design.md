# `mode=verify` — Bump Sheet Integration Design

**Status:** Draft (PR #69 lands Phases 1-4 scaffolding; this doc covers the full target architecture)
**Owner:** Firepan / Assune
**Source methodology:** *The Bump Sheet — Chain-Agnostic Exploit Verification Playbook for Smart Contract Audits*, Gemach DAO Security v1.0
**Compatibility:** Stacked on PR #66 (silent-downgrade observability), PR #67 (bug sweep), PR #69 (this PR)

---

## 1. Why this exists

Hound today does **finding discovery** (Pashov solidity-auditor + 8 sub-agents) and **finding curation** (PR #67 firepan-curator: scope / dead-code / trust-boundary). Neither stage **prosecutes** the findings — i.e., neither:

- Reproduces the bug deterministically against real on-chain state
- Verifies the proposed fix actually closes the bug
- Distinguishes "works at block X only" fork artifacts from structural vulnerabilities
- Bounds impact in dollars with realistic capital + gas + fees
- Produces a clone-and-run PoC the client can hand to their dev team

These are the gaps the Bump Sheet methodology fills. This PR introduces `mode=verify` as the third pipeline stage:

```
mode=auditor   →   produces candidate findings (existing)
                ↓
firepan-curator    →   filters/relabels by scope/dead-code/trust (PR #67)
                ↓
mode=verify    →   prosecutes one finding: phases 1-7 (this PR)
                ↓
Phase 7 sign-off   →   human-in-loop (always)
                ↓
client-export-ready deliverable
```

## 2. Design principles

1. **Single-finding scope.** `mode=verify` operates on exactly one hypothesis at a time. Batching is a wrapper concern. This keeps the artifact set self-contained: one directory per finding.

2. **Dry-run safe by default.** Every external call (anvil, forge, cast, RPC, Claude CLI) must succeed in dry-run mode (no RPC, no fork block) by emitting a scaffold-only artifact. This lets engineers exercise the pipeline without an archive RPC subscription.

3. **Artifacts over narrative.** The deliverable is the artifact set on disk, not a markdown report. A reviewer should be able to `git clone && forge test` against the verifier's output and reach the same verdict.

4. **Phases are best-effort.** Phase N failure must not abort the verifier — it must record the failure in `phases[N].error` and proceed. A partial verification is more useful than a hard-aborted one for triage.

5. **Verdicts are heuristics, not truth.** `verdict ∈ {verified, verified_fragile, unverified, disproved}` is the verifier's *opinion*. The Phase 7 human reviewer always has final authority.

6. **Non-cumulative composition.** `mode=verify` doesn't re-run `mode=auditor`; it consumes the prior audit's output. Same for `mode=auditor` — it doesn't run verification. Stacking is explicit (`mode=auditor_v2 = auditor + curator + verify`, planned for a follow-up).

## 3. Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│  POST /admin/audits/force-run                                          │
│      mode=verify                                                       │
│      verify_finding_id=hyp_xxx                                         │
│      verify_rpc_url=https://… (optional; dry-run if absent)            │
│      verify_fork_block=N (optional; dry-run if absent)                 │
└─────────────────────────────┬─────────────────────────────────────────┘
                              │ (Celery enqueue)
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│  worker.tasks.execute_audit_task (mode=verify branch)                  │
│  1. Re-fetch scan_config['bump_verify'] from DB                        │
│  2. Resolve hypothesis_id → DB Hypothesis row                          │
│  3. Map to FindingInput dataclass                                      │
│  4. Instantiate BumpVerifier(finding, VerifierConfig(...))             │
│  5. verifier.run() — runs Phases 1, 2, 3, 4 sequentially               │
│  6. Persist summary to AuditSession.session_metadata['bump_verify']    │
│  7. Transition scan_execution → 'in_review'                            │
└─────────────────────────────┬─────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│  analysis.bump_verifier.BumpVerifier                                   │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │ Phase 1 — Environment Lock                                       │  │
│  │   capture: forge / cast / anvil / slither / python3 versions     │  │
│  │   hash: RPC URL (first 16 chars of sha256, no API key leak)      │  │
│  │   emit: environment.lock.json                                    │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ Phase 2 — State Acquisition                                      │  │
│  │   spawn: anvil --fork-url X --fork-block-number Y --chain-id Z   │  │
│  │   wait: up to 30s for `cast block-number` to succeed             │  │
│  │   verify: N truth-check storage reads vs expected values         │  │
│  │   emit: fork.command.txt, state.verification.json                │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ Phase 3 — Reproduction Harness                                   │  │
│  │   generate: Foundry test scaffold (Bump Sheet Section 3 template)│  │
│  │   FUTURE: invoke Claude CLI with finding evidence to fill MVE    │  │
│  │   emit: test/exploits/<id>.t.sol, README.md, traces/<id>.txt     │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ Phase 4 — Bumping (block axis only in v1)                        │  │
│  │   for each delta in [-1000, -100, -10, -1, +1, +10, +100]:       │  │
│  │     forge test --fork-block-number (fork_block + delta)          │  │
│  │     record: passed/failed/timeout                                │  │
│  │   verdict: ≥2 passes ⇒ verified; only target ⇒ verified_fragile; │  │
│  │            0 passes ⇒ unverified                                 │  │
│  │   emit: bumps.md                                                 │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ Phase 5 — Impact Bounding [DEFERRED]                             │  │
│  ├─────────────────────────────────────────────────────────────────┤  │
│  │ Phase 6 — Adversary Realism [DEFERRED]                           │  │
│  └─────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────────┐
│  GET /audits/{session_id}/status                                       │
│  Returns:                                                              │
│    bump_verify.verdict: 'verified' | 'verified_fragile' |              │
│                         'unverified' | null                            │
│    bump_verify.phases: [...]                                           │
│    bump_verify.work_dir: path to artifact set                          │
│    (existing) curator_applied, coverage_chunks_processed, ...          │
└───────────────────────────────────────────────────────────────────────┘
```

## 4. Data model

### AuditSession.session_metadata['bump_verify']

```jsonc
{
  "finding_id": "hyp_2edc5bea651b",
  "verdict": "verified",                  // verified | verified_fragile | unverified | disproved
  "verdict_reason": "5/7 block bumps passed",
  "dry_run": false,
  "phases": [
    {"phase": "1_environment_lock",   "status": "ok",      "notes": "locked 5 tools"},
    {"phase": "2_state_acquisition",  "status": "ok",      "notes": "3 of 3 truth checks passed"},
    {"phase": "3_reproduction_harness","status": "ok",     "notes": "MVE filled by Claude (turns=12, cost=$0.41)"},
    {"phase": "4_bumping",            "status": "ok",      "notes": "5/7 bumps passed; verdict=verified"}
  ],
  "work_dir": "/audits/<repo>/.hound_project_<scan_id>/verify/hyp_2edc5bea651b",
  "artifacts": [
    "environment.lock.json",
    "fork.command.txt",
    "state.verification.json",
    "test/exploits/hyp_2edc5bea651b.t.sol",
    "traces/hyp_2edc5bea651b.txt",
    "bumps.md",
    "summary.json",
    "README.md"
  ]
}
```

### Bumps table format

`bumps.md` is a markdown table the human reviewer reads first. Schema:

| Axis | Value | Outcome | Notes |
|---|---|---|---|
| block | 19499000 | passed | — |
| block | 19499990 | passed | — |
| block | 19500000 | passed | (target) |
| block | 19500001 | failed | revert: collateralRatio guard |
| ... | ... | ... | ... |

Future axes (Phase 4 extensions):

- `parameter` — vary attacker capital, loan size, slippage
- `attacker` — try N distinct attacker addresses
- `ordering` — first-in-block / sandwich / last-in-block
- `concurrency` — legitimate user tx in same block
- `patch` — apply proposed fix; PoC must revert; mutate fix (delete a require); PoC must succeed again

## 5. API contract

### Request

```http
POST /admin/audits/force-run
Content-Type: application/json
X-Admin-Key: <hound-admin-key>

{
  "project_id": 5,
  "tenant_id": 2,
  "mode": "verify",
  "verify_finding_id": "hyp_2edc5bea651b",        // required
  "verify_rpc_url": "https://eth-mainnet...",     // optional; dry-run if absent
  "verify_fork_block": 19500000                   // optional; dry-run if absent
}
```

### Response (immediate)

Standard `AuditStartResponse` with `session_id` for tracking. New session is created with `mode=verify` recorded in `scan_config`.

### Status polling

```http
GET /audits/{session_id}/status
```

Returns the standard `AuditStatusResponse` with the new `bump_verify` data nested under `session_metadata`. Frontend should show:

- 🟢 `verified` badge — bumps passed, finding is robust
- 🟡 `verified_fragile` warning — only target block passes, likely fork artifact
- 🔴 `unverified` warning — verifier could not reproduce; reviewer to triage
- ⏳ `running` — phases in progress

### Error contract

| Condition | HTTP | Detail |
|---|---|---|
| Missing `verify_finding_id` | 422 | `"verify_finding_id required when mode='verify'"` |
| Unknown finding_id | 200 (queued) then `failed` status with error in `scan_execution.error_message` | `"verify finding_id not found"` |
| Anvil failed to start | n/a | Phase 2 status=`failed`; subsequent phases continue against scaffold |
| Forge test timeout | n/a | bumps row records `timeout`; doesn't abort |

## 6. Operational considerations

### RPC subscriptions

Phase 2/4 require an Ethereum archive RPC. Cost is per-engagement, not per-audit:

| Provider | Cost/month | Notes |
|---|---|---|
| Alchemy Growth | $49 | 1.5B compute units/month; archive included |
| QuickNode Build | $49 | similar |
| Tenderly DevNet | from $25 | included in their audit-friendly tier |
| Self-host Erigon | infra only | ~$200/mo VPS + 4TB storage for full archive |

A typical verification run (Phase 2 + 7 block bumps) costs ~5,000 CUs. The Growth tier supports ~300,000 verifications/month — abundant.

### Network isolation

The Bump Sheet's hard requirement: when an LLM is the verifier (Phase 3 MVE generation), the worker container MUST be network-isolated to only the pinned RPC. Today's hound worker is on `hound-net` with general outbound — needs hardening.

Proposal (follow-up PR): a `mode=verify`-specific docker-compose override that limits the worker's egress to `extra_hosts` of `<rpc_host>` only. iptables-style. This prevents an LLM accidentally broadcasting to mainnet.

### Cost per verification

Estimated per finding (verified path):

- Phase 1: ~5s, no LLM cost
- Phase 2: ~30s, no LLM cost, ~500 CU on RPC
- Phase 3 (with Claude-MVE): ~3 min, ~$0.30 Claude cost
- Phase 4 (7 block bumps × forge test): ~3 min wall, ~3,500 CU RPC

Total: ~$0.30 LLM + ~4,000 CU RPC per finding. Hard cap at $1 per verification.

### Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| Archive RPC down | Phase 2 anvil fails | Verdict=`unverified`, scaffold returned; ops alert |
| Fork at block N has wrong storage | Phase 2 truth-checks fail | Verdict=`unverified`, reviewer manually picks new block |
| Claude CLI MVE generation fails | Phase 3 status=`failed` | Scaffold-only PoC; reviewer writes MVE manually |
| forge test deps missing | Phase 4 forge test rc≠0 | Bumps recorded as `failed (compile)` for every block |
| Worker OOM mid-run | Celery task killed | Audit-session status=`failed`, partial summary retained |

## 7. Test plan

### Unit (in PR #69)
- [x] AST + import of `analysis/bump_verifier.py`
- [x] Dry-run smoke against synthetic finding emits all 6 artifact files
- [x] Per-phase exception isolation (one failure ≠ overall abort)
- [ ] `VerifierConfig.from_dict()` round-trips with all defaults

### Integration (follow-up)
- [ ] End-to-end `POST mode=verify` with `verify_rpc_url=None` (dry-run) returns `unverified` + scaffold
- [ ] End-to-end with real Alchemy URL + known finding (e.g. a documented historical exploit on DeFiHackLabs) — verify Phase 4 passes ≥2 blocks
- [ ] Failure injection: invalid RPC URL → Phase 2 fails cleanly, Phase 3/4 still emit scaffolds
- [ ] Concurrency: 2 verify tasks in parallel on different findings — each gets isolated `work_dir`, no cross-contamination

### Regression
- [ ] Existing `mode=auditor` runs unaffected (verify branch is in an `if mode == "verify":` early-return)
- [ ] `mode=sweep` / `mode=intuition` continue to route through legacy path

## 8. Phase 5 + 6 — what's deferred

The next iteration adds:

### Phase 5 — Impact Bounding

Module: `analysis.bump_verifier.PhaseFiveImpact`

Inputs:
- Phase 3 trace (attacker_start, attacker_end, victim_start, victim_end)
- Token-price oracle (Chainlink at fork_block, or fixed override)
- Cost model: flash-loan fees (Aave 0.05%, Balancer 0%, Uniswap V3 variable), gas at fork_block, slippage tolerance

Outputs:
- `impact.md`: three numbers (best, median, floor) with explicit assumptions
- `summary.bump_verify.impact_usd`: machine-readable mid-estimate

### Phase 6 — Adversary Realism

Module: `analysis.bump_verifier.PhaseSixAdversary`

LLM call (lightweight model, ~$0.05) that takes the finding + Phase 3 trace + Phase 5 impact and classifies:

- Skill ceiling: script-kiddie / solidity-literate / MEV-infra / cross-chain / nation-state
- Operational footprint: KYC required, whitelist required, etc.
- Profit motive sanity: does USD profit justify operational cost + legal exposure?
- Adversary class: opportunistic / MEV searcher / organized exploit group / nation-state / malicious insider
- Likelihood: High / Medium / Low with one-sentence justification

Output:
- `adversary.md`: paragraph-form analysis
- `summary.bump_verify.adversary_likelihood`: `low|medium|high`

## 9. Roadmap

| Release | Scope |
|---|---|
| **PR #69 (this)** | Phases 1, 2, 3 (scaffold), 4 (block axis). Dry-run safe. End-to-end wiring through API + worker + DB. |
| Follow-up #1 | Claude-driven MVE generation in Phase 3 (replace scaffold with real exploit body) |
| Follow-up #2 | Phase 4 extensions: parameter / attacker / ordering / patch axes |
| Follow-up #3 | Phase 5 (impact bounding) + Phase 6 (adversary realism) |
| Follow-up #4 | Chained `mode=auditor_v2 = auditor + curator + verify` for one-shot end-to-end runs |
| Follow-up #5 | Network-isolation harness (docker-compose override; iptables egress allowlist) |
| Follow-up #6 | Multi-chain support (Solana, Move, Cosmos addenda per Bump Sheet Section 4) |
| Follow-up #7 | Curation gate enforcement — block `in_review → completed` when `verify.verdict != verified` AND `audit_context.scope_files` was provided |

## 10. Open questions

1. **Phase 3 MVE generation — Claude or human?** Today the scaffold ships with `assertTrue(false)` and a TODO. A future Claude-driven step would auto-fill the MVE from the finding's `[poc_construction]` evidence. Risk: hallucinated exploits. Mitigation: only persist MVEs where Phase 4 ≥2 bumps pass. Likely correct.

2. **What's the "patch" for the patch-bump?** Phase 4's final step requires a candidate fix to test against. Two options: (a) require it as a request field; (b) ask Claude to propose a one-line fix per finding. (b) is cheaper but less reliable. (a) is honest but raises the operational bar.

3. **Per-engagement RPC vs shared?** A shared archive RPC works but bleeds engagements together in usage logs. Per-engagement RPCs add ops overhead. Start shared; revisit if a customer asks.

4. **Verdict thresholds (≥2 bumps = verified) — calibrated by what?** Today it's a placeholder. Should be empirically tuned against DeFiHackLabs historical exploits to find the false-positive/false-negative trade.

5. **Multi-finding batch verification?** Today: one call = one finding. Follow-up could batch (one Celery task, many verifications) — cheaper RPC usage. Defer until we have ≥10 findings per engagement on average.

6. **Sign-off (Phase 7) UI?** The methodology requires a human-signed sheet. Today there's no UI for it. Proposal: `/admin/audits/{session_id}/verify/{finding_id}/signoff` POST endpoint with reviewer initials + severity + signoff timestamp; surfaces on the audit-session detail page.

## 11. Backward compatibility

Audits with `mode != "verify"` are entirely unaffected. The new code path is guarded by `if mode == "verify":` and the new `verify_*` fields on `AdminAuditForceRunRequest` are all optional (default `None`).

New `AuditStatusResponse` fields (`bump_verify`) are optional — pre-PR-#69 sessions return `None` for them.

Database: no migrations. All new state lives in existing JSONB columns (`AuditSession.session_metadata` and `ScanExecution.scan_config`).

## 12. Glossary

- **Bump:** systematically varying one axis of the exploit (block, parameter, attacker, ordering, patch) and recording the outcome. The verifier's central activity.
- **Fork artifact:** an "exploit" that only works at one specific block, often due to mempool / state-snapshot coincidence rather than a structural bug.
- **MVE (Minimum Viable Exploit):** the shortest sequence of calls that demonstrates the bug. Section 3 of the Bump Sheet.
- **Truth check:** reading a known-good on-chain value (whale balance, total supply, storage slot) from the fork and comparing to a block explorer to confirm fork fidelity.
- **Patch bump:** applying the proposed fix and re-running the PoC. Must fail. Then mutating the fix (remove a require, flip a comparison) and re-running. Must pass. Catches under-specified tests.

---

*End of design doc. Comments and questions welcome on PR #69.*
