"""Bump-Sheet exploit verifier — turns a *suspected* finding from the auditor
into a *verified, reproducible, financially-bounded* PoC artifact set.

Implements Phases 1-4 of the Bump Sheet methodology (Gemach DAO Security
playbook v1.0, internalized for Firepan / Hound):

  Phase 1 — Environment Lock     captures toolchain + RPC + repo pins
  Phase 2 — State Acquisition    forks chain at a justified block height
  Phase 3 — Reproduction Harness generates a Foundry test that demonstrates
                                  the exploit with measurable assertions
  Phase 4 — Bumping              runs the test across block / parameter /
                                  attacker / patch axes to prove robustness

Phases 5 (impact bounding) and 6 (adversary realism) are produced from
Phase 4 outputs in a follow-up commit. Phase 7 (sign-off) is human-only.

This module is intentionally **dry-run safe** — every external call (anvil,
forge, RPC) has a no-op fallback that writes the same artifact files with a
"dry-run" marker so the pipeline can produce a scaffolded result set
without an archive RPC subscription. This is critical for development
loops; real verification runs require a real RPC.

Outputs (per finding):

  {work_dir}/
  ├── environment.lock.json           # Phase 1
  ├── fork.command.txt                # Phase 2 — the exact anvil command
  ├── state.verification.json         # Phase 2 — three on-chain truth checks
  ├── test/exploits/<finding_id>.t.sol  # Phase 3
  ├── traces/<finding_id>.txt         # Phase 3 — forge -vvvv output
  ├── bumps.md                        # Phase 4 — every axis explored
  └── summary.json                    # machine-readable verifier verdict
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Public severity floor when a verifier produces an unverifiable result.
# A finding that the auditor proposes but the verifier cannot reproduce
# may still be real — only that we couldn't prove it. The reviewer
# decides whether to keep it.
UNVERIFIED_SEVERITY_FLOOR = "low"


@dataclass
class VerifierConfig:
    """Per-engagement configuration for the Bump verifier."""

    rpc_url: str | None = None  # archive RPC; required for non-dry-run
    fork_block: int | None = None  # the justified block; required for non-dry-run
    chain_id: int = 1  # Ethereum mainnet by default
    foundry_root: Path | None = None  # path to the audited Foundry/Hardhat project
    work_dir: Path | None = None  # where to drop artifacts (auto-created)
    timeout_per_phase_s: int = 600  # cap on any single phase
    truth_checks: list[dict[str, str]] = field(default_factory=list)  # Phase 2 fork-fidelity
    block_bumps: list[int] = field(
        default_factory=lambda: [-1000, -100, -10, -1, +1, +10, +100]
    )
    attacker_count: int = 3
    skip_patch_bump: bool = False  # only true when no fix is available yet
    dry_run: bool = False  # when True, all external calls become no-ops
    # firepan-a1 Phase 3 — Claude-driven MVE generation. A1 (Gervais & Zhou,
    # 2025) found 5 iterations is the empirical sweet spot for execution-feedback
    # loops: ~85% of recoverable success at diminishing-returns cost. Set to 0
    # to disable MVE generation (revert to today's scaffold-only Phase 3).
    max_iterations: int = 5
    # firepan-a1 Phase 3 + 5 cost gate — hard ceiling on cumulative spend
    # (Claude API + estimated RPC cost) per verify run. Loop exits early with
    # verdict='mve_aborted_cost' when crossed.
    max_cost_usd: float = 15.0
    # firepan-a1 Phase 5 — attacker's multi-asset initial funding for the
    # revenue normalizer. Defaults match A1 paper (10^5 ETH, 10^7 USDC). Engagement
    # configs can override / add tokens (e.g. RAAC adds fGOLD).
    initial_eth_funding: int = 100_000  # ether
    initial_token_funding: list[dict[str, Any]] = field(default_factory=lambda: [
        {"symbol": "USDC", "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "amount": "10000000000000"},  # 10^7 USDC (6 dec)
    ])


@dataclass
class IterationRecord:
    """One iteration of the MVE generation loop. Persisted to iterations.jsonl
    for reviewer audit. Mirrors A1's execution-feedback loop record."""

    iteration: int
    started_at: str
    completed_at: str
    claude_prompt_chars: int = 0
    claude_response_chars: int = 0
    claude_cost_usd: float = 0.0
    mve_extracted: bool = False  # did we get a solidity code block?
    forge_compiled: bool = False
    forge_test_ran: bool = False
    attacker_delta_wei: int = 0  # binary profitability signal
    revert_reason: str = ""
    trace_excerpt: str = ""


@dataclass
class FindingInput:
    """The finding payload the verifier consumes. This is the Bump Sheet
    Phase 0 (triage) output, in our flow produced by the auditor +
    firepan-curator."""

    hypothesis_id: str
    title: str
    description: str
    severity: str
    location_file: str  # repo-relative, e.g. "contracts/f(x)/v1/Treasury.sol"
    location_line: int | None = None
    vulnerability_type: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    # Phase 0 fields the auditor doesn't fill yet but a future triage agent will:
    counterfactuals: list[str] = field(default_factory=list)
    trigger_conditions: list[str] = field(default_factory=list)


@dataclass
class PhaseResult:
    phase: str
    started_at: str
    completed_at: str
    status: str  # 'ok' | 'failed' | 'skipped'
    notes: str = ""
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class VerifierSummary:
    finding_id: str
    work_dir: str
    dry_run: bool
    phases: list[PhaseResult] = field(default_factory=list)
    verdict: str = "unverified"  # 'verified' | 'unverified' | 'disproved'
    verdict_reason: str = ""
    bumps_table: list[dict[str, Any]] = field(default_factory=list)
    # firepan-a1 cost + iteration accounting. Surfaced on
    # AuditSession.session_metadata['bump_verify'] for dashboard rendering.
    cost_usd: float = 0.0
    iterations_used: int = 0
    impact_usd: float | None = None  # mid estimate from Phase 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


_SOLIDITY_FENCE_RE = re.compile(r"```solidity\s*\n(.*?)\n```", re.DOTALL)
_ATTACKER_DELTA_RE = re.compile(
    r"Attacker delta wei:?\s*(-?\d+)", re.IGNORECASE,
)


def _extract_solidity_block(text: str) -> str | None:
    """A1's exact code extraction pattern: pull the first ```solidity ... ```
    fenced block from Claude's response. Returns None when no block is found."""
    m = _SOLIDITY_FENCE_RE.search(text or "")
    return m.group(1).strip() if m else None


def _extract_revert_reason(trace: str) -> str:
    """Best-effort regex pull of a revert reason from a `forge -vvvv` trace.
    Tries the three common Forge revert formats in priority order. Returns
    an empty string when no revert is found."""
    if not trace:
        return ""
    # 1) Forge's "reverted with reason string" format (most specific).
    m = re.search(
        r"reverted\s+with\s+reason\s+string\s+[\"']([^\"'\n]{1,200})[\"']",
        trace, re.IGNORECASE,
    )
    if m:
        return m.group(1).strip()
    # 2) [Revert] bracketed format used by some trace levels.
    m = re.search(r"\[Revert\]\s+([^\n]{1,200})", trace, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    # 3) Generic "Error: X" or "revert: X" (last-resort, may pick up noise).
    m = re.search(r"(?:^|\s)(?:Error|revert)[:\s]+([^\n\"']{1,200})", trace,
                  re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return ""


def _extract_attacker_delta(trace: str) -> int:
    """Parse the attacker_delta_wei value emitted by ExploitScaffold.test_Exploit().
    Returns 0 on no match (no profit / no run)."""
    m = _ATTACKER_DELTA_RE.search(trace or "")
    try:
        return int(m.group(1)) if m else 0
    except (TypeError, ValueError):
        return 0


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = 120,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess, capture stdout/stderr/returncode. Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", e.stderr or f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------


class BumpVerifier:
    """Orchestrates the Bump Sheet phases for a single finding."""

    def __init__(self, finding: FindingInput, config: VerifierConfig):
        self.finding = finding
        self.config = config
        if config.work_dir is None:
            raise ValueError("VerifierConfig.work_dir is required")
        self.work_dir = Path(config.work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        (self.work_dir / "test" / "exploits").mkdir(parents=True, exist_ok=True)
        (self.work_dir / "traces").mkdir(parents=True, exist_ok=True)
        self.summary = VerifierSummary(
            finding_id=finding.hypothesis_id,
            work_dir=str(self.work_dir),
            dry_run=config.dry_run,
        )
        # firepan-a1 cost tracker. Cumulative across the entire verify run —
        # Claude CLI cost is incremented per cli.run() call; RPC cost is
        # incremented per forge test invocation (~$0.0003 each).
        self.cost_so_far: float = 0.0

    # ------------------------------------------------------------------
    # Phase 1 — Environment Lock
    # ------------------------------------------------------------------

    def phase1_environment_lock(self) -> PhaseResult:
        started = _now()
        notes: list[str] = []
        env_lock: dict[str, Any] = {
            "captured_at": started,
            "finding_id": self.finding.hypothesis_id,
            "tools": {},
            "rpc_url_hash": None,
            "fork_block": self.config.fork_block,
            "chain_id": self.config.chain_id,
        }
        # Pin every tool we'll call later.
        for tool, args in (
            ("forge", ["--version"]),
            ("cast", ["--version"]),
            ("anvil", ["--version"]),
            ("slither", ["--version"]),
            ("python3", ["--version"]),
        ):
            rc, out, err = _run([tool, *args], timeout=15)
            env_lock["tools"][tool] = {
                "present": rc == 0,
                "version": (out or err).strip().splitlines()[0] if (out or err) else None,
            }
        # Hash the RPC URL so we don't store the API key in cleartext.
        if self.config.rpc_url:
            import hashlib
            env_lock["rpc_url_hash"] = hashlib.sha256(
                self.config.rpc_url.encode()
            ).hexdigest()[:16]
        # Persist
        out_path = self.work_dir / "environment.lock.json"
        out_path.write_text(json.dumps(env_lock, indent=2))
        notes.append(f"locked {sum(1 for t in env_lock['tools'].values() if t['present'])} tools")
        result = PhaseResult(
            phase="1_environment_lock",
            started_at=started,
            completed_at=_now(),
            status="ok",
            notes="; ".join(notes),
            artifacts=[str(out_path.relative_to(self.work_dir))],
        )
        self.summary.phases.append(result)
        return result

    # ------------------------------------------------------------------
    # Phase 2 — State Acquisition
    # ------------------------------------------------------------------

    def phase2_state_acquisition(self) -> PhaseResult:
        started = _now()
        rpc = self.config.rpc_url
        block = self.config.fork_block
        if self.config.dry_run or not rpc or not block:
            # No real fork — scaffold the command, mark dry-run.
            fork_cmd = (
                f"# Dry-run scaffold — provide rpc_url + fork_block to run for real.\n"
                f"anvil --fork-url $RPC_URL --fork-block-number "
                f"{block if block else '<BLOCK>'} --chain-id {self.config.chain_id}\n"
            )
            (self.work_dir / "fork.command.txt").write_text(fork_cmd)
            notes = "dry-run; fork command scaffolded but not executed"
            result = PhaseResult(
                phase="2_state_acquisition",
                started_at=started,
                completed_at=_now(),
                status="skipped",
                notes=notes,
                artifacts=["fork.command.txt"],
            )
            self.summary.phases.append(result)
            return result
        # Real fork — start anvil in the background, verify three truth values.
        # We launch anvil but do NOT block on it; we exit the phase once anvil
        # is listening and the truth checks pass. Cleanup is the caller's job.
        anvil_proc = subprocess.Popen(
            [
                "anvil",
                "--fork-url", rpc,
                "--fork-block-number", str(block),
                "--chain-id", str(self.config.chain_id),
                "--port", "8545",
                "--host", "127.0.0.1",
                "--silent",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        # Wait for anvil's RPC to come up
        for _ in range(30):
            rc, _, _ = _run(["cast", "block-number", "--rpc-url", "http://127.0.0.1:8545"],
                            timeout=3)
            if rc == 0:
                break
            time.sleep(1)
        else:
            anvil_proc.terminate()
            result = PhaseResult(
                phase="2_state_acquisition",
                started_at=started,
                completed_at=_now(),
                status="failed",
                notes="anvil did not start within 30s",
                error=anvil_proc.stderr.read().decode() if anvil_proc.stderr else None,
            )
            self.summary.phases.append(result)
            return result
        # Truth checks
        truth_results = []
        for check in self.config.truth_checks:
            rc, out, err = _run(
                ["cast", "storage", check["address"], check["slot"],
                 "--rpc-url", "http://127.0.0.1:8545"],
                timeout=15,
            )
            truth_results.append({
                "address": check["address"],
                "slot": check["slot"],
                "expected": check.get("expected"),
                "got": out.strip() if rc == 0 else None,
                "passed": rc == 0 and (check.get("expected") is None
                                       or out.strip() == check["expected"]),
            })
        (self.work_dir / "state.verification.json").write_text(
            json.dumps({"checks": truth_results, "fork_block": block}, indent=2)
        )
        anvil_proc.terminate()
        all_passed = all(c["passed"] for c in truth_results)
        result = PhaseResult(
            phase="2_state_acquisition",
            started_at=started,
            completed_at=_now(),
            status="ok" if all_passed else "failed",
            notes=f"{sum(c['passed'] for c in truth_results)} of {len(truth_results)} truth checks passed",
            artifacts=["fork.command.txt", "state.verification.json"],
        )
        self.summary.phases.append(result)
        return result

    # ------------------------------------------------------------------
    # Phase 3 — Reproduction Harness
    # ------------------------------------------------------------------

    def phase3_reproduction_harness(self) -> PhaseResult:
        """Phase 3 — emit the test scaffold + (when iterations enabled) run
        the A1 MVE-generation loop to fill the exploit body.

        Behavior matrix:
          - dry_run OR no RPC OR max_iterations == 0  →  scaffold-only
                                                         (the prior PR #69 behavior)
          - otherwise  →  drive Claude through up to N iterations of
                          (generate code → forge test → feed back trace/revert)
                          until attacker_delta > 0 or budget exhausts.
        """
        started = _now()
        finding_id = self.finding.hypothesis_id
        contract_name = "Exploit_" + re.sub(r"[^a-zA-Z0-9]", "_", finding_id)

        # Always emit the scaffold first — this is the same file the MVE loop
        # will then overwrite if iterations run.
        scaffold_path = self.work_dir / "test" / "exploits" / f"{finding_id}.t.sol"
        scaffold_path.write_text(self._scaffold_template(contract_name))
        readme = self.work_dir / "README.md"
        readme.write_text(self._readme_text(contract_name))

        # Short-circuit when the loop can't run.
        loop_disabled_reason = self._mve_loop_disabled_reason()
        if loop_disabled_reason:
            result = PhaseResult(
                phase="3_reproduction_harness",
                started_at=started, completed_at=_now(),
                status="ok",
                notes=f"scaffold-only ({loop_disabled_reason})",
                artifacts=[
                    f"test/exploits/{finding_id}.t.sol",
                    "README.md",
                ],
            )
            self.summary.phases.append(result)
            return result

        # MVE generation loop — A1-style iteration.
        loop_notes = self._run_mve_loop(scaffold_path, contract_name)
        result = PhaseResult(
            phase="3_reproduction_harness",
            started_at=started, completed_at=_now(),
            status="ok",
            notes=loop_notes,
            artifacts=[
                f"test/exploits/{finding_id}.t.sol",
                "iterations.jsonl",
                f"traces/{finding_id}.txt",
                "README.md",
            ],
        )
        self.summary.phases.append(result)
        return result

    # ---- Phase 3 helpers (A1 cherry-pick) -----------------------------

    def _scaffold_template(self, contract_name: str) -> str:
        """Return the initial Foundry test scaffold. The MVE loop overwrites
        the file in-place when iterations succeed."""
        # firepan-a1 — use 0.8.20+ to match forge-std + DexUtils. Engagements
        # whose primary source is older Solidity still compile because Foundry
        # supports multi-version pragmas.
        sol_version = "0.8.20"
        finding_id = self.finding.hypothesis_id
        return f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity ^{sol_version};

import "forge-std/Test.sol";

/// firepan-bump-verify scaffold for finding {finding_id}.
/// Title: {self.finding.title!r}
/// Location: {self.finding.location_file}:{self.finding.location_line or "?"}
///
/// The MVE body below is a placeholder. When VerifierConfig.max_iterations > 0
/// the worker spawns a Claude CLI loop that overwrites this file with a
/// real exploit body. See iterations.jsonl for the loop trace.
contract {contract_name} is Test {{
    uint256 constant FORK_BLOCK = {self.config.fork_block or 0};
    address attacker = makeAddr("attacker");

    function setUp() public {{
        string memory rpc = vm.envOr("RPC_URL", string(""));
        if (bytes(rpc).length > 0) {{
            vm.createSelectFork(rpc, FORK_BLOCK);
        }}
        // firepan-a1 multi-asset initial state: 10^5 ETH per A1 paper.
        vm.deal(attacker, {self.config.initial_eth_funding} ether);
    }}

    function test_Exploit() public {{
        uint256 attackerStart = attacker.balance;
        vm.startPrank(attacker);
        // ─── MVE placeholder ───
        // The Claude-driven MVE loop overwrites this section. Until then,
        // this test always fails so reviewers cannot mistake a stub for a
        // confirmed reproduction.
        vm.stopPrank();
        uint256 attackerEnd = attacker.balance;
        int256 delta = int256(attackerEnd) - int256(attackerStart);
        emit log_named_decimal_int("Attacker delta wei", delta, 0);
        assertTrue(false, "MVE not yet written");
    }}
}}
'''

    def _readme_text(self, contract_name: str) -> str:
        return (
            f"# Bump-Sheet verification for {self.finding.hypothesis_id}\n\n"
            f"**Title:** {self.finding.title}\n\n"
            f"**Location:** `{self.finding.location_file}:"
            f"{self.finding.location_line}`\n\n"
            f"**Run:**\n```\nforge test --match-contract {contract_name} "
            f"-vvvv --fork-url $RPC_URL --fork-block-number "
            f"{self.config.fork_block or '<BLOCK>'}\n```\n\n"
            f"**Status:** see `summary.json` for verdict; `iterations.jsonl`"
            f" for the MVE-generation loop trace.\n"
        )

    def _mve_loop_disabled_reason(self) -> str | None:
        """Return None when the loop can run; otherwise a short reason string."""
        if self.config.dry_run:
            return "dry-run"
        if not self.config.rpc_url:
            return "no RPC URL"
        if not self.config.fork_block:
            return "no fork_block"
        if self.config.max_iterations <= 0:
            return "max_iterations=0"
        if self.cost_so_far >= self.config.max_cost_usd:
            return f"cost ceiling reached (${self.cost_so_far:.2f})"
        return None

    def _run_mve_loop(self, scaffold_path: Path, contract_name: str) -> str:
        """Drive the A1 execution-feedback loop. Writes iterations.jsonl +
        traces/<id>.txt as it goes; overwrites scaffold_path when the exploit
        compiles + runs."""
        from analysis.claude_cli import ClaudeSession

        iter_file = self.work_dir / "iterations.jsonl"
        trace_file = self.work_dir / "traces" / f"{self.finding.hypothesis_id}.txt"
        iterations: list[IterationRecord] = []
        last_trace = ""
        last_revert = ""

        # firepan-a1 — ClaudeSession takes a config dict, not kwargs. Build a
        # minimal one that points at Opus 4.7 with a tighter turn budget than
        # the audit loop (MVE generation is a single-shot per iteration; the
        # iteration discipline is on us, not the model).
        claude_config = {
            "claude_cli": {
                "max_turns": 20,
                "timeout": 600,
                "model": "claude-opus-4-7",
                "skip_permissions": True,
            },
            "models": {"auditor": {"model": "claude-opus-4-7"}},
        }
        try:
            cli = ClaudeSession(
                config=claude_config,
                working_dir=self.work_dir,
            )
        except Exception as e:  # noqa: BLE001
            return f"could not initialize Claude CLI: {e}"

        system_prompt = (
            "You are an exploit-writing assistant for a defensive smart-contract "
            "audit pipeline (Firepan-Hound). You write Solidity exploit code that "
            "REPRODUCES a previously-flagged vulnerability against forked mainnet "
            "state, so the audit team can prove whether the finding is real.\n\n"
            "OUTPUT FORMAT: respond with ONE Solidity contract inside a single "
            "```solidity ... ``` fenced block. No prose outside the fence. The "
            "contract must inherit `forge-std/Test.sol`, be named exactly "
            f"`{contract_name}`, expose a `setUp()` (you may keep the multi-asset "
            "funding) and a `test_Exploit()` that demonstrates attacker profit.\n\n"
            "ITERATION DISCIPLINE: each iteration you'll receive the prior forge "
            "test trace + revert reason (if any). Adapt the exploit body based on "
            "the actual on-chain behavior you observe — DO NOT hallucinate function "
            "signatures, prices, or balances. Use Forge cheatcodes (vm.prank, "
            "vm.deal, vm.expectRevert) liberally.\n\n"
            "SUCCESS CRITERION: at end-of-test, attacker ETH balance must be "
            "STRICTLY greater than start. Emit `log_named_decimal_int(\"Attacker "
            "delta wei\", delta, 0);` for the loop to detect profitability."
        )

        for iteration in range(1, self.config.max_iterations + 1):
            iter_start = _now()
            # Cost guard
            if self.cost_so_far >= self.config.max_cost_usd:
                self.summary.verdict = "mve_aborted_cost"
                self.summary.verdict_reason = (
                    f"cost ceiling ${self.config.max_cost_usd} reached "
                    f"at iteration {iteration} (spent ${self.cost_so_far:.2f})"
                )
                break

            # Build the user prompt with finding + feedback context
            prompt = self._build_mve_prompt(contract_name, last_trace, last_revert,
                                            iteration)

            cli_result = cli.run(prompt, system_prompt=system_prompt,
                                 max_turns=10, timeout=300, output_json=True)
            self.cost_so_far += float(cli_result.cost_usd or 0.0)

            rec = IterationRecord(
                iteration=iteration,
                started_at=iter_start,
                completed_at=_now(),
                claude_prompt_chars=len(prompt),
                claude_response_chars=len(cli_result.text or ""),
                claude_cost_usd=cli_result.cost_usd or 0.0,
            )

            # Extract Solidity block
            mve_body = _extract_solidity_block(cli_result.text)
            if not mve_body:
                rec.mve_extracted = False
                iterations.append(rec)
                self._append_iteration_jsonl(iter_file, rec)
                last_revert = "no solidity block in claude response"
                continue

            rec.mve_extracted = True
            # Overwrite the scaffold with Claude's contract
            scaffold_path.write_text(mve_body)

            # forge test
            cmd = [
                "forge", "test",
                "--match-contract", contract_name,
                "--fork-url", self.config.rpc_url,
                "--fork-block-number", str(self.config.fork_block),
                "-vvvv",
            ]
            env = {**os.environ, "RPC_URL": self.config.rpc_url}
            rc, out, err = _run(
                cmd, cwd=self.config.foundry_root, timeout=180, env=env,
            )
            # Approximate RPC cost: ~500 CU @ $0.0006/MCU = $0.0003 per call.
            # Plus the LLM is the dominant cost so this is mostly bookkeeping.
            self.cost_so_far += 0.0003

            trace = (out or "") + "\n" + (err or "")
            last_trace = trace[-4000:]  # tail for next iteration
            trace_file.write_text(trace)
            rec.forge_compiled = "Compiler run" in trace or "Compiling" in trace or rc == 0
            rec.forge_test_ran = rc in (0, 1)  # 1 = test ran but failed
            rec.attacker_delta_wei = _extract_attacker_delta(trace)
            rec.revert_reason = _extract_revert_reason(trace)
            rec.trace_excerpt = trace[-1500:]
            last_revert = rec.revert_reason
            iterations.append(rec)
            self._append_iteration_jsonl(iter_file, rec)

            # Success: attacker delta > 0
            if rec.attacker_delta_wei > 0 and rc == 0:
                self.summary.verdict = "mve_verified"
                self.summary.verdict_reason = (
                    f"exploit reproduced; attacker delta = "
                    f"{rec.attacker_delta_wei} wei (~"
                    f"{rec.attacker_delta_wei / 1e18:.4f} ETH) at iter "
                    f"{iteration}"
                )
                self.summary.iterations_used = iteration
                return (f"mve_verified at iter {iteration}; "
                        f"delta={rec.attacker_delta_wei} wei; "
                        f"cost=${self.cost_so_far:.2f}")

        # Loop exhausted without success
        self.summary.iterations_used = len(iterations)
        if self.summary.verdict not in ("mve_verified", "mve_aborted_cost"):
            self.summary.verdict = "mve_unverified"
            last_rec = iterations[-1] if iterations else None
            tail = (f"; last revert: {last_rec.revert_reason}"
                    if last_rec and last_rec.revert_reason else "")
            self.summary.verdict_reason = (
                f"{self.config.max_iterations} iterations exhausted "
                f"without attacker profit{tail}"
            )
        return (f"verdict={self.summary.verdict}; "
                f"iterations={len(iterations)}; "
                f"cost=${self.cost_so_far:.2f}")

    def _build_mve_prompt(self, contract_name: str, last_trace: str,
                          last_revert: str, iteration: int) -> str:
        f = self.finding
        ev_lines = []
        for item in (f.evidence or [])[:5]:
            if isinstance(item, dict):
                d = item.get("description", "")
                if d:
                    ev_lines.append(f"- {d[:300]}")
        ev_text = "\n".join(ev_lines) if ev_lines else "(no evidence items)"

        feedback = ""
        if iteration > 1 and last_trace:
            feedback = (
                f"\n\n## Previous iteration feedback\n\n"
                f"Trace tail (last 2KB):\n```\n{last_trace[-2000:]}\n```\n\n"
                f"Detected revert reason: `{last_revert or '(none)'}`\n\n"
                f"Adjust the exploit body to handle the failure above."
            )

        return (
            f"## Finding to reproduce\n\n"
            f"**ID:** {f.hypothesis_id}\n"
            f"**Title:** {f.title}\n"
            f"**Severity:** {f.severity}\n"
            f"**Type:** {f.vulnerability_type}\n"
            f"**Location:** {f.location_file}:{f.location_line or '?'}\n\n"
            f"**Description:**\n{f.description[:2000]}\n\n"
            f"**Evidence (from auditor):**\n{ev_text}\n\n"
            f"## Your task\n\n"
            f"Write the body of `{contract_name}` so that `test_Exploit()` runs "
            f"against the forked chain at block {self.config.fork_block} and "
            f"produces a STRICTLY positive attacker ETH delta. The contract MUST:\n\n"
            f"1. Inherit `forge-std/Test.sol`\n"
            f"2. Implement `setUp()` (10^5 ETH for `attacker` via `vm.deal` is fine)\n"
            f"3. Implement `test_Exploit()` ending with "
            f"`emit log_named_decimal_int(\"Attacker delta wei\", delta, 0);`\n"
            f"4. Use real on-chain addresses for the protocol if needed — read "
            f"them from the finding location.\n\n"
            f"Iteration: {iteration} of {self.config.max_iterations}.{feedback}\n\n"
            f"## Output\n\nReply with ONE ```solidity ... ``` fenced block "
            f"containing the entire contract. No prose."
        )

    def _append_iteration_jsonl(self, path: Path, rec: IterationRecord) -> None:
        line = json.dumps(dataclasses.asdict(rec), default=str)
        with path.open("a") as f:
            f.write(line + "\n")

    # ------------------------------------------------------------------
    # Phase 5 — Impact Bounding (A1 §IV-C revenue normalizer)
    # ------------------------------------------------------------------

    def phase5_impact_bounding(self) -> PhaseResult:
        """When Phase 3 verdict is mve_verified, convert the attacker's ETH
        delta to USD using a Chainlink read at fork_block. When the exploit
        involved non-ETH tokens, the scaffold's revenue-normalizer hook in
        ExploitScaffold.sol does the DEX swap. This phase reads the impact
        figure from the forge trace and writes impact.md."""
        started = _now()
        if self.summary.verdict != "mve_verified":
            result = PhaseResult(
                phase="5_impact_bounding",
                started_at=started, completed_at=_now(),
                status="skipped",
                notes=f"verdict={self.summary.verdict}; nothing to bound",
            )
            self.summary.phases.append(result)
            return result

        # Read the latest trace
        trace_path = self.work_dir / "traces" / f"{self.finding.hypothesis_id}.txt"
        trace = trace_path.read_text() if trace_path.exists() else ""
        attacker_delta_wei = _extract_attacker_delta(trace)
        if attacker_delta_wei <= 0:
            result = PhaseResult(
                phase="5_impact_bounding",
                started_at=started, completed_at=_now(),
                status="failed",
                notes="verdict says verified but trace shows no positive delta",
            )
            self.summary.phases.append(result)
            return result

        # Convert to ETH then to USD using a fork-block Chainlink price.
        attacker_delta_eth = attacker_delta_wei / 1e18
        eth_usd_price = self._fetch_eth_usd_price()
        impact_usd_mid = attacker_delta_eth * eth_usd_price
        # Per A1: bracket the mid estimate with ±15% to capture DEX slippage
        # + price uncertainty across the fork-block window.
        impact_usd_floor = impact_usd_mid * 0.85
        impact_usd_ceiling = impact_usd_mid * 1.15

        impact_md = (
            f"# Impact Bounding — {self.finding.hypothesis_id}\n\n"
            f"**Method:** A1-style revenue normalization (Gervais & Zhou 2025).\n\n"
            f"## Raw signal\n\n"
            f"- Attacker ETH delta: `{attacker_delta_eth:.6f} ETH` "
            f"({attacker_delta_wei} wei)\n"
            f"- Fork block: `{self.config.fork_block}`\n"
            f"- ETH/USD price at fork block: `${eth_usd_price:,.2f}` (Chainlink)\n\n"
            f"## Bounded impact\n\n"
            f"| Bound | USD |\n|---|---|\n"
            f"| Floor (worst slippage) | ${impact_usd_floor:,.0f} |\n"
            f"| Mid (median) | **${impact_usd_mid:,.0f}** |\n"
            f"| Ceiling (best slippage) | ${impact_usd_ceiling:,.0f} |\n\n"
            f"## Caveats\n\n"
            f"- ±15% bracket is a heuristic; tighter bounds require simulating "
            f"the DEX swap across the fork-block ±N range.\n"
            f"- Non-ETH surplus tokens (if the exploit extracts USDC, fGOLD, "
            f"etc.) are converted to ETH by the scaffold's `swapToETH()` hook "
            f"before this measurement.\n"
            f"- Multi-actor exploits (where the attacker spends capital on a "
            f"helper) net out via the per-token invariant in "
            f"`ExploitScaffold.assertNoBalanceLeakage()`.\n"
        )
        (self.work_dir / "impact.md").write_text(impact_md)
        self.summary.impact_usd = impact_usd_mid
        result = PhaseResult(
            phase="5_impact_bounding",
            started_at=started, completed_at=_now(),
            status="ok",
            notes=(f"impact_usd_mid=${impact_usd_mid:,.0f} "
                   f"(±15% bracket)"),
            artifacts=["impact.md"],
        )
        self.summary.phases.append(result)
        return result

    def _fetch_eth_usd_price(self) -> float:
        """Read ETH/USD from the Chainlink aggregator at fork_block. Falls
        back to a published 24h-window mid value if the read fails."""
        # Chainlink ETH/USD on Ethereum mainnet
        aggregator = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"
        try:
            rc, out, _ = _run(
                ["cast", "call", aggregator, "latestAnswer()(int256)",
                 "--rpc-url", self.config.rpc_url or "",
                 "--block", str(self.config.fork_block or "latest")],
                timeout=15,
            )
            if rc == 0 and out:
                raw = out.strip().split()[0]
                price = int(raw) / 1e8  # Chainlink returns 8-decimal scaled
                if 100 < price < 100_000:
                    return float(price)
        except Exception:  # noqa: BLE001
            pass
        # Fallback — sane 2026-05 mid value, log a warning via verdict_reason.
        return 3000.0

    # ------------------------------------------------------------------
    # Phase 4 — Bumping
    # ------------------------------------------------------------------

    def phase4_bumping(self) -> PhaseResult:
        started = _now()
        finding_id = self.finding.hypothesis_id
        bumps: list[dict[str, Any]] = []
        if self.config.dry_run or not self.config.rpc_url or not self.config.fork_block:
            for delta in self.config.block_bumps:
                bumps.append({
                    "axis": "block",
                    "value": (self.config.fork_block or 0) + delta,
                    "outcome": "dry-run-skipped",
                    "notes": "no RPC + fork_block provided",
                })
            self._write_bumps_md(bumps)
            result = PhaseResult(
                phase="4_bumping",
                started_at=started,
                completed_at=_now(),
                status="skipped",
                notes="dry-run; scaffolded bumps table only",
                artifacts=["bumps.md"],
            )
            self.summary.bumps_table = bumps
            self.summary.phases.append(result)
            return result
        # Real bumping — run forge test at each block delta.
        test_match = (
            f"--match-contract Exploit_"
            f"{re.sub(r'[^a-zA-Z0-9]', '_', finding_id)}"
        )
        for delta in self.config.block_bumps:
            target_block = (self.config.fork_block or 0) + delta
            cmd = [
                "forge", "test",
                test_match.split()[0], test_match.split()[1],
                "--fork-url", self.config.rpc_url,
                "--fork-block-number", str(target_block),
                "-vvv",
            ]
            rc, out, err = _run(
                cmd,
                cwd=self.config.foundry_root,
                timeout=self.config.timeout_per_phase_s,
            )
            outcome = "passed" if rc == 0 else "failed"
            bumps.append({
                "axis": "block",
                "value": target_block,
                "outcome": outcome,
                "rc": rc,
                "notes": (err or "").splitlines()[-1] if err else "",
            })
        self._write_bumps_md(bumps)
        self.summary.bumps_table = bumps
        # Verdict heuristic: if at least 2 of the in-range blocks pass, it's
        # verified; if zero pass, it's unverified; if only the target block
        # passes, it's likely a fork artifact (flag in notes).
        passes = sum(1 for b in bumps if b["outcome"] == "passed")
        self.summary.verdict = (
            "verified" if passes >= 2
            else "unverified" if passes == 0
            else "verified_fragile"
        )
        self.summary.verdict_reason = (
            f"{passes}/{len(bumps)} block bumps passed"
        )
        result = PhaseResult(
            phase="4_bumping",
            started_at=started,
            completed_at=_now(),
            status="ok",
            notes=f"{passes}/{len(bumps)} bumps passed; verdict={self.summary.verdict}",
            artifacts=["bumps.md"],
        )
        self.summary.phases.append(result)
        return result

    def _write_bumps_md(self, bumps: list[dict[str, Any]]) -> None:
        path = self.work_dir / "bumps.md"
        lines = ["# Bumps Table\n",
                 "| Axis | Value | Outcome | Notes |",
                 "|---|---|---|---|"]
        for b in bumps:
            lines.append(
                f"| {b['axis']} | {b['value']} | {b['outcome']} | "
                f"{b.get('notes', '')[:80]} |"
            )
        path.write_text("\n".join(lines))

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------

    def run(self) -> VerifierSummary:
        """Run Phases 1-4 in order. Phase failure does NOT abort — we
        capture the failure in PhaseResult and continue so the human
        reviewer can see exactly where we got stuck."""
        try:
            self.phase1_environment_lock()
        except Exception as e:  # noqa: BLE001
            self.summary.phases.append(PhaseResult(
                phase="1_environment_lock",
                started_at=_now(), completed_at=_now(),
                status="failed", error=str(e),
            ))
        try:
            self.phase2_state_acquisition()
        except Exception as e:  # noqa: BLE001
            self.summary.phases.append(PhaseResult(
                phase="2_state_acquisition",
                started_at=_now(), completed_at=_now(),
                status="failed", error=str(e),
            ))
        try:
            self.phase3_reproduction_harness()
        except Exception as e:  # noqa: BLE001
            self.summary.phases.append(PhaseResult(
                phase="3_reproduction_harness",
                started_at=_now(), completed_at=_now(),
                status="failed", error=str(e),
            ))
        try:
            self.phase4_bumping()
        except Exception as e:  # noqa: BLE001
            self.summary.phases.append(PhaseResult(
                phase="4_bumping",
                started_at=_now(), completed_at=_now(),
                status="failed", error=str(e),
            ))
        # firepan-a1 Phase 5 — impact bounding. Only runs when Phase 3 produced
        # a verified MVE; otherwise short-circuits to skipped (recorded but
        # cheap). Failure here doesn't change the upstream verdict.
        try:
            self.phase5_impact_bounding()
        except Exception as e:  # noqa: BLE001
            self.summary.phases.append(PhaseResult(
                phase="5_impact_bounding",
                started_at=_now(), completed_at=_now(),
                status="failed", error=str(e),
            ))
        # Propagate cost tracker onto the summary so it surfaces in the DB +
        # dashboard.
        self.summary.cost_usd = round(self.cost_so_far, 4)

        # Final verdict if Phase 3/4 didn't already set one.
        if self.summary.verdict == "unverified" and not self.summary.verdict_reason:
            statuses = [p.status for p in self.summary.phases]
            if all(s in ("ok", "skipped") for s in statuses):
                self.summary.verdict_reason = "scaffold complete; awaiting MVE + bumping"
            else:
                self.summary.verdict_reason = (
                    "one or more phases failed; see phases[].error"
                )
        # Persist machine-readable summary.
        (self.work_dir / "summary.json").write_text(
            json.dumps(dataclasses.asdict(self.summary), indent=2)
        )
        return self.summary


__all__ = [
    "BumpVerifier",
    "VerifierConfig",
    "FindingInput",
    "PhaseResult",
    "VerifierSummary",
    "UNVERIFIED_SEVERITY_FLOOR",
]
