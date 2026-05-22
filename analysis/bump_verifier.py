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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        started = _now()
        finding_id = self.finding.hypothesis_id
        # The Bump Sheet Section 3 template, parameterized per finding.
        # In a future iteration this is generated by Claude CLI given the
        # finding + source context; for the first cut we ship the scaffold
        # and a clear TODO for the exploit body.
        sol_version = "0.7.6"  # TODO: read from foundry.toml / hardhat.config
        template = f'''// SPDX-License-Identifier: UNLICENSED
pragma solidity {sol_version};

import "forge-std/Test.sol";

/// firepan-bump-verify generated scaffold for finding {finding_id}.
/// Title: {self.finding.title!r}
/// Location: {self.finding.location_file}:{self.finding.location_line or "?"}
///
/// TODO (verifier): replace the MVE body with the minimum-viable exploit.
/// The assertions below are placeholders that the verifier must replace
/// with measurable bad-outcome checks (attacker_balance increased,
/// victim_balance decreased, invariant broken).
contract Exploit_{re.sub(r"[^a-zA-Z0-9]", "_", finding_id)} is Test {{
    uint256 constant FORK_BLOCK = {self.config.fork_block or 0};
    string RPC = vm.envOr("RPC_URL", string(""));

    address attacker = makeAddr("attacker");
    address victim   = address(0); // TODO: real victim

    function setUp() public {{
        if (bytes(RPC).length > 0) {{
            vm.createSelectFork(RPC, FORK_BLOCK);
        }}
        vm.deal(attacker, 10 ether);
    }}

    function test_Exploit() public {{
        uint256 attackerStart = attacker.balance;
        uint256 victimStart   = victim.balance;

        vm.startPrank(attacker);
        // ─── TODO: minimum viable exploit ───
        // The call sequence demonstrating {finding_id}.
        vm.stopPrank();

        uint256 attackerEnd = attacker.balance;
        uint256 victimEnd   = victim.balance;

        emit log_named_decimal_uint("Attacker delta (ETH)", attackerEnd - attackerStart, 18);
        emit log_named_decimal_uint("Victim loss (ETH)",    victimStart - victimEnd, 18);

        // Replace with the actual bad-outcome invariant for this finding.
        assertTrue(false, "MVE not yet written");
    }}

    function test_PatchClosesExploit() public {{
        // Apply the proposed fix in this branch. Re-run. This test MUST
        // fail (revert) once the fix is in place. Without this, the
        // verifier has no proof the fix works.
        assertTrue(false, "patch test not yet written");
    }}
}}
'''
        test_path = self.work_dir / "test" / "exploits" / f"{finding_id}.t.sol"
        test_path.write_text(template)
        readme = self.work_dir / "README.md"
        readme.write_text(
            f"# Bump-Sheet verification for {finding_id}\n\n"
            f"**Title:** {self.finding.title}\n\n"
            f"**Location:** `{self.finding.location_file}:{self.finding.location_line}`\n\n"
            f"**Run:**\n```\nforge test --match-contract Exploit_"
            f"{re.sub(r'[^a-zA-Z0-9]', '_', finding_id)} -vvvv "
            f"--fork-url $RPC_URL --fork-block-number {self.config.fork_block or '<BLOCK>'}\n```\n\n"
            f"**Status:** scaffold-only; MVE body not yet written.\n"
        )
        result = PhaseResult(
            phase="3_reproduction_harness",
            started_at=started,
            completed_at=_now(),
            status="ok",
            notes="scaffold emitted (Claude-driven MVE body in a follow-up step)",
            artifacts=[
                f"test/exploits/{finding_id}.t.sol",
                "README.md",
            ],
        )
        self.summary.phases.append(result)
        return result

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
        # Final verdict if Phase 4 didn't already set one.
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
