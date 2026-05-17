"""
False-positive verification pipeline (fp-check).

When the **Claude Code CLI** is available, the pipeline gives Claude an
autonomous session with full tool access — file operations, bash, Slither,
Foundry, semgrep, Trail of Bits plugins — and asks it to run all seven
verification phases itself:

  1. Data Flow    — trace data flow from source to sink
  2. Exploitability — assess reachability and triggerability
  3. Impact       — quantify impact (numeric gap measurement required)
  4. PoC          — generate + execute a PoC stub
  5. Devil's Advocate — adversarial counter-arguments
  6. Six-Gate Review  — structured checklist + premise re-derivation
  7. Final Verdict    — confirmed / rejected / uncertain

Falls back to ``UnifiedLLMClient.parse()`` per-phase when the CLI is
not on ``$PATH``.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analysis.claude_cli import ClaudeResult, ClaudeSession
from llm.schemas import (
    CandidateFinding,
    FPCheckPhaseResult,
    FPCheckVerdict,
)
from llm.unified_client import UnifiedLLMClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phase prompts
# ---------------------------------------------------------------------------

_PHASE_PROMPTS: dict[str, str] = {
    "data_flow": """\
You are a security auditor performing DATA FLOW ANALYSIS on a candidate vulnerability.

CANDIDATE FINDING:
{finding_json}

SOURCE CODE CONTEXT:
{source_context}

Trace the data flow from the untrusted input (source) to the vulnerable
operation (sink) for this candidate finding.  Identify:
1. The exact source of untrusted data.
2. Every transformation / sanitisation / validation the data passes through.
3. The sink where the vulnerability manifests.
4. Whether any guard or check along the path prevents exploitation.

Return your analysis as JSON matching the FPCheckPhaseResult schema.""",

    "exploitability": """\
You are a security auditor assessing EXPLOITABILITY of a candidate vulnerability.

CANDIDATE FINDING:
{finding_json}

SOURCE CODE CONTEXT:
{source_context}

PREVIOUS PHASE (Data Flow):
{prev_phase}

Determine whether this vulnerability is reachable and triggerable by an
attacker.  Consider:
1. Is the vulnerable code path reachable from an external entry point?
2. What preconditions must hold for the path to execute?
3. Can an attacker control the relevant inputs to trigger the vulnerability?
4. Are there runtime guards (require, assert, access control) that block it?

Return your analysis as JSON matching the FPCheckPhaseResult schema.""",

    "impact": """\
You are a security auditor quantifying the IMPACT of a candidate vulnerability.

CANDIDATE FINDING:
{finding_json}

SOURCE CODE CONTEXT:
{source_context}

PREVIOUS PHASES:
{prev_phases}

Quantify the impact of this vulnerability.  You MUST provide a numeric
measurement — wei-exact where applicable.  Consider:
1. What is the worst-case financial / data / availability loss?
2. Provide a NUMERIC GAP MEASUREMENT (e.g. "4.9% fee undercharge",
   "116 bps divergence", "drain up to 100 ETH").
3. Compare the candidate's claimed gap ({claimed_gap}) against your
   independent assessment.
4. If the measured gap is effectively zero or sub-ppb, this phase FAILS.

Return your analysis as JSON matching the FPCheckPhaseResult schema.
In the 'evidence' field, include your independently measured numeric gap.""",

    "poc_construction": """\
You are a security auditor constructing a PROOF OF CONCEPT for a candidate
vulnerability.

CANDIDATE FINDING:
{finding_json}

SOURCE CODE CONTEXT:
{source_context}

PREVIOUS PHASES:
{prev_phases}

Generate three artefacts:
1. **Pseudo-PoC**: high-level exploit steps in plain English.
2. **Executable stub**: a minimal test / script (Solidity foundry test,
   Python boa test, or equivalent) that demonstrates the vulnerability
   with a concrete numeric assertion.
3. **Negative PoC**: a test that demonstrates the FIX or existing guard
   that would prevent exploitation (if one exists).

CRITICAL — Instrumentation-order discipline:
- Snapshot balances / state AFTER setting up the attacker, not before.
- Do NOT count setup transactions (e.g. boa.deal, token minting) as
  "profit".  Measure only the delta caused by the exploit action.

Return your analysis as JSON matching the FPCheckPhaseResult schema.
In the 'evidence' field, include the three artefacts separated by
"---PSEUDO_POC---", "---EXECUTABLE_STUB---", "---NEGATIVE_POC---" markers.""",

    "devil_advocate": """\
You are a DEVIL'S ADVOCATE reviewer tasked with DISPROVING a candidate
vulnerability finding.

CANDIDATE FINDING:
{finding_json}

SOURCE CODE CONTEXT:
{source_context}

PREVIOUS PHASES:
{prev_phases}

Your job is to argue AGAINST this finding.  Try your hardest to show it is
a false positive.  Consider:
1. Are there guards / mitigations the auditor missed?
2. Is the threat model realistic?  Would a real attacker pursue this?
3. Does the PoC actually prove the claim, or does it measure the wrong thing?
4. Is the numeric gap an artefact of incorrect instrumentation order?
5. Re-derive the premise from scratch — do NOT trust the auditor's setup.

If you cannot find a convincing counter-argument, state so explicitly.

Return your analysis as JSON matching the FPCheckPhaseResult schema.
Set passed=true if the finding SURVIVES your adversarial review (i.e. you
could not disprove it).  Set passed=false if you found a convincing
counter-argument.""",

    "six_gate_review": """\
You are a security auditor performing a structured SIX-GATE REVIEW of a
candidate vulnerability.

CANDIDATE FINDING:
{finding_json}

SOURCE CODE CONTEXT:
{source_context}

ALL PREVIOUS PHASES:
{prev_phases}

Evaluate the finding against each gate.  A gate passes (true) or fails
(false):

Gate 1 — GUARDS PRESENT: Are there existing guards / checks that prevent
         this vulnerability?  (pass = no effective guards found)
Gate 2 — MITIGATIONS: Are there design-level mitigations (e.g. timelocks,
         rate limits, admin-only)?  (pass = no effective mitigations)
Gate 3 — ASSUMPTIONS VALID: Are the auditor's assumptions about state,
         ordering, and preconditions correct?  (pass = assumptions verified)
Gate 4 — INSTRUMENTATION CORRECT: Is the PoC measuring the right thing?
         Specifically, check instrumentation ORDER — balances must be
         snapshotted AFTER setup, not before.  (pass = correct)
Gate 5 — PREMISE RE-DERIVED: Starting from the raw source code (not the
         auditor's description), can you independently arrive at the same
         vulnerability?  (pass = independently reproduced)
Gate 6 — NUMERIC GAP MATCHES: Does the numeric gap claimed by the auditor
         match what you independently measure from the code / PoC?
         (pass = gap matches within 10% or narrative explains discrepancy)

Return your analysis as JSON matching the FPCheckPhaseResult schema.
In the 'evidence' field, list each gate result as "Gate N: PASS/FAIL — reason".
Set passed=true only if at least 5 of 6 gates pass.""",

    "final_verdict": """\
You are a security auditor issuing the FINAL VERDICT on a candidate
vulnerability.

CANDIDATE FINDING:
{finding_json}

ALL PHASE RESULTS:
{all_phases}

Synthesise the results of all six previous phases into a final verdict.
Your options:
  - "confirmed": The vulnerability is real, exploitable, and has a measured
    impact.  All or nearly all phases passed.
  - "rejected": The finding is a false positive.  One or more critical
    phases failed (especially impact, six-gate, or devil's advocate).
  - "uncertain": Evidence is mixed.  Some phases passed, some failed.
    Needs human review.

Return JSON matching the FPCheckVerdict schema with ALL fields populated:
verdict, confidence, phase_results (copy from previous phases), 
devil_advocate_notes, poc_stub, negative_poc, reasoning,
numeric_gap_verified, verified_gap_value.""",
}


# ---------------------------------------------------------------------------
# Claude CLI system prompt for autonomous fp-check
# ---------------------------------------------------------------------------

_FP_CHECK_CLI_SYSTEM = """\
You are a senior security auditor performing **rigorous false-positive
verification** on a candidate vulnerability finding.  You have full tool
access: file operations, bash, Slither, semgrep, and (when available)
Foundry and the Trail of Bits plugin suite.

You MUST run all seven verification phases *autonomously*, using your tools
to read the actual code, run static analysis, generate a PoC, and execute it.

SCOPE DISCIPLINE — read this first:
- Run ``slither <file>`` on the affected file(s) only — never ``slither .``
  on the whole repo.
- For the PoC (Phase 4), a *pseudo-PoC plus an executable stub* is enough.
  You do NOT need a green ``forge test`` run — if the repo's test harness is
  broken/incomplete (common), describe what the test WOULD prove and move on.
  Do NOT run the full test suite (``forge test`` with no args) and do NOT try
  to fix pre-existing failures in unrelated parts of the repo.
- When you have enough evidence to render a verdict, STOP and emit the JSON.
  Do not keep exploring.

=== CANDIDATE FINDING ===
{finding_json}

=== INSTRUCTIONS ===

Run these phases in order.  For each phase, USE YOUR TOOLS — do NOT rely
on the description above alone.

**Phase 1 — Data Flow**
  Read the affected files.  Trace data flow from the untrusted input (source)
  to the vulnerable operation (sink).  Name every transformation and guard.

**Phase 2 — Exploitability**
  Determine reachability: is the vulnerable path reachable from an external
  entry point?  What preconditions are needed?  Can an attacker control the
  relevant inputs?

**Phase 3 — Impact**
  Quantify the impact with a NUMERIC GAP MEASUREMENT.  If the claimed gap
  is "{claimed_gap}", independently verify it by reading the math in the
  code.  If the gap is effectively zero, this phase FAILS.

**Phase 4 — PoC Construction**
  Generate three artefacts:
    a) Pseudo-PoC (plain-English exploit steps)
    b) Executable stub (a Foundry test, Python/boa script, or Hardhat test)
    c) Negative PoC (test showing the fix / existing guard)
  CRITICAL — Instrumentation-order discipline:
    Snapshot balances AFTER setup, not before.  Do NOT count setup
    transactions as profit.

**Phase 5 — Devil's Advocate**
  Argue AGAINST the finding.  Try to show it is a false positive.
  Check for guards the auditor missed, unrealistic threat models, and
  PoC instrumentation errors.

**Phase 6 — Six-Gate Review**
  Evaluate six gates (pass=true / fail=false):
    Gate 1 — GUARDS PRESENT (pass = no effective guards)
    Gate 2 — MITIGATIONS (pass = no effective mitigations)
    Gate 3 — ASSUMPTIONS VALID (pass = assumptions verified)
    Gate 4 — INSTRUMENTATION CORRECT (pass = PoC measures correctly)
    Gate 5 — PREMISE RE-DERIVED (pass = independently reproduced)
    Gate 6 — NUMERIC GAP MATCHES (pass = gap within 10%)

**Phase 7 — Final Verdict**
  Synthesise all phases into: confirmed / rejected / uncertain.

=== OUTPUT FORMAT ===
After completing all phases, output a single ```json block matching this
schema:

{{
  "verdict": "confirmed" | "rejected" | "uncertain",
  "confidence": 0.0-1.0,
  "phase_results": [
    {{
      "phase_name": "data_flow",
      "passed": true/false,
      "confidence": 0.0-1.0,
      "reasoning": "...",
      "evidence": "..."
    }},
    ... (one per phase)
  ],
  "devil_advocate_notes": "strongest counter-arguments",
  "poc_stub": "executable PoC code",
  "negative_poc": "test showing fix/guard",
  "reasoning": "overall verdict reasoning",
  "numeric_gap_verified": true/false,
  "verified_gap_value": "independently measured value"
}}
"""


# ---------------------------------------------------------------------------
# FPCheck pipeline
# ---------------------------------------------------------------------------


@dataclass
class FPCheckPipeline:
    """Seven-phase false-positive verification pipeline.

    When Claude CLI is available, runs a single autonomous session where
    Claude reads code, runs tools, generates PoCs, and verifies findings.
    Falls back to per-phase ``UnifiedLLMClient.parse()`` calls otherwise.
    """

    config: dict[str, Any]
    repo_root: Path | None = None
    debug_logger: Any | None = None
    _phase_cache: dict[str, FPCheckPhaseResult] = field(
        default_factory=dict, init=False, repr=False,
    )

    # ---- public API -------------------------------------------------------

    def run(
        self,
        candidate: CandidateFinding,
        source_context: str,
        *,
        strict: bool = False,
    ) -> FPCheckVerdict:
        """Run the full 7-phase pipeline on a candidate finding.

        Default (strict=False): dispatches to Claude CLI when available +
        repo_root is set, else falls back to per-phase LLM calls. Preserves
        existing TestRunDispatch::test_dispatches_to_* semantics.

        firepan-vff strict=True (used by SingleAuditor): requires CLI; raises
        RuntimeError if CLI is unavailable, repo_root is None, or the CLI
        session errors. Never falls back to per-phase LLM, which would
        re-introduce the YieldNest failure mode the curation gates downstream
        can't fully repair.
        """
        if strict:
            if not (self.repo_root and ClaudeSession.available()):
                raise RuntimeError(
                    "fp-check CLI required (strict=True) but unavailable: "
                    f"repo_root={self.repo_root} claude={shutil.which('claude')}"
                )
            return self._run_cli(candidate, source_context, _strict=True)
        if self.repo_root and ClaudeSession.available():
            return self._run_cli(candidate, source_context)
        return self._run_fallback(candidate, source_context)

    def run_with_cli_fallback(
        self,
        candidate: CandidateFinding,
        source_context: str,
        *,
        strict: bool = False,
    ) -> FPCheckVerdict:
        """Run pipeline with optional Trail of Bits fp-check cross-check.

        firepan-vff: when called from SingleAuditor with strict=True, the
        underlying run() call requires the CLI and raises on failure rather
        than silently falling back to per-phase LLM.
        """
        verdict = self.run(candidate, source_context, strict=strict)

        # If we're NOT already using the full CLI pipeline, try the ToB
        # fp-check plugin as a secondary validation pass.
        if not (self.repo_root and ClaudeSession.available()):
            if self.config.get("fp_check_cli_fallback") and shutil.which("claude"):
                try:
                    cli_result = self._run_tob_plugin_check(candidate)
                except (subprocess.SubprocessError, OSError) as exc:
                    logger.warning("ToB fp-check plugin subprocess failed: %s", exc)
                    cli_result = None
                if cli_result and cli_result != verdict.verdict:
                    logger.warning(
                        "ToB fp-check disagrees: native=%s tob=%s for '%s'",
                        verdict.verdict, cli_result, candidate.title,
                    )
                    if verdict.verdict == "confirmed" and cli_result == "rejected":
                        verdict = FPCheckVerdict(
                            verdict="uncertain",
                            confidence=verdict.confidence * 0.7,
                            phase_results=verdict.phase_results,
                            devil_advocate_notes=verdict.devil_advocate_notes,
                            poc_stub=verdict.poc_stub,
                            negative_poc=verdict.negative_poc,
                            reasoning=(
                                f"{verdict.reasoning}\n\n"
                                f"[ToB PLUGIN DISAGREEMENT] Trail of Bits fp-check "
                                f"returned 'rejected' — downgraded to uncertain."
                            ),
                            numeric_gap_verified=verdict.numeric_gap_verified,
                            verified_gap_value=verdict.verified_gap_value,
                        )

        return verdict

    # ---- Claude CLI pipeline (primary) ------------------------------------

    def _run_cli(
        self,
        candidate: CandidateFinding,
        source_context: str,
        *,
        _strict: bool = False,
    ) -> FPCheckVerdict:
        """Run the full verification as a single Claude CLI session.

        Claude gets the finding description and full tool access.  It reads
        the actual code, runs Slither, generates and executes PoCs, and
        outputs a structured verdict.

        Default (_strict=False): falls back to the per-phase LLM pipeline if
        the CLI session errors. Preserves existing TestRunDispatch tests.

        firepan-vff _strict=True (set by run(strict=True) for SingleAuditor):
        raises RuntimeError on CLI failure instead of falling back.
        """
        finding_json = candidate.model_dump_json(indent=2)
        claimed_gap = candidate.numeric_gap_measurement or "not provided"

        system_prompt = _FP_CHECK_CLI_SYSTEM.format(
            finding_json=finding_json,
            claimed_gap=claimed_gap,
        )

        prompt = (
            "Verify the candidate finding described in your system prompt.\n\n"
            "Start by reading the affected files:\n"
        )
        for ev in candidate.file_line_evidence:
            prompt += f"  - {ev.relpath} (lines {ev.line_start}-{ev.line_end})\n"
        prompt += (
            "\nThen run all 7 verification phases using your tools.\n"
            "Output the final verdict as a ```json block."
        )

        session = ClaudeSession(
            config=self.config,
            working_dir=self.repo_root,  # type: ignore[arg-type]
        )
        cli_cfg = self.config.get("claude_cli", {})
        result = session.run(
            prompt,
            system_prompt=system_prompt,
            max_turns=cli_cfg.get("fp_check_max_turns", 30),
            timeout=cli_cfg.get("fp_check_timeout", 600),
        )

        if result.is_error:
            if _strict:
                raise RuntimeError(
                    f"fp-check CLI failed for '{candidate.title}' (strict mode): "
                    f"{result.raw_json.get('error', '<unknown>')}"
                )
            logger.warning(
                "Claude CLI fp-check failed for '%s' — falling back to per-phase LLM",
                candidate.title,
            )
            return self._run_fallback(candidate, source_context)

        return self._parse_cli_verdict(result, candidate)

    def _parse_cli_verdict(
        self,
        result: ClaudeResult,
        candidate: CandidateFinding,
    ) -> FPCheckVerdict:
        """Parse a Claude CLI result into an FPCheckVerdict."""

        data = result.extract_json()
        if not data or not isinstance(data, dict):
            logger.warning("Could not extract JSON verdict from Claude CLI output")
            return self._error_verdict("Failed to parse Claude CLI output")

        try:
            verdict = FPCheckVerdict.model_validate(data)
            if self.debug_logger:
                self.debug_logger.log(
                    "fp_check",
                    f"CLI verdict: {verdict.verdict} "
                    f"(confidence={verdict.confidence:.2f}, "
                    f"cost=${result.cost_usd:.4f}, turns={result.num_turns})",
                )
            return verdict
        except Exception as exc:
            logger.warning("Malformed fp-check verdict: %s", exc)
            # Try to at least extract the verdict string
            raw_verdict = data.get("verdict", "uncertain")
            raw_confidence = float(data.get("confidence", 0.3))
            return FPCheckVerdict(
                verdict=raw_verdict if raw_verdict in ("confirmed", "rejected", "uncertain") else "uncertain",
                confidence=raw_confidence,
                phase_results=self._extract_partial_phases(data),
                devil_advocate_notes=data.get("devil_advocate_notes", ""),
                poc_stub=data.get("poc_stub", ""),
                negative_poc=data.get("negative_poc", ""),
                reasoning=data.get("reasoning", "Partial parse of CLI output"),
                numeric_gap_verified=data.get("numeric_gap_verified", False),
                verified_gap_value=data.get("verified_gap_value", ""),
            )

    @staticmethod
    def _extract_partial_phases(data: dict) -> list[FPCheckPhaseResult]:
        """Best-effort extraction of phase results from partial JSON."""
        results = []
        for raw in data.get("phase_results", []):
            if isinstance(raw, dict):
                try:
                    results.append(FPCheckPhaseResult.model_validate(raw))
                except Exception:
                    results.append(FPCheckPhaseResult(
                        phase_name=raw.get("phase_name", "unknown"),
                        passed=raw.get("passed", False),
                        confidence=float(raw.get("confidence", 0.0)),
                        reasoning=raw.get("reasoning", ""),
                        evidence=raw.get("evidence", ""),
                    ))
        return results

    # ---- fallback pipeline (per-phase LLM calls) --------------------------

    def _run_fallback(
        self,
        candidate: CandidateFinding,
        source_context: str,
    ) -> FPCheckVerdict:
        self._phase_cache.clear()
        finding_json = candidate.model_dump_json(indent=2)

        phases = [
            "data_flow",
            "exploitability",
            "impact",
            "poc_construction",
            "devil_advocate",
            "six_gate_review",
        ]

        for phase_name in phases:
            result = self._run_phase(phase_name, finding_json, source_context)
            self._phase_cache[phase_name] = result
            if self.debug_logger:
                self.debug_logger.log(
                    "fp_check",
                    f"Phase {phase_name}: passed={result.passed} "
                    f"confidence={result.confidence:.2f}",
                )

        # Final verdict phase consumes all prior results
        verdict = self._run_final_verdict(finding_json)
        return verdict

    # ---- internal phases (fallback mode) ------------------------------------

    def _get_llm(self) -> UnifiedLLMClient:
        return UnifiedLLMClient(
            cfg=self.config,
            profile="auditor",
            debug_logger=self.debug_logger,
        )

    def _format_prev_phases(self, up_to: str | None = None) -> str:
        parts = []
        for name, result in self._phase_cache.items():
            if up_to and name == up_to:
                break
            parts.append(
                f"=== {name.upper()} ===\n"
                f"Passed: {result.passed}\n"
                f"Confidence: {result.confidence}\n"
                f"Reasoning: {result.reasoning}\n"
                f"Evidence: {result.evidence}\n"
            )
        return "\n".join(parts) if parts else "(no previous phases)"

    def _run_phase(
        self,
        phase_name: str,
        finding_json: str,
        source_context: str,
    ) -> FPCheckPhaseResult:
        prompt_template = _PHASE_PROMPTS[phase_name]

        subs: dict[str, str] = {
            "finding_json": finding_json,
            "source_context": source_context,
            "prev_phase": "",
            "prev_phases": "",
            "all_phases": "",
            "claimed_gap": "",
        }

        if phase_name == "exploitability" and "data_flow" in self._phase_cache:
            subs["prev_phase"] = self._format_prev_phases("exploitability")

        if phase_name in ("impact", "poc_construction", "devil_advocate", "six_gate_review"):
            subs["prev_phases"] = self._format_prev_phases(phase_name)

        try:
            finding_data = json.loads(finding_json)
            subs["claimed_gap"] = finding_data.get("numeric_gap_measurement", "not provided")
        except (json.JSONDecodeError, TypeError):
            subs["claimed_gap"] = "not provided"

        prompt = prompt_template.format(**subs)

        llm = self._get_llm()
        try:
            result = llm.parse(
                system=(
                    "You are a rigorous security auditor performing false-positive "
                    "verification. Be precise and evidence-based. When in doubt, "
                    "err on the side of rejecting weak findings."
                ),
                user=prompt,
                schema=FPCheckPhaseResult,
            )
            return result
        except Exception:
            logger.warning("FP-check phase %s failed, marking as not passed", phase_name, exc_info=True)
            return FPCheckPhaseResult(
                phase_name=phase_name,
                passed=False,
                confidence=0.0,
                reasoning=f"Phase {phase_name} failed due to LLM error",
                evidence="",
            )

    def _run_final_verdict(self, finding_json: str) -> FPCheckVerdict:
        all_phases = self._format_prev_phases()
        prompt = _PHASE_PROMPTS["final_verdict"].format(
            finding_json=finding_json,
            all_phases=all_phases,
        )

        llm = self._get_llm()
        try:
            verdict = llm.parse(
                system=(
                    "You are a senior security auditor issuing a final verdict. "
                    "Synthesise all phase results into a definitive assessment."
                ),
                user=prompt,
                schema=FPCheckVerdict,
            )
            if not verdict.phase_results:
                verdict.phase_results = list(self._phase_cache.values())
            return verdict
        except Exception:
            logger.warning("FP-check final verdict failed", exc_info=True)
            return self._error_verdict("Final verdict phase failed due to LLM error")

    # ---- Trail of Bits plugin secondary check -----------------------------

    @staticmethod
    def _run_tob_plugin_check(candidate: CandidateFinding) -> str | None:
        """Shell out to ``claude plugin run fp-check`` (Trail of Bits)."""
        try:
            input_json = candidate.model_dump_json()
            result = subprocess.run(
                ["claude", "plugin", "run", "fp-check"],
                input=input_json,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                logger.warning("ToB fp-check exited %d: %s", result.returncode, result.stderr[:500])
                return None
            output = result.stdout
            # Prefer a structured verdict if the plugin emitted JSON.
            try:
                payload = json.loads(output)
                if isinstance(payload, dict):
                    val = str(payload.get("verdict", "")).strip().lower()
                    if val in ("confirmed", "rejected", "uncertain"):
                        return val
            except (json.JSONDecodeError, ValueError):
                pass
            # Fallback: look for an exact ``Verdict: <value>`` line.  Naive
            # substring matching gives false positives ("not confirmed",
            # narratives mentioning all three values, etc.).
            verdict_line = re.search(
                r"^\s*verdict\s*[:=]\s*(confirmed|rejected|uncertain)\s*$",
                output,
                re.IGNORECASE | re.MULTILINE,
            )
            if verdict_line:
                return verdict_line.group(1).lower()
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as exc:
            logger.debug("ToB fp-check plugin invocation failed: %s", exc)
            return None

    # ---- helpers ----------------------------------------------------------

    def _error_verdict(self, reason: str) -> FPCheckVerdict:
        return FPCheckVerdict(
            verdict="uncertain",
            confidence=0.0,
            phase_results=list(self._phase_cache.values()),
            devil_advocate_notes="",
            poc_stub="",
            negative_poc="",
            reasoning=reason,
            numeric_gap_verified=False,
            verified_gap_value="",
        )
