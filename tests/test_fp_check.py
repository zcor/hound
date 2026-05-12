"""Tests for analysis.fp_check — FPCheckPipeline.

Covers both the Claude CLI path and the per-phase fallback path, including
verdict parsing, partial-phase extraction, the ToB plugin cross-check, and
error handling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from analysis.fp_check import FPCheckPipeline
from llm.schemas import (
    CandidateFinding,
    FileLineEvidence,
    FPCheckPhaseResult,
    FPCheckVerdict,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_candidate(**overrides: Any) -> CandidateFinding:
    """Build a minimal valid CandidateFinding for testing."""
    defaults: dict[str, Any] = {
        "title": "Reentrancy in withdraw()",
        "description": "External call before state update allows re-entrance.",
        "vulnerability_type": "reentrancy",
        "severity": "high",
        "confidence": 0.85,
        "file_line_evidence": [
            FileLineEvidence(
                relpath="contracts/Vault.sol",
                line_start=42,
                line_end=50,
                snippet="payable(msg.sender).call{value: amount}('');"
            ),
        ],
        "reasoning": "The call is made before the balance is zeroed.",
        "numeric_gap_measurement": "drain up to 100 ETH",
    }
    defaults.update(overrides)
    return CandidateFinding(**defaults)


def _make_phase_result(name: str, *, passed: bool = True, confidence: float = 0.9) -> dict:
    return {
        "phase_name": name,
        "passed": passed,
        "confidence": confidence,
        "reasoning": f"{name} reasoning",
        "evidence": f"{name} evidence",
    }


def _make_verdict_dict(
    verdict: str = "confirmed",
    confidence: float = 0.85,
    *,
    num_phases: int = 7,
) -> dict:
    phase_names = [
        "data_flow", "exploitability", "impact",
        "poc_construction", "devil_advocate", "six_gate_review", "final_verdict",
    ]
    return {
        "verdict": verdict,
        "confidence": confidence,
        "phase_results": [
            _make_phase_result(name) for name in phase_names[:num_phases]
        ],
        "devil_advocate_notes": "no counter-argument found",
        "poc_stub": "forge test --match testReentrancy",
        "negative_poc": "// guard prevents re-entrance",
        "reasoning": "All phases confirmed the finding.",
        "numeric_gap_verified": True,
        "verified_gap_value": "drain up to 100 ETH",
    }


@pytest.fixture()
def candidate() -> CandidateFinding:
    return _make_candidate()


@pytest.fixture()
def pipeline(tmp_path: Path) -> FPCheckPipeline:
    """FPCheckPipeline with a minimal config, pointing at a temp dir."""
    return FPCheckPipeline(
        config={
            "claude_cli": {
                "max_turns": 10,
                "timeout": 30,
                "skip_permissions": True,
                "fp_check_max_turns": 5,
                "fp_check_timeout": 20,
            },
            "models": {"auditor": {"provider": "anthropic", "model": "test-model"}},
        },
        repo_root=tmp_path,
    )


# ---------------------------------------------------------------------------
# ClaudeResult.extract_json path (through _parse_cli_verdict)
# ---------------------------------------------------------------------------


class TestParseCliVerdict:
    """Test ``_parse_cli_verdict`` with various CLI output shapes."""

    def test_clean_json(self, pipeline: FPCheckPipeline, candidate: CandidateFinding) -> None:
        """A well-formed JSON verdict is parsed correctly."""
        from analysis.claude_cli import ClaudeResult

        result = ClaudeResult(
            text=json.dumps(_make_verdict_dict()),
            cost_usd=0.12,
            num_turns=8,
        )
        verdict = pipeline._parse_cli_verdict(result, candidate)
        assert verdict.verdict == "confirmed"
        assert verdict.confidence == pytest.approx(0.85)
        assert len(verdict.phase_results) == 7

    def test_fenced_json(self, pipeline: FPCheckPipeline, candidate: CandidateFinding) -> None:
        """Verdict wrapped in a ```json fence."""
        from analysis.claude_cli import ClaudeResult

        text = "Here is my verdict:\n\n```json\n" + json.dumps(_make_verdict_dict()) + "\n```"
        result = ClaudeResult(text=text)
        verdict = pipeline._parse_cli_verdict(result, candidate)
        assert verdict.verdict == "confirmed"

    def test_rejected_verdict(self, pipeline: FPCheckPipeline, candidate: CandidateFinding) -> None:
        from analysis.claude_cli import ClaudeResult

        data = _make_verdict_dict("rejected", 0.9)
        result = ClaudeResult(text=json.dumps(data))
        verdict = pipeline._parse_cli_verdict(result, candidate)
        assert verdict.verdict == "rejected"
        assert verdict.confidence == pytest.approx(0.9)

    def test_partial_json_extracts_verdict_string(
        self, pipeline: FPCheckPipeline, candidate: CandidateFinding,
    ) -> None:
        """When phase_results are malformed, the verdict string is still extracted."""
        from analysis.claude_cli import ClaudeResult

        data = {
            "verdict": "uncertain",
            "confidence": 0.4,
            "phase_results": [{"bad": True}],
            "reasoning": "partial",
        }
        result = ClaudeResult(text=json.dumps(data))
        verdict = pipeline._parse_cli_verdict(result, candidate)
        assert verdict.verdict == "uncertain"
        assert verdict.confidence == pytest.approx(0.4)

    def test_no_json_returns_error_verdict(
        self, pipeline: FPCheckPipeline, candidate: CandidateFinding,
    ) -> None:
        from analysis.claude_cli import ClaudeResult

        result = ClaudeResult(text="This output has no JSON at all.")
        verdict = pipeline._parse_cli_verdict(result, candidate)
        assert verdict.verdict == "uncertain"
        assert verdict.confidence == 0.0


# ---------------------------------------------------------------------------
# _extract_partial_phases
# ---------------------------------------------------------------------------


class TestExtractPartialPhases:
    def test_valid_phases(self) -> None:
        data = {
            "phase_results": [
                _make_phase_result("data_flow"),
                _make_phase_result("exploitability", passed=False),
            ],
        }
        phases = FPCheckPipeline._extract_partial_phases(data)
        assert len(phases) == 2
        assert phases[0].phase_name == "data_flow"
        assert phases[0].passed is True
        assert phases[1].passed is False

    def test_malformed_phases_fallback(self) -> None:
        data = {
            "phase_results": [
                {"phase_name": "data_flow", "bad_field": True},
                {"not_a_phase": True},
            ],
        }
        phases = FPCheckPipeline._extract_partial_phases(data)
        assert len(phases) == 2
        assert phases[0].phase_name == "data_flow"
        assert phases[0].passed is False  # default
        assert phases[1].phase_name == "unknown"

    def test_empty_phase_results(self) -> None:
        assert FPCheckPipeline._extract_partial_phases({}) == []
        assert FPCheckPipeline._extract_partial_phases({"phase_results": []}) == []


# ---------------------------------------------------------------------------
# _run_cli (mocked subsession)
# ---------------------------------------------------------------------------


class TestRunCli:
    """Test ``_run_cli`` with mocked ``ClaudeSession``."""

    @patch("analysis.fp_check.ClaudeSession")
    def test_success(
        self,
        MockSession: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        from analysis.claude_cli import ClaudeResult

        mock_inst = MockSession.return_value
        mock_inst.run.return_value = ClaudeResult(
            text=json.dumps(_make_verdict_dict()),
            cost_usd=0.15,
            num_turns=10,
        )
        MockSession.available.return_value = True

        verdict = pipeline._run_cli(candidate, "source code here")
        assert verdict.verdict == "confirmed"

        # Verify the session was created with the right working_dir
        MockSession.assert_called_once_with(
            config=pipeline.config,
            working_dir=pipeline.repo_root,
        )
        mock_inst.run.assert_called_once()

    @patch("analysis.fp_check.ClaudeSession")
    def test_cli_error_falls_back_to_run_fallback(
        self,
        MockSession: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        """When CLI errors, _run_cli now falls back to _run_fallback."""
        from analysis.claude_cli import ClaudeResult

        mock_inst = MockSession.return_value
        mock_inst.run.return_value = ClaudeResult(
            text="", is_error=True, raw_json={"error": "timeout"},
        )
        MockSession.available.return_value = True

        fallback_verdict = FPCheckVerdict(
            verdict="confirmed",
            confidence=0.85,
            phase_results=[],
            reasoning="Confirmed via fallback",
            numeric_gap_verified=True,
            verified_gap_value="100 ETH",
        )
        with patch.object(pipeline, "_run_fallback", return_value=fallback_verdict) as mock_fb:
            verdict = pipeline._run_cli(candidate, "source code here")
            mock_fb.assert_called_once_with(candidate, "source code here")
        assert verdict.verdict == "confirmed"
        assert verdict.confidence == 0.85


# ---------------------------------------------------------------------------
# _run_fallback (per-phase LLM calls)
# ---------------------------------------------------------------------------


class TestRunFallback:
    """Test the per-phase fallback pipeline with mocked LLM client."""

    @patch("analysis.fp_check.UnifiedLLMClient")
    def test_all_phases_called(
        self,
        MockLLM: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        """Verify all 7 phases are called (6 phases + final verdict)."""
        phase_counter = 0

        def fake_parse(system: str, user: str, schema: type) -> Any:
            nonlocal phase_counter
            phase_counter += 1
            if schema == FPCheckPhaseResult:
                return FPCheckPhaseResult(
                    phase_name=f"phase_{phase_counter}",
                    passed=True,
                    confidence=0.8,
                    reasoning="ok",
                    evidence="ok",
                )
            # Final verdict
            return FPCheckVerdict(
                verdict="confirmed",
                confidence=0.85,
                phase_results=[],
                reasoning="All phases passed",
                numeric_gap_verified=True,
                verified_gap_value="100 ETH",
            )

        mock_inst = MockLLM.return_value
        mock_inst.parse.side_effect = fake_parse

        verdict = pipeline._run_fallback(candidate, "source code here")

        # 6 phase calls + 1 final verdict = 7 calls total
        assert mock_inst.parse.call_count == 7
        assert verdict.verdict == "confirmed"

    @patch("analysis.fp_check.UnifiedLLMClient")
    def test_phase_failure_marks_not_passed(
        self,
        MockLLM: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        """When an LLM call throws, the phase is marked as not-passed."""
        call_count = 0

        def fake_parse(system: str, user: str, schema: type) -> Any:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("LLM API error")
            if schema == FPCheckPhaseResult:
                return FPCheckPhaseResult(
                    phase_name="ok", passed=True, confidence=0.8,
                    reasoning="ok",
                )
            return FPCheckVerdict(
                verdict="uncertain",
                confidence=0.5,
                phase_results=[],
                reasoning="mixed",
            )

        mock_inst = MockLLM.return_value
        mock_inst.parse.side_effect = fake_parse

        pipeline._run_fallback(candidate, "src")
        # The first phase (data_flow) should have failed
        assert "data_flow" in pipeline._phase_cache
        assert pipeline._phase_cache["data_flow"].passed is False
        assert pipeline._phase_cache["data_flow"].confidence == 0.0


# ---------------------------------------------------------------------------
# _run_tob_plugin_check (subprocess)
# ---------------------------------------------------------------------------


class TestToBPluginCheck:
    """Test ``_run_tob_plugin_check`` with mocked subprocess."""

    @patch("analysis.fp_check.subprocess.run")
    def test_confirmed(self, mock_run: MagicMock, candidate: CandidateFinding) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"verdict": "confirmed"}',
            stderr="",
        )
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result == "confirmed"

    @patch("analysis.fp_check.subprocess.run")
    def test_rejected(self, mock_run: MagicMock, candidate: CandidateFinding) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Analysis follows...\nVerdict: rejected\n",
            stderr="",
        )
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result == "rejected"

    @patch("analysis.fp_check.subprocess.run")
    def test_uncertain(self, mock_run: MagicMock, candidate: CandidateFinding) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="verdict: uncertain\n",
            stderr="",
        )
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result == "uncertain"

    @patch("analysis.fp_check.subprocess.run")
    def test_nonzero_exit(self, mock_run: MagicMock, candidate: CandidateFinding) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="fail")
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result is None

    @patch("analysis.fp_check.subprocess.run")
    def test_no_verdict_in_output(self, mock_run: MagicMock, candidate: CandidateFinding) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="nothing useful", stderr="")
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result is None

    @patch("analysis.fp_check.subprocess.run")
    def test_negated_verdict_does_not_match(
        self, mock_run: MagicMock, candidate: CandidateFinding
    ) -> None:
        # Regression: "not confirmed" must not be parsed as "confirmed".
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="The bug is not confirmed and not rejected — needs more analysis.",
            stderr="",
        )
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result is None

    @patch("analysis.fp_check.subprocess.run", side_effect=FileNotFoundError)
    def test_cli_not_found(self, _: MagicMock, candidate: CandidateFinding) -> None:
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result is None

    @patch("analysis.fp_check.subprocess.run")
    def test_timeout(self, mock_run: MagicMock, candidate: CandidateFinding) -> None:
        import subprocess as sp
        mock_run.side_effect = sp.TimeoutExpired(cmd="claude", timeout=120)
        result = FPCheckPipeline._run_tob_plugin_check(candidate)
        assert result is None


# ---------------------------------------------------------------------------
# run_with_cli_fallback (cross-check logic)
# ---------------------------------------------------------------------------


class TestRunWithCliFallback:
    """Test the CLI-fallback hybrid path with ToB cross-check."""

    @patch("analysis.fp_check.shutil.which", return_value="/usr/bin/claude")
    @patch("analysis.fp_check.ClaudeSession")
    @patch("analysis.fp_check.UnifiedLLMClient")
    def test_tob_disagrees_downgrades_to_uncertain(
        self,
        MockLLM: MagicMock,
        MockSession: MagicMock,
        mock_which: MagicMock,
        candidate: CandidateFinding,
        tmp_path: Path,
    ) -> None:
        """When native says confirmed but ToB says rejected → uncertain."""
        # Force fallback path (CLI not available for the pipeline itself)
        MockSession.available.return_value = False

        # The fallback run produces "confirmed"
        confirmed_verdict = FPCheckVerdict(
            verdict="confirmed",
            confidence=0.85,
            phase_results=[],
            reasoning="All phases passed",
        )

        call_count = 0
        def fake_parse(system: str, user: str, schema: type) -> Any:
            nonlocal call_count
            call_count += 1
            if schema == FPCheckPhaseResult:
                return FPCheckPhaseResult(
                    phase_name=f"p{call_count}", passed=True,
                    confidence=0.8, reasoning="ok",
                )
            return confirmed_verdict

        MockLLM.return_value.parse.side_effect = fake_parse

        pipeline = FPCheckPipeline(
            config={
                "fp_check_cli_fallback": True,
                "claude_cli": {"fp_check_max_turns": 5, "fp_check_timeout": 20},
                "models": {"auditor": {"provider": "anthropic", "model": "test"}},
            },
            repo_root=tmp_path,
        )

        with patch.object(
            FPCheckPipeline, "_run_tob_plugin_check", return_value="rejected",
        ):
            verdict = pipeline.run_with_cli_fallback(candidate, "src")

        assert verdict.verdict == "uncertain"
        assert verdict.confidence < 0.85
        assert "ToB PLUGIN DISAGREEMENT" in verdict.reasoning

    @patch("analysis.fp_check.shutil.which", return_value="/usr/bin/claude")
    @patch("analysis.fp_check.ClaudeSession")
    @patch("analysis.fp_check.UnifiedLLMClient")
    def test_tob_agrees_keeps_confirmed(
        self,
        MockLLM: MagicMock,
        MockSession: MagicMock,
        mock_which: MagicMock,
        candidate: CandidateFinding,
        tmp_path: Path,
    ) -> None:
        """When native and ToB both say confirmed, the verdict stays."""
        MockSession.available.return_value = False

        call_count = 0
        def fake_parse(system: str, user: str, schema: type) -> Any:
            nonlocal call_count
            call_count += 1
            if schema == FPCheckPhaseResult:
                return FPCheckPhaseResult(
                    phase_name=f"p{call_count}", passed=True,
                    confidence=0.8, reasoning="ok",
                )
            return FPCheckVerdict(
                verdict="confirmed",
                confidence=0.85,
                phase_results=[],
                reasoning="All passed",
            )

        MockLLM.return_value.parse.side_effect = fake_parse

        pipeline = FPCheckPipeline(
            config={
                "fp_check_cli_fallback": True,
                "claude_cli": {},
                "models": {"auditor": {"provider": "anthropic", "model": "test"}},
            },
            repo_root=tmp_path,
        )

        with patch.object(
            FPCheckPipeline, "_run_tob_plugin_check", return_value="confirmed",
        ):
            verdict = pipeline.run_with_cli_fallback(candidate, "src")

        assert verdict.verdict == "confirmed"
        assert verdict.confidence == pytest.approx(0.85)


# ---------------------------------------------------------------------------
# run() dispatch logic
# ---------------------------------------------------------------------------


class TestRunDispatch:
    """Verify ``run()`` dispatches to CLI or fallback correctly."""

    @patch("analysis.fp_check.ClaudeSession")
    def test_dispatches_to_cli_when_available(
        self,
        MockSession: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        from analysis.claude_cli import ClaudeResult

        MockSession.available.return_value = True
        mock_inst = MockSession.return_value
        mock_inst.run.return_value = ClaudeResult(
            text=json.dumps(_make_verdict_dict()),
        )

        verdict = pipeline.run(candidate, "src")
        assert verdict.verdict == "confirmed"
        mock_inst.run.assert_called_once()

    @patch("analysis.fp_check.ClaudeSession")
    @patch("analysis.fp_check.UnifiedLLMClient")
    def test_dispatches_to_fallback_when_no_cli(
        self,
        MockLLM: MagicMock,
        MockSession: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        MockSession.available.return_value = False

        call_count = 0
        def fake_parse(system: str, user: str, schema: type) -> Any:
            nonlocal call_count
            call_count += 1
            if schema == FPCheckPhaseResult:
                return FPCheckPhaseResult(
                    phase_name=f"p{call_count}", passed=True,
                    confidence=0.8, reasoning="ok",
                )
            return FPCheckVerdict(
                verdict="rejected",
                confidence=0.9,
                phase_results=[],
                reasoning="Guards present",
            )

        MockLLM.return_value.parse.side_effect = fake_parse

        verdict = pipeline.run(candidate, "src")
        assert verdict.verdict == "rejected"

    @patch("analysis.fp_check.ClaudeSession")
    @patch("analysis.fp_check.UnifiedLLMClient")
    def test_dispatches_to_fallback_when_no_repo_root(
        self,
        MockLLM: MagicMock,
        MockSession: MagicMock,
        candidate: CandidateFinding,
    ) -> None:
        """When repo_root is None, fallback is used even if CLI is available."""
        MockSession.available.return_value = True

        call_count = 0
        def fake_parse(system: str, user: str, schema: type) -> Any:
            nonlocal call_count
            call_count += 1
            if schema == FPCheckPhaseResult:
                return FPCheckPhaseResult(
                    phase_name=f"p{call_count}", passed=True,
                    confidence=0.8, reasoning="ok",
                )
            return FPCheckVerdict(
                verdict="confirmed",
                confidence=0.8,
                phase_results=[],
                reasoning="ok",
            )

        MockLLM.return_value.parse.side_effect = fake_parse

        pipeline = FPCheckPipeline(
            config={"models": {"auditor": {"provider": "anthropic", "model": "test"}}},
            repo_root=None,
        )
        pipeline.run(candidate, "src")
        # Should have used fallback (7 calls)
        assert MockLLM.return_value.parse.call_count == 7


# ---------------------------------------------------------------------------
# _format_prev_phases
# ---------------------------------------------------------------------------


class TestFormatPrevPhases:
    def test_empty(self, pipeline: FPCheckPipeline) -> None:
        pipeline._phase_cache.clear()
        assert pipeline._format_prev_phases() == "(no previous phases)"

    def test_formats_all(self, pipeline: FPCheckPipeline) -> None:
        pipeline._phase_cache["data_flow"] = FPCheckPhaseResult(
            phase_name="data_flow",
            passed=True,
            confidence=0.9,
            reasoning="Source → sink traced",
            evidence="Line 42-50",
        )
        pipeline._phase_cache["exploitability"] = FPCheckPhaseResult(
            phase_name="exploitability",
            passed=False,
            confidence=0.3,
            reasoning="Not reachable",
            evidence="Access control blocks it",
        )
        text = pipeline._format_prev_phases()
        assert "DATA_FLOW" in text
        assert "EXPLOITABILITY" in text
        assert "Source → sink traced" in text

    def test_up_to_stops_early(self, pipeline: FPCheckPipeline) -> None:
        pipeline._phase_cache["data_flow"] = FPCheckPhaseResult(
            phase_name="data_flow", passed=True, confidence=0.9, reasoning="ok",
        )
        pipeline._phase_cache["exploitability"] = FPCheckPhaseResult(
            phase_name="exploitability", passed=True, confidence=0.8, reasoning="ok",
        )
        text = pipeline._format_prev_phases(up_to="exploitability")
        assert "DATA_FLOW" in text
        assert "EXPLOITABILITY" not in text


# ---------------------------------------------------------------------------
# _error_verdict
# ---------------------------------------------------------------------------


class TestErrorVerdict:
    def test_returns_uncertain(self, pipeline: FPCheckPipeline) -> None:
        v = pipeline._error_verdict("something broke")
        assert v.verdict == "uncertain"
        assert v.confidence == 0.0
        assert "something broke" in v.reasoning

    def test_includes_cached_phases(self, pipeline: FPCheckPipeline) -> None:
        pipeline._phase_cache["data_flow"] = FPCheckPhaseResult(
            phase_name="data_flow", passed=True, confidence=0.9, reasoning="ok",
        )
        v = pipeline._error_verdict("timeout")
        assert len(v.phase_results) == 1
        assert v.phase_results[0].phase_name == "data_flow"


# ---------------------------------------------------------------------------
# fp_check_cli_fallback toggle
# ---------------------------------------------------------------------------


class TestCliFallbackToggle:
    """Verify that ``fp_check_cli_fallback`` config routes to the right method."""

    @patch("analysis.fp_check.ClaudeSession")
    def test_toggle_off_calls_run(
        self,
        MockSession: MagicMock,
        candidate: CandidateFinding,
    ) -> None:
        """With fp_check_cli_fallback=False, auditor should call ``run()``."""
        config: dict[str, Any] = {
            "model": "test-model",
            "fp_check_cli_fallback": False,
        }
        pipe = FPCheckPipeline(config=config, repo_root=Path("/tmp"))
        MockSession.available.return_value = True
        with patch.object(pipe, "run", return_value=MagicMock()) as mock_run, \
             patch.object(pipe, "run_with_cli_fallback") as mock_rwcf:
            pipe.run(candidate, "source code")
            mock_run.assert_called_once()
            mock_rwcf.assert_not_called()

    @patch("analysis.fp_check.shutil.which", return_value="/usr/local/bin/claude")
    @patch("analysis.fp_check.ClaudeSession")
    def test_toggle_on_enables_tob_plugin(
        self,
        MockSession: MagicMock,
        _mock_which: MagicMock,
        candidate: CandidateFinding,
    ) -> None:
        """With fp_check_cli_fallback=True, ``run_with_cli_fallback`` adds ToB cross-check."""
        config: dict[str, Any] = {
            "model": "test-model",
            "fp_check_cli_fallback": True,
        }
        pipe = FPCheckPipeline(config=config, repo_root=Path("/tmp"))
        MockSession.available.return_value = False  # Force fallback path

        fallback_verdict = FPCheckVerdict(
            verdict="confirmed", confidence=0.9, phase_results=[],
            reasoning="ok", numeric_gap_verified=True, verified_gap_value="10 ETH",
        )
        with patch.object(pipe, "_run_fallback", return_value=fallback_verdict), \
             patch.object(pipe, "_run_tob_plugin_check", return_value=None) as mock_tob:
            result = pipe.run_with_cli_fallback(candidate, "source code")
            mock_tob.assert_called_once_with(candidate)
        assert result.verdict == "confirmed"


# ---------------------------------------------------------------------------
# run(strict=True) — firepan-vff: SingleAuditor opt-in, no silent fallback
# ---------------------------------------------------------------------------


class TestRunStrictMode:
    """Verify firepan-vff strict mode never silently falls back to per-phase LLM."""

    @patch("analysis.fp_check.ClaudeSession")
    def test_strict_raises_when_cli_unavailable(
        self,
        MockSession: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        """strict=True raises RuntimeError when ClaudeSession.available() is False."""
        MockSession.available.return_value = False
        with pytest.raises(RuntimeError, match="fp-check CLI required"):
            pipeline.run(candidate, "source", strict=True)

    @patch("analysis.fp_check.ClaudeSession")
    def test_strict_raises_when_repo_root_missing(
        self,
        MockSession: MagicMock,
        candidate: CandidateFinding,
    ) -> None:
        """strict=True raises RuntimeError when repo_root is None even if CLI is available."""
        MockSession.available.return_value = True
        pipe = FPCheckPipeline(
            config={"models": {"auditor": {"provider": "anthropic", "model": "test"}}},
            repo_root=None,
        )
        with pytest.raises(RuntimeError, match="fp-check CLI required"):
            pipe.run(candidate, "source", strict=True)

    @patch("analysis.fp_check.ClaudeSession")
    def test_strict_cli_error_raises_no_fallback(
        self,
        MockSession: MagicMock,
        pipeline: FPCheckPipeline,
        candidate: CandidateFinding,
    ) -> None:
        """strict=True propagates CLI error as RuntimeError instead of falling back."""
        from analysis.claude_cli import ClaudeResult

        mock_inst = MockSession.return_value
        mock_inst.run.return_value = ClaudeResult(
            text="", is_error=True, raw_json={"error": "timeout"},
        )
        MockSession.available.return_value = True

        # _run_fallback must NOT be called in strict mode
        with patch.object(pipeline, "_run_fallback") as mock_fb:
            with pytest.raises(RuntimeError, match="fp-check CLI failed.*strict mode"):
                pipeline.run(candidate, "source", strict=True)
            mock_fb.assert_not_called()
