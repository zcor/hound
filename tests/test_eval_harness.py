"""
Tests for firepan-tw7 — yieldnest eval harness.

Covers:
- corpus.load_corpus + expected_fp_ids round-trip
- harness.run_curation_pipeline shape (stages, headline metrics)
- offline mode (no source_path) gracefully skips source-grep gate
- in-memory inline source path lets the access-control gate fire
- metrics.CurationReport.summary() produces stable markdown

CI-safe: no network, no LLM calls (mocked), no production DB. Uses
the same `patch("llm.unified_client.UnifiedLLMClient", ...)` pattern as
test_template_fp_filter.py:251 to avoid burning credits.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from eval.corpus import expected_fp_ids, fixture_path, load_corpus
from eval.harness import run_curation_pipeline
from eval.metrics import CurationReport, StageResult


# ---------------------------------------------------------------------------
# Inline mini-corpus matching yieldnest shape, for fast deterministic tests
# without depending on the production-extracted JSONL.
# ---------------------------------------------------------------------------
def _yieldnest_shape_corpus() -> list[dict]:
    """Mimics the yieldnest postmortem shape: 4 AC FPs + 1 non-FP."""
    return [
        {
            "hypothesis_id": "yn_setProvider",
            "id": "yn_setProvider",
            "title": "Missing access control on VaultManager.setProvider",
            "description": "Anyone can call setProvider, allowing arbitrary provider injection.",
            "vulnerability_type": "access_control",
            "status": "confirmed",
            "confidence": 0.9,
            "severity": "high",
            "node_refs": ["VaultManager.setProvider"],
            "evidence": {},
            "junior_model": "deepseek:deepseek-chat",
            "senior_model": "deepseek:deepseek-chat",
            "reported_by_model": "deepseek:deepseek-chat",
            "expected_fp": True,
            "fp_reason": "onlyRole(MODULE_MANAGER_ROLE) on actual function",
        },
        {
            "hypothesis_id": "yn_setFee",
            "id": "yn_setFee",
            "title": "Missing access control on FeeHooks.setPerformanceFee",
            "description": "FeeHooks.setPerformanceFee can be called by anyone.",
            "vulnerability_type": "access_control",
            "status": "confirmed",
            "confidence": 0.9,
            "severity": "high",
            "node_refs": ["FeeHooks.setPerformanceFee"],
            "evidence": {},
            "junior_model": "deepseek:deepseek-chat",
            "senior_model": "deepseek:deepseek-chat",
            "reported_by_model": "deepseek:deepseek-chat",
            "expected_fp": True,
            "fp_reason": "external virtual onlyOwner",
        },
        {
            "hypothesis_id": "yn_setRecipient",
            "id": "yn_setRecipient",
            "title": "Missing access control on FeeHooks.setPerformanceFeeRecipient",
            "description": "Recipient can be replaced by anyone.",
            "vulnerability_type": "access_control",
            "status": "confirmed",
            "confidence": 0.9,
            "severity": "high",
            "node_refs": ["FeeHooks.setPerformanceFeeRecipient"],
            "evidence": {},
            "junior_model": "deepseek:deepseek-chat",
            "senior_model": "deepseek:deepseek-chat",
            "reported_by_model": "deepseek:deepseek-chat",
            "expected_fp": True,
            "fp_reason": "external virtual onlyOwner",
        },
        {
            "hypothesis_id": "yn_setAsset",
            "id": "yn_setAsset",
            "title": "Missing access control on BaseStrategy.setAssetWithdrawable",
            "description": "Asset withdrawability flag is unprotected.",
            "vulnerability_type": "access_control",
            "status": "confirmed",
            "confidence": 0.9,
            "severity": "high",
            "node_refs": ["BaseStrategy.setAssetWithdrawable"],
            "evidence": {},
            "junior_model": "deepseek:deepseek-chat",
            "senior_model": "deepseek:deepseek-chat",
            "reported_by_model": "deepseek:deepseek-chat",
            "expected_fp": True,
            "fp_reason": "onlyRole(ASSET_MANAGER_ROLE)",
        },
        {
            "hypothesis_id": "yn_real_reentrancy",
            "id": "yn_real_reentrancy",
            "title": "Reentrancy in withdraw via external call before state update",
            "description": "Real finding — non-template, should never be filtered.",
            "vulnerability_type": "reentrancy",
            "status": "confirmed",
            "confidence": 0.95,
            "severity": "critical",
            "node_refs": ["Vault.withdraw"],
            "evidence": {},
            "junior_model": "deepseek:deepseek-chat",
            "senior_model": "deepseek:deepseek-chat",
            "reported_by_model": "deepseek:deepseek-chat",
            "expected_fp": False,
            "fp_reason": None,
        },
    ]


@pytest.fixture
def yieldnest_shape_source(tmp_path: Path) -> Path:
    """Inline source mimicking yieldnest's protected setters.

    Each contract has the same modifier the postmortem says was present.
    The harness's source-grep should find the modifiers and demote/drop the
    FP candidates while leaving the reentrancy finding alone.
    """
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "VaultManager.sol").write_text(
        """\
contract VaultManager {
    bytes32 public constant MODULE_MANAGER_ROLE = keccak256("MODULE_MANAGER_ROLE");
    modifier onlyRole(bytes32 r) { _; }

    function setProvider(address provider) external onlyRole(MODULE_MANAGER_ROLE) {
        _provider = provider;
    }
}
"""
    )
    (contracts / "FeeHooks.sol").write_text(
        """\
contract FeeHooks {
    address public owner;
    modifier onlyOwner() { _; }

    function setPerformanceFee(uint256 fee) external virtual onlyOwner {
        _performanceFee = fee;
    }

    function setPerformanceFeeRecipient(address r) external virtual onlyOwner {
        _recipient = r;
    }
}
"""
    )
    (contracts / "BaseStrategy.sol").write_text(
        """\
contract BaseStrategy {
    bytes32 public constant ASSET_MANAGER_ROLE = keccak256("ASSET_MANAGER_ROLE");
    modifier onlyRole(bytes32 r) { _; }

    function setAssetWithdrawable(address asset, bool w)
        external onlyRole(ASSET_MANAGER_ROLE)
    {
        _w[asset] = w;
    }
}
"""
    )
    return tmp_path


# ---------------------------------------------------------------------------
# corpus loader
# ---------------------------------------------------------------------------


class TestCorpus:
    def test_load_missing_corpus_returns_empty(self):
        rows = load_corpus("nonexistent_corpus_zzz")
        assert rows == []

    def test_expected_fp_ids_partitions_correctly(self):
        rows = _yieldnest_shape_corpus()
        ids = expected_fp_ids(rows)
        assert ids == {
            "yn_setProvider", "yn_setFee", "yn_setRecipient", "yn_setAsset",
        }

    def test_fixture_path_returns_absolute_path(self):
        path = fixture_path("anything")
        assert path.is_absolute()
        assert path.suffix == ".jsonl"

    def test_load_real_fixture_when_present(self, tmp_path: Path):
        """If a JSONL fixture is committed, it should round-trip cleanly."""
        # Write a tiny synthetic JSONL into the real fixtures dir under a
        # unique name so we don't collide with the committed yieldnest one.
        from eval.corpus import FIXTURES_DIR
        FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
        fixture = FIXTURES_DIR / "test_synthetic_zz.jsonl"
        try:
            fixture.write_text(
                json.dumps(
                    {"hypothesis_id": "x", "title": "X", "expected_fp": True}
                )
                + "\n"
            )
            rows = load_corpus("test_synthetic_zz")
            assert len(rows) == 1
            assert rows[0]["hypothesis_id"] == "x"
            assert rows[0]["expected_fp"] is True
        finally:
            if fixture.exists():
                fixture.unlink()


# ---------------------------------------------------------------------------
# harness — offline mode
# ---------------------------------------------------------------------------


class TestHarnessOffline:
    def test_offline_skips_source_grep_gate(self):
        """source_path=None → filter_template_fps stage stamps skipped_reason."""
        report = run_curation_pipeline(
            _yieldnest_shape_corpus(),
            source_path=None,
            corpus_name="test_offline",
        )
        assert isinstance(report, CurationReport)
        assert report.input_count == 5
        assert report.expected_fp_count == 4

        # Stage 1 should be present but skipped.
        stage_names = [s.name for s in report.stages]
        assert "filter_template_fps" in stage_names
        s1 = next(s for s in report.stages if s.name == "filter_template_fps")
        assert s1.raw_stats.get("skipped_reason") == "no_source_path"
        assert s1.fps_dropped_or_demoted == 0

        # The skip is also surfaced in skipped_gates for the summary header.
        assert any("filter_template_fps" in g for g in report.skipped_gates)

    def test_offline_still_runs_confabulation_detector(self):
        """Even with source_path=None, the confabulation gate (no source
        needed) should fire — 4/5 access-control survivors with status=confirmed
        is the yieldnest-shape storm.
        """
        report = run_curation_pipeline(
            _yieldnest_shape_corpus(),
            source_path=None,
            corpus_name="test_offline_conf",
        )
        assert report.confabulation_flagged is True
        assert report.confabulation_reason  # non-empty


# ---------------------------------------------------------------------------
# harness — with inline source
# ---------------------------------------------------------------------------


class _MockVerifier:
    """Mirrors test_template_fp_filter._MockVerifier — say no for everything,
    so the lexical modifier shortcut is the only path that fires.
    """

    provider_name = "anthropic"
    model = "claude-sonnet-4-6"

    def raw(self, *, system: str, user: str) -> str:
        return '{"has_access_control": false, "reason": "mocked"}'


class TestHarnessWithSource:
    def test_lexical_modifier_check_drops_yieldnest_fps(
        self, yieldnest_shape_source: Path
    ):
        """With access to the source, the 8kv lexical modifier shortcut
        (or the 7nu view/pure check, once #53 lands) should drop or demote
        the labeled FPs while leaving the reentrancy finding alone.
        """
        with patch(
            "llm.unified_client.UnifiedLLMClient", return_value=_MockVerifier()
        ):
            report = run_curation_pipeline(
                _yieldnest_shape_corpus(),
                source_path=yieldnest_shape_source,
                corpus_name="test_with_source",
            )

        # Reentrancy must NOT be filtered.
        assert report.tps_incorrectly_filtered == 0

        # At least some of the 4 FPs should have been caught lexically.
        # (Exact count depends on whether 7nu landed; on baseline, 8kv's
        # _MODIFIER_HINTS lexical check catches `onlyRole`/`onlyOwner` and
        # the FPs go to 4/4. We assert the looser >=1 invariant since the
        # number of caught FPs is the metric, not a requirement.)
        assert report.fps_correctly_filtered >= 1

    def test_report_summary_renders_markdown_table(self):
        """summary() should produce a stable markdown shape."""
        report = run_curation_pipeline(
            _yieldnest_shape_corpus(),
            source_path=None,
            corpus_name="test_summary",
        )
        out = report.summary()
        # Header
        assert "## Eval Replay — test_summary" in out
        # Markdown table
        assert "| Stage | Input | Output |" in out
        assert "filter_template_fps" in out
        # Headline section
        assert "FPs correctly filtered" in out
        assert "Confabulation flag" in out


# ---------------------------------------------------------------------------
# CurationReport derivation properties
# ---------------------------------------------------------------------------


class TestReportDerivations:
    def test_filter_rate_zero_on_empty_corpus(self):
        report = CurationReport(
            corpus_name="empty", input_count=0, expected_fp_count=0
        )
        assert report.fp_filter_rate == 0.0
        assert report.fps_correctly_filtered == 0
        assert report.tps_incorrectly_filtered == 0

    def test_filter_rate_computes_across_stages(self):
        report = CurationReport(
            corpus_name="x",
            input_count=10,
            expected_fp_count=5,
            stages=[
                StageResult("a", 10, 8, fps_dropped_or_demoted=2, tps_dropped_or_demoted=0),
                StageResult("b", 8, 7, fps_dropped_or_demoted=1, tps_dropped_or_demoted=0),
            ],
        )
        assert report.fps_correctly_filtered == 3
        assert report.fp_filter_rate == pytest.approx(0.6)
        assert report.tps_incorrectly_filtered == 0
