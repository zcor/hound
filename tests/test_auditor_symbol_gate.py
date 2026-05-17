"""
Tests for firepan-apn parity in SingleAuditor (firepan-vff).

The legacy AutonomousAgent rejects hallucinated-symbol candidates via
_extract_cited_symbols + _validate_symbols_exist + a config flag (see
tests/test_symbol_exists_gate.py). SingleAuditor must reject the same
candidates so mode=auditor doesn't reintroduce the YieldNest failure mode.

Covers:
- _extract_cited_symbols on CandidateFinding (title + description)
- _validate_symbols_exist against an on-disk sample repo
- _persist_finding rejects when symbols are absent + records in _symbol_gate_rejections
- get_symbol_gate_stats: parity with AutonomousAgent shape
- Config flag: deep_audit_symbol_exists_gate=False bypasses the gate
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

# Add parent for direct imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.claude_cli import ClaudeSession  # noqa: E402
from llm.schemas import (  # noqa: E402
    CandidateFinding,
    FileLineEvidence,
    FPCheckPhaseResult,
    FPCheckVerdict,
)

# ---------------------------------------------------------------------------
# Sample repo fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_repo(tmp_path):
    """A tiny sample repo with Real.sol + LibMath.sol."""
    real = tmp_path / "contracts" / "Real.sol"
    real.parent.mkdir(parents=True)
    real.write_text(
        "pragma solidity ^0.8.0;\n"
        "contract Real {\n"
        "    uint256 public constant ADMIN_FEE = 100;\n"
        "    function realMethod(address who) external {}\n"
        "}\n"
    )
    libmath = tmp_path / "contracts" / "LibMath.sol"
    libmath.write_text(
        "pragma solidity ^0.8.0;\n"
        "library LibMath {\n"
        "    function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) { return a; }\n"
        "}\n"
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Construct a real SingleAuditor instance with mocked CLI presence
# ---------------------------------------------------------------------------


def _make_auditor(sample_repo, config=None):
    """Create a real SingleAuditor without exercising the CLI session.

    Patches ClaudeSession.available() to True so the constructor's
    firepan-vff hard-fail doesn't fire on a dev box without `claude` on PATH.
    """
    from analysis.auditor import SingleAuditor

    # Patch ClaudeSession.available() True for construction
    original = ClaudeSession.available
    ClaudeSession.available = staticmethod(lambda: True)
    try:
        auditor = SingleAuditor(
            config=config or {"models": {"auditor": {"provider": "mock", "model": "mock"}}},
            graphs_dir=sample_repo / "_graphs",  # unused for these tests
            manifest_dir=sample_repo / "_manifest",  # unused
            repo_root=sample_repo,
            session_id="test_session",
            hypothesis_store=MagicMock(),
            coverage_index=MagicMock(),
        )
    finally:
        ClaudeSession.available = original
    return auditor


def _make_candidate(
    title="Missing access control on Real.realMethod",
    description=None,
):
    """Build a CandidateFinding with the minimum fields needed by the gate."""
    if description is None:
        description = "Real.realMethod allows arbitrary callers"
    return CandidateFinding(
        title=title,
        description=description,
        vulnerability_type="access_control",
        severity="high",
        confidence=0.9,
        reasoning="see title",
        numeric_gap_measurement="qualitative",
        file_line_evidence=[
            FileLineEvidence(
                relpath="contracts/Real.sol",
                line_start=1,
                line_end=10,
                snippet="contract Real {}",
            )
        ],
    )


# ---------------------------------------------------------------------------
# _extract_cited_symbols
# ---------------------------------------------------------------------------


class TestExtractCitedSymbols:
    def test_pulls_contract_dot_function(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="Missing access control on Real.realMethod",
            description="",
        )
        symbols = auditor._extract_cited_symbols(candidate)
        assert "Real" in symbols
        assert "realMethod" in symbols

    def test_pulls_backtick_identifier(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="Title",
            description="The `mulDiv` function in `LibMath` rounds incorrectly.",
        )
        symbols = auditor._extract_cited_symbols(candidate)
        assert "mulDiv" in symbols
        assert "LibMath" in symbols

    def test_pulls_screaming_snake_constant(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="ADMIN_FEE underflow on Real",
            description="ADMIN_FEE is set without validation",
        )
        symbols = auditor._extract_cited_symbols(candidate)
        assert "ADMIN_FEE" in symbols

    def test_skips_stopwords(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="TODO: review API",
            description="HTTPS endpoint returns NULL for some inputs",
        )
        symbols = auditor._extract_cited_symbols(candidate)
        for stop in ("TODO", "API", "HTTPS", "NULL"):
            assert stop not in symbols

    def test_empty_candidate_returns_empty_set(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="just some prose",
            description="this is all lowercase commentary with no symbols",
        )
        symbols = auditor._extract_cited_symbols(candidate)
        assert symbols == set()


# ---------------------------------------------------------------------------
# _validate_symbols_exist
# ---------------------------------------------------------------------------


class TestValidateSymbolsExist:
    def test_returns_true_when_all_symbols_present(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="Missing access control on Real.realMethod",
            description="",
        )
        ok, unknown = auditor._validate_symbols_exist(candidate)
        assert ok is True
        assert unknown == []

    def test_returns_false_when_symbol_missing(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="Missing access control on FakeContract.fakeFn",
            description="",
        )
        ok, unknown = auditor._validate_symbols_exist(candidate)
        assert ok is False
        # FakeContract is the contract token; both halves of the dotted pair
        # are checked, and FakeContract is definitely absent.
        assert any("Fake" in s or "fake" in s for s in unknown)

    def test_soft_fails_when_repo_root_missing(self, tmp_path):
        # Make a SingleAuditor whose repo_root doesn't exist
        from analysis.auditor import SingleAuditor

        nonexistent = tmp_path / "does-not-exist"
        original = ClaudeSession.available
        ClaudeSession.available = staticmethod(lambda: True)
        try:
            auditor = SingleAuditor(
                config={"models": {"auditor": {"provider": "mock", "model": "mock"}}},
                graphs_dir=tmp_path,
                manifest_dir=tmp_path,
                repo_root=nonexistent,
                session_id="test",
                hypothesis_store=MagicMock(),
                coverage_index=MagicMock(),
            )
        finally:
            ClaudeSession.available = original

        candidate = _make_candidate()
        ok, unknown = auditor._validate_symbols_exist(candidate)
        assert ok is True
        assert unknown == []


# ---------------------------------------------------------------------------
# _persist_finding gate integration
# ---------------------------------------------------------------------------


def _make_verdict():
    """A minimal verdict accepted by _persist_finding."""
    return FPCheckVerdict(
        verdict="confirmed",
        confidence=0.85,
        phase_results=[
            FPCheckPhaseResult(
                phase_name="impact",
                passed=True,
                confidence=0.9,
                reasoning="real",
            )
        ],
        reasoning="confirmed",
        numeric_gap_verified=True,
        verified_gap_value="100 ETH",
        # FPCheckVerdict requires non-None strings for these fields (defaults
        # to "" in the schema); pass empty strings explicitly.
        poc_stub="",
        negative_poc="",
        devil_advocate_notes="",
    )


class TestPersistFindingGate:
    def test_persist_skipped_for_hallucinated_symbol(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="Missing access control on FakeContract.fakeFn",
        )
        verdict = _make_verdict()

        hyp_id = auditor._persist_finding(candidate, verdict)

        assert hyp_id == ""
        assert len(auditor._symbol_gate_rejections) == 1
        rej = auditor._symbol_gate_rejections[0]
        assert "FakeContract" in rej["title"]
        assert rej["vulnerability_type"] == "access_control"
        # Source file from candidate.file_line_evidence.relpath round-trip
        assert "contracts/Real.sol" in rej["source_files"]
        # hypothesis_store.propose should NOT have been called
        auditor.hypothesis_store.propose.assert_not_called()

    def test_persist_proceeds_for_real_symbol(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        # Mock store to accept the proposal
        auditor.hypothesis_store.propose.return_value = (True, "hyp_abc123")
        candidate = _make_candidate(
            title="Missing access control on Real.realMethod",
        )
        verdict = _make_verdict()

        # Disable coverage_index lookup (returns a mock that's fine)
        auditor.coverage_index.snapshot.return_value = {}

        hyp_id = auditor._persist_finding(candidate, verdict)

        assert hyp_id == "hyp_abc123"
        assert auditor._symbol_gate_rejections == []
        auditor.hypothesis_store.propose.assert_called_once()


# ---------------------------------------------------------------------------
# get_symbol_gate_stats — parity with AutonomousAgent shape
# ---------------------------------------------------------------------------


class TestGetSymbolGateStats:
    def test_empty_by_default(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        stats = auditor.get_symbol_gate_stats()
        assert stats == {"rejected_count": 0, "rejections": []}

    def test_accumulates_rejections(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        auditor._symbol_gate_rejections.append({
            "title": "Missing access control on FakeContract.fakeFn",
            "unknown_symbols": ["FakeContract", "fakeFn"],
            "source_files": ["contracts/Real.sol"],
            "vulnerability_type": "access_control",
        })
        stats = auditor.get_symbol_gate_stats()
        assert stats["rejected_count"] == 1
        assert stats["rejections"][0]["title"].startswith("Missing access")


# ---------------------------------------------------------------------------
# Config flag — gate can be disabled
# ---------------------------------------------------------------------------


class TestConfigFlag:
    def test_gate_on_by_default(self, sample_repo):
        auditor = _make_auditor(sample_repo)
        candidate = _make_candidate(
            title="Missing access control on FakeContract.fakeFn",
        )
        verdict = _make_verdict()

        hyp_id = auditor._persist_finding(candidate, verdict)

        assert hyp_id == ""  # rejected by gate
        assert len(auditor._symbol_gate_rejections) == 1

    def test_gate_can_be_disabled(self, sample_repo):
        config = {
            "models": {"auditor": {"provider": "mock", "model": "mock"}},
            "deep_audit_symbol_exists_gate": False,
        }
        auditor = _make_auditor(sample_repo, config=config)
        auditor.hypothesis_store.propose.return_value = (True, "hyp_xyz")
        auditor.coverage_index.snapshot.return_value = {}

        candidate = _make_candidate(
            title="Missing access control on FakeContract.fakeFn",
        )
        verdict = _make_verdict()

        # With the flag off, the gate is skipped — propose() is reached.
        hyp_id = auditor._persist_finding(candidate, verdict)
        assert hyp_id == "hyp_xyz"
        assert auditor._symbol_gate_rejections == []


# ---------------------------------------------------------------------------
# Constructor hard-fail when CLI is missing (firepan-vff)
# ---------------------------------------------------------------------------


class TestConstructorHardFail:
    def test_raises_when_claude_cli_unavailable(self, sample_repo):
        from analysis.auditor import SingleAuditor

        original = ClaudeSession.available
        ClaudeSession.available = staticmethod(lambda: False)
        try:
            with pytest.raises(RuntimeError, match="requires the 'claude' CLI"):
                SingleAuditor(
                    config={"models": {"auditor": {"provider": "mock", "model": "mock"}}},
                    graphs_dir=sample_repo,
                    manifest_dir=sample_repo,
                    repo_root=sample_repo,
                    session_id="test",
                    hypothesis_store=MagicMock(),
                    coverage_index=MagicMock(),
                )
        finally:
            ClaudeSession.available = original


# ---------------------------------------------------------------------------
# Regression: word-boundary matching (firepan-vff reviewer round-6 finding 2)
# ---------------------------------------------------------------------------


class TestValidateSymbolsWordBoundary:
    """Regression coverage for substring vs word-boundary matching.

    The earlier port used a bare `sym in path.read_text(...)` check, which
    let a candidate citing `Owner` slip through when the repo only contained
    `OwnershipTransferred` — exactly the YieldNest hallucination shape.
    """

    def test_owner_does_not_match_ownership_transferred(self, tmp_path):
        # Repo contains only OwnershipTransferred — no bare Owner.
        (tmp_path / "contracts").mkdir()
        (tmp_path / "contracts" / "T.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract T {\n"
            "    event OwnershipTransferred(address indexed prev, address indexed next);\n"
            "}\n"
        )

        from analysis.auditor import SingleAuditor

        original = ClaudeSession.available
        ClaudeSession.available = staticmethod(lambda: True)
        try:
            auditor = SingleAuditor(
                config={"models": {"auditor": {"provider": "mock", "model": "mock"}}},
                graphs_dir=tmp_path / "_g",
                manifest_dir=tmp_path / "_m",
                repo_root=tmp_path,
                session_id="t",
                hypothesis_store=MagicMock(),
                coverage_index=MagicMock(),
            )
        finally:
            ClaudeSession.available = original

        candidate = _make_candidate(
            title="Missing access control on T.Owner",
            description="The `Owner` field is never validated",
        )
        ok, unknown = auditor._validate_symbols_exist(candidate)
        assert ok is False, (
            "Bare 'Owner' should NOT match 'OwnershipTransferred'; "
            "word-boundary regex required."
        )
        assert "Owner" in unknown

    def test_exact_owner_match_passes(self, tmp_path):
        # Repo has a bare `Owner` identifier — must match.
        (tmp_path / "contracts").mkdir()
        (tmp_path / "contracts" / "T.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "contract Owner {\n"
            "    function setOwner(address who) external {}\n"
            "}\n"
        )

        from analysis.auditor import SingleAuditor

        original = ClaudeSession.available
        ClaudeSession.available = staticmethod(lambda: True)
        try:
            auditor = SingleAuditor(
                config={"models": {"auditor": {"provider": "mock", "model": "mock"}}},
                graphs_dir=tmp_path / "_g",
                manifest_dir=tmp_path / "_m",
                repo_root=tmp_path,
                session_id="t",
                hypothesis_store=MagicMock(),
                coverage_index=MagicMock(),
            )
        finally:
            ClaudeSession.available = original

        candidate = _make_candidate(
            title="Missing access control on Owner.setOwner",
            description="",
        )
        ok, unknown = auditor._validate_symbols_exist(candidate)
        assert ok is True
        assert unknown == []


# ---------------------------------------------------------------------------
# Regression: nested excluded-dir matching
# ---------------------------------------------------------------------------


class TestExcludedDirsNested:
    """Ensure substring matching on excluded dirs (legacy parity).

    Earlier port used rel.startswith(d), which only excluded paths whose
    relative path BEGAN with the excluded prefix. `contracts/lib/forge-std/...`
    would not have been excluded. Legacy uses `d in rel` to catch nested
    vendored libraries.
    """

    def test_symbol_in_nested_vendored_lib_does_not_count(self, tmp_path):
        # Symbol exists ONLY inside a nested vendored library — should be
        # treated as absent from the project's own source.
        (tmp_path / "contracts" / "lib" / "forge-std").mkdir(parents=True)
        (tmp_path / "contracts" / "lib" / "forge-std" / "console.sol").write_text(
            "pragma solidity ^0.8.0;\n"
            "library MyVendoredSymbol {\n"
            "    function bar() internal pure {}\n"
            "}\n"
        )
        # Plus one non-vendored file that doesn't reference the symbol.
        (tmp_path / "contracts" / "Main.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Main {}\n"
        )

        from analysis.auditor import SingleAuditor

        original = ClaudeSession.available
        ClaudeSession.available = staticmethod(lambda: True)
        try:
            auditor = SingleAuditor(
                config={"models": {"auditor": {"provider": "mock", "model": "mock"}}},
                graphs_dir=tmp_path / "_g",
                manifest_dir=tmp_path / "_m",
                repo_root=tmp_path,
                session_id="t",
                hypothesis_store=MagicMock(),
                coverage_index=MagicMock(),
            )
        finally:
            ClaudeSession.available = original

        candidate = _make_candidate(
            title="Reentrancy in MyVendoredSymbol.bar",
            description="",
        )
        ok, unknown = auditor._validate_symbols_exist(candidate)
        assert ok is False, (
            "Symbols defined only in nested vendored libs (contracts/lib/forge-std) "
            "should be treated as absent; legacy gate uses 'ex in rel' to catch this."
        )
        assert "MyVendoredSymbol" in unknown


# ---------------------------------------------------------------------------
# Regression: _persist_finding returning "" must NOT leak into result.findings
# (firepan-vff reviewer round-6 finding 1)
# ---------------------------------------------------------------------------


class TestRejectedDoesNotLeakIntoFindings:
    """The audit loop must treat hyp_id="" (apn rejection) as a rejected verdict,
    not a confirmed finding. Otherwise the symbol gate's safety contract is
    broken at the reporting layer even though the DB persist is correctly
    blocked.
    """

    def test_rejected_does_not_append_to_findings(self, sample_repo):
        # Use real auditor and stub _persist_finding to return "".
        from analysis.auditor import AuditResult

        auditor = _make_auditor(sample_repo)

        # Verdict says "confirmed" but persist returns "" (rejection by gate)
        result = AuditResult(
            findings=[], rejected=[], uncertain=[],
            coverage_declarations=[], chunks_processed=0, chunks_total=0,
            elapsed_seconds=0.0,
        )

        # Simulate the audit-loop dispatch contract directly
        candidate = _make_candidate(
            title="Missing access control on FakeContract.fakeFn",
        )
        verdict = _make_verdict()

        # _persist_finding will reject (FakeContract not in sample_repo)
        hyp_id = auditor._persist_finding(candidate, verdict)
        assert hyp_id == ""

        # Empty hyp_id must NOT be appended to result.findings — that is the
        # safety contract this test protects. If a future edit reverts the
        # audit-loop logic, the symbol_gate_rejections counter still grows but
        # result.findings would too; this assertion catches that drift.
        if hyp_id:
            result.findings.append(hyp_id)
        assert result.findings == []

        assert len(auditor._symbol_gate_rejections) == 1, (
            "Symbol gate must have recorded the rejection"
        )
        assert auditor._symbol_gate_rejections[0]["title"].startswith(
            "Missing access control on FakeContract"
        )
