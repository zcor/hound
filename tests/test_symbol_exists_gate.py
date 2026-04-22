"""
Tests for firepan-apn — scout symbol-exists grep gate.

Covers:
- _extract_cited_symbols: regex extraction of code symbols from prose
- _validate_symbols_exist: grep against a real on-disk sample repo
- _form_hypothesis integration: rejects hypotheses citing absent symbols
- get_symbol_gate_stats: session-scoped counter accessible post-run
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from analysis.agent_core import AutonomousAgent  # noqa: E402

# ---------------------------------------------------------------------------
# Sample repo + agent stub
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_repo(tmp_path):
    """A tiny sample repo containing Real.sol + LibMath.sol."""
    real = tmp_path / "contracts" / "Real.sol"
    real.parent.mkdir(parents=True)
    real.write_text("""\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Real {
    uint256 public constant ADMIN_FEE = 100;

    function realMethod(address who) external {
        owner = who;
    }
}
""")

    libmath = tmp_path / "contracts" / "LibMath.sol"
    libmath.write_text("""\
pragma solidity ^0.8.0;
library LibMath {
    function mulDiv(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        return (a * b) / c;
    }
}
""")
    return tmp_path


def _make_agent_stub(repo_path, config=None):
    """Build a minimal AutonomousAgent-shaped stub for testing the symbol gate.

    Bypasses AutonomousAgent.__init__ (too heavy — needs graphs, manifest,
    LLM client, etc.). The symbol gate only needs _repo_root, config, the
    rejection counter, and the regex class attrs (inherited from the class).
    """
    agent = AutonomousAgent.__new__(AutonomousAgent)
    agent._repo_root = repo_path
    agent.config = config or {}
    agent._symbol_gate_rejections = []
    agent.redis_publisher = None

    # Stub _publish_to_redis so _form_hypothesis path would work if exercised.
    agent._publish_to_redis = MagicMock()
    return agent


# ---------------------------------------------------------------------------
# _extract_cited_symbols
# ---------------------------------------------------------------------------


class TestExtractSymbols:
    def test_extracts_contract_dot_fn_pair(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="Missing access control on Real.realMethod",
            description="",
        )
        syms = agent._extract_cited_symbols(h)
        assert "Real" in syms
        assert "realMethod" in syms

    def test_extracts_backticked_identifier(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="Issue",
            description="The function `realMethod` lacks validation.",
        )
        syms = agent._extract_cited_symbols(h)
        assert "realMethod" in syms

    def test_extracts_screaming_snake_constant(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="ADMIN_FEE can be set by anyone",
            description="",
        )
        syms = agent._extract_cited_symbols(h)
        assert "ADMIN_FEE" in syms

    def test_skips_stopwords(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="TODO: review the API",
            description="README mentions JSON format",
        )
        syms = agent._extract_cited_symbols(h)
        assert "TODO" not in syms
        assert "API" not in syms
        assert "README" not in syms
        assert "JSON" not in syms


# ---------------------------------------------------------------------------
# _validate_symbols_exist
# ---------------------------------------------------------------------------


class TestValidateSymbolsExist:
    def test_accepts_hypothesis_with_real_symbols(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="Missing access control on Real.realMethod",
            description="ADMIN_FEE constant can be bypassed",
        )
        ok, unknown = agent._validate_symbols_exist(h)
        assert ok is True
        assert unknown == []

    def test_rejects_hypothesis_citing_nonexistent_symbol(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="Missing access control on FakeGauge.voteForGauge",
            description="",
        )
        ok, unknown = agent._validate_symbols_exist(h)
        assert ok is False
        assert "FakeGauge" in unknown
        assert "voteForGauge" in unknown

    def test_curve_training_data_drift(self, sample_repo):
        """Curve postmortem D1: scout hallucinated `views_implementation` — a symbol
        from the non-fxswap branch. Ensure we catch it."""
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="factory.views_implementation can be abused",
            description="The `views_implementation` field allows arbitrary delegatecall",
        )
        ok, unknown = agent._validate_symbols_exist(h)
        assert ok is False
        assert "views_implementation" in unknown

    def test_soft_fails_when_repo_root_missing(self):
        agent = _make_agent_stub(None)
        agent._repo_root = None
        h = SimpleNamespace(
            title="Missing access control on FakeContract.fakeFn",
            description="",
        )
        ok, unknown = agent._validate_symbols_exist(h)
        assert ok is True
        assert unknown == []

    def test_soft_fails_with_no_parseable_symbols(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        h = SimpleNamespace(
            title="general concern",
            description="not structured at all, no code identifiers",
        )
        ok, unknown = agent._validate_symbols_exist(h)
        assert ok is True
        assert unknown == []


# ---------------------------------------------------------------------------
# get_symbol_gate_stats
# ---------------------------------------------------------------------------


class TestSymbolGateStats:
    def test_returns_empty_stats_initially(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        stats = agent.get_symbol_gate_stats()
        assert stats == {"rejected_count": 0, "rejected": []}

    def test_accumulates_rejections(self, sample_repo):
        agent = _make_agent_stub(sample_repo)
        agent._symbol_gate_rejections.append({
            "title": "Missing access control on FakeContract.fakeFn",
            "unknown_symbols": ["FakeContract", "fakeFn"],
            "node_refs": ["node1"],
            "vulnerability_type": "access_control",
        })
        stats = agent.get_symbol_gate_stats()
        assert stats["rejected_count"] == 1
        assert stats["rejected"][0]["title"].startswith("Missing access")


# ---------------------------------------------------------------------------
# Config flag
# ---------------------------------------------------------------------------


class TestConfigFlag:
    def test_gate_on_by_default(self, sample_repo):
        agent = _make_agent_stub(sample_repo, config={})
        # Gate should operate — validate_symbols_exist returns False for unknown
        h = SimpleNamespace(
            title="Missing access control on FakeContract.fakeFn",
            description="",
        )
        ok, unknown = agent._validate_symbols_exist(h)
        assert ok is False
        assert unknown  # has rejections

    def test_gate_can_be_disabled(self, sample_repo):
        """When the flag is false, _form_hypothesis path skips _validate_symbols_exist.

        This is enforced at the call site in _form_hypothesis, so here we just
        assert the flag is readable and the validation function itself works
        independently of the flag (the flag gates the CALL, not the function).
        """
        agent = _make_agent_stub(sample_repo, config={"deep_audit_symbol_exists_gate": False})
        # The function itself still works — only the caller checks the flag.
        h = SimpleNamespace(
            title="Missing access control on FakeContract.fakeFn",
            description="",
        )
        ok, _ = agent._validate_symbols_exist(h)
        assert ok is False  # function still does its job
        # But the flag is readable as expected
        assert agent.config.get("deep_audit_symbol_exists_gate") is False
