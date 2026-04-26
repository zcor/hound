"""
Tests for firepan-8kv — per-pattern template FP filter.

Covers:
- _parse_contract_fn_from_hypothesis: extracts "Contract.fn" and bare fn name
- _fetch_function_declaration: grep-based declaration lookup
- _verifier_same_as_generator: self-verify invariant
- _filter_template_fps: end-to-end filter with mocked verifier
- Full-pipeline: no unknown status values leak to DB
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from database.models import Base, Hypothesis, Project, Tenant  # noqa: E402
from worker.tasks import (  # noqa: E402
    _fetch_function_declaration,
    _filter_template_fps,
    _parse_contract_fn_from_hypothesis,
    _store_hypotheses_in_db,
    _verifier_same_as_generator,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_repo(tmp_path):
    """Build a tiny sample repo with access-modifier'd and unmodified functions."""
    sol = tmp_path / "contracts" / "VaultManager.sol"
    sol.parent.mkdir(parents=True)
    sol.write_text("""\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VaultManager {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function setProvider(address provider) external onlyOwner {
        _provider = provider;
    }

    function setFee(uint256 fee) external {
        // no access control — this is a real bug
        _fee = fee;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
""")
    return tmp_path


@pytest.fixture(scope="function")
def in_memory_db(tmp_path):
    """SQLAlchemy in-memory DB with the full schema."""
    db_path = tmp_path / "template_fp.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def _get_db():
        return TestingSessionLocal()

    try:
        yield _get_db, engine, TestingSessionLocal
    finally:
        engine.dispose()


@pytest.fixture
def project(in_memory_db):
    _get_db, _, TestingSessionLocal = in_memory_db
    db = TestingSessionLocal()
    try:
        tenant = Tenant(name="t1", plan="free")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        p = Project(
            tenant_id=tenant.id,
            name="p1",
            source_path="/tmp/p1",
            git_url="https://github.com/a/p1",
            status="active",
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        return p.id
    finally:
        db.close()


# ---------------------------------------------------------------------------
# _parse_contract_fn_from_hypothesis
# ---------------------------------------------------------------------------


class TestParseContractFn:
    def test_extracts_contract_dot_fn(self):
        h = {"title": "Missing access control on VaultManager.setProvider", "description": ""}
        contract, fn = _parse_contract_fn_from_hypothesis(h)
        assert contract == "VaultManager"
        assert fn == "setProvider"

    def test_falls_back_to_bare_fn(self):
        h = {"title": "No access control on setFoo(uint256)", "description": ""}
        contract, fn = _parse_contract_fn_from_hypothesis(h)
        assert contract is None
        assert fn == "setFoo"

    def test_returns_none_when_unparseable(self):
        h = {"title": "general concern", "description": "not structured"}
        contract, fn = _parse_contract_fn_from_hypothesis(h)
        assert contract is None
        assert fn is None


# ---------------------------------------------------------------------------
# _fetch_function_declaration
# ---------------------------------------------------------------------------


class TestFetchDeclaration:
    def test_finds_modifier_protected_fn(self, sample_repo):
        decl = _fetch_function_declaration(sample_repo, "VaultManager", "setProvider")
        assert decl is not None
        assert "setProvider" in decl
        assert "onlyOwner" in decl

    def test_finds_unmodified_fn(self, sample_repo):
        decl = _fetch_function_declaration(sample_repo, "VaultManager", "setFee")
        assert decl is not None
        assert "setFee" in decl
        assert "onlyOwner" not in decl

    def test_returns_none_for_missing_fn(self, sample_repo):
        decl = _fetch_function_declaration(sample_repo, "VaultManager", "nonExistentFn")
        assert decl is None

    def test_handles_missing_repo(self, tmp_path):
        decl = _fetch_function_declaration(tmp_path / "does_not_exist", "X", "y")
        assert decl is None


# ---------------------------------------------------------------------------
# _verifier_same_as_generator
# ---------------------------------------------------------------------------


class TestVerifierSameAsGenerator:
    def test_same_provider_and_model_returns_true(self):
        cfg = {
            "models": {
                "scout": {"provider": "deepseek", "model": "deepseek-chat"},
                "strategist": {"provider": "deepseek", "model": "deepseek-chat"},
                "template_verifier": {"provider": "deepseek", "model": "deepseek-chat"},
            }
        }
        assert _verifier_same_as_generator(cfg) is True

    def test_different_model_returns_false(self):
        cfg = {
            "models": {
                "scout": {"provider": "deepseek", "model": "deepseek-chat"},
                "strategist": {"provider": "deepseek", "model": "deepseek-chat"},
                "template_verifier": {"provider": "anthropic", "model": "claude-sonnet-4-6"},
            }
        }
        assert _verifier_same_as_generator(cfg) is False

    def test_missing_profile_returns_true(self):
        cfg = {"models": {"scout": {"provider": "deepseek", "model": "deepseek-chat"}}}
        assert _verifier_same_as_generator(cfg) is True


# ---------------------------------------------------------------------------
# _filter_template_fps — end-to-end with mocked verifier
# ---------------------------------------------------------------------------


class _MockVerifier:
    """Stand-in for UnifiedLLMClient; returns a pre-canned has_access_control decision."""

    provider_name = "anthropic"
    model = "claude-sonnet-4-6"

    def __init__(self, answers: dict[str, bool]):
        self._answers = answers

    def raw(self, *, system: str, user: str) -> str:
        # Route by function name appearing in the prompt
        for fn, has_ac in self._answers.items():
            if fn in user:
                return (
                    f'{{"has_access_control": {"true" if has_ac else "false"}, '
                    f'"reason": "mocked for {fn}"}}'
                )
        return '{"has_access_control": false, "reason": "no match"}'


def _base_config(**overrides):
    """Build a baseline config that passes _verifier_same_as_generator (different providers)."""
    cfg = {
        "deep_audit_template_fp_filter": True,
        "models": {
            "scout": {"provider": "deepseek", "model": "deepseek-chat"},
            "strategist": {"provider": "deepseek", "model": "deepseek-chat"},
            "template_verifier": {"provider": "anthropic", "model": "claude-sonnet-4-6"},
        },
    }
    cfg.update(overrides)
    return cfg


class TestFilterTemplateFps:
    def test_rejects_access_control_on_modifier_protected_fn(self, sample_repo):
        hypotheses = [
            {
                "id": "h1",
                "title": "Missing access control on VaultManager.setProvider",
                "description": "Function can be called by anyone",
                "severity": "high",
                "confidence": 0.9,
                "node_ids": ["VaultManager.setProvider"],
            },
        ]
        cfg = _base_config()
        mock_v = _MockVerifier({"setProvider": True})
        with patch("llm.unified_client.UnifiedLLMClient", return_value=mock_v):
            kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)

        # setProvider has onlyOwner → rejected by lexical shortcut (doesn't even hit LLM)
        assert len(kept) == 0
        assert len(stats["rejected"]) == 1
        assert stats["rejected"][0]["function"] == "setProvider"
        assert stats["candidates_checked"] == 1
        assert stats["kept"] == 0

    def test_keeps_access_control_on_unmodified_fn(self, sample_repo):
        hypotheses = [
            {
                "id": "h2",
                "title": "Missing access control on VaultManager.setFee",
                "description": "",
                "severity": "high",
                "confidence": 0.9,
                "node_ids": ["VaultManager.setFee"],
            },
        ]
        cfg = _base_config()
        mock_v = _MockVerifier({"setFee": False})
        with patch("llm.unified_client.UnifiedLLMClient", return_value=mock_v):
            kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)

        assert len(kept) == 1
        assert kept[0]["id"] == "h2"
        assert len(stats["rejected"]) == 0

    def test_non_template_hypotheses_untouched(self, sample_repo):
        hypotheses = [
            {
                "id": "h3",
                "title": "Reentrancy in withdraw",
                "description": "",
                "severity": "critical",
                "confidence": 0.9,
            },
        ]
        cfg = _base_config()
        kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)
        assert len(kept) == 1
        assert stats["candidates_checked"] == 0

    def test_skips_when_verifier_matches_generator(self, sample_repo):
        """firepan-jyo invariant: don't self-verify."""
        hypotheses = [
            {
                "id": "h1",
                "title": "Missing access control on VaultManager.setProvider",
                "description": "",
                "node_ids": ["VaultManager.setProvider"],
            },
        ]
        cfg = _base_config()
        cfg["models"]["template_verifier"] = {"provider": "deepseek", "model": "deepseek-chat"}
        kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)
        assert len(kept) == 1  # untouched
        assert stats["skipped_reason"] == "verifier_matches_generator"

    def test_skips_when_disabled_by_config(self, sample_repo):
        hypotheses = [
            {
                "id": "h1",
                "title": "Missing access control on VaultManager.setProvider",
                "description": "",
                "node_ids": ["VaultManager.setProvider"],
            },
        ]
        cfg = _base_config(deep_audit_template_fp_filter=False)
        kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)
        assert len(kept) == 1
        assert stats["skipped_reason"] == "disabled_by_config"

    def test_yieldnest_replay_shape(self, sample_repo):
        """Replay the yieldnest FP pattern: ~11 setter FPs + 2 non-setter.

        With all setter declarations onlyOwner-modified, expect ~11 rejected.
        """
        # Expand the sample repo to house all yieldnest-shape setters.
        extra = sample_repo / "contracts" / "FeeHooks.sol"
        extra.write_text("""\
pragma solidity ^0.8.0;
contract FeeHooks {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setPerformanceFeeRecipient(address a) external onlyOwner { _p = a; }
    function setBaseWithdrawalFee(uint256 f) external onlyOwner { _f = f; }
    function setAssetWithdrawable(bool v) external onlyOwner { _v = v; }
}
""")

        hypotheses = [
            {
                "id": "yn1",
                "title": "Missing access control on FeeHooks.setPerformanceFeeRecipient",
                "description": "",
                "node_ids": ["FeeHooks.setPerformanceFeeRecipient"],
            },
            {
                "id": "yn2",
                "title": "Missing access control on FeeHooks.setBaseWithdrawalFee",
                "description": "",
                "node_ids": ["FeeHooks.setBaseWithdrawalFee"],
            },
            {
                "id": "yn3",
                "title": "Missing access control on FeeHooks.setAssetWithdrawable",
                "description": "",
                "node_ids": ["FeeHooks.setAssetWithdrawable"],
            },
            {
                "id": "yn4",
                "title": "Missing access control on VaultManager.setProvider",
                "description": "",
                "node_ids": ["VaultManager.setProvider"],
            },
            # Real finding — NOT an FP. Unmodified setFee.
            {
                "id": "real1",
                "title": "Missing access control on VaultManager.setFee",
                "description": "",
                "node_ids": ["VaultManager.setFee"],
            },
            # Not an access-control template at all — should pass through untouched.
            {
                "id": "real2",
                "title": "Reentrancy in withdraw",
                "description": "",
            },
        ]
        cfg = _base_config()
        mock_v = _MockVerifier({})  # lexical shortcut handles all
        with patch("llm.unified_client.UnifiedLLMClient", return_value=mock_v):
            kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)

        kept_ids = {h["id"] for h in kept}
        # 4 modifier-protected setters rejected, setFee + reentrancy kept.
        assert kept_ids == {"real1", "real2"}
        assert len(stats["rejected"]) == 4


# ---------------------------------------------------------------------------
# Full-pipeline: no unknown status values leak to DB
# ---------------------------------------------------------------------------


class TestNoSchemaLeak:
    def test_no_unknown_status_leaks_to_db(self, sample_repo, in_memory_db, project):
        """Guard the invariant: template_fp_filter MUST remove hypotheses,
        never stamp a new status value. Every persisted Hypothesis.status
        must be in the documented enum.
        """
        get_db, _engine, _ = in_memory_db
        valid_statuses = {
            "proposed", "investigating", "supported",
            "confirmed", "rejected", "refuted",
        }

        hypotheses = [
            {
                "id": "h_rejected_by_filter",
                "title": "Missing access control on VaultManager.setProvider",
                "description": "",
                "status": "confirmed",
                "confidence": 0.9,
                "severity": "high",
                "node_ids": ["VaultManager.setProvider"],
            },
            {
                "id": "h_kept",
                "title": "Reentrancy in withdraw",
                "description": "unrelated finding",
                "status": "confirmed",
                "confidence": 0.9,
                "severity": "critical",
            },
        ]

        cfg = _base_config()
        mock_v = _MockVerifier({"setProvider": True})
        with patch("llm.unified_client.UnifiedLLMClient", return_value=mock_v):
            kept, stats = _filter_template_fps(hypotheses, sample_repo, cfg)

        _store_hypotheses_in_db(get_db, project, kept, "session-1")

        db = get_db()
        try:
            persisted = db.query(Hypothesis).all()
            # Only the kept hypothesis should be in DB
            assert len(persisted) == 1
            assert persisted[0].hypothesis_id == "h_kept"
            # Status must be in documented enum
            for h in persisted:
                assert h.status in valid_statuses, (
                    f"Unknown status {h.status!r} leaked into Hypothesis table"
                )
        finally:
            db.close()


# ---------------------------------------------------------------------------
# firepan-281: _store_hypotheses_in_db propagates model provenance
# ---------------------------------------------------------------------------


class TestProvenancePersistence:
    """Verify junior_model / senior_model / reported_by_model survive the
    in-memory-dict → DB row trip. Without this, the yieldnest postmortem
    "DeepSeek verifying DeepSeek" case is invisible after audit completion.
    """

    def test_model_fields_persist_to_db(self, in_memory_db, project):
        get_db, _engine, _ = in_memory_db
        hypotheses = [{
            "id": "h1",
            "description": "Reentrancy in withdraw",
            "vulnerability_type": "reentrancy",
            "status": "confirmed",
            "confidence": 0.9,
            "severity": "critical",
            "junior_model": "deepseek:deepseek-chat",
            "senior_model": "anthropic:claude-sonnet-4-6",
            "reported_by_model": "anthropic:claude-sonnet-4-6",
        }]
        _store_hypotheses_in_db(get_db, project, hypotheses, "session-prov-1")

        db = get_db()
        try:
            persisted = db.query(Hypothesis).all()
            assert len(persisted) == 1
            row = persisted[0]
            assert row.junior_model == "deepseek:deepseek-chat"
            assert row.senior_model == "anthropic:claude-sonnet-4-6"
            assert row.reported_by_model == "anthropic:claude-sonnet-4-6"
        finally:
            db.close()

    def test_reported_by_model_falls_back_to_senior_then_junior(
        self, in_memory_db, project
    ):
        """When reported_by_model is missing, senior wins; if no senior, junior."""
        get_db, _engine, _ = in_memory_db
        hypotheses = [
            {
                "id": "senior_only",
                "description": "Has senior, no explicit reported_by",
                "vulnerability_type": "x",
                "status": "confirmed",
                "confidence": 0.9,
                "junior_model": "deepseek:deepseek-chat",
                "senior_model": "anthropic:claude-sonnet-4-6",
            },
            {
                "id": "junior_only",
                "description": "Junior only — never promoted",
                "vulnerability_type": "x",
                "status": "proposed",
                "confidence": 0.6,
                "junior_model": "deepseek:deepseek-chat",
            },
            {
                "id": "no_models",
                "description": "Legacy hypothesis with no model attribution",
                "vulnerability_type": "x",
                "status": "proposed",
                "confidence": 0.5,
            },
        ]
        _store_hypotheses_in_db(get_db, project, hypotheses, "session-prov-2")

        db = get_db()
        try:
            rows = {h.hypothesis_id: h for h in db.query(Hypothesis).all()}
            assert (
                rows["senior_only"].reported_by_model
                == "anthropic:claude-sonnet-4-6"
            )
            assert rows["junior_only"].reported_by_model == "deepseek:deepseek-chat"
            assert rows["no_models"].reported_by_model is None
        finally:
            db.close()
