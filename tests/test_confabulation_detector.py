"""
Tests for firepan-ygy — confabulation-pattern detector on deep audit finalize.

Covers:
- _detect_confabulation_pattern: both thresholds (absolute >10, relative >50%)
  plus the empty/below-threshold cases.
- Access-control template regex: catches the yieldnest FP title shapes.
- ScanHistoryItem surfaces needs_manual_review + review_reason.
- Legacy rows default to needs_manual_review=False.
"""

import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, Project, ScanExecution, Tenant, User

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db
from server.auth_utils import create_access_token
from worker.tasks import _ACCESS_CONTROL_TEMPLATE_RE, _detect_confabulation_pattern

# =============================================================================
# Fixtures (subset of test_deep_audit_verify.py — kept local for test isolation)
# =============================================================================


@pytest.fixture(scope="function")
def test_db(tmp_path):
    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(test_db):
    import server.api as api_module

    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    def override_get_engine():
        return test_db.get_bind()

    app.dependency_overrides[get_db] = override_get_db
    original_get_engine = api_module.get_engine
    original_engine = api_module._engine
    api_module._engine = test_db.get_bind()
    api_module.get_engine = override_get_engine

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    api_module.get_engine = original_get_engine
    api_module._engine = original_engine


@pytest.fixture
def tenant(test_db):
    t = Tenant(name="t1", email_verified=True)
    test_db.add(t)
    test_db.commit()
    test_db.refresh(t)
    return t


@pytest.fixture
def user(test_db, tenant):
    u = User(
        tenant_id=tenant.id,
        email="a@b.com",
        github_id=99999,
        github_login="tester",
        signup_provider="github",
    )
    test_db.add(u)
    test_db.commit()
    test_db.refresh(u)
    return u


@pytest.fixture
def project(test_db, tenant):
    p = Project(
        tenant_id=tenant.id,
        name="p1",
        source_path="/tmp/p1",
        git_url="https://github.com/a/p1",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(p)
    test_db.commit()
    test_db.refresh(p)
    return p


def _tenant_headers(user):
    token = create_access_token({"user_id": user.id, "tenant_id": user.tenant_id})
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# Template regex
# =============================================================================


class TestAccessControlTemplateRegex:
    """yieldnest scan 77's FP titles (verbatim) should all match the template."""

    @pytest.mark.parametrize(
        "title",
        [
            "Missing access control on LinearWithdrawalFeeLib.setBaseWithdrawalFee",
            "Missing access control on FeeHooks.setPerformanceFeeRecipient",
            "Missing access control on VaultManager.setProvider",
            "Missing access control on BaseStrategy.setAssetWithdrawable",
            "Unauthorized withdrawal fee override leading to theft",
            "FeeHooks constructor lacks role-based access control",
            "LinearWithdrawalFeeLib.feeOnRaw exposes fee calculation without access control",
            "missing role check on setX",
            "No access control on setFoo",
            "Improper access control on bar",
        ],
    )
    def test_yieldnest_fp_titles_match(self, title):
        assert _ACCESS_CONTROL_TEMPLATE_RE.search(title), (
            f"Regex should match yieldnest-style FP title: {title!r}"
        )

    @pytest.mark.parametrize(
        "title",
        [
            "Integer overflow in transfer amount",
            "Reentrancy in withdrawal function",
            "Price manipulation via flash loan",
            "Timestamp dependence",
            "Uninitialized storage pointer",
        ],
    )
    def test_non_access_control_titles_dont_match(self, title):
        assert not _ACCESS_CONTROL_TEMPLATE_RE.search(title), (
            f"Regex should NOT match unrelated title: {title!r}"
        )


# =============================================================================
# _detect_confabulation_pattern
# =============================================================================


def _confirmed_access_control_hyps(n: int) -> list[dict]:
    """Helper: build N confirmed access-control-template hypotheses."""
    return [
        {
            "id": f"h{i}",
            "status": "confirmed",
            "title": f"Missing access control on Contract{i}.setSomething",
            "description": "",
            "severity": "high",
            "confidence": 0.9,
        }
        for i in range(n)
    ]


class TestDetectConfabulationPattern:
    def test_empty_returns_not_flagged(self):
        flagged, reason = _detect_confabulation_pattern([])
        assert flagged is False
        assert reason is None

    def test_no_confirmed_returns_not_flagged(self):
        hyps = [
            {"status": "uncertain", "title": "Missing access control on X.foo"}
            for _ in range(20)
        ]
        flagged, reason = _detect_confabulation_pattern(hyps)
        assert flagged is False
        assert reason is None

    def test_absolute_threshold_at_11_triggers(self):
        """The 'yieldnest at 11 of 13' case — >10 triggers the loud alarm."""
        # 11 access-control confirms + 2 unrelated confirms = 13 total (matches scan 77)
        hyps = _confirmed_access_control_hyps(11) + [
            {"status": "confirmed", "title": "Reentrancy in swap", "description": ""},
            {"status": "confirmed", "title": "Integer overflow", "description": ""},
        ]
        flagged, reason = _detect_confabulation_pattern(hyps)
        assert flagged is True
        assert reason is not None
        assert "11" in reason  # Number of matches should appear in the reason
        assert "access-control" in reason

    def test_absolute_threshold_at_10_does_not_trigger(self):
        """Edge: exactly 10 is the boundary, NOT >10."""
        hyps = _confirmed_access_control_hyps(10) + [
            {"status": "confirmed", "title": "Reentrancy", "description": ""},
            {"status": "confirmed", "title": "Overflow", "description": ""},
            {"status": "confirmed", "title": "Timestamp", "description": ""},
            {"status": "confirmed", "title": "Oracle", "description": ""},
            {"status": "confirmed", "title": "DoS", "description": ""},
            {"status": "confirmed", "title": "Front-run", "description": ""},
            {"status": "confirmed", "title": "Flash loan", "description": ""},
            {"status": "confirmed", "title": "Signature replay", "description": ""},
            {"status": "confirmed", "title": "Sandwich", "description": ""},
            {"status": "confirmed", "title": "Griefing", "description": ""},
            {"status": "confirmed", "title": "Precision loss", "description": ""},
        ]
        flagged, reason = _detect_confabulation_pattern(hyps)
        # 10 access-control / 21 total = 48% — below both thresholds
        assert flagged is False, f"10 access-control confirms should NOT flag: {reason}"

    def test_relative_threshold_above_50pct_triggers(self):
        """6 access-control out of 10 confirmed = 60% → triggers even at low absolute."""
        hyps = _confirmed_access_control_hyps(6) + [
            {"status": "confirmed", "title": "Reentrancy", "description": ""},
            {"status": "confirmed", "title": "Overflow", "description": ""},
            {"status": "confirmed", "title": "Timestamp", "description": ""},
            {"status": "confirmed", "title": "Oracle", "description": ""},
        ]
        flagged, reason = _detect_confabulation_pattern(hyps)
        assert flagged is True
        assert reason is not None
        assert "60%" in reason or "%" in reason

    def test_relative_threshold_ignores_tiny_samples(self):
        """3 of 4 = 75% but total_confirmed < 5 — suppress to avoid noise."""
        hyps = _confirmed_access_control_hyps(3) + [
            {"status": "confirmed", "title": "Reentrancy", "description": ""},
        ]
        flagged, reason = _detect_confabulation_pattern(hyps)
        assert flagged is False

    def test_only_confirmed_counted(self):
        """Rejected/uncertain/proposed hypotheses shouldn't count toward the threshold."""
        confirmed = _confirmed_access_control_hyps(11)
        rejected = [
            {"status": "rejected", "title": f"Missing access control on X{i}.f"}
            for i in range(50)
        ]
        flagged, reason = _detect_confabulation_pattern(confirmed + rejected)
        # Only the 11 confirmed count → triggers absolute threshold
        assert flagged is True

        confirmed_benign = [
            {"status": "confirmed", "title": "Reentrancy", "description": ""}
            for _ in range(20)
        ]
        uncertain_ac = [
            {"status": "uncertain", "title": f"Missing access control on X{i}.f"}
            for i in range(100)
        ]
        flagged2, _ = _detect_confabulation_pattern(confirmed_benign + uncertain_ac)
        # No confirmed access-control → don't flag despite 100 uncertain ones
        assert flagged2 is False


# =============================================================================
# ScanHistoryItem surfaces needs_manual_review
# =============================================================================


class TestScanHistorySurfacesFlag:
    def test_surfaces_needs_manual_review_true(self, client, user, test_db, tenant, project):
        scan = ScanExecution(
            execution_id="flagged_scan",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="https://github.com/a/p1",
            repo_name="p1",
            status="in_review",
            scan_config={"scan_type": "deep"},
            deep_audit_overview={
                "headline": "x",
                "top_concerns": [],
                "triage_counts": {"confirmed": 0, "investigating": 0, "proposed": 0, "rejected": 0, "uncertain": 0},
                "credible_findings_count": 0,
                "credible_findings": [],
                "raw_findings_count": 13,
                "assessment_level": "critical",
                "review_note": None,
                "admin_verified": False,
                "needs_manual_review": True,
                "review_reason": "11 confirmed access-control findings exceed threshold (>10).",
            },
        )
        test_db.add(scan)
        test_db.commit()

        resp = client.get(
            f"/repositories/{project.id}/scans",
            headers=_tenant_headers(user),
        )
        assert resp.status_code == 200
        item = resp.json()["scans"][0]
        assert item["needs_manual_review"] is True
        assert item["review_reason"] and "11" in item["review_reason"]

    def test_legacy_row_without_flag_defaults_false(self, client, user, test_db, tenant, project):
        """Overview written before ygy has no needs_manual_review key — default False."""
        scan = ScanExecution(
            execution_id="legacy_scan",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="https://github.com/a/p1",
            repo_name="p1",
            status="completed",
            scan_config={"scan_type": "deep"},
            deep_audit_overview={
                "headline": "x",
                "assessment_level": "low",
                "credible_findings_count": 0,
                "raw_findings_count": 0,
                "triage_counts": {"confirmed": 0, "investigating": 0, "proposed": 0, "rejected": 0, "uncertain": 0},
                "top_concerns": [],
                "credible_findings": [],
                "review_note": None,
                # No needs_manual_review / review_reason keys — legacy row
            },
        )
        test_db.add(scan)
        test_db.commit()

        resp = client.get(
            f"/repositories/{project.id}/scans",
            headers=_tenant_headers(user),
        )
        assert resp.status_code == 200
        item = resp.json()["scans"][0]
        assert item["needs_manual_review"] is False
        assert item["review_reason"] is None

    def test_surface_scan_has_no_flag(self, client, user, test_db, tenant, project):
        """Surface scans (no overview JSONB) should surface needs_manual_review=False."""
        scan = ScanExecution(
            execution_id="surface_scan",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="https://github.com/a/p1",
            repo_name="p1",
            status="completed",
            scan_config={"scan_type": "surface"},
            # No deep_audit_overview
        )
        test_db.add(scan)
        test_db.commit()

        resp = client.get(
            f"/repositories/{project.id}/scans",
            headers=_tenant_headers(user),
        )
        assert resp.status_code == 200
        item = resp.json()["scans"][0]
        assert item["needs_manual_review"] is False
        assert item["review_reason"] is None
