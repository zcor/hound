"""
Tests for firepan-oi4 — admin_verified gate on deep_audit_overview.

Covers:
- _compute_deep_audit_overview defaults admin_verified=False.
- POST /admin/scans/{id}/verify-overview flips the flag and stamps
  verified_at + verified_by; requires admin auth.
- POST /admin/scans/{id}/unverify-overview clears the flag + stamps;
  idempotent; requires admin auth.
- GET /repositories/{id}/scans surfaces admin_verified in ScanHistoryItem.
- Legacy rows (no admin_verified key) are surfaced as False.
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
def admin_key(monkeypatch):
    import server.api as api_module
    monkeypatch.setattr(api_module, "ADMIN_API_KEY", "test-admin-key")
    return "test-admin-key"


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


@pytest.fixture
def deep_scan(test_db, tenant, project):
    """A completed deep audit with an unverified overview (matches fresh pipeline output)."""
    scan = ScanExecution(
        execution_id="exec_unverified",
        tenant_id=tenant.id,
        project_id=project.id,
        repo_url="https://github.com/a/p1",
        repo_name="p1",
        status="completed",
        risk_score=100,
        risk_level="critical",
        findings=[],
        scan_config={"scan_type": "deep"},
        deep_audit_overview={
            "headline": "model-written headline",
            "top_concerns": [],
            "triage_counts": {"confirmed": 0, "investigating": 0, "proposed": 0, "rejected": 0, "uncertain": 0},
            "credible_findings_count": 0,
            "credible_findings": [],
            "raw_findings_count": 13,
            "assessment_level": "critical",
            "review_note": None,
            "admin_verified": False,
        },
    )
    test_db.add(scan)
    test_db.commit()
    test_db.refresh(scan)
    return scan


def _tenant_headers(user):
    token = create_access_token({"user_id": user.id, "tenant_id": user.tenant_id})
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# Compute-overview default
# =============================================================================


def test_compute_overview_defaults_unverified():
    """Fresh deep audit output is unverified — the bleed-stopper invariant."""
    from worker.tasks import _compute_deep_audit_overview

    overview = _compute_deep_audit_overview(
        raw_count=0,
        curated_hypotheses=[],
        config=None,
    )
    assert isinstance(overview, dict)
    assert overview.get("admin_verified") is False, (
        "Newly finalized deep audits must be unverified until an admin signs off"
    )


# =============================================================================
# Admin verify/unverify endpoints
# =============================================================================


class TestVerifyEndpoint:
    def test_requires_admin_auth(self, client, deep_scan):
        resp = client.post(f"/admin/scans/{deep_scan.execution_id}/verify-overview")
        assert resp.status_code == 403

    def test_rejects_wrong_admin_key(self, client, admin_key, deep_scan):
        resp = client.post(
            f"/admin/scans/{deep_scan.execution_id}/verify-overview",
            headers={"X-Admin-Key": "wrong"},
        )
        assert resp.status_code == 403

    def test_404_on_unknown_scan(self, client, admin_key):
        resp = client.post(
            "/admin/scans/does-not-exist/verify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 404

    def test_400_when_no_overview(self, client, admin_key, test_db, tenant, project):
        scan = ScanExecution(
            execution_id="no_overview",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="https://github.com/a/p1",
            repo_name="p1",
            status="completed",
            scan_config={"scan_type": "surface"},
        )
        test_db.add(scan)
        test_db.commit()

        resp = client.post(
            "/admin/scans/no_overview/verify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 400

    def test_verify_flips_flag_and_stamps(self, client, admin_key, deep_scan, test_db):
        resp = client.post(
            f"/admin/scans/{deep_scan.execution_id}/verify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["admin_verified"] is True
        assert body["verified_at"]  # ISO timestamp

        test_db.refresh(deep_scan)
        overview = deep_scan.deep_audit_overview
        assert overview["admin_verified"] is True
        assert overview["verified_by"] == "admin"
        # All other fields preserved
        assert overview["headline"] == "model-written headline"
        assert overview["assessment_level"] == "critical"


class TestUnverifyEndpoint:
    def test_requires_admin_auth(self, client, deep_scan):
        resp = client.post(f"/admin/scans/{deep_scan.execution_id}/unverify-overview")
        assert resp.status_code == 403

    def test_unverify_clears_stamps(self, client, admin_key, deep_scan, test_db):
        # First verify, then unverify
        client.post(
            f"/admin/scans/{deep_scan.execution_id}/verify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        resp = client.post(
            f"/admin/scans/{deep_scan.execution_id}/unverify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200
        assert resp.json()["admin_verified"] is False

        test_db.refresh(deep_scan)
        overview = deep_scan.deep_audit_overview
        assert overview["admin_verified"] is False
        assert "verified_at" not in overview
        assert "verified_by" not in overview

    def test_unverify_idempotent(self, client, admin_key, deep_scan):
        """Calling unverify on an already-unverified scan succeeds."""
        resp = client.post(
            f"/admin/scans/{deep_scan.execution_id}/unverify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200
        assert resp.json()["admin_verified"] is False


# =============================================================================
# Read path: ScanHistoryItem surfaces admin_verified
# =============================================================================


class TestScanHistorySurfacesFlag:
    def test_history_item_reports_unverified_by_default(self, client, user, deep_scan):
        resp = client.get(
            f"/repositories/{deep_scan.project_id}/scans",
            headers=_tenant_headers(user),
        )
        assert resp.status_code == 200
        scans = resp.json()["scans"]
        assert len(scans) == 1
        assert scans[0]["admin_verified"] is False
        # The model-written assessment_level IS still sent over the wire — the frontend
        # is responsible for gating render. Backend surfaces the data + the flag.
        assert scans[0]["assessment_level"] == "critical"

    def test_history_item_reports_verified_after_flip(
        self, client, admin_key, user, deep_scan
    ):
        client.post(
            f"/admin/scans/{deep_scan.execution_id}/verify-overview",
            headers={"X-Admin-Key": admin_key},
        )
        resp = client.get(
            f"/repositories/{deep_scan.project_id}/scans",
            headers=_tenant_headers(user),
        )
        assert resp.status_code == 200
        assert resp.json()["scans"][0]["admin_verified"] is True

    def test_legacy_row_without_flag_is_unverified(
        self, client, user, test_db, tenant, project
    ):
        """Overview written before firepan-oi4 has no admin_verified key — surface as False."""
        scan = ScanExecution(
            execution_id="legacy_overview",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="https://github.com/a/p1",
            repo_name="p1",
            status="completed",
            scan_config={"scan_type": "deep"},
            deep_audit_overview={
                "headline": "legacy",
                "assessment_level": "moderate",
                "credible_findings_count": 2,
                "raw_findings_count": 2,
                "triage_counts": {"confirmed": 0, "investigating": 0, "proposed": 0, "rejected": 0, "uncertain": 0},
                "top_concerns": [],
                "credible_findings": [],
                "review_note": None,
                # No admin_verified key — pre-oi4 row
            },
        )
        test_db.add(scan)
        test_db.commit()

        resp = client.get(
            f"/repositories/{project.id}/scans",
            headers=_tenant_headers(user),
        )
        assert resp.status_code == 200
        legacy = next(s for s in resp.json()["scans"] if s["execution_id"] == "legacy_overview")
        assert legacy["admin_verified"] is False, (
            "Legacy rows without admin_verified key MUST be treated as unverified"
        )
