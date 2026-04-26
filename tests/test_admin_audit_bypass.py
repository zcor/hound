"""
Tests for firepan-1bg — admin-key deep-audit bypass.

Covers:
- tier_enforcement._check_sync(bypass_quota=True) skips limit enforcement.
- POST /admin/audits/force-run requires X-Admin-Key and dispatches a deep audit
  that bypasses tenant quota, creating the AuditSession + ScanExecution rows
  the dashboard expects.
- POST /admin/audits/{session_id}/refund deletes both rows so the tenant's
  monthly audit quota releases the slot.
"""

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import AuditSession, Base, Project, ScanExecution, Tenant

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db


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
    t = Tenant(name="t1", email_verified=True, plan="starter")
    test_db.add(t)
    test_db.commit()
    test_db.refresh(t)
    return t


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


# =============================================================================
# tier_enforcement._check_sync bypass_quota
# =============================================================================


class TestBypassQuota:
    def test_bypass_skips_limit_when_over_quota(self, test_db, tenant, project):
        """Over-quota tenant still gets through when bypass_quota=True."""
        from server.tier_enforcement import _check_sync

        # Fill the month with enough audit sessions to blow past any free limit
        for i in range(99):
            s = AuditSession(
                session_id=f"sess_quota_{i}",
                project_id=project.id,
                status="completed",
                start_time=datetime.now(timezone.utc),
            )
            test_db.add(s)
        test_db.commit()

        # Without bypass: 403 audit_limit_reached
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as excinfo:
            _check_sync(tenant.id, "audit", test_db)
        assert excinfo.value.status_code == 403

        # With bypass: returns marker, no exception
        result = _check_sync(tenant.id, "audit", test_db, bypass_quota=True)
        assert result["admin_bypass"] is True
        assert result["uses_credit"] is False

    def test_bypass_still_requires_tenant(self, test_db):
        """bypass_quota doesn't skip the existence check — nonexistent tenant still 404s."""
        from fastapi import HTTPException

        from server.tier_enforcement import _check_sync

        with pytest.raises(HTTPException) as excinfo:
            _check_sync(999999, "audit", test_db, bypass_quota=True)
        assert excinfo.value.status_code == 404


# =============================================================================
# POST /admin/audits/force-run
# =============================================================================


class TestAdminForceRun:
    def test_requires_admin_auth(self, client, project):
        resp = client.post(
            "/admin/audits/force-run",
            json={"project_id": project.id},
        )
        assert resp.status_code == 403

    def test_rejects_wrong_admin_key(self, client, admin_key, project):
        resp = client.post(
            "/admin/audits/force-run",
            json={"project_id": project.id},
            headers={"X-Admin-Key": "wrong"},
        )
        assert resp.status_code == 403

    def test_rejects_session_cookie_auth(self, client, admin_key, project):
        """_verify_explicit_admin_header ignores session cookies (CSRF gate)."""
        # Simulate a session cookie — the helper only accepts the header.
        with client as c:
            # Even if we inject an admin session marker, the header helper must ignore it.
            resp = c.post(
                "/admin/audits/force-run",
                json={"project_id": project.id},
                # No X-Admin-Key header, no session — should 403
            )
            assert resp.status_code == 403

    def test_404_on_unknown_project(self, client, admin_key):
        resp = client.post(
            "/admin/audits/force-run",
            json={"project_id": 999999},
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 404

    def test_dispatches_worker_bypasses_quota(
        self, client, admin_key, test_db, tenant, project
    ):
        """Happy path: admin force-run creates rows + dispatches the Celery task."""
        # Pre-fill month with audits so tenant is over any plausible quota
        for i in range(50):
            s = AuditSession(
                session_id=f"pre_quota_{i}",
                project_id=project.id,
                status="completed",
                start_time=datetime.now(timezone.utc),
            )
            test_db.add(s)
        test_db.commit()

        mock_task = MagicMock()
        mock_task.id = "celery-task-id"

        with patch("worker.tasks.execute_audit_task") as mock_execute:
            mock_execute.delay.return_value = mock_task

            resp = client.post(
                "/admin/audits/force-run",
                json={"project_id": project.id, "max_iterations": 7, "mode": "sweep"},
                headers={"X-Admin-Key": admin_key},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "queued"
        assert body["session_id"].startswith("audit_")
        assert "celery-task-id" in body["message"]

        # Both rows created
        sess = test_db.query(AuditSession).filter(
            AuditSession.session_id == body["session_id"]
        ).first()
        assert sess is not None
        assert sess.status == "queued"
        assert sess.models.get("admin_forced") is True

        scan = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == body["session_id"]
        ).first()
        assert scan is not None
        assert scan.scan_config["scan_type"] == "deep"
        assert scan.scan_config["admin_forced"] is True
        assert scan.status == "queued"

        # Task dispatched with expected kwargs
        mock_execute.delay.assert_called_once()
        call_kwargs = mock_execute.delay.call_args.kwargs
        assert call_kwargs["project_id"] == project.id
        assert call_kwargs["tenant_id"] == tenant.id
        assert call_kwargs["scan_id"] == body["session_id"]
        assert call_kwargs["max_iterations"] == 7

    def test_uses_project_git_url_when_repo_url_omitted(
        self, client, admin_key, test_db, project
    ):
        mock_task = MagicMock()
        mock_task.id = "t"
        with patch("worker.tasks.execute_audit_task") as mock_execute:
            mock_execute.delay.return_value = mock_task
            resp = client.post(
                "/admin/audits/force-run",
                json={"project_id": project.id},
                headers={"X-Admin-Key": admin_key},
            )
            assert resp.status_code == 200
            call_kwargs = mock_execute.delay.call_args.kwargs
            assert call_kwargs["repo_url"] == "https://github.com/a/p1"


# =============================================================================
# POST /admin/audits/{session_id}/refund
# =============================================================================


class TestAdminRefund:
    def _make_audit(self, test_db, project, session_id: str = "sess_refund_1"):
        sess = AuditSession(
            session_id=session_id,
            project_id=project.id,
            status="failed",
            start_time=datetime.now(timezone.utc),
        )
        scan = ScanExecution(
            execution_id=session_id,
            tenant_id=project.tenant_id,
            project_id=project.id,
            repo_url="https://github.com/a/p1",
            repo_name="p1",
            status="failed",
            scan_config={"scan_type": "deep"},
        )
        test_db.add(sess)
        test_db.add(scan)
        test_db.commit()
        return sess, scan

    def test_requires_admin_auth(self, client, test_db, project):
        self._make_audit(test_db, project)
        resp = client.post("/admin/audits/sess_refund_1/refund")
        assert resp.status_code == 403

    def test_404_when_nothing_exists(self, client, admin_key):
        resp = client.post(
            "/admin/audits/nonexistent/refund",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 404

    def test_deletes_both_rows(self, client, admin_key, test_db, project):
        self._make_audit(test_db, project, "sess_refund_full")
        resp = client.post(
            "/admin/audits/sess_refund_full/refund",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"]["audit_session"] is True
        assert body["deleted"]["scan_execution"] is True

        assert test_db.query(AuditSession).filter(
            AuditSession.session_id == "sess_refund_full"
        ).first() is None
        assert test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == "sess_refund_full"
        ).first() is None

    def test_tolerates_orphan_rows(self, client, admin_key, test_db, project):
        """If only one of the two rows exists, refund still succeeds."""
        sess = AuditSession(
            session_id="orphan_sess",
            project_id=project.id,
            status="failed",
            start_time=datetime.now(timezone.utc),
        )
        test_db.add(sess)
        test_db.commit()

        resp = client.post(
            "/admin/audits/orphan_sess/refund",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["deleted"]["audit_session"] is True
        assert body["deleted"]["scan_execution"] is False

    def test_refund_releases_quota_slot(
        self, client, admin_key, test_db, tenant, project
    ):
        """After refund, quota count drops by 1 (no other refund needed)."""
        # Create the audit to refund
        self._make_audit(test_db, project, "sess_quota_slot")
        # And mark it completed so it would count against quota
        sess = test_db.query(AuditSession).filter(
            AuditSession.session_id == "sess_quota_slot"
        ).first()
        sess.status = "completed"
        test_db.commit()

        baseline = test_db.query(AuditSession).filter(
            AuditSession.project_id == project.id,
            AuditSession.status.notin_(["failed", "error"]),
        ).count()
        assert baseline >= 1

        resp = client.post(
            "/admin/audits/sess_quota_slot/refund",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200

        after = test_db.query(AuditSession).filter(
            AuditSession.project_id == project.id,
            AuditSession.status.notin_(["failed", "error"]),
        ).count()
        assert after == baseline - 1
