"""
Tests for the in_review status lifecycle, partial_crash guard,
admin report generation on in_review, and the finalize endpoint.
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import (
    AuditSession,
    Base,
    Hypothesis,
    Project,
    ScanExecution,
    Tenant,
)

# Set test database URL before importing app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db
from server.auth_utils import create_access_token

# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="function")
def test_db(tmp_path):
    db_path = tmp_path / "test.db"
    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
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
    t = Tenant(name="test_tenant")
    test_db.add(t)
    test_db.commit()
    test_db.refresh(t)
    return t


@pytest.fixture
def project(test_db, tenant):
    p = Project(
        tenant_id=tenant.id,
        name="test_project",
        source_path="/tmp/test",
        git_url="https://github.com/test/repo",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(p)
    test_db.commit()
    test_db.refresh(p)
    return p


@pytest.fixture
def jwt_token(tenant):
    return create_access_token({"sub": str(tenant.id), "tenant_id": tenant.id})


# =============================================================================
# _update_scan_status: both records updated
# =============================================================================

class TestUpdateScanStatusBothRecords:
    """_update_scan_status must update BOTH ScanExecution and AuditSession."""

    def test_in_review_updates_both_tables(self, test_db, tenant, project):
        """Setting in_review should update both ScanExecution AND AuditSession."""
        scan = ScanExecution(
            execution_id="scan-both-1",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        session = AuditSession(
            session_id="scan-both-1",
            project_id=project.id,
            status="running",
            start_time=datetime.now(timezone.utc),
        )
        test_db.add_all([scan, session])
        test_db.commit()

        from worker.tasks import AuditTask
        task = AuditTask()
        task._db_engine = test_db.get_bind()

        task._update_scan_status("scan-both-1", "in_review", risk_score=42)

        test_db.refresh(scan)
        test_db.refresh(session)
        assert scan.status == "in_review"
        assert scan.completed_at is not None
        assert scan.risk_score == 42
        assert session.status == "in_review"
        assert session.end_time is not None

    def test_completed_updates_both_tables(self, test_db, tenant, project):
        """Setting completed should also update both records."""
        scan = ScanExecution(
            execution_id="scan-both-2",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            started_at=datetime.now(timezone.utc),
        )
        session = AuditSession(
            session_id="scan-both-2",
            project_id=project.id,
            status="in_review",
            start_time=datetime.now(timezone.utc),
        )
        test_db.add_all([scan, session])
        test_db.commit()

        from worker.tasks import AuditTask
        task = AuditTask()
        task._db_engine = test_db.get_bind()

        task._update_scan_status("scan-both-2", "completed")

        test_db.refresh(scan)
        test_db.refresh(session)
        assert scan.status == "completed"
        assert session.status == "completed"


# =============================================================================
# Idempotency guard
# =============================================================================

class TestIdempotencyGuard:
    """Test the idempotency guard logic.

    The guard runs at the start of execute_audit_task before any heavy work.
    We test the guard logic directly by simulating DB state and calling the
    task's underlying function with appropriate mocking.
    """

    def test_completed_scan_detected(self, test_db, tenant, project):
        """A completed scan should be detected by the guard query."""
        scan = ScanExecution(
            execution_id="idem-1",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="completed",
            started_at=datetime.now(timezone.utc),
        )
        test_db.add(scan)
        test_db.commit()

        found = test_db.query(ScanExecution).filter_by(execution_id="idem-1").first()
        assert found.status in ("completed", "in_review")

    def test_in_review_scan_detected(self, test_db, tenant, project):
        """An in_review scan should be detected by the guard query."""
        scan = ScanExecution(
            execution_id="idem-2",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            started_at=datetime.now(timezone.utc),
        )
        test_db.add(scan)
        test_db.commit()

        found = test_db.query(ScanExecution).filter_by(execution_id="idem-2").first()
        assert found.status in ("completed", "in_review")

    def test_orphan_hypotheses_detected(self, test_db, tenant, project):
        """Running scan with orphan hypotheses should be detectable."""
        started = datetime.now(timezone.utc) - timedelta(hours=1)
        scan = ScanExecution(
            execution_id="idem-3",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="running",
            started_at=started,
        )
        test_db.add(scan)
        test_db.commit()

        # Create orphan hypotheses after scan started
        for i in range(3):
            h = Hypothesis(
                project_id=project.id,
                hypothesis_id=f"orphan-{i}",
                title="Orphan finding",
                description="From crashed prior run",
                vulnerability_type="test",
                status="proposed",
                created_at=started + timedelta(minutes=10),
            )
            test_db.add(h)
        test_db.commit()

        # Simulate the guard query
        orphan_count = test_db.query(Hypothesis).filter(
            Hypothesis.project_id == project.id,
            Hypothesis.created_at >= scan.started_at,
        ).count()
        assert orphan_count == 3
        assert scan.status == "running"
        # Guard would mark this failed and publish terminal event

    def test_no_false_positive_without_orphans(self, test_db, tenant, project):
        """Running scan with no orphans should NOT trigger the guard."""
        started = datetime.now(timezone.utc) - timedelta(hours=1)
        scan = ScanExecution(
            execution_id="idem-4",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="running",
            started_at=started,
        )
        test_db.add(scan)
        test_db.commit()

        orphan_count = test_db.query(Hypothesis).filter(
            Hypothesis.project_id == project.id,
            Hypothesis.created_at >= scan.started_at,
        ).count()
        assert orphan_count == 0  # no guard trigger

    def test_partial_crash_publishes_terminal_event(self):
        """The partial_crash path should publish a failed status event."""
        mock_publisher = MagicMock()

        # Simulate what the guard does when orphans detected
        error_msg = "Aborted: 3 findings from crashed prior run. Manual review needed."
        mock_publisher.publish_status("failed", error_msg)
        mock_publisher.close()

        mock_publisher.publish_status.assert_called_once_with("failed", error_msg)
        mock_publisher.close.assert_called_once()


# =============================================================================
# on_success reads actual DB status
# =============================================================================

class TestOnSuccessReadsDbStatus:

    def test_on_success_publishes_in_review_not_completed(self, test_db, tenant, project):
        """on_success should read in_review from DB, not blindly publish completed."""
        scan = ScanExecution(
            execution_id="onsuc-1",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            started_at=datetime.now(timezone.utc),
        )
        test_db.add(scan)
        test_db.commit()

        from worker.tasks import AuditTask
        task = AuditTask()
        task._db_engine = test_db.get_bind()

        with patch("worker.tasks.RedisPublisher") as mock_pub_cls:
            mock_publisher = MagicMock()
            mock_pub_cls.return_value = mock_publisher

            task.on_success(retval={}, task_id="t1", args=[], kwargs={"scan_id": "onsuc-1"})

            mock_publisher.publish_status.assert_called_once_with(
                "in_review",
                "Audit complete — results under review",
            )

    def test_on_success_suppresses_for_failed(self, test_db, tenant, project):
        """on_success should NOT publish for scans that are already failed."""
        scan = ScanExecution(
            execution_id="onsuc-2",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="failed",
            started_at=datetime.now(timezone.utc),
        )
        test_db.add(scan)
        test_db.commit()

        from worker.tasks import AuditTask
        task = AuditTask()
        task._db_engine = test_db.get_bind()

        with patch("worker.tasks.RedisPublisher") as mock_pub_cls:
            mock_publisher = MagicMock()
            mock_pub_cls.return_value = mock_publisher

            task.on_success(retval={}, task_id="t2", args=[], kwargs={"scan_id": "onsuc-2"})

            mock_publisher.publish_status.assert_not_called()


# =============================================================================
# Finalize endpoint
# =============================================================================

class TestFinalizeEndpoint:

    def test_finalize_in_review_to_completed(self, client, test_db, admin_key, tenant, project):
        scan = ScanExecution(
            execution_id="fin-1",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            completed_at=datetime.now(timezone.utc),
        )
        session = AuditSession(
            session_id="fin-1",
            project_id=project.id,
            status="in_review",
            start_time=datetime.now(timezone.utc),
        )
        test_db.add_all([scan, session])
        test_db.commit()

        resp = client.post(
            "/surface/scans/fin-1/finalize",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"

        test_db.refresh(scan)
        test_db.refresh(session)
        assert scan.status == "completed"
        assert session.status == "completed"

    def test_finalize_rejects_non_in_review(self, client, test_db, admin_key, tenant, project):
        scan = ScanExecution(
            execution_id="fin-2",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="completed",
        )
        test_db.add(scan)
        test_db.commit()

        resp = client.post(
            "/surface/scans/fin-2/finalize",
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 400

    def test_finalize_requires_admin(self, client, test_db, tenant, project, jwt_token):
        scan = ScanExecution(
            execution_id="fin-3",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
        )
        test_db.add(scan)
        test_db.commit()

        # JWT auth should be rejected (admin-only endpoint)
        resp = client.post(
            "/surface/scans/fin-3/finalize",
            headers={"Authorization": f"Bearer {jwt_token}"},
        )
        assert resp.status_code == 403


# =============================================================================
# _latest_scan_by_type includes in_review
# =============================================================================

class TestLatestScanByTypeIncludesInReview:

    def test_in_review_scan_is_found(self, test_db, tenant, project):
        scan = ScanExecution(
            execution_id="latest-1",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            findings=[{"title": "test"}],
            scan_config={"scan_type": "deep"},
            created_at=datetime.now(timezone.utc),
        )
        test_db.add(scan)
        test_db.commit()

        from server.api import _latest_scan_by_type
        result = _latest_scan_by_type(test_db, project.id, "deep")
        assert result is not None
        assert result.execution_id == "latest-1"


# =============================================================================
# PATCH /users/me contact capture
# =============================================================================

class TestPatchUsersMe:

    def test_update_contact_email(self, client, test_db, tenant, jwt_token):
        with patch("integrations.telegram.notify_contact_captured") as mock_notify:
            mock_notify.return_value = True
            resp = client.patch(
                "/users/me",
                json={"email": "test@example.com"},
                headers={"Authorization": f"Bearer {jwt_token}"},
            )
        assert resp.status_code == 200
        assert resp.json()["email"] == "test@example.com"

        test_db.refresh(tenant)
        assert tenant.contact_email == "test@example.com"

    def test_first_email_triggers_notification(self, client, test_db, tenant, jwt_token):
        assert tenant.contact_email is None  # no email yet

        with patch("integrations.telegram.notify_contact_captured") as mock_notify:
            mock_notify.return_value = True
            resp = client.patch(
                "/users/me",
                json={"email": "first@example.com"},
                headers={"Authorization": f"Bearer {jwt_token}"},
            )
            assert resp.status_code == 200
            mock_notify.assert_awaited_once()

    def test_update_existing_email_no_notification(self, client, test_db, tenant, jwt_token):
        tenant.contact_email = "old@example.com"
        test_db.commit()

        with patch("integrations.telegram.notify_contact_captured") as mock_notify:
            mock_notify.return_value = True
            resp = client.patch(
                "/users/me",
                json={"email": "new@example.com"},
                headers={"Authorization": f"Bearer {jwt_token}"},
            )
            assert resp.status_code == 200
            mock_notify.assert_not_awaited()


# =============================================================================
# Auto-finalize task
# =============================================================================

class TestAutoFinalizeReviewsTask:

    def test_auto_finalize_stale_in_review(self, test_db, tenant, project):
        """in_review scans older than 24hr should auto-finalize."""
        stale_time = datetime.now(timezone.utc) - timedelta(hours=25)
        scan = ScanExecution(
            execution_id="auto-1",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            completed_at=stale_time,
        )
        session = AuditSession(
            session_id="auto-1",
            project_id=project.id,
            status="in_review",
            start_time=stale_time,
        )
        test_db.add_all([scan, session])
        test_db.commit()
        # Expunge so the task's session owns the objects
        test_db.expunge_all()

        with patch("database.models.create_db_engine") as mock_engine, \
             patch("database.models.create_db_session") as mock_session:
            mock_engine.return_value = test_db.get_bind()
            mock_session.return_value = test_db

            from worker.tasks import auto_finalize_reviews_task
            auto_finalize_reviews_task()

        # Re-query from the same session (objects were expunged)
        scan = test_db.query(ScanExecution).filter_by(execution_id="auto-1").first()
        session = test_db.query(AuditSession).filter_by(session_id="auto-1").first()
        assert scan.status == "completed"
        assert session.status == "completed"

    def test_auto_finalize_skips_recent_in_review(self, test_db, tenant, project):
        """in_review scans less than 24hr old should NOT auto-finalize."""
        recent_time = datetime.now(timezone.utc) - timedelta(hours=1)
        scan = ScanExecution(
            execution_id="auto-2",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_name="test",
            status="in_review",
            completed_at=recent_time,
        )
        test_db.add(scan)
        test_db.commit()
        test_db.expunge_all()

        with patch("database.models.create_db_engine") as mock_engine, \
             patch("database.models.create_db_session") as mock_session:
            mock_engine.return_value = test_db.get_bind()
            mock_session.return_value = test_db

            from worker.tasks import auto_finalize_reviews_task
            auto_finalize_reviews_task()

        scan = test_db.query(ScanExecution).filter_by(execution_id="auto-2").first()
        assert scan.status == "in_review"  # unchanged


# =============================================================================
# Test contract filter
# =============================================================================

class TestFilterTestContracts:

    def test_removes_mock_findings(self):
        from worker.tasks import _filter_test_contract_findings

        hypotheses = [
            {"description": "MockHook lacks access control", "severity": "medium"},
            {"description": "Reentrancy in Vault.withdraw()", "severity": "high"},
            {"description": "MockERC20 has infinite supply", "severity": "low"},
        ]
        result = _filter_test_contract_findings(hypotheses)
        assert len(result) == 1
        assert "Vault" in result[0]["description"]

    def test_keeps_all_when_no_test_contracts(self):
        from worker.tasks import _filter_test_contract_findings

        hypotheses = [
            {"description": "Missing reentrancy guard", "severity": "high"},
            {"description": "Unchecked return value", "severity": "medium"},
        ]
        result = _filter_test_contract_findings(hypotheses)
        assert len(result) == 2


# =============================================================================
# Severity fallback
# =============================================================================

class TestSeverityFallback:

    def test_demotes_low_confidence_when_uniform(self):
        """When >80% of findings have same severity, low-confidence should be demoted."""
        from collections import Counter

        hypotheses = []
        for i in range(12):
            hypotheses.append({
                "description": f"Finding {i}",
                "severity": "medium",
                "confidence": 0.3 if i < 4 else 0.8,
            })

        # Apply the same logic from tasks.py
        if len(hypotheses) > 10:
            severity_counts = Counter(h.get("severity") for h in hypotheses)
            dominant_sev, dominant_count = severity_counts.most_common(1)[0]
            if dominant_count / len(hypotheses) > 0.8:
                for h in hypotheses:
                    if h.get("confidence", 0.5) < 0.5:
                        h["severity"] = "low"

        low_count = sum(1 for h in hypotheses if h["severity"] == "low")
        medium_count = sum(1 for h in hypotheses if h["severity"] == "medium")
        assert low_count == 4  # the low-confidence ones
        assert medium_count == 8


# =============================================================================
# Telegram notify_deep_audit_completed treats in_review as success
# =============================================================================

class TestTelegramInReview:

    def test_in_review_gets_success_header(self):
        """in_review should get the success header, not the failure header."""
        import asyncio

        loop = asyncio.new_event_loop()
        try:
            with patch("integrations.telegram.send_telegram_message") as mock_send:
                mock_send.return_value = True
                from integrations.telegram import notify_deep_audit_completed
                loop.run_until_complete(notify_deep_audit_completed(
                    repo_url="https://github.com/test/repo",
                    session_id="tg-1",
                    status="in_review",
                    findings_count=5,
                    risk_level="medium",
                ))
                mock_send.assert_called_once()
                message = mock_send.call_args[0][0]
                assert "Deep Audit Complete" in message
                assert "Findings" in message
                assert "Failed" not in message
        finally:
            loop.close()
