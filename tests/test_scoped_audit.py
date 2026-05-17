"""
Tests for firepan-nxf — file-scoped deep audits (target_files).

Covers:
- _validate_target_files: syntax + cap + dedup + None coalescing.
- _check_target_files_exist_on_disk: resolved vs missing split, symlink escape guard.
- /admin/audits/force-run accepts target_files, persists to scan_config AND
  AuditSession.session_metadata, passes kwarg to worker.
- /admin/audits/force-run 422 when all target_files miss on cached clone.
- /audits/start honors target_files for paid tenants, silently drops for free.
- /audits/start 422 when paid-tenant target_files miss on cached clone.
- /repositories/{id}/scans surfaces target_files; legacy rows show None.
- execute_audit_task zero-hit handler: scan→failed, error_message set,
  AuditSession deleted.
- execute_audit_task partial-hit: warning logged, scan proceeds.
"""

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import AuditSession, Base, Project, ScanExecution, Tenant, User

os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db
from server.auth_utils import create_access_token

# =============================================================================
# Fixtures — mirror test_admin_audit_bypass.py structure for consistency.
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
def admin_key(monkeypatch):
    import server.api as api_module
    monkeypatch.setattr(api_module, "ADMIN_API_KEY", "test-admin-key")
    return "test-admin-key"


@pytest.fixture
def paid_tenant(test_db):
    """Tenant with a live Stripe sub — honors target_files."""
    t = Tenant(
        name="paid",
        email_verified=True,
        plan="starter",
        stripe_subscription_id="sub_test_123",
    )
    test_db.add(t)
    test_db.commit()
    test_db.refresh(t)
    return t


@pytest.fixture
def free_tenant(test_db):
    """Tenant on free — target_files silently dropped."""
    t = Tenant(name="free", email_verified=True, plan="free")
    test_db.add(t)
    test_db.commit()
    test_db.refresh(t)
    return t


@pytest.fixture
def paid_user(test_db, paid_tenant):
    u = User(
        tenant_id=paid_tenant.id,
        email="paid@example.com",
        github_id=1001,
        github_login="paiduser",
        signup_provider="github",
    )
    test_db.add(u)
    test_db.commit()
    test_db.refresh(u)
    return u


@pytest.fixture
def free_user(test_db, free_tenant):
    u = User(
        tenant_id=free_tenant.id,
        email="free@example.com",
        github_id=1002,
        github_login="freeuser",
        signup_provider="github",
    )
    test_db.add(u)
    test_db.commit()
    test_db.refresh(u)
    return u


def _tenant_headers(user):
    token = create_access_token({"user_id": user.id, "tenant_id": user.tenant_id})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def cloned_project(test_db, paid_tenant, tmp_path):
    """Project with an on-disk clone containing contracts/dao/FeeDistributor.vy."""
    clone_root = tmp_path / "yb_clone"
    (clone_root / "contracts" / "dao").mkdir(parents=True)
    (clone_root / "contracts" / "dao" / "FeeDistributor.vy").write_text(
        "# Vyper 0.4.3\n# FeeDistributor stub\n" + ("pass\n" * 20)
    )
    (clone_root / "contracts" / "dao" / "UnrelatedModule.vy").write_text("# stub\n")
    p = Project(
        tenant_id=paid_tenant.id,
        name="yb-core",
        source_path=str(clone_root),
        git_url="https://github.com/yield-basis/yb-core",
        default_branch="main",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(p)
    test_db.commit()
    test_db.refresh(p)
    return p


@pytest.fixture
def uncloned_project(test_db, paid_tenant):
    """Project without an on-disk clone — forces worker-time validation."""
    p = Project(
        tenant_id=paid_tenant.id,
        name="uncloned",
        source_path="/nonexistent/path",
        git_url="https://github.com/a/b",
        default_branch="main",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(p)
    test_db.commit()
    test_db.refresh(p)
    return p


@pytest.fixture
def free_project(test_db, free_tenant):
    p = Project(
        tenant_id=free_tenant.id,
        name="free-proj",
        source_path="/nonexistent/free",
        git_url="https://github.com/f/p",
        default_branch="main",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(p)
    test_db.commit()
    test_db.refresh(p)
    return p


# =============================================================================
# _validate_target_files — pure syntactic helper
# =============================================================================


class TestValidateTargetFiles:
    def test_none_returns_none(self):
        from server.api import _validate_target_files
        assert _validate_target_files(None) is None

    def test_empty_list_returns_none(self):
        from server.api import _validate_target_files
        assert _validate_target_files([]) is None

    def test_blank_entries_coerce_to_none(self):
        from server.api import _validate_target_files
        assert _validate_target_files(["", "  ", ""]) is None

    def test_trim_and_dedup(self):
        from server.api import _validate_target_files
        result = _validate_target_files([
            "contracts/dao/FeeDistributor.vy",
            "  contracts/dao/FeeDistributor.vy  ",
            "contracts/Other.vy",
        ])
        assert result == ["contracts/dao/FeeDistributor.vy", "contracts/Other.vy"]

    def test_rejects_over_50_at_pydantic_layer(self, client, admin_key):
        """max_length=50 is enforced by pydantic before our helper runs."""
        resp = client.post(
            "/admin/audits/force-run",
            json={
                "project_id": 1,
                "target_files": [f"f{i}.vy" for i in range(51)],
            },
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 422  # pydantic max_length violation

    def test_rejects_leading_slash(self):
        from fastapi import HTTPException

        from server.api import _validate_target_files
        with pytest.raises(HTTPException) as excinfo:
            _validate_target_files(["/etc/passwd"])
        assert excinfo.value.status_code == 422
        assert "repo-relative" in str(excinfo.value.detail).lower()

    def test_rejects_traversal_anywhere(self):
        from fastapi import HTTPException

        from server.api import _validate_target_files
        for bad in ["../etc/passwd", "contracts/../../etc/passwd", ".."]:
            with pytest.raises(HTTPException) as excinfo:
                _validate_target_files([bad])
            assert excinfo.value.status_code == 422
            assert "traversal" in str(excinfo.value.detail).lower()

    def test_rejects_shell_metacharacters(self):
        from fastapi import HTTPException

        from server.api import _validate_target_files
        for bad in ["foo;rm -rf /", "foo|bar", "foo`ls`", "foo$VAR", "foo\x00bar"]:
            with pytest.raises(HTTPException) as excinfo:
                _validate_target_files([bad])
            assert excinfo.value.status_code == 422

    def test_rejects_glob_characters(self):
        from fastapi import HTTPException

        from server.api import _validate_target_files
        for bad in ["contracts/*.vy", "a?.vy", "[abc].vy"]:
            with pytest.raises(HTTPException) as excinfo:
                _validate_target_files([bad])
            assert excinfo.value.status_code == 422

    def test_rejects_non_string_entries(self):
        from fastapi import HTTPException

        from server.api import _validate_target_files
        with pytest.raises(HTTPException):
            _validate_target_files([123])  # type: ignore[list-item]


# =============================================================================
# _check_target_files_exist_on_disk — best-effort existence check
# =============================================================================


class TestCheckTargetFilesExistOnDisk:
    def test_no_source_path_returns_empty(self):
        from server.api import _check_target_files_exist_on_disk
        assert _check_target_files_exist_on_disk(None, ["a.vy"]) == ([], [])
        assert _check_target_files_exist_on_disk("", ["a.vy"]) == ([], [])

    def test_missing_directory_returns_empty(self):
        from server.api import _check_target_files_exist_on_disk
        assert _check_target_files_exist_on_disk("/nonexistent/xyz", ["a.vy"]) == ([], [])

    def test_resolved_and_missing_split(self, tmp_path):
        from server.api import _check_target_files_exist_on_disk
        (tmp_path / "a.vy").write_text("x")
        resolved, missing = _check_target_files_exist_on_disk(
            str(tmp_path), ["a.vy", "missing.vy"]
        )
        assert resolved == ["a.vy"]
        assert missing == ["missing.vy"]

    def test_rejects_symlink_escape(self, tmp_path):
        """Symlinked file pointing outside root → treated as missing."""
        from server.api import _check_target_files_exist_on_disk
        outside = tmp_path / "outside"
        outside.write_text("secret")
        root = tmp_path / "root"
        root.mkdir()
        link = root / "escape.vy"
        link.symlink_to(outside)
        # Symlink resolves outside root → caught as missing (resolve + relative_to fails)
        resolved, missing = _check_target_files_exist_on_disk(str(root), ["escape.vy"])
        assert resolved == []
        assert missing == ["escape.vy"]

    def test_directory_treated_as_missing(self, tmp_path):
        """Directory entries are not files; treated as missing."""
        from server.api import _check_target_files_exist_on_disk
        (tmp_path / "subdir").mkdir()
        resolved, missing = _check_target_files_exist_on_disk(str(tmp_path), ["subdir"])
        assert resolved == []
        assert missing == ["subdir"]


# =============================================================================
# POST /admin/audits/force-run with target_files
# =============================================================================


class TestAdminForceRunScoped:
    def test_happy_path_persists_both_sides_and_dispatches(
        self, client, admin_key, test_db, cloned_project
    ):
        mock_task = MagicMock()
        mock_task.id = "task-scoped-1"
        with patch("worker.tasks.execute_audit_task") as mock_execute:
            mock_execute.delay.return_value = mock_task
            resp = client.post(
                "/admin/audits/force-run",
                json={
                    "project_id": cloned_project.id,
                    "target_files": ["contracts/dao/FeeDistributor.vy"],
                    "mode": "sweep",
                },
                headers={"X-Admin-Key": admin_key},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()

        sess = test_db.query(AuditSession).filter(
            AuditSession.session_id == body["session_id"]
        ).first()
        scan = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == body["session_id"]
        ).first()

        assert scan.scan_config["target_files"] == ["contracts/dao/FeeDistributor.vy"]
        assert sess.session_metadata == {
            "target_files": ["contracts/dao/FeeDistributor.vy"]
        }
        assert scan.scan_config["admin_forced"] is True

        call_kwargs = mock_execute.delay.call_args.kwargs
        assert call_kwargs["target_files"] == ["contracts/dao/FeeDistributor.vy"]

    def test_422_when_none_exist_on_cached_clone(
        self, client, admin_key, cloned_project
    ):
        resp = client.post(
            "/admin/audits/force-run",
            json={
                "project_id": cloned_project.id,
                "target_files": ["contracts/dao/TypoFeeDistributor.vy"],
            },
            headers={"X-Admin-Key": admin_key},
        )
        assert resp.status_code == 422
        detail = resp.json()["detail"]
        assert detail["error"] == "scoped_audit_no_files_match"
        assert detail["missing"] == ["contracts/dao/TypoFeeDistributor.vy"]

    def test_partial_hit_passes_api_check_defers_warning_to_worker(
        self, client, admin_key, cloned_project
    ):
        """≥1 resolved → accepted at API; worker will log the miss."""
        with patch("worker.tasks.execute_audit_task") as mock_execute:
            mock_execute.delay.return_value = MagicMock(id="t")
            resp = client.post(
                "/admin/audits/force-run",
                json={
                    "project_id": cloned_project.id,
                    "target_files": [
                        "contracts/dao/FeeDistributor.vy",
                        "contracts/dao/Ghost.vy",
                    ],
                },
                headers={"X-Admin-Key": admin_key},
            )
        assert resp.status_code == 200
        # Both sent through — worker decides what to warn about.
        kwargs = mock_execute.delay.call_args.kwargs
        assert kwargs["target_files"] == [
            "contracts/dao/FeeDistributor.vy",
            "contracts/dao/Ghost.vy",
        ]

    def test_uncloned_project_defers_to_worker(
        self, client, admin_key, uncloned_project
    ):
        """No cached clone → API accepts; worker-time gate is authoritative."""
        with patch("worker.tasks.execute_audit_task") as mock_execute:
            mock_execute.delay.return_value = MagicMock(id="t")
            resp = client.post(
                "/admin/audits/force-run",
                json={
                    "project_id": uncloned_project.id,
                    "target_files": ["contracts/anything.vy"],
                },
                headers={"X-Admin-Key": admin_key},
            )
        assert resp.status_code == 200

    def test_no_scope_preserves_legacy_behavior(
        self, client, admin_key, test_db, cloned_project
    ):
        """Omit target_files → scan_config has no target_files key, worker kwarg None."""
        with patch("worker.tasks.execute_audit_task") as mock_execute:
            mock_execute.delay.return_value = MagicMock(id="t")
            resp = client.post(
                "/admin/audits/force-run",
                json={"project_id": cloned_project.id},
                headers={"X-Admin-Key": admin_key},
            )
        assert resp.status_code == 200
        sid = resp.json()["session_id"]
        scan = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == sid
        ).first()
        assert "target_files" not in scan.scan_config
        assert mock_execute.delay.call_args.kwargs["target_files"] is None


# =============================================================================
# POST /audits/start with target_files (tenant path)
# =============================================================================


class TestTenantStartAudit:
    def test_paid_tenant_honors_target_files(
        self, client, test_db, paid_user, cloned_project
    ):
        with patch("worker.tasks.execute_audit_task") as mock_execute, \
             patch("server.api.notify_deep_audit_started") as mock_notify:
            mock_execute.delay.return_value = MagicMock(id="t1")
            mock_notify.return_value = True
            resp = client.post(
                "/audits/start",
                json={
                    "repo_url": "https://github.com/yield-basis/yb-core",
                    "project_id": cloned_project.id,
                    "target_files": ["contracts/dao/FeeDistributor.vy"],
                },
                headers=_tenant_headers(paid_user),
            )
        assert resp.status_code == 200, resp.text
        sid = resp.json()["session_id"]
        scan = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == sid
        ).first()
        assert scan.scan_config["target_files"] == ["contracts/dao/FeeDistributor.vy"]
        sess = test_db.query(AuditSession).filter(
            AuditSession.session_id == sid
        ).first()
        assert sess.session_metadata == {
            "target_files": ["contracts/dao/FeeDistributor.vy"]
        }
        assert (
            mock_execute.delay.call_args.kwargs["target_files"]
            == ["contracts/dao/FeeDistributor.vy"]
        )

    def test_free_tenant_silently_drops_target_files(
        self, client, test_db, free_user, free_project, caplog
    ):
        """Free tier: 200 OK, target_files absent from scan_config, logged."""
        import logging
        caplog.set_level(logging.INFO, logger="server.api")
        with patch("worker.tasks.execute_audit_task") as mock_execute, \
             patch("server.api.notify_deep_audit_started") as mock_notify:
            mock_execute.delay.return_value = MagicMock(id="t2")
            mock_notify.return_value = True
            resp = client.post(
                "/audits/start",
                json={
                    "repo_url": "https://github.com/f/p",
                    "project_id": free_project.id,
                    "target_files": ["contracts/some.vy"],
                },
                headers=_tenant_headers(free_user),
            )
        assert resp.status_code == 200, resp.text
        sid = resp.json()["session_id"]
        scan = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == sid
        ).first()
        assert "target_files" not in scan.scan_config
        assert mock_execute.delay.call_args.kwargs["target_files"] is None
        # Log evidence that we noticed
        assert any("target_files ignored" in r.message for r in caplog.records)

    def test_paid_tenant_422_on_all_missing_with_cached_clone(
        self, client, paid_user, cloned_project
    ):
        resp = client.post(
            "/audits/start",
            json={
                "repo_url": "https://github.com/yield-basis/yb-core",
                "project_id": cloned_project.id,
                "target_files": ["contracts/dao/DoesNotExist.vy"],
            },
            headers=_tenant_headers(paid_user),
        )
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "scoped_audit_no_files_match"

    def test_paid_tenant_no_scope_legacy_behavior(
        self, client, test_db, paid_user, cloned_project
    ):
        """Omitting target_files is indistinguishable from the pre-nxf behavior."""
        with patch("worker.tasks.execute_audit_task") as mock_execute, \
             patch("server.api.notify_deep_audit_started") as mock_notify:
            mock_execute.delay.return_value = MagicMock(id="t3")
            mock_notify.return_value = True
            resp = client.post(
                "/audits/start",
                json={
                    "repo_url": "https://github.com/yield-basis/yb-core",
                    "project_id": cloned_project.id,
                },
                headers=_tenant_headers(paid_user),
            )
        assert resp.status_code == 200
        sid = resp.json()["session_id"]
        scan = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == sid
        ).first()
        assert "target_files" not in scan.scan_config


# =============================================================================
# Read path: /repositories/{id}/scans surfaces target_files
# =============================================================================


class TestScanHistoryReadPath:
    def _make_deep_scan(self, test_db, project, tenant, scan_config: dict):
        scan = ScanExecution(
            execution_id=f"exec_{scan_config.get('scan_type', 'd')}_{len(test_db.query(ScanExecution).all())}",
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="https://github.com/yield-basis/yb-core",
            repo_name=project.name,
            status="completed",
            risk_score=10,
            risk_level="low",
            findings=[],
            scan_config=scan_config,
        )
        test_db.add(scan)
        test_db.commit()
        test_db.refresh(scan)
        return scan

    def test_scoped_run_surfaces_target_files(
        self, client, test_db, paid_user, cloned_project, paid_tenant
    ):
        self._make_deep_scan(
            test_db, cloned_project, paid_tenant,
            {"scan_type": "deep", "target_files": ["contracts/dao/FeeDistributor.vy"]},
        )
        resp = client.get(
            f"/repositories/{cloned_project.id}/scans",
            headers=_tenant_headers(paid_user),
        )
        assert resp.status_code == 200
        scans = resp.json()["scans"]
        assert len(scans) == 1
        assert scans[0]["target_files"] == ["contracts/dao/FeeDistributor.vy"]

    def test_whole_repo_run_shows_null_scope(
        self, client, test_db, paid_user, cloned_project, paid_tenant
    ):
        self._make_deep_scan(
            test_db, cloned_project, paid_tenant, {"scan_type": "deep"}
        )
        resp = client.get(
            f"/repositories/{cloned_project.id}/scans",
            headers=_tenant_headers(paid_user),
        )
        assert resp.status_code == 200
        assert resp.json()["scans"][0]["target_files"] is None

    def test_legacy_row_without_scan_config_target_files_shows_null(
        self, client, test_db, paid_user, cloned_project, paid_tenant
    ):
        """Row from before nxf — no target_files key — should report None."""
        self._make_deep_scan(
            test_db, cloned_project, paid_tenant,
            {"scan_type": "deep", "branch": "main", "mode": "sweep"},
        )
        resp = client.get(
            f"/repositories/{cloned_project.id}/scans",
            headers=_tenant_headers(paid_user),
        )
        assert resp.status_code == 200
        assert resp.json()["scans"][0]["target_files"] is None

    def test_malformed_target_files_in_jsonb_falls_back_to_null(
        self, client, test_db, paid_user, cloned_project, paid_tenant
    ):
        """If somehow target_files ends up as a dict/int, don't crash — show None."""
        self._make_deep_scan(
            test_db, cloned_project, paid_tenant,
            {"scan_type": "deep", "target_files": "not-a-list"},
        )
        resp = client.get(
            f"/repositories/{cloned_project.id}/scans",
            headers=_tenant_headers(paid_user),
        )
        assert resp.status_code == 200
        assert resp.json()["scans"][0]["target_files"] is None


# =============================================================================
# Worker: zero-hit + partial-hit behavior
# =============================================================================


class TestWorkerZeroHit:
    """These tests hit the worker function directly with a real manifest built
    against a tmp_path repo. The repo has one file; the target_files list
    determines whether we hit zero, one, or partial."""

    def _scaffold_scan(self, test_db, tenant, project, scan_id: str, target_files):
        """Create the AuditSession + ScanExecution rows /audits/start would create."""
        sess = AuditSession(
            session_id=scan_id,
            project_id=project.id,
            status="queued",
            start_time=datetime.now(timezone.utc),
        )
        scan = ScanExecution(
            execution_id=scan_id,
            tenant_id=tenant.id,
            project_id=project.id,
            repo_url="",
            repo_name=project.name,
            status="queued",
            scan_config={
                "scan_type": "deep",
                "target_files": target_files,
            },
        )
        test_db.add(sess)
        test_db.add(scan)
        test_db.commit()
        return sess, scan

    def test_zero_hit_fails_scan_and_releases_quota(
        self, test_db, paid_tenant, tmp_path
    ):
        """All target_files miss → scan marked failed, AuditSession deleted."""
        # Build a tiny repo with one irrelevant file
        repo = tmp_path / "repo"
        (repo / "contracts").mkdir(parents=True)
        (repo / "contracts" / "Other.vy").write_text("# something\n" * 20)

        project = Project(
            tenant_id=paid_tenant.id,
            name="p",
            source_path=str(repo),
            git_url=str(repo),
            default_branch="main",
            status="active",
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
        )
        test_db.add(project)
        test_db.commit()
        test_db.refresh(project)

        scan_id = "audit_zerohit_1"
        self._scaffold_scan(
            test_db, paid_tenant, project, scan_id,
            ["contracts/DoesNotExist.vy"],
        )

        # Patch the task's DB session helper to route through our test_db.
        from worker.tasks import execute_audit_task
        task_obj = execute_audit_task

        def fake_get_db_session(self=None):
            return test_db

        with patch.object(task_obj, "get_db_session", fake_get_db_session), \
             patch("worker.tasks.RedisPublisher") as MockPublisher, \
             patch("worker.tasks.set_token_context"):
            MockPublisher.return_value = MagicMock()
            result = task_obj.run(
                repo_url=str(repo),  # local path path — no clone
                scan_id=scan_id,
                tenant_id=paid_tenant.id,
                project_id=project.id,
                target_files=["contracts/DoesNotExist.vy"],
            )

        assert result["status"] == "failed"
        assert result["error"] == "scoped_zero_hit"

        # AuditSession gone (quota released)
        sess_after = test_db.query(AuditSession).filter(
            AuditSession.session_id == scan_id
        ).first()
        assert sess_after is None

        # Scan marked failed with clear error_message
        scan_after = test_db.query(ScanExecution).filter(
            ScanExecution.execution_id == scan_id
        ).first()
        assert scan_after.status == "failed"
        assert "none of the requested files exist" in (scan_after.error_message or "").lower()

    def test_partial_hit_proceeds_and_logs_missing(
        self, test_db, paid_tenant, tmp_path, caplog
    ):
        """≥1 resolved → worker proceeds (we just stop execution by mocking graph build)."""
        repo = tmp_path / "repo"
        (repo / "contracts").mkdir(parents=True)
        (repo / "contracts" / "Real.vy").write_text("# exists\n" * 20)

        project = Project(
            tenant_id=paid_tenant.id,
            name="p2",
            source_path=str(repo),
            git_url=str(repo),
            default_branch="main",
            status="active",
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
        )
        test_db.add(project)
        test_db.commit()
        test_db.refresh(project)

        scan_id = "audit_partial_1"
        self._scaffold_scan(
            test_db, paid_tenant, project, scan_id,
            ["contracts/Real.vy", "contracts/Ghost.vy"],
        )

        from worker.tasks import execute_audit_task

        def fake_get_db_session(self=None):
            return test_db

        publisher_mock = MagicMock()
        thoughts: list[str] = []
        publisher_mock.publish_thought.side_effect = lambda msg, **_: thoughts.append(msg)

        # Let the task run through manifest build (our scope-check runs right
        # after walk_repository). We stop it before the real graph-build by
        # intercepting AdaptiveBundler via sys.modules — cheapest way to fail
        # fast without touching real LLM calls.
        import sys
        import types
        stub_bundles = types.ModuleType("ingest.bundles")

        class _BoomBundler:
            def __init__(self, *a, **kw):
                raise RuntimeError("STOP_AFTER_SCOPE_CHECK")

        stub_bundles.AdaptiveBundler = _BoomBundler

        original_bundles = sys.modules.get("ingest.bundles")
        sys.modules["ingest.bundles"] = stub_bundles
        try:
            with patch.object(execute_audit_task, "get_db_session", fake_get_db_session), \
                 patch("worker.tasks.RedisPublisher") as MockPublisher, \
                 patch("worker.tasks.set_token_context"):
                MockPublisher.return_value = publisher_mock
                try:
                    execute_audit_task.run(
                        repo_url=str(repo),
                        scan_id=scan_id,
                        tenant_id=paid_tenant.id,
                        project_id=project.id,
                        target_files=["contracts/Real.vy", "contracts/Ghost.vy"],
                    )
                except Exception:
                    # Graph build bailed by design — we only care whether the
                    # partial-miss warning was emitted first.
                    pass
        finally:
            if original_bundles is not None:
                sys.modules["ingest.bundles"] = original_bundles
            else:
                sys.modules.pop("ingest.bundles", None)

        # The partial-hit warning mentions Ghost.vy in the published thoughts.
        assert any("contracts/Ghost.vy" in t for t in thoughts), f"thoughts={thoughts}"
        # AuditSession still alive — partial hit doesn't delete it.
        sess_after = test_db.query(AuditSession).filter(
            AuditSession.session_id == scan_id
        ).first()
        assert sess_after is not None


class TestDeepAuditModeDefault:
    """firepan-8l1: paid scan_type=deep must default to Claude SingleAuditor.
    The DeepSeek 'sweep' pipeline had a 0/13 TP rate (yieldnest scan 77
    postmortem). A silent revert to default='sweep' re-exposes every paying
    customer to that failure mode, so guard the default structurally."""

    def test_audit_start_request_defaults_to_auditor(self):
        from server.api import AuditStartRequest

        assert AuditStartRequest.model_fields["mode"].default == "auditor"

    def test_agent_api_request_defaults_to_auditor(self):
        from server.agent_routes import AgentAuditRequest

        assert AgentAuditRequest.model_fields["mode"].default == "auditor"
