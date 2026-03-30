"""
Security regression tests for the Hound API.

Tests cover:
- Admin panel authentication
- Write endpoint admin protection
- Read endpoint JWT protection
- Tenant isolation
- Path traversal prevention
- Public endpoints remain accessible
"""

import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import (
    AuditSession,
    Base,
    Graph,
    Hypothesis,
    Project,
    ScanExecution,
    Tenant,
    User,
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
    """Create a test database using SQLite in a temp file."""
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
    """Create a test client with dependency override."""
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
    """Patch legacy API admin key (module-level variable)."""
    import server.api as api_module
    monkeypatch.setattr(api_module, "ADMIN_API_KEY", "test-admin-key")
    return "test-admin-key"


@pytest.fixture
def tenant_a(test_db):
    """Create tenant A for isolation tests."""
    tenant = Tenant(name="tenant_a", email_verified=True)
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


@pytest.fixture
def tenant_b(test_db):
    """Create tenant B for isolation tests."""
    tenant = Tenant(name="tenant_b", email_verified=True)
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


@pytest.fixture
def project_a(test_db, tenant_a):
    """Create a project owned by tenant A."""
    project = Project(
        tenant_id=tenant_a.id,
        name="project_a",
        source_path="/tmp/project_a",
        git_url="https://github.com/a/repo",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(project)
    test_db.commit()
    test_db.refresh(project)
    return project


@pytest.fixture
def project_b(test_db, tenant_b):
    """Create a project owned by tenant B."""
    project = Project(
        tenant_id=tenant_b.id,
        name="project_b",
        source_path="/tmp/project_b",
        git_url="https://github.com/b/repo",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(project)
    test_db.commit()
    test_db.refresh(project)
    return project


@pytest.fixture
def session_a(test_db, project_a):
    """Create an audit session for project A."""
    session = AuditSession(
        project_id=project_a.id,
        session_id="sess_a_001",
        status="completed",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
    )
    test_db.add(session)
    test_db.commit()
    test_db.refresh(session)
    return session


@pytest.fixture
def session_b(test_db, project_b):
    """Create an audit session for project B."""
    session = AuditSession(
        project_id=project_b.id,
        session_id="sess_b_001",
        status="completed",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
    )
    test_db.add(session)
    test_db.commit()
    test_db.refresh(session)
    return session


@pytest.fixture
def graph_a(test_db, project_a):
    """Create a graph for project A."""
    graph = Graph(
        project_id=project_a.id,
        name="SystemArchitecture",
        internal_name="SystemArchitecture",
        data={"name": "SystemArchitecture", "nodes": [], "edges": []},
    )
    test_db.add(graph)
    test_db.commit()
    test_db.refresh(graph)
    return graph


@pytest.fixture
def hypothesis_a(test_db, project_a):
    """Create a hypothesis for project A."""
    hyp = Hypothesis(
        project_id=project_a.id,
        hypothesis_id="hyp_a_001",
        title="Test finding A",
        description="Vuln in project A",
        vulnerability_type="Reentrancy",
        status="confirmed",
        confidence=0.9,
        severity="high",
    )
    test_db.add(hyp)
    test_db.commit()
    test_db.refresh(hyp)
    return hyp


def jwt_headers(tenant):
    """Create JWT auth headers for a tenant."""
    token = create_access_token({
        "tenant_id": tenant.id,
        "user_id": tenant.id,
        "github_login": "test",
    })
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# TestAdminPanelAuth
# =============================================================================


class TestAdminPanelAuth:
    """Test that /admin/home (FastAPI) requires admin auth."""

    def test_admin_home_requires_auth(self, client, admin_key):
        """/admin/home is a FastAPI endpoint protected by require_admin."""
        response = client.get("/admin/home", follow_redirects=False)
        # Without X-Admin-Key header, should get 401 or 303 redirect
        assert response.status_code in (401, 303)

    def test_admin_home_with_key(self, client, admin_key):
        """/admin/home accessible with X-Admin-Key."""
        response = client.get(
            "/admin/home",
            headers={"X-Admin-Key": admin_key},
            follow_redirects=False,
        )
        assert response.status_code == 200

    def test_admin_home_with_wrong_key(self, client, admin_key):
        """/admin/home rejects wrong key."""
        response = client.get(
            "/admin/home",
            headers={"X-Admin-Key": "wrong-key"},
            follow_redirects=False,
        )
        assert response.status_code in (401, 303)


# =============================================================================
# TestWriteEndpointsRequireAdmin
# =============================================================================


class TestWriteEndpointsRequireAdmin:
    """Test that POST /projects requires admin authentication."""

    def test_create_project_without_auth_returns_401(self, client, admin_key, tenant_a):
        """POST /projects without admin key returns 401."""
        response = client.post("/projects", json={
            "name": "test",
            "source_path": "/tmp/test",
        })
        assert response.status_code == 401

    def test_create_project_with_wrong_key_returns_401(self, client, admin_key, tenant_a):
        """POST /projects with wrong admin key returns 401."""
        response = client.post(
            "/projects",
            json={"name": "test", "source_path": "/tmp/test"},
            headers={"X-Admin-Key": "wrong-key"},
        )
        assert response.status_code == 401

    def test_create_project_with_valid_key(self, client, admin_key, tenant_a):
        """POST /projects with valid admin key succeeds (may 400 for invalid path, not 401)."""
        response = client.post(
            "/projects",
            json={"name": "test", "source_path": "/tmp/test"},
            headers={"X-Admin-Key": admin_key},
        )
        # 400 is expected because /tmp/test doesn't exist; the point is it's NOT 401
        assert response.status_code != 401


# =============================================================================
# TestReadEndpointsRequireJWT
# =============================================================================


class TestReadEndpointsRequireJWT:
    """Test that read endpoints return 401 without JWT auth."""

    ENDPOINTS = [
        ("GET", "/projects"),
        ("GET", "/organizations/1"),
        ("GET", "/organizations/1/members"),
        ("GET", "/subscriptions/current"),
        ("GET", "/usage/current-month"),
        ("GET", "/repositories"),
        ("GET", "/findings"),
        ("GET", "/findings/stats"),
        ("GET", "/users/me"),
    ]

    @pytest.mark.parametrize("method,path", ENDPOINTS)
    def test_endpoint_requires_jwt(self, client, method, path):
        """Unauthenticated request returns 401."""
        response = client.request(method, path)
        assert response.status_code == 401, f"{method} {path} returned {response.status_code}, expected 401"

    @pytest.mark.parametrize("method,path", ENDPOINTS[:3])
    def test_endpoint_with_invalid_token_returns_401(self, client, method, path):
        """Request with invalid JWT returns 401."""
        response = client.request(method, path, headers={"Authorization": "Bearer invalid-token"})
        assert response.status_code == 401


# =============================================================================
# TestTenantIsolation
# =============================================================================


class TestTenantIsolation:
    """Test that tenants cannot access each other's data."""

    def test_tenant_a_sees_own_projects(self, client, project_a, tenant_a):
        """Tenant A can see their own projects."""
        response = client.get("/projects", headers=jwt_headers(tenant_a))
        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 1
        assert all(p["name"] != "project_b" for p in data)

    def test_tenant_a_cannot_see_tenant_b_projects(self, client, project_a, project_b, tenant_a, tenant_b):
        """Tenant A's project list should not include tenant B's projects."""
        response = client.get("/projects", headers=jwt_headers(tenant_a))
        assert response.status_code == 200
        data = response.json()
        project_names = [p["name"] for p in data]
        assert "project_b" not in project_names

    def test_tenant_b_cannot_see_tenant_a_projects(self, client, project_a, project_b, tenant_a, tenant_b):
        """Tenant B's project list should not include tenant A's projects."""
        response = client.get("/projects", headers=jwt_headers(tenant_b))
        assert response.status_code == 200
        data = response.json()
        project_names = [p["name"] for p in data]
        assert "project_a" not in project_names

    def test_tenant_a_cannot_access_tenant_b_sessions(
        self, client, project_b, session_b, tenant_a
    ):
        """Tenant A cannot see tenant B's project sessions."""
        response = client.get(
            f"/projects/{project_b.id}/sessions",
            headers=jwt_headers(tenant_a),
        )
        # Should return 404 (project not found for this tenant) or empty list
        assert response.status_code in (404, 200)
        if response.status_code == 200:
            assert len(response.json()) == 0

    def test_tenant_a_cannot_access_tenant_b_session_graph(
        self, client, session_b, graph_a, tenant_a, project_b
    ):
        """Tenant A cannot access tenant B's session graph."""
        response = client.get(
            f"/sessions/{session_b.session_id}/graph",
            headers=jwt_headers(tenant_a),
        )
        # Should return 404 (session not found for this tenant)
        assert response.status_code == 404

    def test_tenant_a_cannot_access_tenant_b_session_findings(
        self, client, session_b, tenant_a, project_b
    ):
        """Tenant A cannot access tenant B's session findings."""
        response = client.get(
            f"/sessions/{session_b.session_id}/findings",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 404

    def test_tenant_a_cannot_access_tenant_b_audit_status(
        self, client, session_b, tenant_a, project_b
    ):
        """Tenant A cannot access tenant B's audit status."""
        response = client.get(
            f"/audits/{session_b.session_id}/status",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 404

    def test_tenant_a_cannot_access_tenant_b_organization(
        self, client, tenant_a, tenant_b
    ):
        """Tenant A cannot access tenant B's organization."""
        response = client.get(
            f"/organizations/{tenant_b.id}",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 404

    def test_tenant_a_cannot_access_tenant_b_org_members(
        self, client, tenant_a, tenant_b
    ):
        """Tenant A cannot access tenant B's organization members."""
        response = client.get(
            f"/organizations/{tenant_b.id}/members",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 404

    def test_tenant_a_can_access_own_organization(self, client, tenant_a):
        """Tenant A can access their own organization."""
        response = client.get(
            f"/organizations/{tenant_a.id}",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 200
        assert response.json()["name"] == "tenant_a"

    def test_tenant_a_can_access_own_findings(self, client, tenant_a, hypothesis_a):
        """Tenant A can see their own findings."""
        response = client.get("/findings", headers=jwt_headers(tenant_a))
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1

    def test_tenant_b_cannot_see_tenant_a_findings(
        self, client, tenant_b, hypothesis_a, project_a
    ):
        """Tenant B cannot see tenant A's findings."""
        response = client.get("/findings", headers=jwt_headers(tenant_b))
        assert response.status_code == 200
        data = response.json()
        finding_ids = [f["hypothesis_id"] for f in data["findings"]]
        assert "hyp_a_001" not in finding_ids

    def test_tenant_a_cannot_access_tenant_b_repository(
        self, client, project_b, tenant_a
    ):
        """Tenant A cannot access tenant B's repository detail."""
        response = client.get(
            f"/repositories/{project_b.id}",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 404

    def test_tenant_a_cannot_access_tenant_b_repository_scans(
        self, client, project_b, tenant_a
    ):
        """Tenant A cannot access tenant B's repository scans."""
        response = client.get(
            f"/repositories/{project_b.id}/scans",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 404


# =============================================================================
# TestPathTraversal
# =============================================================================


class TestPathTraversal:
    """Test path traversal prevention in project creation."""

    def test_path_traversal_in_name(self, client, admin_key):
        """Project name with '..' is rejected."""
        response = client.post(
            "/projects",
            json={"name": "../etc/passwd", "source_path": "/tmp/test"},
            headers={"X-Admin-Key": admin_key},
        )
        assert response.status_code == 400
        assert "path traversal" in response.json()["detail"].lower()

    def test_path_traversal_in_source_path(self, client, admin_key):
        """Source path with '..' is rejected."""
        response = client.post(
            "/projects",
            json={"name": "legit_project", "source_path": "/tmp/../../etc/passwd"},
            headers={"X-Admin-Key": admin_key},
        )
        assert response.status_code == 400
        assert "path traversal" in response.json()["detail"].lower()

    def test_normal_name_succeeds(self, client, admin_key):
        """Normal project name is not rejected for path traversal."""
        response = client.post(
            "/projects",
            json={"name": "my_project", "source_path": "/tmp/my_project"},
            headers={"X-Admin-Key": admin_key},
        )
        # May fail for other reasons (path doesn't exist), but not 400 for traversal
        if response.status_code == 400:
            assert "path traversal" not in response.json()["detail"].lower()


# =============================================================================
# TestPublicEndpointsStillWork
# =============================================================================


class TestPublicEndpointsStillWork:
    """Test that public endpoints remain accessible without auth."""

    def test_health_endpoint(self, client):
        """GET /health returns 200 without any auth."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_root_endpoint(self, client):
        """GET / returns 200 without any auth."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Hound Dashboard API"

    def test_github_webhook_accessible(self, client):
        """POST /webhooks/github is accessible without JWT (uses its own auth)."""
        response = client.post(
            "/webhooks/github",
            json={"action": "test"},
            headers={"X-GitHub-Event": "ping"},
        )
        # Should not return 401 — webhooks use signature verification, not JWT
        assert response.status_code != 401


# =============================================================================
# Fixtures for endpoint auth tests
# =============================================================================


@pytest.fixture
def scan_a(test_db, project_a, tenant_a):
    """Create a scan execution owned by tenant A."""
    scan = ScanExecution(
        execution_id="scan_a_001",
        project_id=project_a.id,
        tenant_id=tenant_a.id,
        repo_name="project_a",
        repo_url="https://github.com/a/repo",
        status="completed",
        scan_config={"scan_type": "surface"},
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()
    test_db.refresh(scan)
    return scan


@pytest.fixture
def github_user_a(test_db, tenant_a):
    """Create a user with GitHub linked for tenant A."""
    user = User(
        tenant_id=tenant_a.id,
        email="user_a@test.com",
        github_id=111,
        github_login="user_a",
        github_access_token="ghp_fake_token_a",
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def github_user_b(test_db, tenant_b):
    """Create a user with GitHub linked for tenant B."""
    user = User(
        tenant_id=tenant_b.id,
        email="user_b@test.com",
        github_id=222,
        github_login="user_b",
        github_access_token="ghp_fake_token_b",
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


def jwt_headers_for_user(tenant, user):
    """Create JWT auth headers with user_id matching a real User row."""
    token = create_access_token({
        "tenant_id": tenant.id,
        "user_id": user.id,
        "github_login": user.github_login,
    })
    return {"Authorization": f"Bearer {token}"}


# =============================================================================
# TestEndpointAuth — auth enforcement on previously-unauthenticated endpoints
# =============================================================================


class TestEndpointAuth:
    """Test that previously-unauthenticated endpoints now require auth."""

    def test_delete_scan_requires_auth(self, client):
        """DELETE /surface/scans/xxx without auth header returns 401."""
        response = client.delete("/surface/scans/nonexistent")
        assert response.status_code == 401

    def test_delete_scan_cross_tenant(self, client, scan_a, tenant_b):
        """Tenant B cannot delete tenant A's scan."""
        response = client.delete(
            f"/surface/scans/{scan_a.execution_id}",
            headers=jwt_headers(tenant_b),
        )
        assert response.status_code == 404

    def test_delete_scan_own_tenant(self, client, scan_a, tenant_a):
        """Tenant A can delete their own scan."""
        response = client.delete(
            f"/surface/scans/{scan_a.execution_id}",
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

    def test_trigger_scan_cross_tenant(
        self, client, project_b, tenant_a, github_user_a
    ):
        """Tenant A cannot trigger scan on tenant B's repo."""
        response = client.post(
            f"/repositories/{project_b.id}/scan",
            headers=jwt_headers_for_user(tenant_a, github_user_a),
        )
        assert response.status_code == 404

    def test_finalize_requires_auth(self, client):
        """POST /sessions/xxx/finalize without auth returns 401."""
        response = client.post(
            "/sessions/nonexistent/finalize",
            json={"threshold": 0.5},
        )
        assert response.status_code == 401

    def test_poc_requires_auth(self, client):
        """POST /sessions/xxx/poc without auth returns 401."""
        response = client.post(
            "/sessions/nonexistent/poc",
            json={},
        )
        assert response.status_code == 401

    def test_report_requires_auth(self, client, admin_key):
        """POST /sessions/xxx/report without auth returns 401."""
        response = client.post(
            "/sessions/nonexistent/report",
            json={"format": "html"},
        )
        assert response.status_code == 401

    def test_report_admin_auth_passes(self, client, admin_key):
        """Request with valid X-Admin-Key gets past auth (404 for nonexistent session)."""
        response = client.post(
            "/sessions/nonexistent/report",
            json={"format": "html"},
            headers={"X-Admin-Key": admin_key},
        )
        # 404 proves auth passed — it reached the session lookup
        assert response.status_code == 404

    def test_session_finalize_own_tenant(self, client, session_a, tenant_a):
        """Tenant A can finalize own session (empty result — no pending hypotheses)."""
        response = client.post(
            f"/sessions/{session_a.session_id}/finalize",
            json={"threshold": 0.5},
            headers=jwt_headers(tenant_a),
        )
        assert response.status_code == 200
        assert response.json()["total_reviewed"] == 0

    def test_session_endpoints_cross_tenant(
        self, client, session_b, tenant_a, project_b
    ):
        """Tenant A cannot access tenant B's session via finalize, poc, or report."""
        headers = jwt_headers(tenant_a)

        # /finalize
        r1 = client.post(
            f"/sessions/{session_b.session_id}/finalize",
            json={"threshold": 0.5},
            headers=headers,
        )
        assert r1.status_code == 404

        # /poc
        r2 = client.post(
            f"/sessions/{session_b.session_id}/poc",
            json={},
            headers=headers,
        )
        assert r2.status_code == 404

        # /report
        r3 = client.post(
            f"/sessions/{session_b.session_id}/report",
            json={"format": "html"},
            headers=headers,
        )
        assert r3.status_code == 404
