"""
Tests for the FastAPI server endpoints.
"""

import os
from datetime import datetime, timedelta, timezone

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
    Tenant,
    User,
)

# Set test database URL before importing app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db
from server.auth_utils import create_access_token
from server.token_crypto import encrypt_token


class FakeGitHubResponse:
    """Small helper for mocking GitHub API responses."""

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class FakeAsyncClient:
    """Deterministic async client for GitHub API endpoint tests."""

    def __init__(self, responses=None):
        self._responses = list(responses or [])

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        if not self._responses:
            raise AssertionError("Unexpected GET request")
        return self._responses.pop(0)


# Test database setup
@pytest.fixture(scope="function")
def test_db(tmp_path):
    """Create a test database using SQLite in a temp file."""
    # Use file-based SQLite to avoid in-memory connection issues
    db_path = tmp_path / "test.db"
    db_url = f"sqlite:///{db_path}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create tables
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

    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    def override_get_engine():
        # Return the test engine
        return test_db.get_bind()

    app.dependency_overrides[get_db] = override_get_db
    # Also override the get_engine function to ensure it uses test DB
    import server.api as api_module
    original_get_engine = api_module.get_engine
    original_engine = api_module._engine
    
    # Reset the global engine and override the function
    api_module._engine = test_db.get_bind()
    api_module.get_engine = override_get_engine
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Restore original
    app.dependency_overrides.clear()
    api_module.get_engine = original_get_engine
    api_module._engine = original_engine


@pytest.fixture
def sample_tenant(test_db):
    """Create a sample tenant for testing."""
    tenant = Tenant(name="test_tenant", email_verified=True)
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


def auth_headers(tenant):
    """Create JWT auth headers for a tenant."""
    token = create_access_token({
        "tenant_id": tenant.id,
        "user_id": tenant.id,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def github_user(test_db, sample_tenant):
    """Create a user with GitHub linked (needed for scan endpoints)."""
    from server.token_crypto import encrypt_token
    user = User(
        github_id=12345678,
        github_login="testuser",
        email="test@example.com",
        name="Test User",
        avatar_url="https://avatars.githubusercontent.com/u/12345678",
        tenant_id=sample_tenant.id,
        signup_provider="github",
        github_token_encrypted=encrypt_token("ghp_test_token"),
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


def github_auth_headers(user):
    """Create JWT auth headers for a user with GitHub linked."""
    token = create_access_token({
        "tenant_id": user.tenant_id,
        "user_id": user.id,
    })
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_key(monkeypatch):
    """Enable admin auth and return the key."""
    import server.api as api_module
    monkeypatch.setattr(api_module, "ADMIN_API_KEY", "test-admin-key")
    return "test-admin-key"


@pytest.fixture
def sample_project(test_db, sample_tenant):
    """Create a sample project for testing."""
    project = Project(
        tenant_id=sample_tenant.id,
        name="test_project",
        source_path="/tmp/test_project",
        git_url="https://github.com/test/repo",
        description="Test project",
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(project)
    test_db.commit()
    test_db.refresh(project)
    return project


@pytest.fixture
def sample_session(test_db, sample_project):
    """Create a sample audit session for testing."""
    session = AuditSession(
        project_id=sample_project.id,
        session_id="sess_20250116_120000_abc123",
        status="completed",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        models={"scout": "gpt-4o", "strategist": "gpt-4o-mini"},
        token_usage={"total_tokens": 1000, "input_tokens": 500, "output_tokens": 500},
        coverage={"nodes": {"visited": 10, "total": 100}, "cards": {"visited": 5, "total": 50}},
        investigations=[{"goal": "Test investigation", "iterations_completed": 5}],
    )
    test_db.add(session)
    test_db.commit()
    test_db.refresh(session)
    return session


@pytest.fixture
def sample_graph(test_db, sample_project):
    """Create a sample graph for testing."""
    graph = Graph(
        project_id=sample_project.id,
        name="SystemArchitecture",
        internal_name="SystemArchitecture",
        data={
            "name": "SystemArchitecture",
            "nodes": [
                {"id": "node1", "label": "Component A"},
                {"id": "node2", "label": "Component B"},
            ],
            "edges": [{"source": "node1", "target": "node2", "label": "calls"}],
        },
    )
    test_db.add(graph)
    test_db.commit()
    test_db.refresh(graph)
    return graph


@pytest.fixture
def sample_hypothesis(test_db, sample_project):
    """Create a sample hypothesis for testing."""
    hypothesis = Hypothesis(
        project_id=sample_project.id,
        hypothesis_id="hyp_20250116_120000_xyz789",
        title="SQL Injection in login endpoint",
        description="The login endpoint is vulnerable to SQL injection attacks",
        vulnerability_type="SQL Injection",
        status="confirmed",
        confidence=0.9,
        severity="high",
        node_refs=["node1", "node2"],
        evidence={"code_snippet": "SELECT * FROM users WHERE id = <user_input>"},
        reported_by_model="gpt-4o",
        junior_model="gpt-4o-mini",
        senior_model="gpt-4o",
    )
    test_db.add(hypothesis)
    test_db.commit()
    test_db.refresh(hypothesis)
    return hypothesis


# Tests


def test_root_endpoint(client):
    """Test the root endpoint returns API information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "version" in data
    assert "endpoints" in data
    assert data["name"] == "Hound Dashboard API"


def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data


def test_list_projects_empty(client, sample_tenant):
    """Test listing projects when none exist."""
    response = client.get("/projects", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_list_projects_with_data(client, sample_project, sample_tenant):
    """Test listing projects with existing data."""
    response = client.get("/projects", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["name"] == "test_project"
    assert data[0]["status"] == "active"
    assert "graphs_count" in data[0]
    assert "sessions_count" in data[0]
    assert "hypotheses_count" in data[0]
    assert "confirmed_count" in data[0]


def test_list_project_sessions_empty(client, sample_project, sample_tenant):
    """Test listing sessions for a project with no sessions."""
    response = client.get(f"/projects/{sample_project.id}/sessions", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_list_project_sessions_with_data(client, sample_project, sample_session, sample_tenant):
    """Test listing sessions for a project with existing sessions."""
    response = client.get(f"/projects/{sample_project.id}/sessions", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["session_id"] == "sess_20250116_120000_abc123"
    assert data[0]["status"] == "completed"
    assert "models" in data[0]
    assert "token_usage" in data[0]
    assert "coverage" in data[0]
    assert data[0]["investigations_count"] == 1


def test_list_project_sessions_not_found(client, sample_tenant):
    """Test listing sessions for a non-existent project."""
    response = client.get("/projects/999/sessions", headers=auth_headers(sample_tenant))
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_session_graph(client, sample_session, sample_graph, sample_tenant):
    """Test getting graph data for a session."""
    response = client.get(f"/sessions/{sample_session.session_id}/graph", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert "nodes" in data
    assert "edges" in data
    assert data["name"] == "SystemArchitecture"
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1


def test_get_session_graph_not_found(client, sample_tenant):
    """Test getting graph for a non-existent session."""
    response = client.get("/sessions/nonexistent_session/graph", headers=auth_headers(sample_tenant))
    assert response.status_code == 404


def test_get_session_findings_empty(client, sample_session, sample_tenant):
    """Test getting findings for a session with no confirmed hypotheses."""
    response = client.get(f"/sessions/{sample_session.session_id}/findings", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_get_session_findings_with_data(client, sample_session, sample_hypothesis, sample_tenant):
    """Test getting findings for a session with confirmed hypotheses."""
    response = client.get(f"/sessions/{sample_session.session_id}/findings", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["hypothesis_id"] == "hyp_20250116_120000_xyz789"
    assert data[0]["title"] == "SQL Injection in login endpoint"
    assert data[0]["status"] == "confirmed"
    assert data[0]["confidence"] == 0.9
    assert data[0]["severity"] == "high"
    assert data[0]["vulnerability_type"] == "SQL Injection"


def test_get_session_findings_not_found(client, sample_tenant):
    """Test getting findings for a non-existent session."""
    response = client.get("/sessions/nonexistent_session/findings", headers=auth_headers(sample_tenant))
    assert response.status_code == 404


def test_websocket_connection(client, sample_session):
    """Test WebSocket connection for session logs."""
    with client.websocket_connect(f"/ws/sessions/{sample_session.session_id}") as websocket:
        # Should receive connection confirmation
        data = websocket.receive_json()
        assert data["type"] == "connected"
        assert data["session_id"] == sample_session.session_id
        assert "timestamp" in data
        assert "Subscribing to audit updates" in data["message"]

        # Send a ping message
        websocket.send_text("ping")

        # Should receive pong (or keepalive if Redis not available)
        response = websocket.receive_json()
        assert response["type"] in ("pong", "keepalive")
        assert "timestamp" in response


@pytest.mark.parametrize(
    "project_data,expected_status",
    [
        # Valid project with source_path
        (
            {
                "name": "valid_project",
                "source_path": "/tmp/test",
                "description": "Valid project",
            },
            400,  # Will fail in test because path doesn't exist
        ),
        # Missing both source_path and git_url
        ({"name": "invalid_project", "description": "Missing source"}, 400),
    ],
)
def test_create_project_validation(client, sample_tenant, admin_key, project_data, expected_status):
    """Test project creation with various input validations."""
    response = client.post("/projects", json=project_data, headers={"X-Admin-Key": admin_key})
    assert response.status_code == expected_status


def test_projects_with_stats(client, sample_project, sample_graph, sample_session, sample_hypothesis, sample_tenant):
    """Test that project list includes correct statistics."""
    response = client.get("/projects", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1

    project = data[0]
    assert project["graphs_count"] == 1
    assert project["sessions_count"] == 1
    assert project["hypotheses_count"] == 1
    assert project["confirmed_count"] == 1


# ============================================================================
# Tests for new SaaS endpoints
# ============================================================================

def test_audit_start_endpoint_validation(client, sample_tenant):
    """Test that /audits/start requires repo_url."""
    # Missing repo_url should fail validation
    response = client.post("/audits/start", json={}, headers=auth_headers(sample_tenant))
    assert response.status_code == 422  # Validation error


def test_audit_start_worker_import(client, sample_tenant, monkeypatch):
    """Test /audits/start handles worker import gracefully."""
    # Mock the Celery task to avoid actual execution
    from unittest.mock import MagicMock, patch

    mock_task = MagicMock()
    mock_task.id = "mock_task_id_12345"

    with patch("worker.tasks.execute_audit_task") as mock_execute:
        mock_execute.delay.return_value = mock_task

        response = client.post(
            "/audits/start",
            json={
                "repo_url": "https://github.com/test/repo",
            },
            headers=auth_headers(sample_tenant),
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "session_id" in data
        assert data["status"] == "queued"
        assert "websocket_url" in data
        assert "mock_task_id" in data["message"]
        
        # Verify the task was called with correct args
        mock_execute.delay.assert_called_once()
        call_kwargs = mock_execute.delay.call_args.kwargs
        assert call_kwargs["repo_url"] == "https://github.com/test/repo"
        assert call_kwargs["tenant_id"] == sample_tenant.id


def test_audit_status_not_found(client, sample_tenant):
    """Test audit status for non-existent session."""
    response = client.get("/audits/nonexistent_session/status", headers=auth_headers(sample_tenant))
    assert response.status_code == 404


def test_audit_status_found(client, sample_session, sample_tenant):
    """Test audit status for existing session."""
    response = client.get(f"/audits/{sample_session.session_id}/status", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == sample_session.session_id
    assert data["status"] == sample_session.status


def test_github_webhook_invalid_json(client):
    """Test GitHub webhook with invalid JSON."""
    response = client.post(
        "/webhooks/github",
        content=b"not json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400


def test_github_webhook_installation_event(client):
    """Test GitHub webhook handles installation events."""
    from unittest.mock import AsyncMock, patch

    payload = {
        "action": "created",
        "installation": {
            "id": 12345,
            "account": {"login": "test-org", "type": "Organization"},
        },
    }
    with patch("server.api.notify_app_installed", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = True
        response = client.post(
            "/webhooks/github",
            json=payload,
            headers={
                "X-GitHub-Event": "installation",
                "X-Hub-Signature-256": "",  # No signature verification in dev mode
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["event"] == "installation"
    assert data["action"] == "created"
    assert data["tenant_id"] is not None


def test_github_webhook_pr_event_skipped(client):
    """Test GitHub webhook skips non-actionable PR events."""
    payload = {
        "action": "closed",  # Not opened/synchronize
        "pull_request": {"number": 42},
        "repository": {"full_name": "test/repo"},
        "installation": {"id": 12345},
    }
    response = client.post(
        "/webhooks/github",
        json=payload,
        headers={
            "X-GitHub-Event": "pull_request",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["skipped"] is True


def test_github_webhook_push_event(client):
    """Test GitHub webhook handles push events."""
    payload = {
        "ref": "refs/heads/feature-branch",  # Not default branch
        "repository": {
            "full_name": "test/repo",
            "default_branch": "main",
        },
    }
    response = client.post(
        "/webhooks/github",
        json=payload,
        headers={
            "X-GitHub-Event": "push",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["skipped"] is True
    assert "Not default branch" in data.get("reason", "")


# ============================================================================
# Dashboard API Endpoint Tests
# ============================================================================


def test_get_current_user(client, sample_tenant, github_user):
    """Test getting current user profile."""
    token = create_access_token({"tenant_id": sample_tenant.id, "user_id": github_user.id, "github_login": "test"})
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == sample_tenant.id
    assert data["org_id"] == sample_tenant.id
    assert data["name"] == sample_tenant.name
    assert data["role"] == "admin"
    assert "suggested_email" in data


def test_get_current_user_not_found(client):
    """Test getting current user with invalid tenant ID."""
    token = create_access_token({"tenant_id": 999, "user_id": 999, "github_login": "ghost"})
    response = client.get("/users/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_organization(client, sample_tenant):
    """Test getting organization details."""
    response = client.get(f"/organizations/{sample_tenant.id}", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == sample_tenant.id
    assert data["name"] == sample_tenant.name
    assert data["status"] == sample_tenant.status
    assert "created_at" in data
    assert "updated_at" in data


def test_get_organization_not_found(client, sample_tenant):
    """Test getting non-existent organization."""
    response = client.get("/organizations/999", headers=auth_headers(sample_tenant))
    assert response.status_code == 404


def test_list_organization_members(client, sample_tenant):
    """Test listing organization members."""
    response = client.get(f"/organizations/{sample_tenant.id}/members", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["name"] == sample_tenant.name
    assert data[0]["role"] == "owner"


def test_list_organization_members_not_found(client, sample_tenant):
    """Test listing members for non-existent organization."""
    response = client.get("/organizations/999/members", headers=auth_headers(sample_tenant))
    assert response.status_code == 404


def test_get_current_subscription(client, sample_tenant):
    """Test getting current subscription."""
    response = client.get("/subscriptions/current", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id"] == sample_tenant.id
    assert data["org_name"] == sample_tenant.name
    assert "plan" in data
    assert "status" in data


def test_get_current_subscription_active_trial_uses_effective_plan(client, sample_tenant, test_db):
    """Active trials should report starter limits and can_view_details."""
    sample_tenant.status = "active"
    sample_tenant.trial_plan = "starter"
    sample_tenant.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=14)
    test_db.commit()

    response = client.get("/subscriptions/current", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["plan"] == "starter"
    assert data["is_trial"] is True
    assert data["can_view_details"] is True
    assert data["plan_limits"]["scans_per_month"] == 40
    assert data["trial_plan"] == "starter"
    assert data["trial_ends_at"] is not None


def test_get_current_subscription_paid_beats_trial(client, sample_tenant, test_db):
    """Paid subscriptions should override active trial metadata."""
    sample_tenant.status = "active"
    sample_tenant.plan = "professional"
    sample_tenant.stripe_subscription_id = "sub_123"
    sample_tenant.trial_plan = "starter"
    sample_tenant.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=14)
    test_db.commit()

    response = client.get("/subscriptions/current", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["plan"] == "professional"
    assert data["is_trial"] is False
    assert data["can_view_details"] is True
    assert data["plan_limits"]["scans_per_month"] == 180


def test_get_current_subscription_not_found(client, test_db):
    """Test getting subscription for non-existent tenant."""
    # Create a tenant so JWT is valid, but it has no subscription data matching tenant 999
    ghost_tenant = Tenant(name="ghost_tenant")
    test_db.add(ghost_tenant)
    test_db.commit()
    test_db.refresh(ghost_tenant)
    # Use a JWT with a non-existent tenant_id
    token = create_access_token({"tenant_id": 999, "user_id": 999, "github_login": "ghost"})
    response = client.get("/subscriptions/current", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 404


def test_email_verification_gate_blocks_unverified(client, test_db):
    """Test that gated endpoints return 403 for unverified tenants."""
    unverified = Tenant(name="unverified_tenant", email_verified=False)
    test_db.add(unverified)
    test_db.commit()
    test_db.refresh(unverified)
    token = create_access_token({"tenant_id": unverified.id, "user_id": unverified.id})
    headers = {"Authorization": f"Bearer {token}"}

    # These endpoints require verified email
    gated = [
        ("GET", "/findings"),
        ("GET", "/findings/stats"),
    ]
    for method, path in gated:
        response = client.request(method, path, headers=headers)
        assert response.status_code == 403, f"{method} {path} should be gated"
        detail = response.json().get("detail", {})
        assert detail.get("error") == "email_not_verified"


def test_email_verification_gate_allows_verified(client, sample_tenant):
    """Test that gated endpoints pass through for verified tenants."""
    # sample_tenant has email_verified=True
    response = client.get("/findings", headers=auth_headers(sample_tenant))
    # Should not be 403 (may be 200 with empty list)
    assert response.status_code != 403


def test_subscription_includes_email_verified(client, sample_tenant):
    """Test that subscription response includes email_verified field."""
    response = client.get("/subscriptions/current", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert "email_verified" in data
    assert data["email_verified"] is True


def test_get_current_month_usage(client, sample_tenant, test_db):
    """Test getting usage statistics for current month."""
    from datetime import datetime, timezone

    from database.models import ScanExecution, TokenUsageLog

    # Create some usage data
    token_log = TokenUsageLog(
        tenant_id=sample_tenant.id,
        provider="openai",
        model="gpt-4o",
        input_tokens=1000,
        output_tokens=500,
        cost_usd=0.05,
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(token_log)

    scan = ScanExecution(
        execution_id="scan_test_123",
        tenant_id=sample_tenant.id,
        repo_name="test_repo",
        status="completed",
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    response = client.get("/usage/current-month", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["tenant_id"] == sample_tenant.id
    assert "period" in data
    assert data["scans_count"] >= 1
    assert data["total_cost_usd"] >= 0
    assert "token_usage" in data


def test_list_repositories_empty(client, sample_tenant):
    """Test listing repositories when none exist."""
    response = client.get("/repositories", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert "repositories" in data
    assert "total" in data
    assert data["total"] == 0
    assert len(data["repositories"]) == 0


def test_list_repositories_with_data(client, sample_project, sample_tenant):
    """Test listing repositories with existing projects."""
    response = client.get("/repositories", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["repositories"]) >= 1
    assert data["repositories"][0]["name"] == sample_project.name
    assert "scans_count" in data["repositories"][0]
    assert "findings_count" in data["repositories"][0]


def test_list_repositories_pagination(client, sample_tenant, test_db):
    """Test repository list pagination."""
    from datetime import datetime, timezone

    from database.models import Project

    # Create multiple projects
    for i in range(5):
        project = Project(
            tenant_id=sample_tenant.id,
            name=f"test_repo_{i}",
            status="active",
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
        )
        test_db.add(project)
    test_db.commit()

    # Test first page
    response = client.get("/repositories?page=1&page_size=2", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert len(data["repositories"]) == 2
    assert data["total"] >= 5


def test_list_repositories_search(client, sample_project, sample_tenant):
    """Test repository search functionality."""
    response = client.get("/repositories?search=test", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert any("test" in repo["name"].lower() for repo in data["repositories"])


def test_trigger_repository_scan(client, sample_project, github_user):
    """Test triggering a scan for a repository."""
    from unittest.mock import MagicMock, patch

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            response = client.post(f"/repositories/{sample_project.id}/scan", headers=github_auth_headers(github_user))
    assert response.status_code == 200
    data = response.json()
    assert "execution_id" in data
    assert data["repository_id"] == sample_project.id
    assert data["status"] == "pending"


def test_trigger_repository_scan_not_found(client, github_user):
    """Test triggering scan for non-existent repository."""
    from unittest.mock import patch

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        response = client.post("/repositories/999/scan", headers=github_auth_headers(github_user))
    assert response.status_code == 404


def test_list_repository_scans_empty(client, sample_project, sample_tenant):
    """Test listing scans for repository with no scans."""
    response = client.get(f"/repositories/{sample_project.id}/scans", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["repository_id"] == sample_project.id
    assert data["total"] == 0
    assert len(data["scans"]) == 0


def test_list_repository_scans_with_data(client, sample_project, sample_tenant, test_db):
    """Test listing scans for repository with existing scans."""
    from datetime import datetime, timezone

    from database.models import ScanExecution

    # Create scan executions
    scan = ScanExecution(
        execution_id="scan_test_456",
        project_id=sample_project.id,
        tenant_id=sample_project.tenant_id,
        repo_name=sample_project.name,
        status="completed",
        risk_score=75,
        risk_level="high",
        findings=[{"pattern_id": "test", "title": "Test finding"}],
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    response = client.get(f"/repositories/{sample_project.id}/scans", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["scans"]) >= 1
    assert data["scans"][0]["execution_id"] == "scan_test_456"
    assert data["scans"][0]["status"] == "completed"
    assert data["scans"][0]["findings_count"] == 1


def test_list_repository_scans_not_found(client, sample_tenant):
    """Test listing scans for non-existent repository."""
    response = client.get("/repositories/999/scans", headers=auth_headers(sample_tenant))
    assert response.status_code == 404


def test_list_all_findings_empty(client, sample_tenant):
    """Test listing all findings when none exist."""
    response = client.get("/findings", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert "findings" in data
    assert data["total"] == 0
    assert len(data["findings"]) == 0


def test_list_all_findings_with_data(client, sample_hypothesis, sample_tenant):
    """Test listing all findings with existing hypotheses."""
    response = client.get("/findings", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["findings"]) >= 1
    assert data["findings"][0]["hypothesis_id"] == sample_hypothesis.hypothesis_id


def test_list_all_findings_filter_severity(client, sample_hypothesis, sample_tenant):
    """Test filtering findings by severity."""
    response = client.get("/findings?severity=high", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    if data["total"] > 0:
        assert all(f["severity"] == "high" for f in data["findings"])


def test_list_all_findings_filter_status(client, sample_hypothesis, sample_tenant):
    """Test filtering findings by status."""
    response = client.get("/findings?status=confirmed", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    if data["total"] > 0:
        assert all(f["status"] == "confirmed" for f in data["findings"])


def test_list_all_findings_filter_repository(client, sample_hypothesis, sample_tenant, sample_project):
    """Test filtering findings by repository."""
    response = client.get(f"/findings?repository_id={sample_project.id}", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1


def test_list_all_findings_pagination(client, sample_tenant, sample_project, test_db):
    """Test findings list pagination."""
    from datetime import datetime, timezone

    from database.models import Hypothesis

    # Create multiple hypotheses
    for i in range(5):
        hyp = Hypothesis(
            project_id=sample_project.id,
            hypothesis_id=f"hyp_test_{i}",
            title=f"Test hypothesis {i}",
            description="Test description",
            vulnerability_type="Test",
            status="proposed",
            confidence=0.5,
            severity="medium",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        test_db.add(hyp)
    test_db.commit()

    response = client.get("/findings?page=1&page_size=2", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert len(data["findings"]) <= 2


def test_get_findings_statistics_empty(client, sample_tenant):
    """Test getting findings statistics when none exist."""
    response = client.get("/findings/stats", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert "by_severity" in data
    assert "by_status" in data
    assert "by_repository" in data


def test_get_findings_statistics_with_data(client, sample_hypothesis, sample_tenant):
    """Test getting findings statistics with existing data."""
    response = client.get("/findings/stats", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert data["by_severity"]["high"] >= 1
    assert data["by_status"]["confirmed"] >= 1
    assert len(data["by_repository"]) >= 1


def test_surface_scans_with_tenant_filter(client, sample_tenant, test_db):
    """Test surface scans endpoint with tenant_id filter."""
    from datetime import datetime, timezone

    from database.models import ScanExecution
    
    # Create scan for specific tenant
    scan = ScanExecution(
        execution_id="scan_tenant_test",
        tenant_id=sample_tenant.id,
        repo_name="test_repo",
        status="completed",
        risk_level="medium",
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()
    
    token = create_access_token({"tenant_id": sample_tenant.id, "user_id": sample_tenant.id, "github_login": "test"})
    response = client.get("/surface/scans", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert "scans" in data
    # All scans should belong to the specified tenant
    # (We can't easily verify this without more complex queries)


# =============================================================================
# Scan dispatch, findings count, and stats regression tests
# =============================================================================


def test_trigger_scan_dispatches_celery_task(client, sample_project, github_user, test_db):
    """Test that triggering a scan calls execute_scan_task.delay()."""
    from unittest.mock import MagicMock, patch

    mock_task = MagicMock()
    sample_project.installation_id = 88888
    test_db.commit()

    # Bypass tier enforcement — patched at the source module
    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            mock_module = sys.modules["worker.tasks"]
            mock_module.execute_scan_task = mock_task

            response = client.post(f"/repositories/{sample_project.id}/scan", headers=github_auth_headers(github_user))

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "pending"
    assert "execution_id" in data
    mock_task.delay.assert_called_once()
    call_kwargs = mock_task.delay.call_args
    assert call_kwargs.kwargs["repo_url"] == sample_project.git_url
    assert call_kwargs.kwargs["tenant_id"] == sample_project.tenant_id
    assert call_kwargs.kwargs["installation_id"] == 88888
    assert call_kwargs.kwargs["github_user_id"] == github_user.id


def test_trigger_scan_dispatches_github_user_id_for_oauth_repo(client, sample_project, github_user):
    """OAuth-triggered scans should pass the acting user id to the worker."""
    from unittest.mock import MagicMock, patch

    mock_task = MagicMock()

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            mock_module = sys.modules["worker.tasks"]
            mock_module.execute_scan_task = mock_task

            response = client.post(
                f"/repositories/{sample_project.id}/scan",
                headers=github_auth_headers(github_user),
            )

    assert response.status_code == 200
    call_kwargs = mock_task.delay.call_args.kwargs
    assert call_kwargs["installation_id"] is None
    assert call_kwargs["github_user_id"] == github_user.id


def test_trigger_scan_passes_user_branch_to_worker_and_persists_in_scan_config(
    client, sample_project, github_user, test_db
):
    """User-supplied branch flows into worker kwargs AND ScanExecution.scan_config."""
    from unittest.mock import MagicMock, patch

    from database.models import ScanExecution

    mock_task = MagicMock()

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            sys.modules["worker.tasks"].execute_scan_task = mock_task

            response = client.post(
                f"/repositories/{sample_project.id}/scan",
                json={"branch": "feature/some-branch"},
                headers=github_auth_headers(github_user),
            )

    assert response.status_code == 200
    assert mock_task.delay.call_args.kwargs["branch"] == "feature/some-branch"

    scan = (
        test_db.query(ScanExecution)
        .filter(ScanExecution.project_id == sample_project.id)
        .order_by(ScanExecution.created_at.desc())
        .first()
    )
    assert scan is not None
    assert (scan.scan_config or {}).get("branch") == "feature/some-branch"
    assert (scan.scan_config or {}).get("scan_type") == "surface"


def test_trigger_scan_falls_back_to_default_branch_when_body_omitted(
    client, sample_project, github_user, test_db
):
    """No body → resolve to project.default_branch (or 'main' if column NULL)."""
    from unittest.mock import MagicMock, patch

    from database.models import ScanExecution

    mock_task = MagicMock()

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            sys.modules["worker.tasks"].execute_scan_task = mock_task

            response = client.post(
                f"/repositories/{sample_project.id}/scan",
                headers=github_auth_headers(github_user),
            )

    assert response.status_code == 200
    expected_branch = sample_project.default_branch or "main"
    assert mock_task.delay.call_args.kwargs["branch"] == expected_branch

    scan = (
        test_db.query(ScanExecution)
        .filter(ScanExecution.project_id == sample_project.id)
        .order_by(ScanExecution.created_at.desc())
        .first()
    )
    assert (scan.scan_config or {}).get("branch") == expected_branch


def test_trigger_scan_rejects_branch_with_shell_metacharacters(
    client, sample_project, github_user
):
    """Defence in depth: branches with `;`, backtick, etc. are 400, not dispatched."""
    from unittest.mock import MagicMock, patch

    mock_task = MagicMock()

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            sys.modules["worker.tasks"].execute_scan_task = mock_task

            response = client.post(
                f"/repositories/{sample_project.id}/scan",
                json={"branch": "main; rm -rf /"},
                headers=github_auth_headers(github_user),
            )

    assert response.status_code == 400
    mock_task.delay.assert_not_called()


def test_trigger_scan_dispatch_failure_returns_500(client, sample_project, github_user, test_db):
    """Test that dispatch failure marks scan as failed and returns 500."""
    from unittest.mock import patch

    from database.models import ScanExecution

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": False}
        return _check

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        # Make worker.tasks import raise ImportError
        original_import = __import__
        def _blocked_import(name, *args, **kwargs):
            if name == "worker.tasks":
                raise ImportError("No module named 'worker.tasks'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_blocked_import):
            response = client.post(f"/repositories/{sample_project.id}/scan", headers=github_auth_headers(github_user))

    assert response.status_code == 500

    # Verify the scan record was marked failed
    scan = test_db.query(ScanExecution).filter(
        ScanExecution.project_id == sample_project.id
    ).order_by(ScanExecution.created_at.desc()).first()
    assert scan is not None
    assert scan.status == "failed"
    assert "Failed to dispatch scan" in (scan.error_message or "")


def test_trigger_scan_dispatch_failure_refunds_credit(client, sample_project, github_user, test_db):
    """Test that dispatch failure refunds credit when uses_credit is True."""
    from unittest.mock import MagicMock, patch

    from database.models import ScanExecution

    mock_refund = MagicMock()

    def fake_require(action):
        async def _check(request):
            return {"uses_credit": True}
        return _check

    original_import = __import__
    def _blocked_import(name, *args, **kwargs):
        if name == "worker.tasks":
            raise ImportError("No module named 'worker.tasks'")
        return original_import(name, *args, **kwargs)

    with patch("server.tier_enforcement.require_plan_allowance", fake_require):
        with patch("builtins.__import__", side_effect=_blocked_import):
            with patch("server.tier_enforcement.refund_scan_credit", mock_refund):
                response = client.post(f"/repositories/{sample_project.id}/scan", headers=github_auth_headers(github_user))

    assert response.status_code == 500
    # Refund should have been called
    mock_refund.assert_called_once()


def test_findings_count_uses_surface_scan(client, sample_project, sample_tenant, test_db):
    """Test that findings_count comes from latest completed surface scan."""
    from datetime import datetime, timezone

    from database.models import ScanExecution

    # Create a completed scan with findings
    scan = ScanExecution(
        execution_id="scan_findings_test",
        project_id=sample_project.id,
        tenant_id=sample_project.tenant_id,
        repo_name=sample_project.name,
        status="completed",
        findings=[
            {"pattern_id": "reentrancy", "severity": "high", "title": "Reentrancy"},
            {"pattern_id": "overflow", "severity": "medium", "title": "Overflow"},
            {"pattern_id": "access", "severity": "critical", "title": "Access Control"},
        ],
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    response = client.get("/repositories", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    repo = next(r for r in data["repositories"] if r["id"] == sample_project.id)
    assert repo["findings_count"] == 3


def test_findings_count_uses_latest_scan_only(client, sample_project, sample_tenant, test_db):
    """Test that findings_count uses latest scan, not cumulative across scans."""
    from datetime import datetime, timedelta, timezone

    from database.models import ScanExecution

    now = datetime.now(timezone.utc)

    # Older scan with 5 findings
    old_scan = ScanExecution(
        execution_id="scan_old",
        project_id=sample_project.id,
        tenant_id=sample_project.tenant_id,
        repo_name=sample_project.name,
        status="completed",
        findings=[{"severity": "high", "title": f"Finding {i}"} for i in range(5)],
        created_at=now - timedelta(hours=2),
    )

    # Newer scan with 2 findings
    new_scan = ScanExecution(
        execution_id="scan_new",
        project_id=sample_project.id,
        tenant_id=sample_project.tenant_id,
        repo_name=sample_project.name,
        status="completed",
        findings=[
            {"severity": "critical", "title": "Finding A"},
            {"severity": "low", "title": "Finding B"},
        ],
        created_at=now,
    )

    test_db.add(old_scan)
    test_db.add(new_scan)
    test_db.commit()

    response = client.get("/repositories", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    repo = next(r for r in data["repositories"] if r["id"] == sample_project.id)
    # Should be 2 (latest scan), not 7 (cumulative)
    assert repo["findings_count"] == 2


def test_findings_count_single_repo(client, sample_project, sample_tenant, test_db):
    """Test findings_count on the single repository detail endpoint."""
    from datetime import datetime, timezone

    from database.models import ScanExecution

    scan = ScanExecution(
        execution_id="scan_detail_test",
        project_id=sample_project.id,
        tenant_id=sample_project.tenant_id,
        repo_name=sample_project.name,
        status="completed",
        findings=[
            {"severity": "high", "title": "Finding 1"},
            {"severity": "medium", "title": "Finding 2"},
        ],
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    response = client.get(f"/repositories/{sample_project.id}", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["findings_count"] == 2


def test_findings_stats_includes_surface_scans(client, sample_tenant, sample_project, test_db):
    """Test that /findings/stats includes surface scan findings in severity counts."""
    from datetime import datetime, timezone

    from database.models import ScanExecution

    scan = ScanExecution(
        execution_id="scan_stats_test",
        project_id=sample_project.id,
        tenant_id=sample_tenant.id,
        repo_name=sample_project.name,
        status="completed",
        findings=[
            {"severity": "critical", "title": "Critical Bug"},
            {"severity": "high", "title": "High Bug"},
            {"severity": "medium", "title": "Medium Bug"},
        ],
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    response = client.get("/findings/stats", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 3
    assert data["by_severity"]["critical"] >= 1
    assert data["by_severity"]["high"] >= 1
    assert data["by_severity"]["medium"] >= 1
    assert data["by_status"]["scanner_detected"] >= 3
    assert sample_project.name in data["by_repository"]


def _create_stripe_tables(db):
    """Create stripe_processed_events table for SQLite test DB."""
    import sqlite3
    from sqlalchemy import event, text

    engine = db.get_bind()
    if engine.dialect.name == "sqlite":
        # Register NOW() for SQLite compat with raw SQL in stripe_routes
        @event.listens_for(engine, "connect")
        def _register_now(dbapi_conn, connection_record):
            import datetime as _dt
            dbapi_conn.create_function(
                "NOW", 0, lambda: _dt.datetime.now(_dt.timezone.utc).isoformat()
            )

        # Register on the existing raw connection too
        raw = db.connection().connection.dbapi_connection
        import datetime as _dt
        raw.create_function("NOW", 0, lambda: _dt.datetime.now(_dt.timezone.utc).isoformat())

    db.execute(text("""
        CREATE TABLE IF NOT EXISTS stripe_processed_events (
            event_id VARCHAR PRIMARY KEY,
            status VARCHAR NOT NULL DEFAULT 'processing',
            processed_at TIMESTAMP
        )
    """))
    db.commit()


def test_stripe_webhook_sends_telegram_notification(client, sample_tenant, test_db):
    """Test that Stripe webhook dispatches Telegram notification on successful checkout."""
    from unittest.mock import AsyncMock, MagicMock, patch

    _create_stripe_tables(test_db)

    sample_tenant.stripe_customer_id = "cus_test123"
    test_db.commit()

    fake_session = {
        "mode": "subscription",
        "customer": "cus_test123",
        "subscription": "sub_test456",
        "metadata": {"tenant_id": str(sample_tenant.id), "plan": "starter", "period": "monthly"},
    }
    fake_event = MagicMock()
    fake_event.id = "evt_test_notify"
    fake_event.type = "checkout.session.completed"
    fake_event.data.object = fake_session

    with patch("stripe.Webhook.construct_event", return_value=fake_event):
        with patch("server.stripe_routes.notify_payment_event", new_callable=AsyncMock) as mock_notify:
            mock_notify.return_value = True
            response = client.post(
                "/webhooks/stripe",
                content=b'{}',
                headers={"Stripe-Signature": "test_sig"},
            )

    assert response.status_code == 200
    mock_notify.assert_called_once()
    call_kwargs = mock_notify.call_args.kwargs
    assert call_kwargs["event_type"] == "subscription_created"
    assert call_kwargs["event_id"] == "evt_test_notify"
    assert call_kwargs["plan"] == "starter"


def test_stripe_webhook_returns_200_on_telegram_failure(client, sample_tenant, test_db):
    """Test that Stripe webhook returns 200 even if Telegram notification fails."""
    from unittest.mock import AsyncMock, MagicMock, patch

    _create_stripe_tables(test_db)

    sample_tenant.stripe_customer_id = "cus_test_fail"
    test_db.commit()

    fake_session = {
        "mode": "subscription",
        "customer": "cus_test_fail",
        "subscription": "sub_test_fail",
        "metadata": {"tenant_id": str(sample_tenant.id), "plan": "starter", "period": "monthly"},
    }
    fake_event = MagicMock()
    fake_event.id = "evt_test_tg_fail"
    fake_event.type = "checkout.session.completed"
    fake_event.data.object = fake_session

    with patch("stripe.Webhook.construct_event", return_value=fake_event):
        with patch("server.stripe_routes.notify_payment_event", new_callable=AsyncMock) as mock_notify:
            mock_notify.side_effect = Exception("Telegram API down")
            response = client.post(
                "/webhooks/stripe",
                content=b'{}',
                headers={"Stripe-Signature": "test_sig"},
            )

    assert response.status_code == 200


def test_findings_stats_surface_scans_dont_affect_confirmed(
    client, sample_tenant, sample_project, sample_hypothesis, test_db
):
    """Test that surface scan findings don't increment the 'confirmed' status count."""
    from datetime import datetime, timezone

    from database.models import ScanExecution

    scan = ScanExecution(
        execution_id="scan_confirmed_test",
        project_id=sample_project.id,
        tenant_id=sample_tenant.id,
        repo_name=sample_project.name,
        status="completed",
        findings=[
            {"severity": "critical", "title": "Surface Finding"},
        ],
        created_at=datetime.now(timezone.utc),
    )
    test_db.add(scan)
    test_db.commit()

    response = client.get("/findings/stats", headers=auth_headers(sample_tenant))
    assert response.status_code == 200
    data = response.json()
    # confirmed count should only reflect the sample_hypothesis (1), not surface scans
    assert data["by_status"]["confirmed"] == 1
    # scanner_detected should reflect surface scan findings
    assert data["by_status"]["scanner_detected"] >= 1


# --- Telegram notification & webhook installation tests ---


def test_github_webhook_installation_creates_tenant(client, test_db):
    """Test GitHub webhook installation event creates a tenant with correct fields."""
    from unittest.mock import AsyncMock, patch

    with patch("server.api.notify_app_installed", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = True
        payload = {
            "action": "created",
            "installation": {
                "id": 12345,
                "account": {"login": "acme-corp", "type": "Organization"},
            },
        }
        response = client.post(
            "/webhooks/github",
            json=payload,
            headers={
                "X-GitHub-Event": "installation",
                "X-Hub-Signature-256": "",
            },
        )
    assert response.status_code == 200
    data = response.json()
    assert data["event"] == "installation"
    assert data["action"] == "created"
    assert data["tenant_id"] is not None

    # Verify tenant was created in DB
    tenant = test_db.query(Tenant).filter(Tenant.installation_id == 12345).first()
    assert tenant is not None
    assert tenant.status == "pending"
    assert tenant.github_account_login == "acme-corp"
    assert tenant.github_account_type == "Organization"
    assert tenant.name == "github_acme-corp"

    # Verify notification was called
    mock_notify.assert_called_once()
    call_kwargs = mock_notify.call_args[1]
    assert call_kwargs["github_account"] == "acme-corp"
    assert call_kwargs["account_type"] == "Organization"
    assert call_kwargs["installation_id"] == 12345
    assert call_kwargs["tenant_id"] == tenant.id


def test_github_webhook_installation_idempotent(client, test_db):
    """Test that posting the same installation payload twice creates only one tenant."""
    payload = {
        "action": "created",
        "installation": {
            "id": 77777,
            "account": {"login": "repeat-org", "type": "Organization"},
        },
    }
    headers = {
        "X-GitHub-Event": "installation",
        "X-Hub-Signature-256": "",
    }
    from unittest.mock import AsyncMock, patch

    with patch("server.api.notify_app_installed", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = True
        response1 = client.post("/webhooks/github", json=payload, headers=headers)
        response2 = client.post("/webhooks/github", json=payload, headers=headers)

    assert response1.status_code == 200
    assert response2.status_code == 200

    tenants = test_db.query(Tenant).filter(Tenant.installation_id == 77777).all()
    assert len(tenants) == 1


def test_github_webhook_installation_deleted(client, test_db):
    """Test that 'deleted' action preserves the tenant."""
    tenant = Tenant(
        name="github_deleteme",
        installation_id=99999,
        status="active",
        github_account_login="deleteme",
        github_account_type="User",
    )
    test_db.add(tenant)
    test_db.commit()

    payload = {
        "action": "deleted",
        "installation": {
            "id": 99999,
            "account": {"login": "deleteme", "type": "User"},
        },
    }
    response = client.post(
        "/webhooks/github",
        json=payload,
        headers={
            "X-GitHub-Event": "installation",
            "X-Hub-Signature-256": "",
        },
    )
    assert response.status_code == 200

    # Tenant should still exist
    preserved = test_db.query(Tenant).filter(Tenant.installation_id == 99999).first()
    assert preserved is not None
    assert preserved.status == "active"


def test_list_installation_repos_returns_tenant_installation_repos(client, test_db, sample_tenant):
    """Installation repo endpoint should use the tenant installation token."""
    from unittest.mock import patch

    sample_tenant.installation_id = 12345
    project = Project(
        tenant_id=sample_tenant.id,
        name="existing",
        git_url="https://github.com/acme-corp/existing.git",
        github_repo_id=111,
        status="active",
        created_at=datetime.now(timezone.utc),
        last_accessed=datetime.now(timezone.utc),
    )
    test_db.add(project)
    test_db.commit()

    fake_client = FakeAsyncClient(responses=[
        FakeGitHubResponse({
            "total_count": 2,
            "repositories": [
                {
                    "id": 111,
                    "name": "existing",
                    "full_name": "acme-corp/existing",
                    "private": True,
                    "default_branch": "main",
                    "html_url": "https://github.com/acme-corp/existing",
                    "updated_at": "2026-03-17T00:00:00Z",
                },
                {
                    "id": 222,
                    "name": "new-repo",
                    "full_name": "acme-corp/new-repo",
                    "private": True,
                    "default_branch": "main",
                    "html_url": "https://github.com/acme-corp/new-repo",
                    "updated_at": "2026-03-17T00:00:00Z",
                },
            ],
        })
    ])

    with patch("integrations.github_auth.get_installation_token", return_value="inst_token"):
        with patch("server.api.httpx.AsyncClient", return_value=fake_client):
            response = client.get("/github/installation-repos", headers=auth_headers(sample_tenant))

    assert response.status_code == 200
    data = response.json()
    assert data["total_count"] == 2
    assert len(data["repos"]) == 2
    assert data["repos"][0]["already_added"] is True
    assert data["repos"][1]["already_added"] is False


def test_create_repository_sends_notification(client, test_db, sample_tenant):
    """Test that POST /repositories sends notify_repo_added with correct kwargs."""
    from unittest.mock import AsyncMock, patch

    sample_tenant.github_account_login = "testacct"
    test_db.commit()

    with patch("server.api.notify_repo_added", new_callable=AsyncMock) as mock_notify:
        mock_notify.return_value = True
        response = client.post(
            "/repositories",
            json={
                "name": "my-contract",
                "full_name": "testacct/my-contract",
                "git_url": "https://github.com/testacct/my-contract",
                "default_branch": "main",
            },
            headers=auth_headers(sample_tenant),
        )
    assert response.status_code == 201

    mock_notify.assert_called_once()
    call_kwargs = mock_notify.call_args[1]
    assert call_kwargs["repo_name"] == "my-contract"
    assert call_kwargs["repo_url"] == "https://github.com/testacct/my-contract"
    assert call_kwargs["github_account"] == "testacct"
    assert call_kwargs["tenant_id"] == sample_tenant.id
    assert call_kwargs["full_name"] == "testacct/my-contract"


def test_create_repository_uses_tenant_installation_id_for_project_and_autoscan(client, test_db, sample_tenant):
    """Repository creation should persist tenant installation_id and pass it to the worker."""
    from unittest.mock import AsyncMock, MagicMock, patch

    sample_tenant.installation_id = 77777
    test_db.commit()

    with patch("server.api.notify_repo_added", new_callable=AsyncMock):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            mock_module = sys.modules["worker.tasks"]
            mock_module.execute_scan_task = MagicMock()

            response = client.post(
                "/repositories",
                json={
                    "name": "org-repo",
                    "full_name": "acme-corp/org-repo",
                    "git_url": "https://github.com/acme-corp/org-repo.git",
                    "default_branch": "main",
                    "is_private": True,
                },
                headers=auth_headers(sample_tenant),
            )

    assert response.status_code == 201
    project = test_db.query(Project).filter(Project.name == "org-repo").first()
    assert project is not None
    assert project.installation_id == 77777
    call_kwargs = mock_module.execute_scan_task.delay.call_args.kwargs
    assert call_kwargs["installation_id"] == 77777


def test_create_repository_autoscan_uses_github_user_id_without_installation(
    client, test_db, github_user
):
    """Autoscan should pass the acting GitHub user id when no installation exists."""
    from unittest.mock import AsyncMock, MagicMock, patch

    # User needs repo scope for private repo auto-scan
    github_user.github_token_scopes = "repo,read:org,read:user,user:email"
    test_db.commit()

    with patch("server.api.notify_repo_added", new_callable=AsyncMock):
        with patch.dict("sys.modules", {"worker.tasks": MagicMock()}):
            import sys
            mock_module = sys.modules["worker.tasks"]
            mock_module.execute_scan_task = MagicMock()

            response = client.post(
                "/repositories",
                json={
                    "name": "oauth-private-repo",
                    "full_name": "testuser/oauth-private-repo",
                    "git_url": "https://github.com/testuser/oauth-private-repo",
                    "default_branch": "main",
                    "is_private": True,
                },
                headers=github_auth_headers(github_user),
            )

    assert response.status_code == 201
    call_kwargs = mock_module.execute_scan_task.delay.call_args.kwargs
    assert call_kwargs["installation_id"] is None
    assert call_kwargs["github_user_id"] == github_user.id


def test_github_webhook_installation_signed(client, test_db):
    """Test that webhook signature verification works end-to-end."""
    import hashlib
    import hmac as hmac_mod
    import json

    from unittest.mock import AsyncMock, patch

    secret = "test-webhook-secret"
    payload = {
        "action": "created",
        "installation": {
            "id": 55555,
            "account": {"login": "signed-org", "type": "Organization"},
        },
    }
    body = json.dumps(payload).encode()
    sig = hmac_mod.new(secret.encode(), body, hashlib.sha256).hexdigest()

    import server.api as api_module

    original_secret = api_module.GITHUB_WEBHOOK_SECRET
    api_module.GITHUB_WEBHOOK_SECRET = secret
    try:
        with patch("server.api.notify_app_installed", new_callable=AsyncMock) as mock_notify:
            mock_notify.return_value = True
            # Valid signature → 200
            response = client.post(
                "/webhooks/github",
                content=body,
                headers={
                    "X-GitHub-Event": "installation",
                    "X-Hub-Signature-256": f"sha256={sig}",
                    "Content-Type": "application/json",
                },
            )
        assert response.status_code == 200
        tenant = test_db.query(Tenant).filter(Tenant.installation_id == 55555).first()
        assert tenant is not None
        assert tenant.github_account_login == "signed-org"

        # Bad signature → 401
        response_bad = client.post(
            "/webhooks/github",
            content=body,
            headers={
                "X-GitHub-Event": "installation",
                "X-Hub-Signature-256": "sha256=badsignature",
                "Content-Type": "application/json",
            },
        )
        assert response_bad.status_code == 401
    finally:
        api_module.GITHUB_WEBHOOK_SECRET = original_secret
