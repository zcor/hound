"""
Tests for the FastAPI server endpoints.
"""

import json
import os
from datetime import datetime
from pathlib import Path

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
)

# Set test database URL before importing app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db, get_engine


# Test database setup
@pytest.fixture(scope="function")
def test_db():
    """Create a test database using SQLite in-memory."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
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
    api_module.get_engine = override_get_engine
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Restore original
    app.dependency_overrides.clear()
    api_module.get_engine = original_get_engine


@pytest.fixture
def sample_tenant(test_db):
    """Create a sample tenant for testing."""
    tenant = Tenant(name="test_tenant")
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


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
        created_at=datetime.utcnow(),
        last_accessed=datetime.utcnow(),
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
        start_time=datetime.utcnow(),
        end_time=datetime.utcnow(),
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
    response = client.get("/projects")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_list_projects_with_data(client, sample_project):
    """Test listing projects with existing data."""
    response = client.get("/projects")
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


def test_list_project_sessions_empty(client, sample_project):
    """Test listing sessions for a project with no sessions."""
    response = client.get(f"/projects/{sample_project.id}/sessions")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_list_project_sessions_with_data(client, sample_project, sample_session):
    """Test listing sessions for a project with existing sessions."""
    response = client.get(f"/projects/{sample_project.id}/sessions")
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
    response = client.get("/projects/999/sessions")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_get_session_graph(client, sample_session, sample_graph):
    """Test getting graph data for a session."""
    response = client.get(f"/sessions/{sample_session.session_id}/graph")
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
    response = client.get("/sessions/nonexistent_session/graph")
    assert response.status_code == 404


def test_get_session_findings_empty(client, sample_session):
    """Test getting findings for a session with no confirmed hypotheses."""
    response = client.get(f"/sessions/{sample_session.session_id}/findings")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_get_session_findings_with_data(client, sample_session, sample_hypothesis):
    """Test getting findings for a session with confirmed hypotheses."""
    response = client.get(f"/sessions/{sample_session.session_id}/findings")
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
    response = client.get("/sessions/nonexistent_session/findings")
    assert response.status_code == 404


def test_websocket_connection(client, sample_session):
    """Test WebSocket connection for session logs."""
    with client.websocket_connect(f"/ws/sessions/{sample_session.session_id}") as websocket:
        # Should receive connection confirmation
        data = websocket.receive_json()
        assert data["type"] == "connected"
        assert data["session_id"] == sample_session.session_id
        assert "timestamp" in data

        # Send a test message
        websocket.send_text("test message")

        # Should receive echo (placeholder implementation)
        response = websocket.receive_json()
        assert response["type"] == "echo"
        assert response["data"] == "test message"


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
def test_create_project_validation(client, sample_tenant, project_data, expected_status):
    """Test project creation with various input validations."""
    response = client.post("/projects", json=project_data)
    assert response.status_code == expected_status


def test_projects_with_stats(client, sample_project, sample_graph, sample_session, sample_hypothesis):
    """Test that project list includes correct statistics."""
    response = client.get("/projects")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1

    project = data[0]
    assert project["graphs_count"] == 1
    assert project["sessions_count"] == 1
    assert project["hypotheses_count"] == 1
    assert project["confirmed_count"] == 1
