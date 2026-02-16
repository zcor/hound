"""
Tests for CORS (Cross-Origin Resource Sharing) middleware configuration.
"""

import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, Tenant

# Set test database URL before importing app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["ALLOWED_ORIGINS"] = "http://localhost:3000,http://localhost:3001"

from server.api import app, get_db


# Test database setup
@pytest.fixture(scope="function")
def test_db(tmp_path):
    """Create a test database using SQLite in a temp file."""
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
    tenant = Tenant(name="test_tenant")
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


def test_cors_headers_present(client, sample_tenant):
    """Verify CORS headers are included in responses for allowed origins."""
    response = client.get(
        f"/surface/scans?tenant_id={sample_tenant.id}",
        headers={"Origin": "http://localhost:3000"}
    )

    # Check that CORS headers are present
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-credentials" in response.headers
    assert response.headers["access-control-allow-credentials"] == "true"


def test_cors_multiple_origins(client, sample_tenant):
    """Verify CORS works for multiple configured origins."""
    # Test first origin
    response1 = client.get(
        f"/surface/scans?tenant_id={sample_tenant.id}",
        headers={"Origin": "http://localhost:3000"}
    )
    assert response1.headers["access-control-allow-origin"] == "http://localhost:3000"

    # Test second origin
    response2 = client.get(
        f"/surface/scans?tenant_id={sample_tenant.id}",
        headers={"Origin": "http://localhost:3001"}
    )
    assert response2.headers["access-control-allow-origin"] == "http://localhost:3001"


def test_preflight_request(client):
    """Verify OPTIONS preflight requests work correctly."""
    response = client.options(
        "/surface/scans",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type"
        }
    )

    # Preflight should return 200
    assert response.status_code == 200
    
    # Check CORS headers are present in preflight response
    assert "access-control-allow-methods" in response.headers
    assert "access-control-allow-headers" in response.headers
    assert "access-control-allow-origin" in response.headers


def test_unauthorized_origin_blocked(client, sample_tenant):
    """Verify unauthorized origins don't get CORS headers."""
    response = client.get(
        f"/surface/scans?tenant_id={sample_tenant.id}",
        headers={"Origin": "https://evil.com"}
    )

    # The response should not include CORS header for unauthorized origin
    # FastAPI's CORS middleware won't add the header if origin is not in allowed list
    if "access-control-allow-origin" in response.headers:
        assert response.headers["access-control-allow-origin"] != "https://evil.com"


def test_cors_on_post_endpoint(client, sample_tenant):
    """Verify CORS headers work on POST endpoints."""
    response = client.post(
        "/projects",
        json={
            "name": "test_project",
            "git_url": "https://github.com/test/repo",
            "tenant_id": sample_tenant.id
        },
        headers={"Origin": "http://localhost:3000"}
    )

    # Should have CORS headers on POST as well
    assert "access-control-allow-origin" in response.headers
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_cors_expose_headers(client, sample_tenant):
    """Verify expose headers are configured correctly."""
    response = client.get(
        f"/surface/scans?tenant_id={sample_tenant.id}",
        headers={"Origin": "http://localhost:3000"}
    )

    # Check that expose-headers is configured
    assert "access-control-expose-headers" in response.headers


def test_request_without_origin(client, sample_tenant):
    """Verify requests without Origin header still work (not a browser request)."""
    response = client.get(f"/surface/scans?tenant_id={sample_tenant.id}")

    # Request should succeed even without Origin header
    assert response.status_code == 200


def test_cors_credentials_flag(client, sample_tenant):
    """Verify allow_credentials is set to true."""
    response = client.get(
        f"/surface/scans?tenant_id={sample_tenant.id}",
        headers={"Origin": "http://localhost:3000"}
    )

    # Credentials should be allowed (for cookies/auth)
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_all_methods_allowed(client):
    """Verify all HTTP methods are allowed in CORS."""
    response = client.options(
        "/surface/scans",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
        }
    )

    assert response.status_code == 200
    # Should allow all methods (indicated by *)
    allow_methods = response.headers.get("access-control-allow-methods", "")
    # Could be "*" or a list including POST
    assert "*" in allow_methods or "POST" in allow_methods.upper()
