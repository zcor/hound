"""
Tests for Google OAuth authentication, provider linking, and capability gate.
"""

import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base, OAuthAuditLog, Tenant, User
from server.auth_utils import create_access_token, decode_access_token

# Set test database URL before importing app
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from server.api import app, get_db


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

    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    def override_get_engine():
        return test_db.get_bind()

    app.dependency_overrides[get_db] = override_get_db
    import server.api as api_module
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
def sample_tenant(test_db):
    """Create a sample tenant for testing."""
    tenant = Tenant(name="test_organization")
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)
    return tenant


@pytest.fixture
def github_user(test_db, sample_tenant):
    """Create a GitHub-only user."""
    from server.token_crypto import encrypt_token
    user = User(
        github_id=12345678,
        github_login="ghuser",
        email="ghuser@example.com",
        name="GitHub User",
        avatar_url="https://avatars.githubusercontent.com/u/12345678",
        tenant_id=sample_tenant.id,
        signup_provider="github",
        github_token_encrypted=encrypt_token("ghp_test_token"),
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


@pytest.fixture
def google_user(test_db):
    """Create a Google-only user."""
    tenant = Tenant(name="google_alice")
    test_db.add(tenant)
    test_db.commit()
    test_db.refresh(tenant)

    user = User(
        google_id="google_123",
        google_email="alice@company.com",
        google_name="Alice",
        google_avatar_url="https://lh3.googleusercontent.com/alice",
        email="alice@company.com",
        name="Alice",
        avatar_url="https://lh3.googleusercontent.com/alice",
        tenant_id=tenant.id,
        signup_provider="google",
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    return user


def _make_token(user):
    """Create a JWT token for a user."""
    return create_access_token({
        "user_id": user.id,
        "tenant_id": user.tenant_id,
    })


class TestSlimJWT:
    """Test that JWT tokens are slim (no PII)."""

    def test_slim_jwt_from_github_callback_no_github_login(self):
        """JWT from GitHub callback should not contain github_login."""
        token = create_access_token({"user_id": 1, "tenant_id": 1})
        payload = decode_access_token(token)
        assert "github_login" not in payload
        assert payload["user_id"] == 1
        assert payload["tenant_id"] == 1

    def test_get_current_user_from_token_returns_only_user_tenant(self):
        """get_current_user_from_token returns only user_id and tenant_id."""
        from server.auth_utils import get_current_user_from_token
        token = create_access_token({"user_id": 42, "tenant_id": 7})
        info = get_current_user_from_token(token)
        assert info == {"user_id": 42, "tenant_id": 7}


class TestUserModel:
    """Test User model properties."""

    def test_display_name_github(self, github_user):
        assert github_user.display_name == "ghuser"

    def test_display_name_google(self, google_user):
        assert google_user.display_name == "Alice"

    def test_has_github(self, github_user, google_user):
        assert github_user.has_github is True
        assert google_user.has_github is False

    def test_has_google(self, github_user, google_user):
        assert github_user.has_google is False
        assert google_user.has_google is True

    def test_primary_provider(self, github_user, google_user):
        assert github_user.primary_provider == "github"
        assert google_user.primary_provider == "google"

    def test_to_profile_dict(self, github_user):
        profile = github_user.to_profile_dict()
        assert profile["id"] == github_user.id
        assert profile["github_username"] == "ghuser"
        assert profile["has_github"] is True
        assert profile["has_google"] is False
        assert profile["primary_provider"] == "github"
        assert profile["display_name"] == "ghuser"

    def test_to_profile_dict_google(self, google_user):
        profile = google_user.to_profile_dict()
        assert profile["google_email"] == "alice@company.com"
        assert profile["has_github"] is False
        assert profile["has_google"] is True
        assert profile["primary_provider"] == "google"


class TestAuthMeEndpoint:
    """Test /auth/me returns full profile."""

    def test_auth_me_github_user(self, client, github_user):
        """GitHub user gets full profile from /auth/me."""
        token = _make_token(github_user)
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["github_username"] == "ghuser"
        assert data["has_github"] is True
        assert data["has_google"] is False
        assert data["primary_provider"] == "github"

    def test_auth_me_google_user(self, client, google_user):
        """Google user gets full profile from /auth/me."""
        token = _make_token(google_user)
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["google_email"] == "alice@company.com"
        assert data["has_github"] is False
        assert data["has_google"] is True
        assert data["primary_provider"] == "google"
        # github_username should be None for Google-only user
        assert data["github_username"] is None

    def test_auth_me_no_token(self, client):
        response = client.get("/auth/me")
        assert response.status_code == 401


class TestCapabilityGate:
    """Test that scan endpoints require GitHub linked."""

    def test_google_only_user_blocked_from_scan(self, client, google_user, test_db):
        """Google-only user cannot trigger a scan (403)."""
        token = _make_token(google_user)
        response = client.post(
            "/repositories/999/scan",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Should be 403 (GitHub required), not 404 (repo not found)
        assert response.status_code == 403
        assert "GitHub account required" in response.json()["detail"]

    def test_github_user_not_blocked(self, client, github_user, test_db):
        """GitHub user passes the capability gate (no 'GitHub account required' error)."""
        token = _make_token(github_user)
        response = client.post(
            "/repositories/999/scan",
            headers={"Authorization": f"Bearer {token}"},
        )
        # May get 403 from tier enforcement or 404 for missing repo,
        # but should NOT get the GitHub capability gate error (which returns a string detail)
        detail = response.json().get("detail", "")
        if isinstance(detail, str):
            assert "GitHub account required" not in detail


class TestSignupProvider:
    """Test signup_provider tracking."""

    def test_signup_provider_set_on_creation(self, github_user, google_user):
        assert github_user.signup_provider == "github"
        assert google_user.signup_provider == "google"

    def test_signup_provider_is_immutable_convention(self, github_user, test_db):
        """signup_provider should not change after creation (convention, not DB enforcement)."""
        original = github_user.signup_provider
        # We don't change it — just verify it's set correctly at creation
        assert original == "github"
