"""Tests for the /t page view beacon endpoint."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from database.models import Base, PageView

# Use in-memory SQLite with StaticPool for cross-thread sharing
_test_engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(bind=_test_engine)


def _get_test_db():
    db = TestSession()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def setup_db():
    """Create tables before each test, drop after."""
    Base.metadata.create_all(_test_engine)
    yield
    Base.metadata.drop_all(_test_engine)


@pytest.fixture
def client():
    """Create a test client with overridden DB dependency and engine."""
    from fastapi.testclient import TestClient

    import server.api as api_module
    from server.api import app, get_db

    # Override both the dependency and the global engine (prevents get_engine()
    # from creating its own SQLite/Postgres engine on first request)
    old_engine = api_module._engine
    api_module._engine = _test_engine
    app.dependency_overrides[get_db] = _get_test_db
    yield TestClient(app)
    app.dependency_overrides.pop(get_db, None)
    api_module._engine = old_engine


def _count_page_views():
    db = TestSession()
    count = db.query(PageView).count()
    db.close()
    return count


def _get_first_page_view():
    db = TestSession()
    row = db.query(PageView).first()
    db.close()
    return row


def test_beacon_creates_page_view(client):
    """Valid beacon request creates a PageView row."""
    response = client.post(
        "/t",
        json={"p": "/pricing", "r": "https://google.com", "v": "550e8400-e29b-41d4-a716-446655440000"},
        headers={"Origin": "https://firepan.com"},
    )
    assert response.status_code == 204
    assert _count_page_views() == 1
    row = _get_first_page_view()
    assert row.path == "/pricing"
    assert row.referrer == "https://google.com"
    assert row.visitor_id == "550e8400-e29b-41d4-a716-446655440000"


def test_beacon_returns_204_on_malformed_json(client):
    """Malformed JSON returns 204 (silent drop)."""
    response = client.post(
        "/t",
        content="not json",
        headers={"Content-Type": "application/json", "Origin": "https://firepan.com"},
    )
    assert response.status_code == 204
    assert _count_page_views() == 0


def test_beacon_rejects_invalid_path(client):
    """Path not starting with / is silently dropped."""
    response = client.post(
        "/t",
        json={"p": "no-leading-slash", "v": "550e8400-e29b-41d4-a716-446655440000"},
        headers={"Origin": "https://firepan.com"},
    )
    assert response.status_code == 204
    assert _count_page_views() == 0


def test_beacon_truncates_long_fields(client):
    """Fields exceeding max length are truncated."""
    long_path = "/" + "a" * 600
    response = client.post(
        "/t",
        json={"p": long_path, "r": "x" * 1500, "v": "550e8400-e29b-41d4-a716-446655440000"},
        headers={"Origin": "https://firepan.com"},
    )
    assert response.status_code == 204
    row = _get_first_page_view()
    assert row is not None
    assert len(row.path) <= 500
    assert len(row.referrer) <= 1000


def test_beacon_rejects_bad_origin(client):
    """Non-firepan origin is silently dropped."""
    response = client.post(
        "/t",
        json={"p": "/", "v": "550e8400-e29b-41d4-a716-446655440000"},
        headers={"Origin": "https://evilfirepan.com"},
    )
    assert response.status_code == 204
    assert _count_page_views() == 0


def test_beacon_allows_subdomain_origin(client):
    """Subdomain *.firepan.com is allowed."""
    response = client.post(
        "/t",
        json={"p": "/welcome", "v": "550e8400-e29b-41d4-a716-446655440000"},
        headers={"Origin": "https://app.firepan.com"},
    )
    assert response.status_code == 204
    assert _count_page_views() == 1


def test_beacon_invalid_visitor_id_stored_as_null(client):
    """Short or invalid visitor_id is stored as NULL."""
    response = client.post(
        "/t",
        json={"p": "/", "v": "short"},
        headers={"Origin": "https://firepan.com"},
    )
    assert response.status_code == 204
    row = _get_first_page_view()
    assert row is not None
    assert row.visitor_id is None


def test_beacon_no_origin_header_allowed(client):
    """Request with no Origin header is allowed (same-origin sendBeacon)."""
    response = client.post(
        "/t",
        json={"p": "/", "v": "550e8400-e29b-41d4-a716-446655440000"},
    )
    assert response.status_code == 204
    assert _count_page_views() == 1
