"""Tests for integrations.lifecycle_emails.

Focus areas matching the plan's Verification section:
  - Idempotency via (tenant_id, code, dedup_key) unique constraint
  - `email_unsubscribed` honored except when force_send=True
  - `email_verified` gating for codes with require_verified=True
  - `mutually_exclusive_with` prevents sibling welcome emails
  - `dispatch()` never retries failed rows inline
  - `attempt_count` incremented exactly once per SendGrid POST
  - `metadata_json` carries everything needed to resend byte-equivalent email

These tests mock `integrations.email.send_template_email` so nothing hits the
real SendGrid API.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from database.models import SentEmail, Tenant, User, create_db_engine, create_db_session, init_database
from integrations import lifecycle_emails as le
from integrations.lifecycle_emails import EmailCode

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _env(monkeypatch):
    """Ensure env vars are present for all tests (LIFECYCLE_CONFIG needs template_id)."""
    monkeypatch.setenv("SENDGRID_API_KEY", "SG.test")
    monkeypatch.setenv("SENDGRID_TEMPLATE_ID_DEFAULT", "d-test-template")
    monkeypatch.setenv("HOUND_SECRET_KEY", "test-secret-key-32-bytes-min-for-hmac")
    monkeypatch.setenv("API_BASE_URL", "http://localhost:8000")
    monkeypatch.setenv("FRONTEND_URL", "http://localhost:3000")


@pytest.fixture
def db():
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    init_database(engine)
    session = create_db_session(engine)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def tenant(db):
    t = Tenant(
        name="test_tenant",
        contact_email="test@example.com",
        email_verified=True,
        email_verified_at=datetime.now(timezone.utc),
        status="active",
    )
    db.add(t)
    db.flush()
    u = User(
        github_id=999,
        github_login="testuser",
        email="test@example.com",
        name="Test User",
        tenant_id=t.id,
        signup_provider="github",
    )
    db.add(u)
    db.commit()
    db.refresh(t)
    return t


@pytest.fixture
def fake_send():
    """Replace send_template_email with a successful AsyncMock."""
    mock = AsyncMock(return_value=(True, None))
    with patch("integrations.lifecycle_emails.send_template_email", mock):
        yield mock


@pytest.fixture
def fake_send_fail():
    """Replace send_template_email with a failing AsyncMock."""
    mock = AsyncMock(return_value=(False, "SendGrid 500: simulated transient"))
    with patch("integrations.lifecycle_emails.send_template_email", mock):
        yield mock


def _run(coro):
    """Run an async coroutine synchronously without closing the module-level loop.

    Matches the pattern used by tests/test_telegram.py — using asyncio.run() here
    would close the default event loop and break other tests in the same session.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_dispatch_sends_and_records(db, tenant, fake_send):
    result = _run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result == "sent"
    fake_send.assert_called_once()
    rows = db.query(SentEmail).filter_by(tenant_id=tenant.id).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.code == EmailCode.GETTING_STARTED.value
    assert row.status == "sent"
    assert row.attempt_count == 1
    assert row.sent_at is not None
    assert row.send_error is None
    # metadata_json captures resend payload
    assert row.metadata_json is not None
    assert row.metadata_json["to_email"] == "test@example.com"
    assert "extra_data" in row.metadata_json


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_duplicate_dispatch_returns_duplicate(db, tenant, fake_send):
    _ = asyncio.run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    result2 = asyncio.run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result2 == "duplicate"
    # Only one SendGrid call
    assert fake_send.call_count == 1
    rows = db.query(SentEmail).filter_by(tenant_id=tenant.id).all()
    assert len(rows) == 1


def test_different_dedup_keys_send_separately(db, tenant, fake_send):
    """DEEP_AUDIT_DONE pattern: each audit session is its own dedup key."""
    r1 = _run(le.dispatch(
        EmailCode.DEEP_AUDIT_DONE, tenant, db,
        dedup_key="audit:session_aaa",
        extra_data={"project_name": "p", "findings_count": 3, "assessment_level": "LOW", "session_id": "aaa"},
    ))
    r2 = _run(le.dispatch(
        EmailCode.DEEP_AUDIT_DONE, tenant, db,
        dedup_key="audit:session_bbb",
        extra_data={"project_name": "p", "findings_count": 5, "assessment_level": "HIGH", "session_id": "bbb"},
    ))
    assert r1 == "sent"
    assert r2 == "sent"
    assert fake_send.call_count == 2
    rows = db.query(SentEmail).filter_by(tenant_id=tenant.id).order_by(SentEmail.id).all()
    assert len(rows) == 2
    assert {r.dedup_key for r in rows} == {"audit:session_aaa", "audit:session_bbb"}


# ---------------------------------------------------------------------------
# Unsubscribe + verified gating
# ---------------------------------------------------------------------------

def test_unsubscribed_tenant_skipped_for_lifecycle(db, tenant, fake_send):
    tenant.email_unsubscribed = True
    db.commit()
    result = _run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result == "skipped"
    fake_send.assert_not_called()


def test_unsubscribed_tenant_still_receives_force_send(db, tenant, fake_send):
    tenant.email_unsubscribed = True
    db.commit()
    result = _run(le.dispatch(
        EmailCode.DEEP_AUDIT_DONE, tenant, db,
        dedup_key="audit:x",
        extra_data={"project_name": "p", "findings_count": 1, "assessment_level": "LOW", "session_id": "x"},
        force_send=True,
    ))
    assert result == "sent"
    fake_send.assert_called_once()


def test_require_verified_skipped_for_unverified(db, fake_send):
    t = Tenant(
        name="unverified",
        contact_email="u@example.com",
        email_verified=False,
        status="active",
    )
    db.add(t)
    db.commit()
    result = _run(le.dispatch(
        EmailCode.GETTING_STARTED, t, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result == "skipped"
    fake_send.assert_not_called()


def test_welcome_verify_sends_for_unverified(db, fake_send):
    """WELCOME_VERIFY is the verify-me email — it must send even when email_verified=False."""
    t = Tenant(
        name="github_user",
        contact_email="new@example.com",
        email_verified=False,
        status="active",
    )
    db.add(t)
    db.commit()
    result = _run(le.dispatch(
        EmailCode.WELCOME_VERIFY, t, db,
        dedup_key=EmailCode.WELCOME_VERIFY.value,
    ))
    assert result == "sent"


def test_missing_contact_email_skipped(db, fake_send):
    t = Tenant(name="no_email", status="active")
    db.add(t)
    db.commit()
    result = _run(le.dispatch(
        EmailCode.WELCOME_VERIFY, t, db,
        dedup_key=EmailCode.WELCOME_VERIFY.value,
    ))
    assert result == "skipped"


# ---------------------------------------------------------------------------
# Mutually exclusive welcome siblings
# ---------------------------------------------------------------------------

def test_welcome_verified_blocked_when_welcome_verify_already_sent(db, tenant, fake_send):
    """After WELCOME_VERIFY sends, WELCOME_VERIFIED must skip (mutually exclusive)."""
    _run(le.dispatch(
        EmailCode.WELCOME_VERIFY, tenant, db,
        dedup_key=EmailCode.WELCOME_VERIFY.value,
    ))
    result = _run(le.dispatch(
        EmailCode.WELCOME_VERIFIED, tenant, db,
        dedup_key=EmailCode.WELCOME_VERIFIED.value,
    ))
    assert result == "skipped"
    assert fake_send.call_count == 1


# ---------------------------------------------------------------------------
# Failed send + invariant: dispatch() does not retry failed rows inline
# ---------------------------------------------------------------------------

def test_failed_send_marks_row_failed(db, tenant, fake_send_fail):
    result = _run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result == "failed"
    row = db.query(SentEmail).filter_by(tenant_id=tenant.id).one()
    assert row.status == "failed"
    assert row.attempt_count == 1
    assert row.send_error and "SendGrid" in row.send_error


def test_dispatch_does_not_retry_failed_rows(db, tenant, fake_send_fail):
    """Invariant #1: dispatch() never retries status='failed' rows inline."""
    result1 = asyncio.run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result1 == "failed"
    assert fake_send_fail.call_count == 1

    # Second dispatch attempt with the same key should return "duplicate" —
    # NOT "sent" or "failed" from a retry.
    result2 = asyncio.run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    assert result2 == "duplicate"
    # No extra SendGrid POST — only the initial failed attempt
    assert fake_send_fail.call_count == 1
    # attempt_count stayed at 1 — helper was the only writer and only ran once
    row = db.query(SentEmail).filter_by(tenant_id=tenant.id).one()
    assert row.attempt_count == 1
    assert row.status == "failed"


# ---------------------------------------------------------------------------
# metadata_json contract (invariant #4)
# ---------------------------------------------------------------------------

def test_metadata_json_snapshots_resend_payload(db, tenant, fake_send):
    extra = {"project_name": "curve-finance/curve-contract", "session_id": "scan_123",
             "findings_count": 12, "assessment_level": "HIGH"}
    _run(le.dispatch(
        EmailCode.DEEP_AUDIT_DONE, tenant, db,
        dedup_key="audit:scan_123",
        extra_data=extra,
        force_send=True,
    ))
    row = db.query(SentEmail).filter_by(dedup_key="audit:scan_123").one()
    # All three pieces the retry task needs to reconstruct the email
    assert row.metadata_json["extra_data"] == extra
    assert row.metadata_json["force_send"] is True
    assert row.metadata_json["to_email"] == "test@example.com"


def test_to_email_snapshotted_at_send_time(db, tenant, fake_send):
    """If tenant.contact_email changes later, retries still go to the original address."""
    _run(le.dispatch(
        EmailCode.GETTING_STARTED, tenant, db,
        dedup_key=EmailCode.GETTING_STARTED.value,
    ))
    # Simulate a tenant renaming their contact email
    tenant.contact_email = "changed@example.com"
    db.commit()
    row = db.query(SentEmail).filter_by(tenant_id=tenant.id).one()
    assert row.metadata_json["to_email"] == "test@example.com"  # original snapshot


# ---------------------------------------------------------------------------
# Escape contract — body_content is raw HTML passthrough in the template,
# so extra_data fields substituted into the body MUST be HTML-escaped to
# prevent script injection. Subject/CTA fields are plain text — they keep
# apostrophes raw (template uses triple-braces for subject too).
# ---------------------------------------------------------------------------

def test_body_escapes_extra_data_to_prevent_html_injection(db, tenant, fake_send):
    """A malicious project_name must not inject HTML into the rendered body."""
    _run(le.dispatch(
        EmailCode.DEEP_AUDIT_DONE, tenant, db,
        dedup_key="audit:evil",
        extra_data={
            "project_name": "<script>alert(1)</script>",
            "session_id": "evil",
            "findings_count": 0,
            "assessment_level": "LOW",
        },
        force_send=True,
    ))
    fake_send.assert_called_once()
    _args, kwargs = fake_send.call_args
    body = kwargs["dynamic_data"]["body_content"]
    assert "<script>" not in body, "body_content must HTML-escape user-controlled fields"
    assert "&lt;script&gt;" in body, "expected HTML-entity-encoded script tag"


def test_subject_and_cta_not_double_escaped(db, tenant, fake_send):
    """Subject / cta_label stay plain text — apostrophes should pass through, not become `&#x27;`."""
    _run(le.dispatch(
        EmailCode.FIRST_SCAN_CELEBRATION, tenant, db,
        dedup_key=EmailCode.FIRST_SCAN_CELEBRATION.value,
    ))
    fake_send.assert_called_once()
    _args, kwargs = fake_send.call_args
    data = kwargs["dynamic_data"]
    # The subject is "You haven't actually used Firepan yet." — apostrophe must
    # render as a real apostrophe, not as `&#x27;` or `&apos;`.
    assert "haven't" in data["subject_line"]
    assert "&apos;" not in data["subject_line"]
    assert "&#x27;" not in data["subject_line"]


# ---------------------------------------------------------------------------
# first_name resolution
# ---------------------------------------------------------------------------

def test_resolve_first_name_variants():
    u1 = User(github_id=1, name="Gerrit Hall", tenant_id=1, signup_provider="github")
    assert le.resolve_first_name(u1) == "Gerrit"

    u2 = User(google_id="g", google_name="Alice Smith", tenant_id=1, signup_provider="google")
    assert le.resolve_first_name(u2) == "Alice"

    u3 = User(github_id=3, github_login="someuser", tenant_id=1, signup_provider="github")
    assert le.resolve_first_name(u3) == "someuser"

    u4 = User(github_id=4, tenant_id=1, signup_provider="github")
    assert le.resolve_first_name(u4) == "there"

    assert le.resolve_first_name(None) == "there"


# ---------------------------------------------------------------------------
# Unsubscribe token round-trip
# ---------------------------------------------------------------------------

def test_unsubscribe_token_roundtrip():
    token = le.build_unsubscribe_token(42)
    assert le.verify_unsubscribe_token(token) == 42


def test_unsubscribe_token_rejects_tampering():
    token = le.build_unsubscribe_token(42)
    # Flip a character somewhere in the middle
    if len(token) > 10:
        tampered = token[:5] + ("A" if token[5] != "A" else "B") + token[6:]
        assert le.verify_unsubscribe_token(tampered) is None


def test_unsubscribe_token_rejects_garbage():
    assert le.verify_unsubscribe_token("") is None
    assert le.verify_unsubscribe_token("!!!not-base64!!!") is None
    assert le.verify_unsubscribe_token("YWJjLmRlZi5naGk=") is None  # valid b64 but bad shape
