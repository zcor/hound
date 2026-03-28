"""Tests for Telegram notification functions."""

import asyncio

from unittest.mock import AsyncMock, patch

from integrations.telegram import (
    notify_payment_event,
    notify_repo_added,
    notify_app_installed,
    notify_deep_audit_started,
    notify_deep_audit_completed,
    notify_funnel_digest,
    _escape_html,
)


def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


def test_subscription_created():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="subscription_created",
            tenant_name="Acme Corp",
            tenant_id=42,
            customer_id="cus_abc123",
            event_id="evt_xyz789",
            plan="professional",
            period="annual",
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "New Subscriber!" in msg
    assert "Acme Corp" in msg
    assert "professional" in msg
    assert "annual" in msg
    assert "cus_abc123" in msg
    assert "evt_xyz789" in msg
    assert "42" in msg


def test_credit_purchase():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="credit_purchase",
            tenant_name="Beta Inc",
            tenant_id=7,
            customer_id="cus_def456",
            event_id="evt_aaa111",
            scans_granted=50,
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "Credit Purchase!" in msg
    assert "Beta Inc" in msg
    assert "+50" in msg
    assert "cus_def456" in msg


def test_subscription_updated():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="subscription_updated",
            tenant_name="Gamma LLC",
            tenant_id=99,
            customer_id="cus_ghi789",
            event_id="evt_bbb222",
            plan="enterprise",
            period="monthly",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "Plan Changed!" in msg
    assert "enterprise" in msg
    assert "monthly" in msg


def test_subscription_deleted():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="subscription_deleted",
            tenant_name="Delta Co",
            tenant_id=3,
            customer_id="cus_jkl012",
            event_id="evt_ccc333",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "Subscription Canceled" in msg
    assert "Delta Co" in msg


def test_payment_failed():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="payment_failed",
            tenant_name="Epsilon Ltd",
            tenant_id=5,
            customer_id="cus_mno345",
            event_id="evt_ddd444",
            invoice_id="in_eee555",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "Payment Failed!" in msg
    assert "in_eee555" in msg


def test_unknown_event_type():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="unknown_event",
            tenant_name="Test",
        ))
    assert result is False
    mock_send.assert_not_called()


def test_html_escaping():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_payment_event(
            event_type="subscription_created",
            tenant_name="<script>alert('xss')</script>",
            tenant_id=1,
            customer_id="cus_test",
            event_id="evt_test",
            plan="starter",
            period="monthly",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "<script>" not in msg
    assert "&lt;script&gt;" in msg


def test_escape_html_helper():
    assert _escape_html("a < b & c > d") == "a &lt; b &amp; c &gt; d"
    assert _escape_html("normal text") == "normal text"


def test_notify_repo_added():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_repo_added(
            repo_name="my-contract",
            repo_url="https://github.com/acme/my-contract",
            github_account="acme",
            tenant_id=22,
            full_name="acme/my-contract",
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "Repo Added!" in msg
    assert "acme/my-contract" in msg
    assert "acme" in msg
    assert "22" in msg
    # Should NOT contain waitlist language
    assert "Waitlist" not in msg
    assert "GitHub App Install" not in msg


def test_notify_repo_added_minimal():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_repo_added(
            repo_name="my-repo",
            repo_url="https://github.com/user/my-repo",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "Repo Added!" in msg
    assert "my-repo" in msg
    # No account or tenant_id lines
    assert "Account:" not in msg
    assert "Tenant ID:" not in msg


def test_notify_app_installed():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_app_installed(
            github_account="acme-corp",
            account_type="Organization",
            tenant_id=23,
            installation_id=98765,
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "GitHub App Install!" in msg
    assert "acme-corp" in msg
    assert "Organization" in msg
    assert "23" in msg
    assert "98765" in msg
    # Should NOT contain waitlist or repo-added language
    assert "Waitlist" not in msg
    assert "Repo Added!" not in msg


def test_notify_app_installed_minimal():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_app_installed(
            github_account="solo-dev",
            account_type="User",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "GitHub App Install!" in msg
    assert "solo-dev" in msg
    assert "User" in msg
    # No tenant_id or installation_id lines
    assert "Tenant ID:" not in msg
    assert "Installation ID:" not in msg


def test_notify_deep_audit_started():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_deep_audit_started(
            repo_url="https://github.com/acme/contracts",
            session_id="sess-abc123",
            tenant_id=42,
            project_name="Acme Contracts",
            mode="sweep",
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "Deep Audit Started" in msg
    assert "acme/contracts" in msg
    assert "sess-abc123" in msg
    assert "42" in msg
    assert "Acme Contracts" in msg
    assert "sweep" in msg


def test_notify_deep_audit_started_minimal():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_deep_audit_started(
            repo_url="https://github.com/user/repo",
            session_id="sess-xyz",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "Deep Audit Started" in msg
    assert "sess-xyz" in msg
    # No optional fields
    assert "Project:" not in msg
    assert "Mode:" not in msg
    assert "Tenant ID:" not in msg


def test_notify_deep_audit_completed_success():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_deep_audit_completed(
            repo_url="https://github.com/acme/contracts",
            session_id="sess-abc123",
            tenant_id=42,
            status="completed",
            findings_count=15,
            risk_level="high",
            risk_score=78.5,
            assessment_level="Needs Attention",
            project_name="Acme Contracts",
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "Deep Audit Complete" in msg
    assert "acme/contracts" in msg
    assert "15" in msg
    # assessment_level preferred over risk_level
    assert "Needs Attention" in msg
    assert "78.5" in msg
    assert "42" in msg
    assert "Acme Contracts" in msg
    # Should NOT contain failure language
    assert "Failed" not in msg
    assert "Error:" not in msg


def test_notify_deep_audit_completed_success_fallback_risk():
    """When assessment_level is None, falls back to risk_level."""
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_deep_audit_completed(
            repo_url="https://github.com/acme/repo",
            session_id="sess-999",
            status="completed",
            findings_count=3,
            risk_level="medium",
            risk_score=45.0,
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "medium" in msg
    assert "45.0" in msg


def test_notify_deep_audit_completed_failure():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_deep_audit_completed(
            repo_url="https://github.com/acme/contracts",
            session_id="sess-abc123",
            tenant_id=42,
            status="failed",
            error_message="Time limit exceeded",
            project_name="Acme Contracts",
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "Deep Audit Failed" in msg
    assert "Time limit exceeded" in msg
    assert "acme/contracts" in msg
    assert "42" in msg
    # Should NOT contain success language
    assert "Findings:" not in msg
    assert "Risk Score:" not in msg


def test_notify_deep_audit_completed_html_escaping():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_deep_audit_completed(
            repo_url="https://github.com/test/repo",
            session_id="sess-test",
            status="failed",
            error_message="<script>alert('xss')</script>",
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "<script>" not in msg
    assert "&lt;script&gt;" in msg


def test_notify_funnel_digest():
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_funnel_digest(
            period_label="Week of Mar 21\u2013Mar 28",
            visitors_7d=142,
            visitors_unique_7d=89,
            signups_7d=3,
            scans_7d=5,
            new_paid_7d=0,
            visitors_30d=580,
            visitors_unique_30d=312,
            signups_30d=9,
            scans_30d=18,
            new_paid_30d=1,
            active_paid=1,
            ever_paid=1,
            total_users=13,
            total_scans=20,
        ))
    assert result is True
    mock_send.assert_called_once()
    msg = mock_send.call_args[0][0]
    assert "Weekly Funnel Digest" in msg
    assert "Mar 21" in msg
    assert "142" in msg
    assert "89" in msg
    assert "580" in msg
    assert "3.4%" in msg  # Visit -> Signup: 3/89
    assert "Active paid: 1" in msg
    assert "Users: 13" in msg


def test_notify_funnel_digest_zero_division():
    """Conversion percentages handle zero denominators gracefully."""
    with patch("integrations.telegram.send_telegram_message", new_callable=AsyncMock) as mock_send:
        mock_send.return_value = True
        result = _run(notify_funnel_digest(
            period_label="Week of Mar 21\u2013Mar 28",
            visitors_7d=0,
            visitors_unique_7d=0,
            signups_7d=0,
            scans_7d=0,
            new_paid_7d=0,
            visitors_30d=0,
            visitors_unique_30d=0,
            signups_30d=0,
            scans_30d=0,
            new_paid_30d=0,
            active_paid=0,
            ever_paid=0,
            total_users=0,
            total_scans=0,
        ))
    assert result is True
    msg = mock_send.call_args[0][0]
    assert "N/A" in msg
