"""Tests for Telegram notification functions."""

import asyncio

from unittest.mock import AsyncMock, patch

from integrations.telegram import notify_payment_event, _escape_html


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
