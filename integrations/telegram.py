"""
Telegram bot integration for FirePan notifications.

Sends notifications to the FirePan internal Telegram group when
important events occur (e.g., new repository synced, waitlist signup).
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

# Telegram configuration from environment
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# Telegram API base URL
TELEGRAM_API_BASE = "https://api.telegram.org"


async def send_telegram_message(
    message: str,
    chat_id: str | None = None,
    parse_mode: str = "HTML",
    disable_notification: bool = False,
) -> bool:
    """
    Send a message to a Telegram chat.

    Args:
        message: The message text to send (supports HTML formatting)
        chat_id: Target chat ID (defaults to TELEGRAM_CHAT_ID env var)
        parse_mode: Message parse mode ("HTML" or "Markdown")
        disable_notification: If True, send silently without notification

    Returns:
        True if message was sent successfully, False otherwise
    """
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return False

    if not TELEGRAM_BOT_TOKEN:
        logger.warning("TELEGRAM_BOT_TOKEN not configured - skipping notification")
        return False

    target_chat = chat_id or TELEGRAM_CHAT_ID
    if not target_chat:
        logger.warning("No chat_id provided and TELEGRAM_CHAT_ID not configured")
        return False

    url = f"{TELEGRAM_API_BASE}/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": target_chat,
        "text": message,
        "parse_mode": parse_mode,
        "disable_notification": disable_notification,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            result = response.json()

            if result.get("ok"):
                logger.info(f"Telegram message sent to chat {target_chat}")
                return True
            else:
                logger.error(f"Telegram API error: {result.get('description')}")
                return False

    except httpx.TimeoutException:
        logger.error("Telegram API request timed out")
        return False
    except httpx.HTTPStatusError as e:
        logger.error(f"Telegram API HTTP error: {e.response.status_code}")
        return False
    except Exception as e:
        logger.exception(f"Failed to send Telegram message: {e}")
        return False


async def notify_new_repo_synced(
    github_account: str,
    account_type: str,
    email: str | None = None,
    tenant_id: int | None = None,
    installation_id: int | None = None,
    repos: list[str] | None = None,
) -> bool:
    """
    Send notification when a new GitHub repository is synced.

    Args:
        github_account: GitHub username or organization name
        account_type: "User" or "Organization"
        email: Contact email if provided
        tenant_id: Database tenant ID
        installation_id: GitHub App installation ID
        repos: List of repository full names (e.g., ["owner/repo1", "owner/repo2"])

    Returns:
        True if notification was sent successfully
    """
    # Build the notification message
    emoji = "👤" if account_type == "User" else "🏢"

    # Create clickable GitHub link if we have a real account name
    if github_account.startswith("installation_"):
        account_display = _escape_html(github_account)
    else:
        account_display = f'<a href="https://github.com/{_escape_html(github_account)}">{_escape_html(github_account)}</a>'

    message_parts = [
        "🔥 <b>New Waitlist Signup!</b>",
        "",
        f"{emoji} <b>Account:</b> {account_display}",
        f"📋 <b>Type:</b> {account_type}",
    ]

    if email:
        message_parts.append(f"📧 <b>Email:</b> {_escape_html(email)}")

    if repos:
        repo_lines = []
        for repo in repos:
            if repo == "...":
                repo_lines.append("  • ...")
            else:
                repo_lines.append(f'  • <a href="https://github.com/{_escape_html(repo)}">{_escape_html(repo)}</a>')
        message_parts.append("📦 <b>Repos:</b>\n" + "\n".join(repo_lines))

    if tenant_id:
        message_parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")

    message = "\n".join(message_parts)
    return await send_telegram_message(message)


async def notify_repo_added(
    repo_name: str,
    repo_url: str,
    github_account: str | None = None,
    tenant_id: int | None = None,
    full_name: str | None = None,
) -> bool:
    """
    Send notification when an existing user adds a repository.

    Args:
        repo_name: Repository name (e.g., "my-contract")
        repo_url: Git URL or HTTPS URL of the repo
        github_account: GitHub username or org that owns the repo
        tenant_id: Database tenant ID
        full_name: Full repo name (e.g., "acme/my-contract")

    Returns:
        True if notification was sent successfully
    """
    display_name = full_name or repo_name
    # Build clickable repo link
    repo_link = f'<a href="{_escape_html(repo_url)}">{_escape_html(display_name)}</a>' if repo_url else _escape_html(display_name)

    message_parts = [
        "📦 <b>Repo Added!</b>",
        "",
        f"📁 <b>Repo:</b> {repo_link}",
    ]

    if github_account:
        account_link = f'<a href="https://github.com/{_escape_html(github_account)}">{_escape_html(github_account)}</a>'
        message_parts.append(f"👤 <b>Account:</b> {account_link}")

    if tenant_id:
        message_parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")

    message = "\n".join(message_parts)
    return await send_telegram_message(message)


async def notify_app_installed(
    github_account: str,
    account_type: str,
    tenant_id: int | None = None,
    installation_id: int | None = None,
) -> bool:
    """
    Send notification when someone installs the GitHub App via webhook.

    Args:
        github_account: GitHub username or organization name
        account_type: "User" or "Organization"
        tenant_id: Database tenant ID (if created)
        installation_id: GitHub App installation ID

    Returns:
        True if notification was sent successfully
    """
    emoji = "👤" if account_type == "User" else "🏢"
    account_link = f'<a href="https://github.com/{_escape_html(github_account)}">{_escape_html(github_account)}</a>'

    message_parts = [
        "🔥 <b>New GitHub App Install!</b>",
        "",
        f"{emoji} <b>Account:</b> {account_link}",
        f"📋 <b>Type:</b> {account_type}",
    ]

    if tenant_id:
        message_parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")

    if installation_id:
        message_parts.append(f"🔧 <b>Installation ID:</b> {installation_id}")

    message = "\n".join(message_parts)
    return await send_telegram_message(message)


async def notify_payment_event(
    event_type: str,
    tenant_name: str | None = None,
    tenant_id: int | None = None,
    customer_id: str | None = None,
    event_id: str | None = None,
    plan: str | None = None,
    period: str | None = None,
    scans_granted: int | None = None,
    invoice_id: str | None = None,
) -> bool:
    """
    Send a Telegram notification for a Stripe payment event.

    Returns True if the message was sent successfully.
    """
    templates = {
        "subscription_created": {
            "header": "\U0001f4b0 <b>New Subscriber!</b>",
            "fields": ["tenant", "plan", "period", "customer_id", "event_id", "tenant_id"],
        },
        "credit_purchase": {
            "header": "\U0001f4b3 <b>Credit Purchase!</b>",
            "fields": ["tenant", "scans_granted", "customer_id", "event_id", "tenant_id"],
        },
        "subscription_updated": {
            "header": "\U0001f504 <b>Plan Changed!</b>",
            "fields": ["tenant", "plan", "period", "customer_id", "event_id", "tenant_id"],
        },
        "subscription_deleted": {
            "header": "\u26a0\ufe0f <b>Subscription Canceled</b>",
            "fields": ["tenant", "customer_id", "event_id", "tenant_id"],
        },
        "payment_failed": {
            "header": "\U0001f6a8 <b>Payment Failed!</b>",
            "fields": ["tenant", "invoice_id", "customer_id", "event_id", "tenant_id"],
        },
    }

    template = templates.get(event_type)
    if not template:
        logger.warning("Unknown payment event type: %s", event_type)
        return False

    field_renderers = {
        "tenant": lambda: f"\U0001f3e2 <b>Tenant:</b> {_escape_html(str(tenant_name or 'Unknown'))}",
        "plan": lambda: f"\U0001f4cb <b>Plan:</b> {_escape_html(str(plan or 'N/A'))}",
        "period": lambda: f"\U0001f4c5 <b>Period:</b> {_escape_html(str(period or 'N/A'))}",
        "customer_id": lambda: f"\U0001f194 <b>Customer:</b> {_escape_html(str(customer_id or 'N/A'))}",
        "event_id": lambda: f"\U0001f50d <b>Event:</b> {_escape_html(str(event_id or 'N/A'))}",
        "tenant_id": lambda: f"\U0001f522 <b>Tenant ID:</b> {tenant_id}",
        "scans_granted": lambda: f"\U0001f4e6 <b>Scans:</b> +{scans_granted}",
        "invoice_id": lambda: f"\U0001f9fe <b>Invoice:</b> {_escape_html(str(invoice_id or 'N/A'))}",
    }

    parts = [template["header"], ""]
    for field in template["fields"]:
        renderer = field_renderers.get(field)
        if renderer:
            parts.append(renderer())

    message = "\n".join(parts)
    return await send_telegram_message(message)


async def notify_deep_audit_started(
    repo_url: str,
    session_id: str,
    tenant_id: int | None = None,
    project_name: str | None = None,
    mode: str | None = None,
) -> bool:
    """
    Send notification when a deep audit is started/queued.

    Args:
        repo_url: Repository URL being audited
        session_id: Audit session ID
        tenant_id: Tenant ID that initiated the audit
        project_name: Human-readable project name (optional)
        mode: Audit mode (e.g., "sweep", "targeted")

    Returns:
        True if notification was sent successfully
    """
    repo_display = f'<a href="{_escape_html(repo_url)}">{_escape_html(repo_url)}</a>' if repo_url.startswith("http") else _escape_html(repo_url)

    message_parts = [
        "🔬 <b>Deep Scan Started</b>",
        "",
        f"📁 <b>Repo:</b> {repo_display}",
    ]

    if project_name:
        message_parts.append(f"📋 <b>Project:</b> {_escape_html(project_name)}")

    message_parts.append(f"🔑 <b>Session:</b> <code>{_escape_html(session_id)}</code>")

    if mode:
        message_parts.append(f"⚙️ <b>Mode:</b> {_escape_html(mode)}")

    if tenant_id is not None:
        message_parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")

    message = "\n".join(message_parts)
    return await send_telegram_message(message)


async def notify_deep_audit_completed(
    repo_url: str,
    session_id: str,
    tenant_id: int | None = None,
    status: str = "completed",
    findings_count: int | None = None,
    risk_level: str | None = None,
    risk_score: float | None = None,
    assessment_level: str | None = None,
    error_message: str | None = None,
    project_name: str | None = None,
) -> bool:
    """
    Send notification when a deep audit completes (success or failure).

    Args:
        repo_url: Repository URL that was audited
        session_id: Audit session ID
        tenant_id: Tenant ID
        status: "completed" or "failed"
        findings_count: Number of findings (success only)
        risk_level: Raw risk level (e.g., "high", "medium")
        risk_score: Numeric risk score
        assessment_level: Curated assessment from deep audit overview (preferred over risk_level)
        error_message: Error details (failure only)
        project_name: Human-readable project name (optional)

    Returns:
        True if notification was sent successfully
    """
    repo_display = f'<a href="{_escape_html(repo_url)}">{_escape_html(repo_url)}</a>' if repo_url.startswith("http") else _escape_html(repo_url)

    if status in ("completed", "in_review"):
        header = "✅ <b>Deep Scan Complete</b>"
    else:
        header = "❌ <b>Deep Scan Failed</b>"

    message_parts = [
        header,
        "",
        f"📁 <b>Repo:</b> {repo_display}",
    ]

    if project_name:
        message_parts.append(f"📋 <b>Project:</b> {_escape_html(project_name)}")

    if status in ("completed", "in_review"):
        if findings_count is not None:
            message_parts.append(f"🔍 <b>Findings:</b> {findings_count}")

        # Prefer curated assessment_level over raw risk_level
        display_level = assessment_level or risk_level
        if display_level:
            message_parts.append(f"⚠️ <b>Assessment:</b> {_escape_html(str(display_level))}")

        if risk_score is not None:
            message_parts.append(f"📊 <b>Risk Score:</b> {risk_score}")
    else:
        if error_message:
            message_parts.append(f"💥 <b>Error:</b> {_escape_html(str(error_message))}")

    message_parts.append(f"🔑 <b>Session:</b> <code>{_escape_html(session_id)}</code>")

    if tenant_id is not None:
        message_parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")

    message = "\n".join(message_parts)
    return await send_telegram_message(message)


async def notify_deep_audit_flagged(
    repo_url: str,
    session_id: str,
    tenant_id: int | None,
    reason: str,
    findings_count: int | None = None,
    project_name: str | None = None,
) -> bool:
    """
    Alert ops when a deep audit's confirmed findings look like a template-FP storm
    (firepan-ygy). Pages to the standard ops Telegram so a human can intervene before
    the scan gets casually verified.

    Args:
        repo_url: Repository URL that was audited
        session_id: Audit session ID
        tenant_id: Tenant ID (for dashboard lookup)
        reason: Human-readable reason the scan was flagged
        findings_count: Total confirmed findings (context, optional)
        project_name: Human-readable project name (optional)
    """
    repo_display = (
        f'<a href="{_escape_html(repo_url)}">{_escape_html(repo_url)}</a>'
        if repo_url.startswith("http") else _escape_html(repo_url)
    )
    parts = [
        "🚨 <b>Deep Scan Flagged for Manual Review</b>",
        "",
        f"📁 <b>Repo:</b> {repo_display}",
    ]
    if project_name:
        parts.append(f"📋 <b>Project:</b> {_escape_html(project_name)}")
    if findings_count is not None:
        parts.append(f"🔍 <b>Confirmed findings:</b> {findings_count}")
    parts.append(f"⚠️ <b>Reason:</b> {_escape_html(reason)}")
    parts.append(f"🔑 <b>Session:</b> <code>{_escape_html(session_id)}</code>")
    if tenant_id is not None:
        parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")
    return await send_telegram_message("\n".join(parts))


async def notify_funnel_digest(
    period_label: str,
    visitors_7d: int,
    visitors_unique_7d: int,
    signups_7d: int,
    scans_7d: int,
    new_paid_7d: int,
    visitors_30d: int,
    visitors_unique_30d: int,
    signups_30d: int,
    scans_30d: int,
    new_paid_30d: int,
    active_paid: int,
    ever_paid: int,
    total_users: int,
    total_scans: int,
) -> bool:
    """Send weekly funnel digest to internal Telegram channel."""

    def _pct(num: int, denom: int) -> str:
        if denom == 0:
            return "N/A"
        return f"{num / denom * 100:.1f}%"

    message = (
        f"\U0001f4ca <b>Weekly Funnel Digest</b>\n"
        f"{_escape_html(period_label)}\n"
        f"\n"
        f"<b>Funnel (7d / 30d):</b>\n"
        f"\U0001f310 Page views:      {visitors_7d} / {visitors_30d}\n"
        f"\U0001f464 Unique visitors:  {visitors_unique_7d} / {visitors_unique_30d}\n"
        f"\U0001f4dd Signups:          {signups_7d} / {signups_30d}\n"
        f"\U0001f52c Scans started:    {scans_7d} / {scans_30d}\n"
        f"\U0001f4b0 New paid:         {new_paid_7d} / {new_paid_30d}\n"
        f"\n"
        f"<b>Conversion (7d):</b>\n"
        f"  Visit \u2192 Signup:  {_pct(signups_7d, visitors_unique_7d)}\n"
        f"  Signup \u2192 Scan:   {_pct(scans_7d, signups_7d)}\n"
        f"  Scan \u2192 Paid:    {_pct(new_paid_7d, scans_7d)}\n"
        f"\n"
        f"<b>Totals:</b>\n"
        f"  Active paid: {active_paid} | Ever paid: {ever_paid} | Users: {total_users} | Scans: {total_scans}"
    )
    return await send_telegram_message(message)


async def notify_stripe_webhook_stale(
    last_event_days_ago: int,
    monthly_paid_count: int,
    extra_issues: list[str] | None = None,
) -> bool:
    """Alert when Stripe webhook health check finds issues."""
    parts = [
        "\u26a0\ufe0f <b>Stripe Webhook Health Alert</b>",
        "",
        f"\U0001f4c5 <b>Last processed event:</b> {last_event_days_ago} days ago" if last_event_days_ago >= 0 else "\U0001f4c5 <b>Last processed event:</b> unknown",
        f"\U0001f4b3 <b>Monthly paid tenants:</b> {monthly_paid_count}" if monthly_paid_count >= 0 else "",
    ]

    if extra_issues:
        parts.append("")
        parts.append("<b>Issues:</b>")
        for issue in extra_issues:
            parts.append(f"  \u2022 {_escape_html(issue)}")

    parts.extend([
        "",
        "<b>Check:</b> <code>curl https://api.firepan.com/health/stripe</code>",
        "<b>Dashboard:</b> Stripe \u2192 Developers \u2192 Webhooks \u2192 Deliveries",
    ])

    message = "\n".join(p for p in parts if p is not None)
    return await send_telegram_message(message)


async def notify_daily_digest(
    stripe_status: str,
    beads_tasks: list[dict] | None = None,
    stripe_issues: list[str] | None = None,
    total_open: int | None = None,
) -> bool:
    """Daily team digest: one-line Stripe health + top Beads tasks.

    beads_tasks: pre-curated list (already filtered to non-P4, capped at ~5).
    total_open:  total count of open+in_progress+blocked (non-P4) for the
                 "N of M" header. If None, falls back to len(beads_tasks).
    """
    stripe_icon = "\u2705" if not stripe_issues else "\u26a0\ufe0f"
    parts = [
        "\U0001f4cb <b>Daily Digest</b>",
        "",
        f"{stripe_icon} <b>Stripe:</b> {_escape_html(stripe_status)}",
    ]
    if stripe_issues:
        for issue in stripe_issues:
            parts.append(f"  \u2022 {_escape_html(issue)}")

    # Beads tasks
    if beads_tasks:
        shown = len(beads_tasks)
        total = total_open if total_open is not None else shown
        parts.append("")
        parts.append(f"\U0001f4cc <b>Top Tasks ({shown} of {total})</b>")
        for task in beads_tasks:
            priority = task.get("priority", "")
            title = _escape_html(task.get("title", "untitled"))
            assignee = task.get("assignee", "")
            status = task.get("status", "open")
            p_label = f"P{priority}" if priority != "" else ""
            assignee_label = f" \u2022 {_escape_html(assignee)}" if assignee else ""
            if status == "in_progress":
                marker = "\u25b6"  # ▶
            elif status == "blocked":
                marker = "\u26d4"  # ⛔
            else:
                marker = "  "
            parts.append(f"  {marker} {p_label} {title}{assignee_label}")
        remaining = total - shown
        if remaining > 0:
            parts.append(f"  <i>... and {remaining} more</i>")
    elif beads_tasks is not None:
        parts.append("")
        parts.append("\U0001f4cc <b>Top Tasks:</b> no active tasks")
    else:
        parts.append("")
        parts.append("\U0001f4cc <b>Top Tasks:</b> <i>bd summary unavailable</i>")

    message = "\n".join(parts)
    return await send_telegram_message(message)


async def notify_contact_captured(
    tenant_id: int,
    tenant_name: str,
    email: str,
) -> bool:
    """Notify team when a user provides their contact email for the first time."""
    message_parts = [
        "📧 <b>Contact Email Captured!</b>",
        "",
        f"🆔 <b>Tenant ID:</b> {tenant_id}",
        f"👤 <b>Account:</b> {_escape_html(tenant_name)}",
        f"📧 <b>Email:</b> {_escape_html(email)}",
    ]
    message = "\n".join(message_parts)
    return await send_telegram_message(message)


def _escape_html(text: str) -> str:
    """Escape HTML special characters for Telegram HTML parse mode."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
