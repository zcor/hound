"""
Telegram bot integration for FirePan notifications.

Sends notifications to the FirePan internal Telegram group when
important events occur (e.g., new repository synced, waitlist signup).
"""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Telegram configuration from environment
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

# Telegram API base URL
TELEGRAM_API_BASE = "https://api.telegram.org"


async def send_telegram_message(
    message: str,
    chat_id: Optional[str] = None,
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
    email: Optional[str] = None,
    tenant_id: Optional[int] = None,
    installation_id: Optional[int] = None,
) -> bool:
    """
    Send notification when a new GitHub repository is synced.

    Args:
        github_account: GitHub username or organization name
        account_type: "User" or "Organization"
        email: Contact email if provided
        tenant_id: Database tenant ID
        installation_id: GitHub App installation ID

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
        f"🔥 <b>New Waitlist Signup!</b>",
        f"",
        f"{emoji} <b>Account:</b> {account_display}",
        f"📋 <b>Type:</b> {account_type}",
    ]

    if email:
        message_parts.append(f"📧 <b>Email:</b> {_escape_html(email)}")

    if installation_id:
        # Link to GitHub App installation settings
        message_parts.append(f"🔗 <b>Installation:</b> <a href=\"https://github.com/settings/installations/{installation_id}\">{installation_id}</a>")

    if tenant_id:
        message_parts.append(f"🆔 <b>Tenant ID:</b> {tenant_id}")

    message = "\n".join(message_parts)
    return await send_telegram_message(message)


def _escape_html(text: str) -> str:
    """Escape HTML special characters for Telegram HTML parse mode."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
