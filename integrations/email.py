"""
Email integration for FirePan notifications.

Uses SendGrid for transactional emails (audit completion, etc.).
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL", "noreply@firepan.com")
FROM_NAME = os.environ.get("SENDGRID_FROM_NAME", "FirePan")

SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"


async def send_email(
    to_email: str,
    subject: str,
    html_content: str,
) -> bool:
    """Send an email via SendGrid API.

    Returns True if sent successfully, False otherwise.
    """
    if not SENDGRID_API_KEY:
        logger.warning("SENDGRID_API_KEY not configured — skipping email")
        return False

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": FROM_EMAIL, "name": FROM_NAME},
        "subject": subject,
        "content": [{"type": "text/html", "value": html_content}],
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                SENDGRID_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {SENDGRID_API_KEY}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201, 202):
                logger.info("Email sent to %s: %s", to_email, subject)
                return True
            else:
                logger.error(
                    "SendGrid error %d: %s", response.status_code, response.text
                )
                return False
    except Exception:
        logger.exception("Failed to send email to %s", to_email)
        return False


async def send_audit_complete_email(
    to_email: str,
    project_name: str,
    findings_count: int,
    assessment_level: str | None = None,
    session_id: str | None = None,
) -> bool:
    """Send audit completion notification email."""
    assessment_text = assessment_level.upper() if assessment_level else "COMPLETE"
    dashboard_url = "https://app.firepan.com/audits"

    subject = f"FirePan Audit Complete: {project_name} — {assessment_text}"

    html_content = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #1a1a1a; margin-bottom: 4px;">Your Deep Audit is Ready</h2>
        <p style="color: #666; margin-top: 0;">Results for <strong>{project_name}</strong></p>

        <div style="background: #f8f9fa; border-radius: 8px; padding: 16px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 8px 0; color: #666;">Assessment</td>
                    <td style="padding: 8px 0; text-align: right; font-weight: 600;">{assessment_text}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; color: #666;">Findings</td>
                    <td style="padding: 8px 0; text-align: right; font-weight: 600;">{findings_count}</td>
                </tr>
            </table>
        </div>

        <a href="{dashboard_url}" style="display: inline-block; background: #2563eb; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600;">
            View Full Report
        </a>

        <p style="color: #999; font-size: 12px; margin-top: 30px;">
            FirePan — Continuous Smart Contract Security
        </p>
    </div>
    """

    return await send_email(to_email, subject, html_content)
