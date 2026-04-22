"""
Email integration for FirePan notifications.

Uses SendGrid for transactional emails (audit completion, etc.).
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)


def _env(name: str, default: str | None = None) -> str | None:
    """Read env at call time, not import time.

    Celery workers, FastAPI workers, and scripts all import this module at
    different times. Reading at import time means changes to os.environ after
    dotenv-loading don't propagate.
    """
    return os.environ.get(name, default)


SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"


async def send_email(
    to_email: str,
    subject: str,
    html_content: str,
) -> bool:
    """Send an email via SendGrid API.

    Returns True if sent successfully, False otherwise.
    """
    api_key = _env("SENDGRID_API_KEY")
    from_email = _env("SENDGRID_FROM_EMAIL", "noreply@firepan.com")
    from_name = _env("SENDGRID_FROM_NAME", "Firepan Team")
    if not api_key:
        logger.warning("SENDGRID_API_KEY not configured — skipping email")
        return False

    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_email, "name": from_name},
        "subject": subject,
        "content": [{"type": "text/html", "value": html_content}],
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                SENDGRID_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
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


async def send_template_email(
    to_email: str,
    template_id: str,
    dynamic_data: dict,
    *,
    categories: list[str] | None = None,
    custom_args: dict | None = None,
) -> tuple[bool, str | None]:
    """Send a Dynamic Template email via SendGrid API.

    All lifecycle emails go through this function. Subject is controlled by the
    template's `subject: {{subject_line}}` configuration (we don't set a top-level
    subject here — it would override the template).

    Returns (success, error_message). On success, error_message is None. On
    failure, error_message is a short description suitable for `SentEmail.send_error`.
    """
    api_key = _env("SENDGRID_API_KEY")
    from_email = _env("SENDGRID_FROM_EMAIL", "noreply@firepan.com")
    from_name = _env("SENDGRID_FROM_NAME", "Firepan Team")
    reply_to = _env("SENDGRID_REPLY_TO", "support@firepan.com")

    if not api_key:
        logger.warning("SENDGRID_API_KEY not configured — skipping template email")
        return False, "SENDGRID_API_KEY not configured"
    if not template_id:
        logger.error("No template_id provided for send_template_email")
        return False, "no template_id provided"

    payload: dict = {
        "personalizations": [{
            "to": [{"email": to_email}],
            "dynamic_template_data": dynamic_data,
        }],
        "from": {"email": from_email, "name": from_name},
        "reply_to": {"email": reply_to},
        "template_id": template_id,
    }
    if categories:
        payload["categories"] = categories
    if custom_args:
        # SendGrid custom_args must be strings
        payload["custom_args"] = {k: str(v) for k, v in custom_args.items()}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                SENDGRID_API_URL,
                json=payload,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
            )
            if response.status_code in (200, 201, 202):
                logger.info(
                    "Template email sent to %s (template=%s, categories=%s)",
                    to_email, template_id, categories,
                )
                return True, None
            else:
                err = f"SendGrid {response.status_code}: {response.text[:500]}"
                logger.error(err)
                return False, err
    except Exception as exc:
        logger.exception("Failed to send template email to %s", to_email)
        return False, f"exception: {type(exc).__name__}: {exc}"


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
        <h2 style="color: #1a1a1a; margin-bottom: 4px;">Your Deep Scan is Ready</h2>
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
