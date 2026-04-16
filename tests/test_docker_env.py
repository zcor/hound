"""Structural test: critical env vars must be in docker-compose.yml.

This test exists because STRIPE_WEBHOOK_SECRET was in .env but not in
docker-compose.yml for 31 days (Feb 28 - Mar 29, 2026), causing all
Stripe webhooks to silently fail signature verification.

If this test had existed when Stripe billing was added, it would have
caught the missing env var immediately.
"""

from pathlib import Path

import yaml


HOUND_ROOT = Path(__file__).parent.parent


# Env vars that MUST be in docker-compose.yml api service.
# If code reads them and they're missing from compose, the container gets
# empty strings and features silently break.
CRITICAL_API_VARS = {
    # Stripe — webhook outage root cause
    "STRIPE_SECRET_KEY",
    "STRIPE_WEBHOOK_SECRET",
    "STRIPE_LIVE_CONFIRMED",
    # Database & infrastructure
    "DATABASE_URL",
    "REDIS_URL",
    # Auth
    "JWT_SECRET_KEY",
    "HOUND_ADMIN_KEY",
    "HOUND_SECRET_KEY",
    # GitHub OAuth
    "GITHUB_CLIENT_ID",
    "GITHUB_CLIENT_SECRET",
    # CORS
    "HOUND_ALLOWED_ORIGINS",
    # Token encryption
    "TOKEN_ENCRYPTION_KEY",
    # Telegram
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
}


def _parse_compose_env_vars(service_name: str) -> set[str]:
    """Extract env var names from a docker-compose.yml service."""
    compose_path = HOUND_ROOT / "docker-compose.yml"
    with open(compose_path) as f:
        compose = yaml.safe_load(f)

    service = compose.get("services", {}).get(service_name, {})
    env_section = service.get("environment", {})

    if isinstance(env_section, dict):
        return set(env_section.keys())
    elif isinstance(env_section, list):
        # Handle list format: ["KEY=value", ...]
        return {item.split("=", 1)[0] for item in env_section if "=" in item}
    return set()


def test_critical_env_vars_in_api_service():
    """All critical env vars must be passed through in docker-compose.yml api service."""
    compose_vars = _parse_compose_env_vars("api")
    missing = CRITICAL_API_VARS - compose_vars
    assert not missing, (
        f"Critical env vars missing from docker-compose.yml api service: {sorted(missing)}. "
        f"These vars are read by code via os.environ.get() but not passed to the container. "
        f"Add them to the api service environment section."
    )


def test_worker_has_telegram_vars():
    """Worker needs Telegram vars for funnel digest and stripe health tasks."""
    compose_vars = _parse_compose_env_vars("worker")
    required = {"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"}
    missing = required - compose_vars
    assert not missing, (
        f"Worker missing Telegram env vars: {sorted(missing)}. "
        f"Required for funnel digest and stripe health alert tasks."
    )


def test_beat_has_required_vars():
    """Beat scheduler needs database and Redis connectivity."""
    compose_vars = _parse_compose_env_vars("beat")
    required = {"DATABASE_URL", "REDIS_URL", "CELERY_BROKER_URL"}
    missing = required - compose_vars
    assert not missing, f"Beat missing required env vars: {sorted(missing)}"


# -----------------------------------------------------------------------------
# Lifecycle email funnel — SendGrid env vars must be wired to api/worker/beat
# -----------------------------------------------------------------------------

# Rationale: same Stripe-incident pattern. If SENDGRID_* vars are in .env but
# not in docker-compose.yml environment section, containers get empty strings
# and all lifecycle emails silently fail. api dispatches event-driven emails
# (WELCOME_*, DEEP_AUDIT_DONE) and serves the unsubscribe endpoint. worker runs
# the lifecycle tick + retry task. beat schedules them.

SENDGRID_LIFECYCLE_VARS = {
    "SENDGRID_API_KEY",
    "SENDGRID_FROM_EMAIL",
    "SENDGRID_FROM_NAME",
    "SENDGRID_REPLY_TO",
    "SENDGRID_TEMPLATE_ID_DEFAULT",
    "API_BASE_URL",
}


def test_api_has_sendgrid_lifecycle_vars():
    compose_vars = _parse_compose_env_vars("api")
    missing = SENDGRID_LIFECYCLE_VARS - compose_vars
    assert not missing, (
        f"API service missing lifecycle email env vars: {sorted(missing)}. "
        f"Without these, WELCOME_VERIFY/WELCOME_VERIFIED/DEEP_AUDIT_DONE dispatches and "
        f"the unsubscribe endpoint will silently fail with empty-string config."
    )


def test_worker_has_sendgrid_lifecycle_vars():
    compose_vars = _parse_compose_env_vars("worker")
    missing = SENDGRID_LIFECYCLE_VARS - compose_vars
    assert not missing, (
        f"Worker service missing lifecycle email env vars: {sorted(missing)}. "
        f"Worker runs run_lifecycle_tick_task + retry_failed_lifecycle_emails_task; "
        f"without these, Beat-driven lifecycle emails (GETTING_STARTED, FIRST_SCAN_CELEBRATION) silently fail."
    )


def test_beat_has_sendgrid_lifecycle_vars():
    compose_vars = _parse_compose_env_vars("beat")
    missing = SENDGRID_LIFECYCLE_VARS - compose_vars
    assert not missing, (
        f"Beat service missing lifecycle email env vars: {sorted(missing)}. "
        f"Beat imports worker tasks at startup (including run_lifecycle_tick_task) — "
        f"SendGrid env must be present even though Beat itself doesn't call SendGrid."
    )
