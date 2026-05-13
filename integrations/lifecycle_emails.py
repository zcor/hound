"""Lifecycle email dispatcher for FirePan onboarding and nurture funnel.

Owns: "for this event + this tenant, send this email, idempotently."

Architecture (load-bearing invariants — do not violate):
  1. `dispatch()` NEVER retries failed rows. Request-path hooks attempt exactly
     one send; on `IntegrityError` against an existing `status='failed'` row,
     `dispatch()` returns `"duplicate"` and exits.
  2. Beat task `retry_failed_lifecycle_emails_task` owns ALL retry/backoff
     behavior via exponential backoff keyed on `last_attempt_at`.
  3. `_perform_send_and_update_status(row, tenant, db)` is the ONLY code that
     increments `attempt_count`. One SendGrid POST = one increment.
  4. `metadata_json` contains everything needed to resend byte-equivalent email
     content: `{"extra_data": {...}, "force_send": bool, "to_email": "..."}`.
     The retry task reconstructs the send from `metadata_json` alone.

See `/Users/gerrithall/.claude/plans/eventual-shimmying-flame.md` and Ian's
cadence source `tmp/firepan-email-cadences.md` for product context.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html as _html
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database.models import SentEmail, Tenant, User
from integrations.email import send_template_email

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# EmailCode enum — matches Ian's cadence in tmp/firepan-email-cadences.md
# ---------------------------------------------------------------------------

class EmailCode(str, Enum):
    # Ian #1 — event (signup), split by verification state
    WELCOME_VERIFY           = "01a_welcome_verify"           # GitHub path; copy: "verify your email"
    WELCOME_VERIFIED         = "01b_welcome_verified"         # Google path; copy: "you're in, here's what's next"
    # Ian #2 — Beat, 1h post-verify
    GETTING_STARTED          = "02_getting_started"
    # Ian #3 — Beat, 30min post-first-surface-scan (the paywall push)
    FIRST_SCAN_CELEBRATION   = "03_first_scan_celebration"
    # Ian #4-11 — follow-up PR
    CICD_INTEGRATION         = "04_cicd_integration"
    OBJECTION_HANDLING       = "05_objection_handling"
    MID_TRIAL_CHECKIN        = "06_mid_trial_checkin"
    TRIAL_3_DAYS_LEFT        = "07_trial_3_days_left"
    TRIAL_FINAL_CALL         = "08_trial_final_call"
    TRIAL_EXPIRED            = "09_trial_expired"
    EDUCATIONAL_D21          = "10_educational_d21"
    FINAL_WINBACK            = "11_final_winback"
    # Non-lifecycle transactional
    DEEP_AUDIT_DONE          = "tx_deep_audit_done"


# ---------------------------------------------------------------------------
# EmailSpec — per-code configuration (copy + behavior flags)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmailSpec:
    """Static config for one email code. All copy edits land here.

    `cta_url_template` is a Python format string (str.format) that receives
    dispatch-time `extra_data` as keyword args, e.g. `"{app_base}/audits/{session_id}"`.
    """
    subject_line: str
    hero_subtitle: str
    category: str
    body_content_html: str
    cta_label: str
    cta_url_template: str
    # Behavior flags
    require_verified: bool = False        # skip if tenant.email_verified=False
    force_send: bool = False              # ignore tenant.email_unsubscribed
    mutually_exclusive_with: tuple[EmailCode, ...] = ()  # don't send if any of these already sent


# ---------------------------------------------------------------------------
# Copy — sourced from tmp/firepan-email-cadences.md (Ian's Google Doc)
# ---------------------------------------------------------------------------
# Keep the inline HTML tight and free of per-email template tags — the master
# SendGrid design wraps everything with header/footer/unsubscribe. Only put
# hero copy + body paragraphs + optional P.S. here.
#
# STYLING NOTES (2026-04-16 — after the first send rendered unreadable):
#   - The SendGrid design uses a DARK theme: bg #0D0D0D, body text #CCCCCC,
#     muted #AAAAAA, accent #DEFF71.
#   - Ian's `{{{body_content}}}` slot is wrapped in an outer
#     `<p style="color:#CCCCCC">`. When our body HTML contains nested `<p>`
#     tags, Gmail / Outlook break out of the outer `<p>` and the inner ones
#     inherit nothing — rendering as near-invisible very-dark-grey text.
#   - Fix: do NOT wrap paragraphs in `<p>`. Use `<div style="margin:0 0 18px 0">`
#     blocks (block-level, colors can be set explicitly, no `<p>`-in-`<p>` issue).
#   - Every block sets an explicit color from the design palette so email
#     clients that strip the outer wrapper still render readably.
#   - Code blocks use a dark-mode-appropriate bg (#1A1A1A) and light text.

_TEXT_COLOR = "#CCCCCC"         # primary body
_MUTED_COLOR = "#AAAAAA"        # PS / sender footer (muted but still readable on #0D0D0D)
_ACCENT_COLOR = "#DEFF71"       # brand yellow accent
_BLOCK_STYLE = f"margin:0 0 18px 0; font-family:Arial,sans-serif; font-size:15px; color:{_TEXT_COLOR}; line-height:1.7;"
_MUTED_STYLE = f"margin:0 0 12px 0; font-family:Arial,sans-serif; font-size:14px; color:{_MUTED_COLOR}; line-height:1.6;"
_CODE_STYLE = "margin:0 0 18px 0; background:#1A1A1A; border:1px solid #2A2A2A; padding:12px 14px; border-radius:6px; font-family:'Space Mono',Consolas,monospace; font-size:13px; color:#E0E0E0; white-space:pre-wrap;"
_UL_STYLE = f"margin:0 0 18px 0; padding-left:22px; font-family:Arial,sans-serif; font-size:15px; color:{_TEXT_COLOR}; line-height:1.7;"

_WELCOME_VERIFY_BODY = f"""
<div style="{_BLOCK_STYLE}">Welcome to Firepan. You just signed up for the most important thing you can do for your protocol — continuous security monitoring that works as fast as you ship.</div>
<div style="{_BLOCK_STYLE}">Before you can run your first scan, one quick step: <strong style="color:#FFFFFF;">verify your email.</strong></div>
<div style="{_BLOCK_STYLE}">Once verified, you'll be able to:</div>
<ul style="{_UL_STYLE}">
  <li>Run a Surface Scan on your contracts in ~2 seconds</li>
  <li>Get a security score from 0–100 across your codebase</li>
  <li>See open vulnerabilities sorted by severity</li>
</ul>
<div style="{_BLOCK_STYLE}">Your trial is already running — most teams get value in the first 24 hours.</div>
<div style="{_MUTED_STYLE}">— The Firepan Team</div>
<div style="{_MUTED_STYLE}">P.S. If you have a Solidity or Vyper repo ready, installing the <a href="https://github.com/apps/firepan-ai" style="color:{_ACCENT_COLOR};">Firepan GitHub App</a> takes about 60 seconds and will automatically scan every PR going forward.</div>
"""

_WELCOME_VERIFIED_BODY = f"""
<div style="{_BLOCK_STYLE}">Welcome to Firepan. You just signed up for the most important thing you can do for your protocol — continuous security monitoring that works as fast as you ship.</div>
<div style="{_BLOCK_STYLE}">You're all set — let's get your contracts scan-ready.</div>
<div style="{_BLOCK_STYLE}">Once signed in, you'll be able to:</div>
<ul style="{_UL_STYLE}">
  <li>Run a Surface Scan on your contracts in ~2 seconds</li>
  <li>Get a security score from 0–100 across your codebase</li>
  <li>See open vulnerabilities sorted by severity</li>
</ul>
<div style="{_BLOCK_STYLE}">Your trial is already running — most teams get value in the first 24 hours.</div>
<div style="{_MUTED_STYLE}">— The Firepan Team</div>
<div style="{_MUTED_STYLE}">P.S. If you have a Solidity or Vyper repo ready, installing the <a href="https://github.com/apps/firepan-ai" style="color:{_ACCENT_COLOR};">Firepan GitHub App</a> takes about 60 seconds and will automatically scan every PR going forward.</div>
"""

_GETTING_STARTED_BODY = f"""
<div style="{_BLOCK_STYLE}">You're verified. Now let's make your contracts scan-ready.</div>
<div style="{_BLOCK_STYLE}">You have three ways to get started — pick the one that fits your workflow:</div>
<div style="{_BLOCK_STYLE}"><strong style="color:#FFFFFF;">Option 1: GitHub App (Recommended)</strong><br/>Install the GitHub App → select your repos → done. Every PR gets automatically scanned from here on.</div>
<div style="{_BLOCK_STYLE}"><strong style="color:#FFFFFF;">Option 2: CLI</strong></div>
<div style="{_CODE_STYLE}">pip install firepan-cli
firepan login
firepan scan https://github.com/your-org/your-repo --format html</div>
<div style="{_BLOCK_STYLE}"><strong style="color:#FFFFFF;">Option 3: Dashboard</strong><br/>Head to your Repositories page, connect a repo, and hit "Run Surface Scan."</div>
<div style="{_BLOCK_STYLE}">Most teams get their first results in under 5 minutes. The security score alone tends to be eye-opening.</div>
<div style="{_MUTED_STYLE}">— The Firepan Team</div>
"""

_FIRST_SCAN_CELEBRATION_BODY = f"""
<div style="{_BLOCK_STYLE}">Your first Firepan scan just finished.</div>
<div style="{_BLOCK_STYLE}">That's a good start, but here's the truth:</div>
<div style="{_BLOCK_STYLE}"><strong style="color:#FFFFFF;">You haven't actually used Firepan yet.</strong></div>
<div style="{_BLOCK_STYLE}">Surface scans are fast — they catch obvious issues.</div>
<div style="{_BLOCK_STYLE}"><strong style="color:#FFFFFF;">Deep Audits are where things break.</strong></div>
<div style="{_BLOCK_STYLE}">Deep Audits are where Firepan:</div>
<ul style="{_UL_STYLE}">
  <li>Traces reentrancy paths across contracts</li>
  <li>Maps access control chains end-to-end</li>
  <li>Identifies edge cases that look safe in isolation but fail in composition</li>
</ul>
<div style="{_BLOCK_STYLE}">It's not a scan. It's a full system analysis powered by frontier-model AI with verification gates — the same audit that produced the Yield Basis case study.</div>
<div style="{_BLOCK_STYLE}">Most teams that convert run a Deep Audit within their first 24 hours — because it's the first time they actually <em style="color:#FFFFFF;">see</em> their risk. Your trial includes one.</div>
<div style="{_BLOCK_STYLE}">If you want help interpreting results, just reply. Happy to take a look.</div>
<div style="{_MUTED_STYLE}">— The Firepan Team</div>
"""

_DEEP_AUDIT_DONE_BODY = f"""
<div style="{_BLOCK_STYLE}">Your Deep Audit for <strong style="color:#FFFFFF;">{{project_name}}</strong> is complete.</div>
<div style="{_BLOCK_STYLE}"><strong style="color:#FFFFFF;">Assessment:</strong> {{assessment_level}}<br/><strong style="color:#FFFFFF;">Findings:</strong> {{findings_count}}</div>
<div style="{_BLOCK_STYLE}">Open the full report in your dashboard to review findings, severity breakdowns, and proof-of-concept details for each.</div>
<div style="{_MUTED_STYLE}">— The Firepan Team</div>
"""


# ---------------------------------------------------------------------------
# LIFECYCLE_CONFIG — MVP has 5 codes wired (1a, 1b, 2, 3, DEEP_AUDIT_DONE)
# ---------------------------------------------------------------------------
# Follow-up PR extends this dict with codes 4–11.

LIFECYCLE_CONFIG: dict[EmailCode, EmailSpec] = {
    EmailCode.WELCOME_VERIFY: EmailSpec(
        subject_line="Your smart contracts deserve better than a one-time audit",
        hero_subtitle="Verify your email to run your first scan",
        category="onboarding",
        body_content_html=_WELCOME_VERIFY_BODY,
        cta_label="Verify My Email →",
        cta_url_template="{app_base}/verify-email",
        require_verified=False,  # this IS the verify email
        mutually_exclusive_with=(EmailCode.WELCOME_VERIFIED,),
    ),
    EmailCode.WELCOME_VERIFIED: EmailSpec(
        subject_line="Your smart contracts deserve better than a one-time audit",
        hero_subtitle="You're in — let's get you scanning",
        category="onboarding",
        body_content_html=_WELCOME_VERIFIED_BODY,
        cta_label="Connect a Repo →",
        cta_url_template="{app_base}/repositories",
        require_verified=False,  # Google auto-verifies, but we don't gate either way
        mutually_exclusive_with=(EmailCode.WELCOME_VERIFY,),
    ),
    EmailCode.GETTING_STARTED: EmailSpec(
        subject_line="Your first scan takes 60 seconds. Here's how.",
        hero_subtitle="Three ways to get Firepan running today",
        category="onboarding",
        body_content_html=_GETTING_STARTED_BODY,
        cta_label="Go to My Dashboard →",
        cta_url_template="{app_base}/repositories",
        require_verified=True,
    ),
    EmailCode.FIRST_SCAN_CELEBRATION: EmailSpec(
        subject_line="You haven't actually used Firepan yet.",
        hero_subtitle="Surface scans are just the preview",
        category="activation",
        body_content_html=_FIRST_SCAN_CELEBRATION_BODY,
        cta_label="Run a Deep Audit →",
        cta_url_template="{app_base}/audits",
        require_verified=True,
    ),
    EmailCode.DEEP_AUDIT_DONE: EmailSpec(
        subject_line="Your Firepan audit of {project_name} is ready",
        hero_subtitle="Assessment: {assessment_level} • {findings_count} findings",
        category="transactional",
        body_content_html=_DEEP_AUDIT_DONE_BODY,
        cta_label="View Full Report →",
        cta_url_template="{app_base}/audits",
        require_verified=False,  # transactional — send even if not verified (rare edge case)
        force_send=True,         # transactional — ignore email_unsubscribed
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(name: str, default: str | None = None) -> str | None:
    """Read env at call time, not import time."""
    return os.environ.get(name, default)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _app_base_url() -> str:
    # Used by CTA templates that link to the dashboard.
    return _env("FRONTEND_URL") or _env("APP_BASE_URL") or "https://app.firepan.com"


def _api_base_url() -> str:
    # Used to build unsubscribe URLs.
    return _env("API_BASE_URL") or "https://api.firepan.com"


def _template_id() -> str | None:
    return _env("SENDGRID_TEMPLATE_ID_DEFAULT")


def resolve_first_name(user: User | None) -> str:
    """Extract a usable first name from a User record. Fallback chain:

        user.name (first whitespace token) → user.google_name (first token)
            → user.github_login → "there"
    """
    if user is None:
        return "there"
    for raw in (user.name, user.google_name):
        if raw:
            token = raw.strip().split()[0] if raw.strip() else ""
            if token:
                return token
    if getattr(user, "github_login", None):
        return user.github_login
    return "there"


def build_unsubscribe_token(tenant_id: int) -> str:
    """HMAC-signed opaque token for the unsubscribe link.

    Shape: urlsafe_b64(f"{tenant_id}.{issued_at}.{hmac[:32]}")
    """
    secret = _env("HOUND_SECRET_KEY") or ""
    if not secret:
        logger.warning("HOUND_SECRET_KEY not set — unsubscribe tokens will not verify")
    issued_at = int(_now().timestamp())
    msg = f"{tenant_id}.{issued_at}".encode()
    sig = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:32]
    raw = f"{tenant_id}.{issued_at}.{sig}".encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def verify_unsubscribe_token(token: str, max_age_days: int = 180) -> int | None:
    """Verify an unsubscribe token and return the tenant_id it was issued for.

    Returns None on any validation failure (invalid base64, missing parts,
    bad signature, expired token). Constant-time comparison on the signature.
    """
    if not token:
        return None
    try:
        # Add padding back (urlsafe_b64encode strips it with rstrip above)
        padded = token + "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except Exception:
        return None

    parts = raw.split(".")
    if len(parts) != 3:
        return None
    tenant_id_str, issued_at_str, sig = parts

    try:
        tenant_id = int(tenant_id_str)
        issued_at = int(issued_at_str)
    except ValueError:
        return None

    # Expiry check
    age = int(_now().timestamp()) - issued_at
    if age < 0 or age > max_age_days * 86400:
        return None

    secret = _env("HOUND_SECRET_KEY") or ""
    msg = f"{tenant_id}.{issued_at}".encode()
    expected = hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:32]

    if not hmac.compare_digest(expected, sig):
        return None
    return tenant_id


def _build_unsubscribe_url(tenant_id: int) -> str:
    return f"{_api_base_url()}/email/unsubscribe?t={build_unsubscribe_token(tenant_id)}"


def _render_subject(spec: EmailSpec, extra_data: dict) -> str:
    """Render the subject_line template with extra_data — safe for missing keys."""
    try:
        return spec.subject_line.format(**extra_data)
    except (KeyError, IndexError):
        return spec.subject_line


def _render_cta_url(spec: EmailSpec, extra_data: dict) -> str:
    """Render the CTA URL template with extra_data + `app_base`."""
    ctx = {"app_base": _app_base_url(), **extra_data}
    try:
        return spec.cta_url_template.format(**ctx)
    except (KeyError, IndexError):
        return _app_base_url()


def _render_dynamic_data(
    *,
    spec: EmailSpec,
    user: User | None,
    tenant: Tenant,
    extra_data: dict,
    unsubscribe_url: str,
) -> dict:
    """Assemble the `dynamic_template_data` payload for the SendGrid Dynamic Template.

    The FirePan SendGrid design (id c1af79cf-…) uses these handlebars vars:
    subject_line, hero_subtitle, category, body_content, cta_label, cta_url,
    first_name, unsubscribe. Everything else (Sender_*, unsubscribe_preferences)
    is provided by SendGrid itself.

    Escape contract (matched to `scripts/sendgrid_setup_template.py` template setup):
      - `body_content`: rendered as `{{{body_content}}}` (triple-braces, raw HTML).
        Any user-controlled fields we `.format()` into the body MUST be HTML-escaped
        first — otherwise a malicious `project_name` could inject scripts.
      - `subject_line`: rendered as `{{{subject_line}}}` (triple-braces, plain text
        passthrough). Apostrophes are preserved; we don't put HTML in subjects.
      - All other vars (hero_subtitle, cta_label, cta_url, first_name): rendered as
        `{{var}}` (double-braces). SendGrid HTML-escapes them — we pass plain text.
    """
    # `body_content` is sent as raw HTML passthrough in the SendGrid template
    # (the design uses `{{{body_content}}}` per scripts/sendgrid_setup_template.py),
    # so any user-controlled fields we format INTO the body must be HTML-escaped
    # first. `app_base` comes from our own env, safe to leave raw.
    safe_ctx = {"app_base": _app_base_url()}
    for k, v in extra_data.items():
        if isinstance(v, str):
            safe_ctx[k] = _html.escape(v, quote=True)
        else:
            safe_ctx[k] = v

    # subject_line / hero_subtitle / cta_label / cta_url are plain-text fields
    # rendered via double-brace {{var}} in the template (SendGrid HTML-escapes
    # automatically), so they use the UN-escaped extra_data — otherwise single
    # quotes would render as `&#x27;`. The subject field itself is triple-braced
    # in our setup script so apostrophes there also pass through raw.
    plain_ctx = {"app_base": _app_base_url(), **extra_data}

    try:
        body = spec.body_content_html.format(**safe_ctx)
    except (KeyError, IndexError):
        body = spec.body_content_html

    try:
        hero = spec.hero_subtitle.format(**plain_ctx)
    except (KeyError, IndexError):
        hero = spec.hero_subtitle

    return {
        "subject_line": _render_subject(spec, plain_ctx),
        "hero_subtitle": hero,
        "category": spec.category,
        "body_content": body,
        "cta_label": spec.cta_label,
        "cta_url": _render_cta_url(spec, plain_ctx),
        "first_name": resolve_first_name(user),
        "unsubscribe": unsubscribe_url,
    }


# ---------------------------------------------------------------------------
# Shared helper — ONLY writer of attempt_count + during-send last_attempt_at
# ---------------------------------------------------------------------------

async def _perform_send_and_update_status(
    row: SentEmail,
    tenant: Tenant,
    db: Session,
) -> Literal["sent", "failed"]:
    """Issue one SendGrid POST and update row status.

    Invariant: this is the ONLY place `attempt_count` is incremented.
    One SendGrid POST attempt == one `attempt_count + 1`.

    Caller is responsible for ensuring `row` is already in `status='pending'`
    (via INSERT in dispatch() or re-claim UPDATE in retry task) and that
    `row.metadata_json` has `extra_data`, `force_send`, `to_email`.
    """
    # (a) bump attempt_count + last_attempt_at BEFORE POST
    now = _now()
    row.attempt_count = (row.attempt_count or 0) + 1
    row.last_attempt_at = now
    db.commit()

    # Rehydrate payload from metadata_json — source-of-truth for retry correctness.
    metadata = row.metadata_json or {}
    extra_data = metadata.get("extra_data") or {}
    to_email = metadata.get("to_email")
    if not to_email:
        row.status = "failed"
        row.send_error = "metadata_json missing to_email"
        db.commit()
        logger.error("SentEmail id=%s has no to_email in metadata_json", row.id)
        return "failed"

    code = EmailCode(row.code)
    spec = LIFECYCLE_CONFIG.get(code)
    if spec is None:
        row.status = "failed"
        row.send_error = f"no EmailSpec for code {row.code}"
        db.commit()
        logger.error("No EmailSpec for code=%s (row id=%s)", row.code, row.id)
        return "failed"

    # Render payload fresh — deterministic from metadata.
    user = None
    if tenant.users:
        # Pick the earliest-created user for name resolution — stable across retries.
        user = sorted(tenant.users, key=lambda u: u.created_at)[0]
    unsubscribe_url = _build_unsubscribe_url(tenant.id)
    dynamic_data = _render_dynamic_data(
        spec=spec, user=user, tenant=tenant,
        extra_data=extra_data, unsubscribe_url=unsubscribe_url,
    )

    template_id = row.template_id or _template_id()
    if not template_id:
        row.status = "failed"
        row.send_error = "SENDGRID_TEMPLATE_ID_DEFAULT not configured"
        db.commit()
        logger.error("No template_id available for SentEmail id=%s", row.id)
        return "failed"

    # Update the stored subject snapshot now that we've rendered it
    row.subject = dynamic_data["subject_line"]
    if not row.template_id:
        row.template_id = template_id
    db.commit()

    # (b) POST to SendGrid
    ok, err = await send_template_email(
        to_email=to_email,
        template_id=template_id,
        dynamic_data=dynamic_data,
        categories=["lifecycle", code.value],
        custom_args={"tenant_id": tenant.id, "email_code": code.value, "sent_email_id": row.id},
    )

    # (c) flip status based on outcome
    if ok:
        row.status = "sent"
        row.sent_at = _now()
        row.send_error = None
        db.commit()
        return "sent"
    else:
        row.status = "failed"
        row.send_error = (err or "unknown send failure")[:2000]
        db.commit()
        return "failed"


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

DispatchResult = Literal["sent", "duplicate", "skipped", "failed"]

STALE_PENDING_MINUTES = 10


async def dispatch(
    code: EmailCode,
    tenant: Tenant,
    db: Session,
    *,
    dedup_key: str,
    extra_data: dict[str, Any] | None = None,
    force_send: bool = False,
) -> DispatchResult:
    """Send a lifecycle email, idempotently.

    Invariants (see module docstring):
      - Never retries `status='failed'` rows — that's the Beat task's job.
      - Never mutates `attempt_count` directly — `_perform_send_and_update_status` does.

    Args:
        code: which email to send (see EmailCode enum).
        tenant: recipient tenant (db-attached).
        db: SQLAlchemy session.
        dedup_key: idempotency key scoped to (tenant_id, code). For once-per-lifetime
            codes pass `code.value`; for per-event codes (DEEP_AUDIT_DONE) pass
            `f"audit:{session_id}"`.
        extra_data: merge vars for the email body + CTA, e.g.
            `{"project_name": "foo", "session_id": "abc", "assessment_level": "HIGH"}`.
        force_send: ignore `tenant.email_unsubscribed` (transactional override).
    """
    extra_data = extra_data or {}
    spec = LIFECYCLE_CONFIG.get(code)
    if spec is None:
        logger.error("dispatch() called with unknown code=%s — no LIFECYCLE_CONFIG entry", code)
        return "skipped"

    # --- Resolve recipient ---
    to_email = (tenant.contact_email or "").strip()
    if not to_email:
        logger.info("dispatch %s tenant=%s: no contact_email — skipped", code.value, tenant.id)
        return "skipped"

    # require_verified gating (transactional force_send bypasses this)
    if spec.require_verified and not tenant.email_verified:
        logger.info("dispatch %s tenant=%s: not verified — skipped", code.value, tenant.id)
        return "skipped"

    # unsubscribe gating
    effective_force = force_send or spec.force_send
    if tenant.email_unsubscribed and not effective_force:
        logger.info("dispatch %s tenant=%s: unsubscribed — skipped", code.value, tenant.id)
        return "skipped"

    # mutual-exclusion gating (e.g. WELCOME_VERIFY ⊥ WELCOME_VERIFIED)
    if spec.mutually_exclusive_with:
        mx_codes = [c.value for c in spec.mutually_exclusive_with]
        existing = (
            db.query(SentEmail)
            .filter(SentEmail.tenant_id == tenant.id)
            .filter(SentEmail.code.in_(mx_codes))
            .filter(SentEmail.status != "failed")  # only 'sent' or 'pending' blocks
            .first()
        )
        if existing:
            logger.info(
                "dispatch %s tenant=%s: mutually exclusive with already-sent %s — skipped",
                code.value, tenant.id, existing.code,
            )
            return "skipped"

    # --- Claim via INSERT (unique on tenant_id, code, dedup_key) ---
    now = _now()
    metadata = {
        "extra_data": extra_data,
        "force_send": effective_force,
        "to_email": to_email,
    }
    row = SentEmail(
        tenant_id=tenant.id,
        code=code.value,
        dedup_key=dedup_key,
        status="pending",
        created_at=now,
        last_attempt_at=now,   # claim marker (NOT an attempt timestamp)
        attempt_count=0,       # helper owns incrementing
        template_id=_template_id(),
        subject=None,          # set by helper after render
        metadata_json=metadata,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Existing row — inspect its status and decide
        existing_row = (
            db.query(SentEmail)
            .filter(
                SentEmail.tenant_id == tenant.id,
                SentEmail.code == code.value,
                SentEmail.dedup_key == dedup_key,
            )
            .first()
        )
        if existing_row is None:
            # Shouldn't happen, but be safe
            logger.error(
                "dispatch %s tenant=%s: IntegrityError but no existing row found",
                code.value, tenant.id,
            )
            return "failed"

        if existing_row.status == "sent":
            return "duplicate"

        if existing_row.status == "failed":
            # Invariant 1: dispatch() never retries failed rows — Beat owns it.
            return "duplicate"

        # status == "pending"
        stale_cutoff = now - timedelta(minutes=STALE_PENDING_MINUTES)
        if existing_row.last_attempt_at and existing_row.last_attempt_at >= stale_cutoff:
            # Another dispatch in flight — skip
            return "duplicate"

        # Stale pending — try to re-claim with guarded UPDATE
        original_last_attempt = existing_row.last_attempt_at
        claim_q = (
            db.query(SentEmail)
            .filter(
                SentEmail.id == existing_row.id,
                SentEmail.status == "pending",
                SentEmail.last_attempt_at == original_last_attempt,
            )
            .update(
                {
                    SentEmail.last_attempt_at: now,
                    SentEmail.send_error: None,
                },
                synchronize_session=False,
            )
        )
        db.commit()
        if claim_q != 1:
            # Lost the race
            return "duplicate"
        db.refresh(existing_row)
        row = existing_row

    # --- Send (via shared helper) ---
    try:
        result = await _perform_send_and_update_status(row, tenant, db)
    except Exception:
        logger.exception(
            "Exception during _perform_send_and_update_status for SentEmail id=%s", row.id,
        )
        # Mark failed — Beat will retry
        try:
            row.status = "failed"
            row.send_error = "exception in helper (see logs)"
            db.commit()
        except Exception:
            db.rollback()
        return "failed"

    if result == "sent":
        # Maintain tenant.last_email_sent_at (used by follow-up throttle rules)
        try:
            tenant.last_email_sent_at = _now()
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to update tenant.last_email_sent_at for tenant=%s", tenant.id)

    return result


# ---------------------------------------------------------------------------
# Convenience: safe_dispatch — swallow exceptions so request paths don't break
# ---------------------------------------------------------------------------

async def safe_dispatch(
    code: EmailCode,
    tenant: Tenant,
    db: Session,
    *,
    dedup_key: str,
    extra_data: dict[str, Any] | None = None,
    force_send: bool = False,
) -> DispatchResult | None:
    """Wrapper around dispatch() that never raises.

    Use this in request-path hooks (OAuth callbacks, webhook handlers) where
    an email-send failure should not break the request. Mirrors the pattern
    used by existing `_log_oauth_event` and telegram notify calls.
    """
    try:
        return await dispatch(code, tenant, db, dedup_key=dedup_key, extra_data=extra_data, force_send=force_send)
    except Exception:
        logger.exception(
            "safe_dispatch(%s) for tenant=%s raised — swallowed", code.value, tenant.id,
        )
        return None
