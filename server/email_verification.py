"""
Email verification gate for FirePan tenants.

Every tenant must verify a contact email before using analysis features.
Google OAuth emails are auto-verified. Manual entry requires a 6-digit code.
"""

import json
import logging
import os
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database.models import Tenant

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Redis helpers (same pattern as auth_routes._get_redis)
# ---------------------------------------------------------------------------

async def _get_redis():
    import redis.asyncio as aioredis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return aioredis.from_url(redis_url)


# Atomic Lua script for verify-code.
# KEYS[1] = verify key, ARGV[1] = submitted code
# Returns {status, payload}:
#   {0, ""} = no pending key
#   {1, remaining} = wrong code, attempts incremented
#   {2, ""} = too many attempts, key deleted
#   {3, email} = correct code, key consumed
_VERIFY_LUA = """
local raw = redis.call('GET', KEYS[1])
if not raw then
    return {0, ""}
end
local data = cjson.decode(raw)
if data.code ~= ARGV[1] then
    data.attempts = (data.attempts or 0) + 1
    if data.attempts >= 5 then
        redis.call('DEL', KEYS[1])
        return {2, ""}
    end
    local ttl = redis.call('TTL', KEYS[1])
    if ttl > 0 then
        redis.call('SETEX', KEYS[1], ttl, cjson.encode(data))
    end
    return {1, tostring(5 - data.attempts)}
end
redis.call('DEL', KEYS[1])
return {3, data.email}
"""


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class SendCodeRequest(BaseModel):
    email: str


class VerifyCodeRequest(BaseModel):
    code: str


# ---------------------------------------------------------------------------
# Route mounting (called from api.py after dependencies are defined)
# ---------------------------------------------------------------------------

def mount_email_routes(app):
    """Register email verification routes on the FastAPI app.

    Called from api.py after get_current_tenant_id and get_db are defined.
    Avoids circular imports by deferring the import.
    """
    from server.api import get_current_tenant_id, get_db
    from server.auth_utils import reject_preview_writes

    @app.post("/email/send-code")
    async def send_verification_code(
        body: SendCodeRequest,
        tenant_id: int = Depends(get_current_tenant_id),
        db: Session = Depends(get_db),
        _: None = Depends(reject_preview_writes),
    ):
        """Send a 6-digit verification code to the given email address."""
        email = body.email.strip().lower()
        if not email or "@" not in email:
            raise HTTPException(400, "Invalid email address")

        # Rate limit: max 3 sends per 10 min
        redis = await _get_redis()
        try:
            rate_key = f"email_verify_rate:{tenant_id}"
            count = await redis.incr(rate_key)
            if count == 1:
                await redis.expire(rate_key, 600)
            if count > 3:
                raise HTTPException(429, "Too many verification attempts. Try again in a few minutes.")

            # Generate 6-digit code
            code = str(secrets.randbelow(900000) + 100000)

            # Store in Redis with 10-min TTL
            verify_key = f"email_verify:{tenant_id}"
            await redis.setex(
                verify_key,
                600,
                json.dumps({"code": code, "email": email, "attempts": 0}),
            )
        finally:
            await redis.aclose()

        # Send email
        from integrations.email import send_email
        html = _verification_email_html(code)
        sent = await send_email(email, "FirePan — Verify Your Email", html)
        if not sent:
            logger.warning("Failed to send verification email to %s (tenant %d)", email, tenant_id)
            # Clean up: delete the stored code so the user isn't rate-limited with no code
            redis2 = await _get_redis()
            try:
                await redis2.delete(f"email_verify:{tenant_id}")
            finally:
                await redis2.aclose()
            raise HTTPException(502, "Failed to send verification email. Please try again.")

        logger.info("Verification code sent to %s (tenant %d)", email, tenant_id)
        return {"status": "sent"}

    @app.post("/email/verify-code")
    async def verify_email_code(
        body: VerifyCodeRequest,
        tenant_id: int = Depends(get_current_tenant_id),
        db: Session = Depends(get_db),
        _: None = Depends(reject_preview_writes),
    ):
        """Verify a 6-digit code and mark the tenant's email as verified."""
        code = body.code.strip()

        redis = await _get_redis()
        try:
            verify_key = f"email_verify:{tenant_id}"
            # Atomic Lua script: check code, increment attempts or consume
            # Returns: [status, email_or_remaining]
            #   status 0 = no pending verification
            #   status 1 = wrong code (email_or_remaining = attempts remaining)
            #   status 2 = too many attempts (deleted)
            #   status 3 = match (email_or_remaining = email, key deleted)
            result = await redis.eval(
                _VERIFY_LUA,
                1,
                verify_key,
                code,
            )
            status = int(result[0])
            payload = result[1].decode() if isinstance(result[1], bytes) else str(result[1])

            if status == 0:
                raise HTTPException(400, "No pending verification. Please request a new code.")
            elif status == 2:
                raise HTTPException(400, "Too many incorrect attempts. Please request a new code.")
            elif status == 1:
                remaining = int(payload)
                raise HTTPException(400, f"Incorrect code. {remaining} attempts remaining.")
            # status == 3: success
            stored_email = payload
        finally:
            await redis.aclose()

        # Update tenant
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant:
            raise HTTPException(404, "Tenant not found")

        now = datetime.now(timezone.utc)
        was_empty = not tenant.contact_email
        tenant.contact_email = stored_email
        tenant.email_verified = True
        tenant.email_verified_at = now
        db.commit()

        # Notify team of contact capture
        if was_empty:
            try:
                from integrations.telegram import notify_contact_captured
                await notify_contact_captured(
                    tenant_id=tenant_id,
                    tenant_name=tenant.github_account_login or tenant.name,
                    email=stored_email,
                )
            except Exception:
                pass

        logger.info("Email verified for tenant %d: %s", tenant_id, stored_email)
        return {"status": "verified", "email": stored_email}


# ---------------------------------------------------------------------------
# require_verified_email dependency factory
# ---------------------------------------------------------------------------

def _make_require_verified_email(get_current_tenant_id):
    """Factory that creates the dependency with the correct tenant_id source.

    Called from api.py so the dependency captures the correct get_current_tenant_id
    and get_db without a circular import.
    """
    from server.api import get_db

    async def require_verified_email(
        tenant_id: int = Depends(get_current_tenant_id),
        db: Session = Depends(get_db),
    ) -> None:
        tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
        if not tenant or not tenant.email_verified:
            raise HTTPException(403, detail={
                "error": "email_not_verified",
                "message": "Please verify your email address to continue.",
            })
    return require_verified_email


# ---------------------------------------------------------------------------
# Email template
# ---------------------------------------------------------------------------

def _verification_email_html(code: str) -> str:
    return f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
        <h2 style="color: #1a1a1a; margin-bottom: 8px; font-size: 20px;">Verify your email</h2>
        <p style="color: #666; margin-top: 0; font-size: 14px;">Enter this code in FirePan to verify your email address:</p>

        <div style="background: #f0f4ff; border: 2px solid #2563eb; border-radius: 12px; padding: 24px; margin: 24px 0; text-align: center;">
            <span style="font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 36px; letter-spacing: 8px; font-weight: 700; color: #1a1a1a;">{code}</span>
        </div>

        <p style="color: #999; font-size: 12px;">
            This code expires in 10 minutes. If you didn't request this, you can safely ignore this email.
        </p>

        <p style="color: #999; font-size: 12px; margin-top: 24px;">
            FirePan &mdash; Continuous Smart Contract Security
        </p>
    </div>
    """
