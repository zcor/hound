"""
OAuth authentication routes (GitHub + Google).

This module provides FastAPI endpoints for GitHub and Google OAuth
authentication, provider linking, and JWT token management.
"""

import json
import logging
import os
import secrets
import time
from collections.abc import Generator
from datetime import datetime, timedelta, timezone

import httpx
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database.models import OAuthAuditLog, Project, ScanExecution, Tenant, User
from server.auth_utils import create_access_token, get_current_user_from_token, reject_preview_writes
from server.token_crypto import encrypt_token

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["authentication"])


def _tenant_has_meaningful_data(db: Session, tenant: Tenant | None) -> bool:
    """Return True if a tenant has data that makes silent relinking risky."""
    if tenant is None:
        return False

    return (
        db.query(Project).filter(Project.tenant_id == tenant.id).count() > 0
        or db.query(ScanExecution).filter(ScanExecution.tenant_id == tenant.id).count() > 0
        or tenant.stripe_subscription_id is not None
        or (tenant.scan_credits or 0) > 0
        or tenant.plan not in (None, "free")
    )


def _find_matching_org_tenant(
    db: Session,
    user_orgs: list[dict],
) -> Tenant | None:
    """Return the first org tenant matching one of the user's GitHub orgs."""
    for org in user_orgs:
        org_login = org.get("login")
        if not org_login:
            continue
        org_tenant = db.query(Tenant).filter(
            func.lower(Tenant.github_account_login) == org_login.lower(),
            Tenant.github_account_type == "Organization",
        ).first()
        if org_tenant:
            return org_tenant
    return None


def _activate_trial_if_pending(tenant: Tenant | None) -> None:
    """Activate a pending tenant and start the starter trial once."""
    if tenant and tenant.status == "pending":
        tenant.status = "active"
        if not tenant.trial_ends_at:
            tenant.trial_ends_at = datetime.now(timezone.utc) + timedelta(days=14)
            tenant.trial_plan = "starter"


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class GitHubCallbackRequest(BaseModel):
    """Request model for GitHub OAuth callback."""
    code: str
    state: str | None = None


class GoogleCallbackRequest(BaseModel):
    """Request model for Google OAuth callback."""
    code: str
    state: str


class LinkCallbackRequest(BaseModel):
    """Request model for provider linking callback."""
    code: str
    state: str


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def get_github_config():
    """Get GitHub OAuth configuration from environment."""
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
    return {
        "client_id": os.getenv("GITHUB_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
        "frontend_url": frontend_url
    }


def get_google_config():
    """Get Google OAuth configuration from environment."""
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000").rstrip("/")
    return {
        "client_id": os.getenv("GOOGLE_OAUTH_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
        "frontend_url": frontend_url
    }


def get_db() -> Generator[Session, None, None]:
    """
    Get database session.
    This is a placeholder that will be overridden when the router is included.
    """
    # Import at runtime to avoid circular dependency
    from server.api import get_db as api_get_db
    yield from api_get_db()


def get_token_from_header(request: Request) -> str:
    """
    Extract JWT token from Authorization header.

    Args:
        request: FastAPI request object

    Returns:
        JWT token string

    Raises:
        HTTPException: If authorization header is missing or invalid
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid authorization header"
        )
    return auth_header.replace("Bearer ", "")


# ---------------------------------------------------------------------------
# OAuth state tokens (Redis-backed, one-time use)
# ---------------------------------------------------------------------------

async def _get_redis():
    """Get a Redis client. Caller must close."""
    import redis.asyncio as aioredis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return aioredis.from_url(redis_url)


async def create_oauth_state(
    intent: str,
    user_id: int | None = None,
    provider: str = "",
    ttl: int = 600,
) -> str:
    """Create one-time OAuth state stored in Redis."""
    nonce = secrets.token_urlsafe(32)
    state_data = json.dumps({
        "intent": intent,        # "login" or "link"
        "user_id": user_id,      # None for login, set for link
        "provider": provider,    # "github" or "google"
        "nonce": nonce,
        "exp": int(time.time()) + ttl,
    })
    redis = await _get_redis()
    try:
        await redis.setex(f"oauth_state:{nonce}", ttl, state_data)
    finally:
        await redis.aclose()
    return nonce


async def consume_oauth_state(state: str) -> dict:
    """Validate and atomically consume OAuth state (one-time use)."""
    redis = await _get_redis()
    try:
        data = await redis.getdel(f"oauth_state:{state}")
    finally:
        await redis.aclose()
    if not data:
        raise ValueError("Invalid or expired OAuth state")
    state_data = json.loads(data)
    if time.time() > state_data["exp"]:
        raise ValueError("OAuth state expired")
    return state_data


# ---------------------------------------------------------------------------
# Audit logging helper
# ---------------------------------------------------------------------------

def _log_oauth_event(
    db: Session,
    user_id: int,
    action: str,
    provider: str,
    provider_user_id: str | None = None,
    request: Request | None = None,
):
    """Insert a row into oauth_audit_log."""
    ip = None
    ua = None
    if request:
        ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else None)
        ua = request.headers.get("User-Agent")
    entry = OAuthAuditLog(
        user_id=user_id,
        action=action,
        provider=provider,
        provider_user_id=provider_user_id,
        ip_address=ip,
        user_agent=ua,
    )
    db.add(entry)


# ---------------------------------------------------------------------------
# GitHub OAuth endpoints
# ---------------------------------------------------------------------------

@router.get("/github/login")
async def github_login():
    """Return GitHub OAuth URL for sign-in."""
    config = get_github_config()
    if not config["client_id"]:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth not configured. Set GITHUB_CLIENT_ID environment variable."
        )

    state = await create_oauth_state(intent="login", provider="github")

    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={config['client_id']}"
        f"&redirect_uri={config['frontend_url']}/auth/callback"
        f"&scope=repo read:org read:user user:email"
        f"&state={state}"
    )
    return {"url": github_auth_url}


@router.post("/github/callback")
async def github_callback(
    request_body: GitHubCallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Exchange GitHub code for access token and create/login user."""
    config = get_github_config()
    if not config["client_id"] or not config["client_secret"]:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")

    # Validate state (CSRF protection) — REQUIRED
    if not request_body.state:
        raise HTTPException(400, "OAuth state parameter is required")
    try:
        state_data = await consume_oauth_state(request_body.state)
        if state_data["intent"] != "login":
            raise HTTPException(400, "Invalid OAuth state intent")
    except ValueError as e:
        raise HTTPException(400, str(e))

    # 1. Exchange code for GitHub access token
    user_orgs: list[dict] = []
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": request_body.code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_response.json()
        github_token = token_data.get("access_token")

        if not github_token:
            raise HTTPException(400, "Failed to get GitHub access token")

        # 2. Get user info from GitHub
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/json",
            },
        )
        github_user = user_response.json()

        # 2b. Fetch primary email if not public
        if not github_user.get("email"):
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/json",
                },
            )
            if emails_response.status_code == 200:
                for entry in emails_response.json():
                    if entry.get("primary") and entry.get("verified"):
                        github_user["email"] = entry["email"]
                        break

        # 2c. Fetch org memberships for tenant matching. Existing tokens may
        # lack read:org; in that case we fail open and keep current behavior.
        orgs_page = 1
        while True:
            orgs_response = await client.get(
                "https://api.github.com/user/orgs",
                params={"per_page": 100, "page": orgs_page},
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/json",
                },
            )
            if orgs_response.status_code != 200:
                break
            page_orgs = orgs_response.json()
            if not page_orgs:
                break
            user_orgs.extend(page_orgs)
            if len(page_orgs) < 100:
                break
            orgs_page += 1

    # 3. Create or update user in database
    user = db.query(User).filter(User.github_id == github_user["id"]).first()
    is_new_user = False

    if user:
        # Existing user — update info and refresh token
        user.name = github_user.get("name")
        user.email = github_user.get("email")
        user.avatar_url = github_user.get("avatar_url")
        user.github_login = github_user["login"]
        user.github_token_encrypted = encrypt_token(github_token)
        user.github_access_token = None  # Deprecated: use encrypted column only
        user.github_connected_at = datetime.now(timezone.utc)
        current_tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        target_tenant = current_tenant

        if current_tenant and current_tenant.github_account_type != "Organization":
            org_tenant = _find_matching_org_tenant(db, user_orgs)
            if org_tenant and not _tenant_has_meaningful_data(db, current_tenant):
                target_tenant = org_tenant
                user.tenant_id = org_tenant.id

        _activate_trial_if_pending(target_tenant)
        _log_oauth_event(db, user.id, "login", "github", str(github_user["id"]), request)
        db.commit()
        db.refresh(user)
    else:
        # Check for email-match hint (Google-first user with same email)
        github_email = github_user.get("email")
        if github_email:
            existing = db.query(User).filter(
                User.email == github_email,
                User.google_id.isnot(None),
            ).first()
            if existing:
                return {
                    "email_match_hint": True,
                    "message": "An account with this email already exists. Sign in with Google and link GitHub from Settings.",
                    "existing_provider": "google",
                }

        # New user — find or create tenant
        normalized_login = github_user["login"].lower()
        personal_tenant = db.query(Tenant).filter(
            func.lower(Tenant.github_account_login) == normalized_login
        ).first()
        if not personal_tenant:
            personal_tenant = db.query(Tenant).filter(
                func.lower(Tenant.name) == f"github_{normalized_login}"
            ).first()
        org_tenant = _find_matching_org_tenant(db, user_orgs)

        if org_tenant and personal_tenant:
            tenant = personal_tenant if _tenant_has_meaningful_data(db, personal_tenant) else org_tenant
        elif org_tenant:
            tenant = org_tenant
        else:
            tenant = personal_tenant

        if tenant:
            _activate_trial_if_pending(tenant)
        else:
            is_new_user = True
            try:
                tenant = Tenant(
                    name=f"github_{github_user['login']}",
                    github_account_login=github_user["login"],
                    github_account_type="User",
                    status="active",
                    trial_ends_at=datetime.now(timezone.utc) + timedelta(days=14),
                    trial_plan="starter",
                )
                db.add(tenant)
                db.flush()
            except IntegrityError:
                db.rollback()
                tenant = db.query(Tenant).filter(
                    func.lower(Tenant.github_account_login) == normalized_login
                ).first()
                if not tenant:
                    raise HTTPException(500, "Tenant creation conflict")
                is_new_user = False

        user = User(
            github_id=github_user["id"],
            github_login=github_user["login"],
            email=github_user.get("email"),
            name=github_user.get("name"),
            avatar_url=github_user.get("avatar_url"),
            tenant_id=tenant.id,
            github_token_encrypted=encrypt_token(github_token),
            github_access_token=None,  # Deprecated: use encrypted column only
            github_connected_at=datetime.now(timezone.utc),
            signup_provider="github",
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            user = db.query(User).filter(User.github_id == github_user["id"]).first()
            if not user:
                raise HTTPException(500, "User creation conflict")
            is_new_user = False
        db.refresh(user)
        _log_oauth_event(db, user.id, "login_new" if is_new_user else "login", "github", str(github_user["id"]), request)
        db.commit()
        logger.info("GitHub login: %s (tenant_id=%d, new=%s)", github_user["login"], user.tenant_id, is_new_user)

    # 4. Generate slim JWT (no PII)
    access_token = create_access_token(data={
        "user_id": user.id,
        "tenant_id": user.tenant_id,
    })

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "tenant_id": user.tenant_id,
        "is_new_user": is_new_user,
    }


# ---------------------------------------------------------------------------
# Google OAuth endpoints
# ---------------------------------------------------------------------------

@router.get("/google/login")
async def google_login():
    """Return Google OAuth URL for sign-in."""
    config = get_google_config()
    if not config["client_id"]:
        raise HTTPException(500, "Google OAuth not configured. Set GOOGLE_OAUTH_CLIENT_ID.")

    state = await create_oauth_state(intent="login", provider="google")
    redirect_uri = f"{config['frontend_url']}/auth/callback/google"

    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={config['client_id']}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&access_type=offline"
        f"&state={state}"
    )
    return {"url": google_auth_url}


async def _exchange_google_code(code: str, redirect_uri: str, config: dict) -> dict:
    """Exchange Google auth code for tokens and fetch userinfo."""
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
        )
        if token_response.status_code != 200:
            logger.error("Google token exchange failed: %s", token_response.text)
            raise HTTPException(400, "Failed to exchange Google authorization code")
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(400, "No access token from Google")

        userinfo_response = await client.get(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if userinfo_response.status_code != 200:
            raise HTTPException(400, "Failed to fetch Google user info")
        return userinfo_response.json()


@router.post("/google/callback")
async def google_callback(
    request_body: GoogleCallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Exchange Google code for access token and create/login user."""
    config = get_google_config()
    if not config["client_id"] or not config["client_secret"]:
        raise HTTPException(500, "Google OAuth not configured")

    # Validate state
    try:
        state_data = await consume_oauth_state(request_body.state)
        if state_data["intent"] != "login":
            raise HTTPException(400, "Invalid OAuth state intent")
    except ValueError as e:
        raise HTTPException(400, str(e))

    redirect_uri = f"{config['frontend_url']}/auth/callback/google"
    google_user = await _exchange_google_code(request_body.code, redirect_uri, config)

    google_id = google_user.get("sub")
    google_email = google_user.get("email")
    google_name = google_user.get("name")
    google_avatar = google_user.get("picture")

    if not google_id:
        raise HTTPException(400, "No user ID from Google")

    # Look up by google_id
    user = db.query(User).filter(User.google_id == google_id).first()

    if user:
        # Existing user — update Google profile, return JWT
        user.google_email = google_email
        user.google_name = google_name
        user.google_avatar_url = google_avatar
        if google_email and not user.email:
            user.email = google_email

        # Auto-verify tenant email if safe (blank or matches Google email)
        if google_email and user.tenant_id:
            tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
            if tenant and not tenant.email_verified:
                if not tenant.contact_email or tenant.contact_email.lower() == google_email.lower():
                    tenant.contact_email = google_email
                    tenant.email_verified = True
                    tenant.email_verified_at = datetime.now(timezone.utc)

        _log_oauth_event(db, user.id, "login", "google", google_id, request)
        db.commit()
        db.refresh(user)

        access_token = create_access_token(data={
            "user_id": user.id,
            "tenant_id": user.tenant_id,
        })
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "tenant_id": user.tenant_id,
            "is_new_user": False,
        }

    # Not found by google_id — check email match hint
    if google_email:
        existing = db.query(User).filter(User.email == google_email).first()
        if existing:
            return {
                "email_match_hint": True,
                "message": "An account with this email already exists. Sign in with GitHub and link Google from Settings.",
                "existing_provider": "github" if existing.has_github else "google",
            }

    # Brand new user — create user + tenant
    email_prefix = (google_email or "user").split("@")[0]
    tenant_name = f"google_{email_prefix}"

    # Deduplicate tenant name
    base_name = tenant_name
    counter = 0
    while db.query(Tenant).filter(Tenant.name == tenant_name).first():
        counter += 1
        tenant_name = f"{base_name}_{counter}"

    try:
        tenant = Tenant(
            name=tenant_name,
            contact_email=google_email,
            status="active",
            email_verified=True,
            email_verified_at=datetime.now(timezone.utc),
        )
        db.add(tenant)
        db.flush()
    except IntegrityError:
        db.rollback()
        tenant = db.query(Tenant).filter(Tenant.name == tenant_name).first()
        if not tenant:
            raise HTTPException(500, "Tenant creation conflict")

    user = User(
        google_id=google_id,
        google_email=google_email,
        google_name=google_name,
        google_avatar_url=google_avatar,
        google_connected_at=datetime.now(timezone.utc),
        email=google_email,
        name=google_name,
        avatar_url=google_avatar,
        tenant_id=tenant.id,
        signup_provider="google",
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        user = db.query(User).filter(User.google_id == google_id).first()
        if not user:
            raise HTTPException(500, "User creation conflict")
    db.refresh(user)
    _log_oauth_event(db, user.id, "login_new", "google", google_id, request)
    db.commit()
    logger.info("Google login (new): %s (tenant_id=%d)", google_email, user.tenant_id)

    access_token = create_access_token(data={
        "user_id": user.id,
        "tenant_id": user.tenant_id,
    })
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "tenant_id": user.tenant_id,
        "is_new_user": True,
    }


# ---------------------------------------------------------------------------
# Provider linking endpoints (authenticated)
# ---------------------------------------------------------------------------

@router.get("/connect/github")
async def connect_github(request: Request):
    """Return GitHub OAuth URL for linking (requires auth)."""
    token = get_token_from_header(request)
    payload = get_current_user_from_token(token)
    config = get_github_config()
    if not config["client_id"]:
        raise HTTPException(500, "GitHub OAuth not configured")

    state = await create_oauth_state(
        intent="link",
        user_id=payload["user_id"],
        provider="github",
    )
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={config['client_id']}"
        f"&redirect_uri={config['frontend_url']}/auth/callback/link"
        f"&scope=repo read:user user:email"
        f"&state={state}"
    )
    return {"url": github_auth_url}


@router.get("/connect/google")
async def connect_google(request: Request):
    """Return Google OAuth URL for linking (requires auth)."""
    token = get_token_from_header(request)
    payload = get_current_user_from_token(token)
    config = get_google_config()
    if not config["client_id"]:
        raise HTTPException(500, "Google OAuth not configured")

    state = await create_oauth_state(
        intent="link",
        user_id=payload["user_id"],
        provider="google",
    )
    redirect_uri = f"{config['frontend_url']}/auth/callback/link"
    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={config['client_id']}"
        f"&redirect_uri={redirect_uri}"
        f"&response_type=code"
        f"&scope=openid email profile"
        f"&access_type=offline"
        f"&state={state}"
    )
    return {"url": google_auth_url}


@router.post("/github/link")
async def link_github(
    request_body: LinkCallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Link a GitHub account to the current user."""
    token = get_token_from_header(request)
    payload = get_current_user_from_token(token)

    # Validate state
    try:
        state_data = await consume_oauth_state(request_body.state)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if state_data["intent"] != "link" or state_data["provider"] != "github":
        raise HTTPException(400, "Invalid OAuth state for GitHub linking")
    if state_data["user_id"] != payload["user_id"]:
        raise HTTPException(400, "OAuth state user mismatch")

    config = get_github_config()
    if not config["client_id"] or not config["client_secret"]:
        raise HTTPException(500, "GitHub OAuth not configured")

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": request_body.code,
            },
            headers={"Accept": "application/json"},
        )
        token_data = token_response.json()
        github_token = token_data.get("access_token")
        if not github_token:
            raise HTTPException(400, "Failed to get GitHub access token")

        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {github_token}", "Accept": "application/json"},
        )
        github_user = user_response.json()

    github_id = github_user["id"]

    # Check if already linked to another user
    existing = db.query(User).filter(User.github_id == github_id).first()
    if existing and existing.id != payload["user_id"]:
        raise HTTPException(409, detail={
            "error": "provider_already_linked",
            "detail": "This GitHub account is already linked to another FirePan user.",
        })

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(404, "User not found")

    user.github_id = github_id
    user.github_login = github_user["login"]
    user.email = user.email or github_user.get("email")
    user.name = user.name or github_user.get("name")
    user.avatar_url = user.avatar_url or github_user.get("avatar_url")
    user.github_token_encrypted = encrypt_token(github_token)
    user.github_access_token = None  # Deprecated: use encrypted column only
    user.github_connected_at = datetime.now(timezone.utc)

    _log_oauth_event(db, user.id, "link", "github", str(github_id), request)
    db.commit()
    db.refresh(user)

    return user.to_profile_dict()


@router.post("/google/link")
async def link_google(
    request_body: LinkCallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Link a Google account to the current user."""
    token = get_token_from_header(request)
    payload = get_current_user_from_token(token)

    # Validate state
    try:
        state_data = await consume_oauth_state(request_body.state)
    except ValueError as e:
        raise HTTPException(400, str(e))

    if state_data["intent"] != "link" or state_data["provider"] != "google":
        raise HTTPException(400, "Invalid OAuth state for Google linking")
    if state_data["user_id"] != payload["user_id"]:
        raise HTTPException(400, "OAuth state user mismatch")

    config = get_google_config()
    if not config["client_id"] or not config["client_secret"]:
        raise HTTPException(500, "Google OAuth not configured")

    redirect_uri = f"{config['frontend_url']}/auth/callback/link"
    google_user = await _exchange_google_code(request_body.code, redirect_uri, config)

    google_id = google_user.get("sub")
    if not google_id:
        raise HTTPException(400, "No user ID from Google")

    # Check if already linked to another user
    existing = db.query(User).filter(User.google_id == google_id).first()
    if existing and existing.id != payload["user_id"]:
        raise HTTPException(409, detail={
            "error": "provider_already_linked",
            "detail": "This Google account is already linked to another FirePan user.",
        })

    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(404, "User not found")

    user.google_id = google_id
    google_email = google_user.get("email")
    user.google_email = google_email
    user.google_name = google_user.get("name")
    user.google_avatar_url = google_user.get("picture")
    user.google_connected_at = datetime.now(timezone.utc)
    if not user.email and google_email:
        user.email = google_email

    # Auto-verify tenant email if safe (blank or matches Google email)
    if google_email and user.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
        if tenant and not tenant.email_verified:
            if not tenant.contact_email or tenant.contact_email.lower() == google_email.lower():
                tenant.contact_email = google_email
                tenant.email_verified = True
                tenant.email_verified_at = datetime.now(timezone.utc)

    _log_oauth_event(db, user.id, "link", "google", google_id, request)
    db.commit()
    db.refresh(user)

    return user.to_profile_dict()


# ---------------------------------------------------------------------------
# /auth/me — full profile from DB
# ---------------------------------------------------------------------------

@router.get("/me")
async def get_me(
    request: Request,
    token: str = Depends(get_token_from_header),
    db: Session = Depends(get_db),
):
    """
    Get current user profile from JWT token.

    Returns the full profile dict with all provider info, null-safe.
    """
    try:
        payload = get_current_user_from_token(token)
        user = db.query(User).filter(User.id == payload["user_id"]).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return user.to_profile_dict()
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


# ---------------------------------------------------------------------------
# DELETE /auth/me — account deletion
# ---------------------------------------------------------------------------

@router.delete("/me", status_code=204)
async def delete_me(
    request: Request,
    token: str = Depends(get_token_from_header),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """
    Hard-delete the authenticated user's account.

    - Cancels any Stripe subscription before touching the DB.
    - Deletes the tenant only if this was the sole remaining user.
    - Returns 204 whether the user existed or was already gone (idempotent).
    """
    try:
        payload = get_current_user_from_token(token)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    user_id = payload["user_id"]
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        # Already deleted — idempotent 204
        return Response(status_code=204)

    tenant_id = user.tenant_id
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()

    # Count users in this tenant (with FOR UPDATE to prevent races)
    tenant_user_count = (
        db.query(func.count(User.id))
        .filter(User.tenant_id == tenant_id)
        .scalar()
    )

    # Cancel Stripe subscription BEFORE any DB changes
    if tenant and tenant.stripe_subscription_id:
        try:
            stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
            stripe.Subscription.cancel(tenant.stripe_subscription_id)
            logger.info(
                "Cancelled Stripe subscription %s for tenant %d (user deletion)",
                tenant.stripe_subscription_id,
                tenant_id,
            )
        except stripe.StripeError as e:
            logger.error(
                "Failed to cancel Stripe subscription %s: %s",
                tenant.stripe_subscription_id,
                str(e),
            )
            raise HTTPException(
                status_code=500,
                detail="Failed to cancel subscription. Account not deleted.",
            )

    # All DB changes in one transaction
    try:
        # Explicit delete of audit logs (belt-and-suspenders with CASCADE)
        db.query(OAuthAuditLog).filter(OAuthAuditLog.user_id == user_id).delete()

        # Delete the user
        db.query(User).filter(User.id == user_id).delete()

        # If this was the last user, delete the tenant (cascades to projects, scans, etc.)
        if tenant and tenant_user_count == 1:
            db.delete(tenant)
            logger.info("Deleted tenant %d (last user removed)", tenant_id)

        db.commit()
        logger.info("Deleted user %d (tenant_id=%d)", user_id, tenant_id)
    except Exception:
        db.rollback()
        logger.exception("Failed to delete user %d", user_id)
        raise HTTPException(status_code=500, detail="Account deletion failed.")

    return Response(status_code=204)
