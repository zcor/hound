"""
FastAPI server for Hound Dashboard API.

Provides REST and WebSocket endpoints to serve data to the React frontend.
This is the main entry point for the Hound SaaS architecture.

Architecture:
    Web Server (this file):
        - Handles HTTP requests and validates input
        - Creates database records for audits
        - Dispatches work to Celery worker queue
        - Handles GitHub webhook events
        
    Worker Queue (worker/tasks.py):
        - Executes long-running audits in background
        - Publishes progress to Redis Pub/Sub
        
    Redis:
        - Message broker for Celery tasks
        - Pub/Sub for real-time progress streaming

Endpoints:
    POST /audits/start - Start a new audit (async, returns immediately)
    POST /webhooks/github - Handle GitHub App events
    GET /ws/sessions/{id} - WebSocket for live progress
    GET /projects - List projects
    POST /projects - Create project
    GET /sessions/{id}/findings - Get audit findings
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

# Load environment variables from .env file
from dotenv import load_dotenv

load_dotenv()

import httpx  # noqa: E402
import redis.asyncio as aioredis  # noqa: E402
from fastapi import (  # noqa: E402
    BackgroundTasks,
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import HTMLResponse, RedirectResponse, Response  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, ConfigDict, Field, model_validator  # noqa: E402
from slowapi import Limiter  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402
from slowapi.util import get_remote_address  # noqa: E402
from sqlalchemy import func, text  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from starlette.middleware.sessions import SessionMiddleware  # noqa: E402

from commands.project import ProjectManager  # noqa: E402
from database.models import (  # noqa: E402
    ArenaSponsorInterest,
    AuditSession,
    Base,
    Graph,
    Hypothesis,
    PageView,
    PaymentLog,
    Project,
    ScanExecution,
    Team,
    TeamMember,
    Tenant,
    User,
    create_db_engine,
    create_db_session,
)
from integrations.telegram import (  # noqa: E402
    notify_app_installed,
    notify_arena_sponsor_interest,
    notify_deep_audit_started,
    notify_new_repo_synced,
    notify_repo_added,
)
from server.auth_utils import reject_preview_writes  # noqa: E402
from server.token_crypto import decrypt_token  # noqa: E402

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///hound.db")

# Redis configuration for state tokens
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# GitHub App configuration
GITHUB_APP_SLUG = os.environ.get("GITHUB_APP_SLUG", "firepan-ai")

# Rate limiter for auth endpoints
limiter = Limiter(key_func=get_remote_address)


def rate_limit_key_tenant_or_ip(request: Request) -> str:
    """Custom key for slowapi: tenant_id from verified auth state, else IP."""
    tenant_id = getattr(request.state, "tenant_id", None)
    if tenant_id is not None:
        return f"tenant:{tenant_id}"
    return f"ip:{request.client.host}"

# =============================================================================
# ADMIN AUTHENTICATION
# =============================================================================
# Set HOUND_ADMIN_KEY environment variable to protect admin panel.
# Fails CLOSED when HOUND_ADMIN_KEY is unset, UNLESS HOUND_DEV_MODE=1.
ADMIN_API_KEY = os.environ.get("HOUND_ADMIN_KEY", "")
_DEV_MODE = os.environ.get("HOUND_DEV_MODE", "") == "1"


def verify_admin_auth(request: Request) -> bool:
    """
    Verify admin authentication.
    Returns True if authenticated, False if not.

    Fails CLOSED: if HOUND_ADMIN_KEY is not set the admin panel is locked
    unless HOUND_DEV_MODE=1 (explicit local development opt-in).
    """
    # Fail closed unless explicitly in dev mode
    if not ADMIN_API_KEY:
        return _DEV_MODE

    # Starlette session (set by SQLAdmin auth backend login)
    if request.session.get("admin_logged_in"):
        return True

    # Admin preview marker (set by preview_dashboard_action)
    if request.session.get("admin_preview_authorized"):
        return True

    # API key in header (programmatic access)
    api_key = request.headers.get("X-Admin-Key") or request.headers.get("Authorization", "").replace("Bearer ", "")
    if api_key == ADMIN_API_KEY:
        return True

    # API key in query param (browser access)
    api_key = request.query_params.get("admin_key")
    if api_key == ADMIN_API_KEY:
        return True

    return False


def require_admin(request: Request):
    """Dependency to require admin authentication."""
    if not verify_admin_auth(request):
        # For HTML pages, redirect to login
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(status_code=303, detail="Redirect to login", headers={"Location": "/admin/login"})
        raise HTTPException(status_code=401, detail="Admin authentication required. Set X-Admin-Key header or admin_key query param.")


def _verify_explicit_admin_header(request: Request) -> bool:
    """Check admin credentials via X-Admin-Key header ONLY.

    Unlike verify_admin_auth(), this:
    - Does NOT auto-allow when ADMIN_API_KEY is unset (no open-dev shortcut)
    - Does NOT accept session cookies (CSRF risk on side-effecting endpoints)
    - Does NOT accept query-param auth (leaks into logs/referrers)

    Use this for data endpoints called by admin.py internally.
    """
    if not ADMIN_API_KEY:
        return False  # No open-dev shortcut

    api_key = request.headers.get("X-Admin-Key") or ""
    return api_key == ADMIN_API_KEY


async def require_tenant_or_admin(request: Request) -> int | None:
    """Accept either tenant JWT or explicit admin header auth.

    Returns tenant_id (int) for tenant callers, None for admin callers.
    Raises 401 if neither succeeds. Does NOT auto-allow in open-dev mode.
    """
    if _verify_explicit_admin_header(request):
        return None  # Admin caller — skip tenant ownership check

    # Fall through to tenant JWT (raises 401 if invalid/missing)
    return await get_current_tenant_id(request)


# Create engine lazily to avoid connection errors during import
_engine = None


def get_engine():
    """Get or create database engine."""
    global _engine
    if _engine is None:
        _engine = create_db_engine(DATABASE_URL)
        # Initialize database tables
        Base.metadata.create_all(_engine)
    return _engine


# Create FastAPI app
app = FastAPI(
    title="Hound Dashboard API",
    description="API for Hound security analysis dashboard",
    version="1.0.0",
    root_path=os.environ.get("ROOT_PATH", ""),  # For reverse proxy / port forwarding
)

# Session middleware for flash messages in admin panel
# NOTE: Added BEFORE CORS so CORS is outermost (Starlette middleware is LIFO)
session_secret = os.environ.get("HOUND_SECRET_KEY", secrets.token_urlsafe(32))
app.add_middleware(SessionMiddleware, secret_key=session_secret)

# Configure CORS — must be added AFTER SessionMiddleware so it wraps it
# (Starlette processes middleware in reverse addition order)
# Checks both HOUND_ALLOWED_ORIGINS (production) and ALLOWED_ORIGINS (Assune's dev)
ALLOWED_ORIGINS = os.environ.get("HOUND_ALLOWED_ORIGINS",
    os.getenv("ALLOWED_ORIGINS", "http://localhost:3000")).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Add rate limiter state and exception handler
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})


# Middleware to fix URL generation for proxied requests (Codespaces, ngrok, etc.)
@app.middleware("http")
async def fix_forwarded_headers(request: Request, call_next):
    """
    Ensure X-Forwarded-Proto and X-Forwarded-Host are respected for URL generation.
    This fixes admin panel links when accessed via HTTPS proxy (Codespaces, ngrok, etc.).
    """
    # If we have forwarded proto, update the scope
    forwarded_proto = request.headers.get("x-forwarded-proto")
    if forwarded_proto:
        request.scope["scheme"] = forwarded_proto
    
    # If we have forwarded host, we need to update the headers
    # Starlette uses the Host header for URL generation
    forwarded_host = request.headers.get("x-forwarded-host")
    if forwarded_host:
        # Rebuild headers with the forwarded host as Host
        new_headers = []
        for name, value in request.scope["headers"]:
            if name.lower() == b"host":
                new_headers.append((b"host", forwarded_host.encode()))
            else:
                new_headers.append((name, value))
        request.scope["headers"] = new_headers
    
    response = await call_next(request)
    return response

# Mount static files for generated reports
reports_base_dir = Path.home() / ".hound" / "reports"
reports_base_dir.mkdir(parents=True, exist_ok=True)

try:
    app.mount("/reports", StaticFiles(directory=str(reports_base_dir), html=True), name="reports")
except Exception as e:
    logger.warning(f"Failed to mount reports directory: {e}")

# Mount SQLAdmin dashboard at /admin
from server.admin import setup_admin  # noqa: E402

# Initialize admin panel (deferred until engine is ready)
_admin = None


def get_admin():
    """Get or create admin panel."""
    global _admin
    if _admin is None:
        engine = get_engine()
        _admin = setup_admin(app, engine)
    return _admin


# Initialize admin and validate x402 on startup
@app.on_event("startup")
async def startup_event():
    """Initialize admin panel, apply schema patches, and validate x402 config on startup."""
    get_admin()

    # Apply idempotent schema patches (e.g. new columns on existing tables)
    from database.models import ensure_schema
    ensure_schema(get_engine())

    # Fail-fast: validate x402 config if enabled
    from server.x402_config import get_x402_config
    try:
        config = get_x402_config()
        if config:
            logger.info("x402 payments enabled with %d paid routes", len(config.route_pricing))
    except RuntimeError as e:
        logger.error("x402 configuration error: %s", e)
        raise


# Register authentication routes
from server.auth_routes import router as auth_router  # noqa: E402

app.include_router(auth_router)

# Register Stripe billing routes
try:
    from server.stripe_routes import (
        router as stripe_router,  # noqa: E402
        webhook_router as stripe_webhook_router,  # noqa: E402
    )

    app.include_router(stripe_router)           # /billing/* — authenticated endpoints
    app.include_router(stripe_webhook_router)    # /webhooks/stripe — Stripe signature only
except Exception as e:
    logger.warning("Stripe routes not loaded (stripe package may not be installed): %s", e)

# Register x402 discount/coupon routes
from server.x402_routes import router as x402_router  # noqa: E402

app.include_router(x402_router)

# Redirect for URL compatibility - auditsession -> audit-session
from starlette.responses import RedirectResponse as StarletteRedirect  # noqa: E402


@app.get("/admin/auditsession/{path:path}")
async def redirect_auditsession(path: str):
    """Redirect old auditsession URLs to audit-session."""
    return StarletteRedirect(f"/admin/audit-session/{path}", status_code=301)


# =============================================================================
# ADMIN TENANT PREVIEW (read-only impersonation)
# =============================================================================

class PreviewExchangeRequest(BaseModel):
    code: str

class PreviewExchangeResponse(BaseModel):
    token: str
    tenant_id: int
    tenant_name: str


# Dependency for database session
def get_db():
    """Get database session."""
    engine = get_engine()
    db = create_db_session(engine)
    try:
        yield db
    finally:
        db.close()


# Authentication dependency for protected endpoints
async def get_current_tenant_id(request: Request) -> int:
    """
    Extract tenant_id from JWT token for authenticated requests.
    
    This dependency can be used to protect endpoints that require authentication.
    It extracts the tenant_id from the JWT token in the Authorization header.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tenant ID from the JWT token
        
    Raises:
        HTTPException: If token is missing, invalid, or expired
    """
    from server.auth_routes import get_token_from_header
    from server.auth_utils import get_current_user_from_token
    
    try:
        token = get_token_from_header(request)
        payload = get_current_user_from_token(token)
        tenant_id = payload.get("tenant_id")
        
        if not tenant_id:
            raise HTTPException(status_code=401, detail="Invalid token: missing tenant_id")
        
        return tenant_id
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {str(e)}")


# Optional authentication - returns None if no token provided
async def get_optional_tenant_id(request: Request) -> int | None:
    """
    Extract tenant_id from JWT token if present, otherwise return None.
    
    This is useful for endpoints that work both with and without authentication,
    but may have different behavior based on authentication status.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Tenant ID from JWT token if present, None otherwise
    """
    try:
        return await get_current_tenant_id(request)
    except HTTPException:
        return None


# Get current user from JWT token
async def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """
    Extract user from JWT token for authenticated requests.
    
    This dependency can be used to protect endpoints that require authentication
    and need access to the full user object.
    
    Args:
        request: FastAPI request object
        db: Database session
        
    Returns:
        User object from database
        
    Raises:
        HTTPException: If token is missing, invalid, expired, or user not found
    """
    # NOTE: we use decode_access_token() rather than get_current_user_from_token()
    # because the latter strips the payload down to {user_id, tenant_id} and
    # drops custom claims like `admin_preview` — which we need to see here so
    # we can distinguish "preview with no User row" (404) from "broken token" (401).
    # CLAUDE.md gotcha #admin-preview memorialises this trap.
    from server.auth_routes import get_token_from_header
    from server.auth_utils import decode_access_token

    try:
        token = get_token_from_header(request)
        payload = decode_access_token(token)
        user_id = payload.get("user_id")

        # Admin-preview tokens are tenant-scoped with user_id=0 and carry an
        # `admin_preview: true` claim.  They pass JWT verification (the token
        # is genuinely issued by us) but there is no backing User row to
        # return, so this endpoint responds 404.  We must NOT 401 here: the
        # frontend treats 401 as "session expired" and silently drops the
        # preview, kicking the admin out of their own preview mid-navigation.
        if not user_id:
            if payload.get("admin_preview"):
                raise HTTPException(status_code=404, detail="User not found (admin preview)")
            raise HTTPException(status_code=401, detail="Invalid token: missing user_id")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return user
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {str(e)}")


# =============================================================================
# TEAM ADMIN GATE — require admin role on the caller's tenant team
# =============================================================================

def require_team_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TeamMember:
    """Require the caller to be an admin of their tenant-wide team.

    Returns the TeamMember row for downstream use (e.g., to know the caller's
    team_id without re-querying). 404 if the tenant has no team (pre-backfill
    edge case); 403 if the caller is not an admin.
    """
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    if not tenant or not tenant.team_id:
        raise HTTPException(status_code=404, detail="Tenant team not found")
    member = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == tenant.team_id, TeamMember.user_id == current_user.id)
        .first()
    )
    if not member or member.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return member


# =============================================================================
# GITHUB CAPABILITY GATE — require linked GitHub for scan operations
# =============================================================================

async def require_github_linked(request: Request, db: Session = Depends(get_db)) -> User:
    """Require that the current user has a linked GitHub account with token.

    Use as a FastAPI dependency on scan-triggering endpoints.
    Google-only users must link GitHub before running scans.
    """
    from server.auth_routes import get_token_from_header
    from server.auth_utils import get_current_user_from_token

    token = get_token_from_header(request)
    try:
        payload = get_current_user_from_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user or not user.github_id or not user.github_token_encrypted:
        raise HTTPException(
            status_code=403,
            detail="GitHub account required. Connect GitHub in Settings to run scans.",
            headers={"X-Requires-Github": "true"},
        )
    return user


# =============================================================================
# EMAIL VERIFICATION GATE — require verified email for analysis endpoints
# =============================================================================

from server.email_verification import _make_require_verified_email, mount_email_routes  # noqa: E402

mount_email_routes(app)
require_verified_email = _make_require_verified_email(get_current_tenant_id)


# =============================================================================
# EMAIL UNSUBSCRIBE — canonical URL for lifecycle emails
# =============================================================================
# Token shape is defined in integrations/lifecycle_emails.py. Self-contained HMAC
# opaque token; no login required.

@app.get("/email/unsubscribe", response_class=HTMLResponse)
async def email_unsubscribe(t: str = "", db: Session = Depends(get_db)):
    """Honor an unsubscribe click from a lifecycle email.

    The token carries the tenant_id + HMAC signature. We flip
    tenant.email_unsubscribed=True (idempotent) and return a simple HTML page.
    Transactional emails (force_send=True, e.g. DEEP_AUDIT_DONE) still go through.
    """
    from integrations.lifecycle_emails import verify_unsubscribe_token

    tenant_id = verify_unsubscribe_token(t)
    if tenant_id is None:
        return HTMLResponse(
            content=(
                "<html><body style='font-family:-apple-system,sans-serif;max-width:500px;margin:60px auto;padding:24px;'>"
                "<h2>Invalid link</h2>"
                "<p>This unsubscribe link is invalid or has expired.</p>"
                "<p style='color:#666;font-size:13px;'>Email <a href='mailto:support@firepan.com'>support@firepan.com</a> if you keep receiving mail.</p>"
                "</body></html>"
            ),
            status_code=400,
        )

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if tenant is None:
        return HTMLResponse(
            content="<html><body><h2>Account not found</h2></body></html>",
            status_code=404,
        )

    if not tenant.email_unsubscribed:
        tenant.email_unsubscribed = True
        db.commit()

    return HTMLResponse(
        content=(
            "<html><body style='font-family:-apple-system,sans-serif;max-width:500px;margin:60px auto;padding:24px;'>"
            "<h2>You've been unsubscribed</h2>"
            "<p>You will no longer receive marketing emails from Firepan.</p>"
            "<p style='color:#666;font-size:14px;'>Critical security notifications (completed deep audits, etc.) will still reach you.</p>"
            "<p><a href='https://app.firepan.com'>Return to Firepan</a></p>"
            "</body></html>"
        ),
        status_code=200,
    )


# =============================================================================
# ARENA SPONSOR INTEREST — public splash form at arena.firepan.com
# =============================================================================
# No auth. Honeypot + dwell-time check + rate limit. Writes to
# arena_sponsor_interest table and pings Firepan ops Telegram.

class ArenaInterestCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=255)
    name: str | None = Field(default=None, max_length=255)
    protocol: str | None = Field(default=None, max_length=255)
    estimated_pool_usd: int | None = Field(default=None, ge=0, le=1_000_000_000)
    message: str | None = Field(default=None, max_length=2000)
    source: str | None = Field(default="splash", max_length=32)
    website: str | None = Field(default=None, max_length=255)  # honeypot
    elapsed_ms: int | None = Field(default=None, ge=0)


@app.post("/arena/interest")
@limiter.limit("5/minute")
async def arena_interest(
    request: Request,
    payload: ArenaInterestCreate,
    db: Session = Depends(get_db),
):
    """Public sponsor interest capture from arena.firepan.com splash page.

    Silently drops bot submissions (honeypot + dwell-time) with 200s so scrapers
    don't learn the filters. Real submissions are stored and pinged to Telegram.
    """
    # Honeypot: any value in `website` = bot. Silent 200, no DB write.
    if payload.website:
        return {"ok": True}
    # Dwell-time: form rendered and submitted in < 2s = bot. Silent 200.
    if payload.elapsed_ms is not None and payload.elapsed_ms < 2000:
        return {"ok": True}
    # Email shape: reject obviously malformed
    if "@" not in payload.email or "." not in payload.email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="Invalid email")

    # Hash the submitter's IP for abuse review without storing raw PII.
    client_ip = request.client.host if request.client else ""
    salt = os.environ.get("HOUND_SECRET_KEY", "")
    ip_hash = (
        hashlib.sha256(f"{client_ip}:{salt}".encode()).hexdigest()
        if client_ip else None
    )
    user_agent = (request.headers.get("user-agent") or "")[:500]

    row = ArenaSponsorInterest(
        email=payload.email,
        name=payload.name,
        protocol=payload.protocol,
        estimated_pool_usd=payload.estimated_pool_usd,
        message=payload.message,
        source=payload.source or "splash",
        ip_hash=ip_hash,
        user_agent=user_agent,
    )
    db.add(row)
    db.commit()

    try:
        await notify_arena_sponsor_interest(
            email=payload.email,
            name=payload.name,
            protocol=payload.protocol,
            estimated_pool_usd=payload.estimated_pool_usd,
            message=payload.message,
        )
    except Exception as e:
        logger.warning("Arena interest Telegram notify failed: %s", e)

    return {"ok": True}


# =============================================================================
# AGENT-NATIVE AUDIT ROUTES — mounted after dependencies are defined
# =============================================================================

from server.agent_routes import configure_dependencies as _configure_agent_deps, router as agent_router  # noqa: E402

_configure_agent_deps(get_db, get_current_tenant_id)
app.include_router(agent_router)


# =============================================================================
# ADMIN TENANT PREVIEW — endpoints (after get_db is defined)
# =============================================================================

@app.get("/admin/tenant/{tenant_id}/preview")
async def admin_generate_preview_code(
    tenant_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    """Generate a one-time preview code and redirect to the dashboard."""
    if not verify_admin_auth(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    # Consume the session marker so it can't be reused
    request.session.pop("admin_preview_authorized", None)

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    code = secrets.token_urlsafe(32)
    redis_client = get_auth_redis_client()
    try:
        await redis_client.setex(
            f"admin_preview:{code}",
            120,  # 2 min TTL
            json.dumps({"tenant_id": tenant_id, "tenant_name": tenant.name}),
        )
    finally:
        await redis_client.aclose()

    frontend_url = os.environ.get("FRONTEND_URL", "https://app.firepan.com")
    return RedirectResponse(f"{frontend_url}/admin-preview?code={code}", status_code=302)


@app.post("/admin/preview/exchange", response_model=PreviewExchangeResponse)
@limiter.limit("10/minute")
async def exchange_preview_code(request: Request, body: PreviewExchangeRequest):
    """Exchange a one-time preview code for a short-lived read-only JWT."""
    redis_client = get_auth_redis_client()
    try:
        key = f"admin_preview:{body.code}"
        data_raw = await redis_client.getdel(key)  # atomic consume
        if not data_raw:
            raise HTTPException(status_code=400, detail="Invalid or expired preview code")
    finally:
        await redis_client.aclose()

    data = json.loads(data_raw)
    from server.auth_utils import create_access_token
    token = create_access_token(
        data={
            "user_id": 0,
            "tenant_id": data["tenant_id"],
            "admin_preview": True,
        },
        expires_delta=timedelta(hours=1),
    )

    return PreviewExchangeResponse(
        token=token,
        tenant_id=data["tenant_id"],
        tenant_name=data["tenant_name"],
    )


# ============================================================================
# INTERACTIVE ADMIN DASHBOARD PAGES
# ============================================================================

@app.get("/admin/home", response_class=HTMLResponse)
def admin_home(request: Request, db: Session = Depends(get_db), _auth: bool = Depends(require_admin)):
    """
    Admin home page with quick links to all features.
    """
    from sqlalchemy import func

    from database.models import TokenUsageLog
    
    # Get quick stats
    total_projects = db.query(func.count(Project.id)).scalar() or 0
    total_scans = db.query(func.count(ScanExecution.id)).scalar() or 0
    total_findings = db.query(func.count(Hypothesis.id)).scalar() or 0
    
    # Token stats (last 30 days)
    since = datetime.now() - timedelta(days=30)
    total_cost = db.query(func.sum(TokenUsageLog.cost_usd)).filter(
        TokenUsageLog.created_at >= since
    ).scalar() or 0
    db.query(func.sum(TokenUsageLog.total_tokens)).filter(
        TokenUsageLog.created_at >= since
    ).scalar() or 0
    
    # Get active config profile
    active_profile = _active_config_profile
    config = get_active_config()
    models = config.get("models", {})
    
    # Build model badges for display
    profile_badges = {
        "default": ("Default", "secondary"),
        "deepseek": ("DeepSeek", "success"),
        "premium": ("Premium", "warning"),
        "example": ("Example", "info"),
    }
    badge_text, badge_color = profile_badges.get(active_profile, (active_profile, "secondary"))
    
    # Get primary model for display
    primary_model = "Not configured"
    if models:
        first_profile = list(models.values())[0]
        provider = first_profile.get("provider", "?")
        model = first_profile.get("model", "?")
        primary_model = f"{provider}/{model}"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Hound Admin - Home</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{ background: #f5f5f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: white;
                border-radius: 12px;
                padding: 25px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                text-align: center;
                transition: transform 0.2s;
            }}
            .stat-card:hover {{ transform: translateY(-5px); }}
            .stat-value {{ font-size: 36px; font-weight: bold; color: #667eea; }}
            .stat-label {{ color: #666; font-size: 14px; margin-top: 5px; }}
            .link-card {{
                background: white;
                border-radius: 12px;
                padding: 25px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                text-decoration: none;
                color: inherit;
                display: block;
                transition: all 0.2s;
            }}
            .link-card:hover {{ 
                transform: translateY(-5px); 
                box-shadow: 0 8px 20px rgba(0,0,0,0.15);
                color: inherit;
            }}
            .link-icon {{
                font-size: 40px;
                margin-bottom: 15px;
                color: #667eea;
            }}
            .link-title {{ font-size: 18px; font-weight: 600; margin-bottom: 8px; }}
            .link-desc {{ color: #666; font-size: 14px; }}
            .section-title {{ 
                font-size: 20px; 
                font-weight: 600; 
                margin: 30px 0 20px 0;
                color: #333;
            }}
            .config-selector {{
                background: rgba(255,255,255,0.15);
                border-radius: 8px;
                padding: 15px 20px;
                margin-top: 20px;
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            .config-selector select {{
                padding: 8px 15px;
                border-radius: 6px;
                border: none;
                font-size: 14px;
                min-width: 200px;
            }}
            .config-selector .model-info {{
                opacity: 0.9;
                font-size: 13px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1><i class="fas fa-shield-dog"></i> Hound Admin</h1>
                <p style="opacity: 0.9; margin: 0;">Security Analysis Platform Dashboard</p>
                
                <div class="d-flex justify-content-between align-items-start mt-3">
                    <div class="config-selector" style="margin-top: 0;">
                        <label style="font-weight: 500;"><i class="fas fa-cog"></i> LLM Config:</label>
                        <select id="configProfile" onchange="switchConfig(this.value)">
                            <option value="default" {"selected" if active_profile == "default" else ""}>Default</option>
                            <option value="deepseek" {"selected" if active_profile == "deepseek" else ""}>🚀 DeepSeek (95% cheaper)</option>
                            <option value="premium" {"selected" if active_profile == "premium" else ""}>⭐ Premium (best quality)</option>
                        </select>
                        <span class="model-info">Primary model: <strong>{primary_model}</strong></span>
                        <span class="badge bg-{badge_color}">{badge_text}</span>
                    </div>
                    {"<a href='/admin/logout' class='btn btn-outline-light btn-sm'><i class='fas fa-sign-out-alt'></i> Logout</a>" if ADMIN_API_KEY else ""}
                </div>
            </div>
        </div>
        
        <div class="container">
            <!-- Quick Stats -->
            <div class="row g-4 mb-4">
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-value">{total_projects}</div>
                        <div class="stat-label">Projects</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-value">{total_scans}</div>
                        <div class="stat-label">Surface Scans</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-value">{total_findings}</div>
                        <div class="stat-label">Findings</div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-card">
                        <div class="stat-value" style="color: #28a745;">${total_cost:.2f}</div>
                        <div class="stat-label">LLM Cost (30d)</div>
                    </div>
                </div>
            </div>
            
            <!-- Cost & Analytics -->
            <div class="section-title"><i class="fas fa-chart-line"></i> Cost & Analytics</div>
            <div class="row g-4 mb-4">
                <div class="col-md-4">
                    <a href="/admin/cost-dashboard" class="link-card">
                        <div class="link-icon"><i class="fas fa-coins"></i></div>
                        <div class="link-title">Cost Dashboard</div>
                        <div class="link-desc">View LLM token usage and costs. Track spending by model, project, and profile.</div>
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/admin/token-usage-log/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-list-alt"></i></div>
                        <div class="link-title">Token Usage Logs</div>
                        <div class="link-desc">Browse detailed logs of every LLM API call with token counts and costs.</div>
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/admin/token-stats" class="link-card">
                        <div class="link-icon"><i class="fas fa-chart-bar"></i></div>
                        <div class="link-title">Stats API (JSON)</div>
                        <div class="link-desc">Raw statistics endpoint for building custom dashboards and integrations.</div>
                    </a>
                </div>
            </div>
            
            <!-- Lead Generation -->
            <div class="section-title"><i class="fas fa-magnet"></i> Lead Generation</div>
            <div class="row g-4 mb-4">
                <div class="col-md-4">
                    <a href="/admin/scan-execution/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-radar"></i></div>
                        <div class="link-title">Surface Scans</div>
                        <div class="link-desc">Manage lightweight security scans. Run scans, view findings, convert to projects.</div>
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/admin/scan-execution/create" class="link-card">
                        <div class="link-icon"><i class="fas fa-plus-circle"></i></div>
                        <div class="link-title">New Scan</div>
                        <div class="link-desc">Start a new surface scan by entering a GitHub repository URL.</div>
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/surface/stats" class="link-card">
                        <div class="link-icon"><i class="fas fa-chart-pie"></i></div>
                        <div class="link-title">Scan Statistics</div>
                        <div class="link-desc">View scan analytics: risk levels, completion rates, recent activity.</div>
                    </a>
                </div>
            </div>
            
            <!-- Audit Management -->
            <div class="section-title"><i class="fas fa-shield-alt"></i> Audit Management</div>
            <div class="row g-4 mb-4">
                <div class="col-md-3">
                    <a href="/admin/project/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-code-branch"></i></div>
                        <div class="link-title">Projects</div>
                        <div class="link-desc">Manage audit projects, build graphs, run audits.</div>
                    </a>
                </div>
                <div class="col-md-3">
                    <a href="/admin/audit-session/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-search"></i></div>
                        <div class="link-title">Audit Sessions</div>
                        <div class="link-desc">View running and completed audit sessions.</div>
                    </a>
                </div>
                <div class="col-md-3">
                    <a href="/admin/hypothesis/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-lightbulb"></i></div>
                        <div class="link-title">Findings</div>
                        <div class="link-desc">Review vulnerability findings, confirm or reject.</div>
                    </a>
                </div>
                <div class="col-md-3">
                    <a href="/admin/graph/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-project-diagram"></i></div>
                        <div class="link-title">Knowledge Graphs</div>
                        <div class="link-desc">Browse code knowledge graphs built for analysis.</div>
                    </a>
                </div>
            </div>
            
            <!-- System -->
            <div class="section-title"><i class="fas fa-cog"></i> System</div>
            <div class="row g-4 mb-5">
                <div class="col-md-4">
                    <a href="/admin/tenant/list" class="link-card">
                        <div class="link-icon"><i class="fas fa-building"></i></div>
                        <div class="link-title">Tenants</div>
                        <div class="link-desc">Manage multi-tenant organizations and GitHub installations.</div>
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/health" class="link-card">
                        <div class="link-icon"><i class="fas fa-heartbeat"></i></div>
                        <div class="link-title">Health Check</div>
                        <div class="link-desc">API health status and system information.</div>
                    </a>
                </div>
                <div class="col-md-4">
                    <a href="/docs" class="link-card">
                        <div class="link-icon"><i class="fas fa-book"></i></div>
                        <div class="link-title">API Documentation</div>
                        <div class="link-desc">Interactive Swagger/OpenAPI documentation for all endpoints.</div>
                    </a>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            async function switchConfig(profileId) {{
                try {{
                    const response = await fetch(`/config/profiles/${{profileId}}/activate`, {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }}
                    }});
                    
                    if (response.ok) {{
                        const data = await response.json();
                        // Show success toast
                        const toast = document.createElement('div');
                        toast.className = 'alert alert-success position-fixed';
                        toast.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
                        toast.innerHTML = `<strong>✅ Config Switched!</strong><br>Now using: ${{profileId}}`;
                        document.body.appendChild(toast);
                        setTimeout(() => toast.remove(), 3000);
                        
                        // Reload to update the page
                        setTimeout(() => location.reload(), 1000);
                    }} else {{
                        const err = await response.json();
                        alert('Failed to switch config: ' + err.detail);
                    }}
                }} catch (e) {{
                    alert('Error switching config: ' + e.message);
                }}
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@app.get("/admin/dashboard/{project_id}", response_class=HTMLResponse)
async def admin_project_dashboard(project_id: int, request: Request, db: Session = Depends(get_db), _auth: bool = Depends(require_admin)):
    """
    Interactive project dashboard with graph visualization, findings, and activity.
    Brings chatbot-style visualization features to the admin panel.
    """
    # Get project
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return HTMLResponse(content="<h1>Project not found</h1>", status_code=404)
    
    # Get graphs
    graphs = db.query(Graph).filter(Graph.project_id == project_id).all()
    
    # Get findings
    findings = db.query(Hypothesis).filter(Hypothesis.project_id == project_id).order_by(Hypothesis.confidence.desc()).all()
    
    # Get sessions
    sessions = db.query(AuditSession).filter(AuditSession.project_id == project_id).order_by(AuditSession.start_time.desc()).limit(10).all()
    
    # Get active session if any
    active_session = None
    for s in sessions:
        if s.status in ('running', 'queued'):
            active_session = s
            break
    
    # Prepare graph data for D3 visualization
    graphs_json = {}
    for g in graphs:
        graphs_json[g.name] = g.data if g.data else {"nodes": [], "edges": []}
    
    # Prepare findings data
    findings_json = [
        {
            "id": f.hypothesis_id,
            "title": f.title,
            "description": f.description,
            "vulnerability_type": f.vulnerability_type,
            "status": f.status,
            "confidence": f.confidence,
            "severity": f.severity,
            "node_refs": f.node_refs or [],
            "evidence": f.evidence or {},
        }
        for f in findings
    ]
    
    # Prepare sessions data
    sessions_json = [
        {
            "id": s.session_id,
            "status": s.status,
            "started": s.start_time.isoformat() if s.start_time else None,
            "ended": s.end_time.isoformat() if s.end_time else None,
            "token_usage": s.token_usage,
            "models": s.models,
        }
        for s in sessions
    ]
    
    # Aggregate token usage across all sessions
    total_tokens = {"input": 0, "output": 0, "total": 0, "calls": 0}
    model_usage = {}
    for s in sessions:
        if s.token_usage:
            tu = s.token_usage.get("total_usage", {})
            total_tokens["input"] += tu.get("input_tokens", 0)
            total_tokens["output"] += tu.get("output_tokens", 0)
            total_tokens["total"] += tu.get("total_tokens", 0)
            total_tokens["calls"] += tu.get("call_count", 0)
            
            by_model = s.token_usage.get("by_model", {})
            for model_key, usage in by_model.items():
                if model_key not in model_usage:
                    model_usage[model_key] = {"input": 0, "output": 0, "total": 0, "calls": 0}
                model_usage[model_key]["input"] += usage.get("input_tokens", 0)
                model_usage[model_key]["output"] += usage.get("output_tokens", 0)
                model_usage[model_key]["total"] += usage.get("total_tokens", 0)
                model_usage[model_key]["calls"] += usage.get("call_count", 0)
    
    # Cost estimates per 1M tokens (approximate pricing)
    model_pricing = {
        "anthropic:claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
        "anthropic:claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
        "anthropic:claude-3-5-sonnet-20241022": {"input": 3.00, "output": 15.00},
        "anthropic:claude-3-opus": {"input": 15.00, "output": 75.00},
        "anthropic:claude-3-haiku": {"input": 0.25, "output": 1.25},
        "openai:gpt-4o": {"input": 2.50, "output": 10.00},
        "openai:gpt-4o-mini": {"input": 0.15, "output": 0.60},
        "openai:gpt-4-turbo": {"input": 10.00, "output": 30.00},
        "openai:o1": {"input": 15.00, "output": 60.00},
        "openai:o1-mini": {"input": 3.00, "output": 12.00},
        "deepseek:deepseek-chat": {"input": 0.14, "output": 0.28},
        "deepseek:deepseek-reasoner": {"input": 0.55, "output": 2.19},
        "gemini:gemini-2.0-flash": {"input": 0.10, "output": 0.40},
        "gemini:gemini-1.5-pro": {"input": 1.25, "output": 5.00},
        "xai:grok-2": {"input": 2.00, "output": 10.00},
    }
    
    # Calculate estimated costs
    estimated_cost = 0.0
    for model_key, usage in model_usage.items():
        pricing = model_pricing.get(model_key, {"input": 3.00, "output": 15.00})  # Default to Sonnet pricing
        input_cost = (usage["input"] / 1_000_000) * pricing["input"]
        output_cost = (usage["output"] / 1_000_000) * pricing["output"]
        estimated_cost += input_cost + output_cost
    
    usage_json = {
        "total": total_tokens,
        "by_model": model_usage,
        "estimated_cost": round(estimated_cost, 4),
        "pricing": model_pricing,
    }
    
    # Pre-generate model usage HTML to avoid nested f-string issues
    if model_usage:
        model_usage_html = ""
        for model, usage in model_usage.items():
            model_name = model.split(':')[-1] if ':' in model else model
            model_provider = model.split(':')[0] if ':' in model else 'unknown'
            model_usage_html += f'''
                <div class="model-item">
                    <div class="model-name">{model_name}</div>
                    <div class="model-provider">{model_provider}</div>
                    <div class="model-stats">
                        <span>{usage["total"]:,} tokens</span>
                        <span>{usage["calls"]} calls</span>
                    </div>
                </div>'''
    else:
        model_usage_html = '<div class="empty-state"><div class="icon">📈</div><div>No usage data yet.<br>Run an audit to track token usage.</div></div>'
    
    # Get base URL for WebSocket
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_proto = "wss" if proto == "https" else "ws"
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Dashboard: {project.name}</title>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
            
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: linear-gradient(135deg, #0f1419 0%, #1a1f2e 100%);
                color: #e6edf3;
                min-height: 100vh;
            }}
            
            .header {{
                background: linear-gradient(135deg, #1c2128 0%, #2d333b 100%);
                padding: 16px 24px;
                border-bottom: 1px solid #30a14e33;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            
            .header h1 {{
                font-size: 20px;
                font-weight: 600;
                color: #30a14e;
            }}
            
            .header .back-link {{
                color: #58a6ff;
                text-decoration: none;
                font-size: 14px;
            }}
            
            .header .back-link:hover {{ text-decoration: underline; }}
            
            .controls {{
                background: #161b22;
                padding: 12px 24px;
                border-bottom: 1px solid #30363d;
                display: flex;
                gap: 20px;
                align-items: center;
                flex-wrap: wrap;
            }}
            
            .control-group {{
                display: flex;
                flex-direction: column;
                gap: 4px;
            }}
            
            .control-group label {{
                font-size: 11px;
                color: #7d8590;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            select, button, input {{
                background: #21262d;
                color: #e6edf3;
                border: 1px solid #30363d;
                padding: 8px 12px;
                border-radius: 6px;
                font-family: inherit;
                font-size: 13px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            
            select:hover, button:hover {{ background: #30363d; border-color: #30a14e; }}
            button.primary {{ background: #238636; border-color: #238636; }}
            button.primary:hover {{ background: #2ea043; }}
            button.danger {{ background: #da3633; border-color: #da3633; }}
            
            .main-container {{
                display: grid;
                grid-template-columns: 1fr 400px;
                height: calc(100vh - 120px);
            }}
            
            .graph-container {{
                background: #0d1117;
                position: relative;
                overflow: hidden;
            }}
            
            .graph-container svg {{
                width: 100%;
                height: 100%;
            }}
            
            .sidebar {{
                background: #161b22;
                border-left: 1px solid #30363d;
                overflow-y: auto;
                display: flex;
                flex-direction: column;
            }}
            
            .tabs {{
                display: flex;
                border-bottom: 1px solid #30363d;
                background: #1c2128;
            }}
            
            .tab {{
                flex: 1;
                padding: 12px;
                text-align: center;
                cursor: pointer;
                font-size: 13px;
                font-weight: 500;
                color: #7d8590;
                border-bottom: 2px solid transparent;
                transition: all 0.2s;
            }}
            
            .tab:hover {{ color: #e6edf3; background: #21262d; }}
            .tab.active {{ color: #30a14e; border-bottom-color: #30a14e; }}
            
            .tab-content {{
                flex: 1;
                overflow-y: auto;
                padding: 16px;
            }}
            
            .tab-pane {{ display: none; }}
            .tab-pane.active {{ display: block; }}
            
            .finding-item {{
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            
            .finding-item:hover {{
                border-color: #30a14e;
                transform: translateY(-1px);
            }}
            
            .finding-item.rejected {{
                opacity: 0.6;
            }}
            
            .finding-item.rejected .finding-title {{
                text-decoration: line-through;
            }}
            
            .finding-header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 8px;
            }}
            
            .finding-title {{
                font-weight: 600;
                font-size: 14px;
                color: #e6edf3;
                flex: 1;
            }}
            
            .badge {{
                font-size: 11px;
                padding: 2px 8px;
                border-radius: 999px;
                font-weight: 500;
            }}
            
            .badge.critical {{ background: #da3633; color: #fff; }}
            .badge.high {{ background: #d29922; color: #fff; }}
            .badge.medium {{ background: #58a6ff; color: #fff; }}
            .badge.low {{ background: #3d444d; color: #aaa; }}
            .badge.confirmed {{ background: #238636; color: #fff; }}
            .badge.rejected {{ background: #6e7681; color: #fff; }}
            .badge.proposed {{ background: #1f6feb; color: #fff; }}
            
            .finding-meta {{
                font-size: 12px;
                color: #7d8590;
                margin-top: 6px;
            }}
            
            .confidence-bar {{
                height: 4px;
                background: #30363d;
                border-radius: 2px;
                margin-top: 8px;
                overflow: hidden;
            }}
            
            .confidence-bar .fill {{
                height: 100%;
                background: linear-gradient(90deg, #30a14e, #56d364);
                transition: width 0.3s;
            }}
            
            .actions {{
                display: flex;
                gap: 6px;
                margin-top: 10px;
            }}
            
            .actions button {{
                flex: 1;
                padding: 6px 10px;
                font-size: 12px;
            }}
            
            .actions .confirm {{ background: #238636; border-color: #238636; }}
            .actions .reject {{ background: #6e7681; border-color: #6e7681; }}
            
            .node-info {{
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 12px;
            }}
            
            .node-info h4 {{
                font-size: 14px;
                color: #30a14e;
                margin-bottom: 8px;
            }}
            
            .node-info .detail {{
                font-size: 12px;
                color: #8b949e;
                margin-bottom: 4px;
            }}
            
            .node-info .detail strong {{
                color: #e6edf3;
            }}
            
            .node-info code {{
                background: #0d1117;
                padding: 8px;
                border-radius: 4px;
                display: block;
                margin-top: 8px;
                font-family: 'JetBrains Mono', monospace;
                font-size: 11px;
                white-space: pre-wrap;
                max-height: 200px;
                overflow-y: auto;
                color: #e6edf3;
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
                margin-bottom: 16px;
            }}
            
            .stat-card {{
                background: #21262d;
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                text-align: center;
            }}
            
            .stat-value {{
                font-size: 24px;
                font-weight: 600;
                color: #30a14e;
            }}
            
            .stat-label {{
                font-size: 11px;
                color: #7d8590;
                text-transform: uppercase;
                margin-top: 4px;
            }}
            
            #legend {{
                position: absolute;
                top: 16px;
                right: 16px;
                background: rgba(22, 27, 34, 0.95);
                border: 1px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                max-width: 200px;
                backdrop-filter: blur(10px);
            }}
            
            #legend h4 {{
                font-size: 11px;
                text-transform: uppercase;
                color: #7d8590;
                margin-bottom: 8px;
                border-bottom: 1px solid #30363d;
                padding-bottom: 6px;
            }}
            
            .legend-item {{
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 11px;
                color: #8b949e;
                margin: 4px 0;
            }}
            
            .legend-color {{
                width: 12px;
                height: 12px;
                border-radius: 50%;
            }}
            
            #tooltip {{
                position: absolute;
                background: rgba(22, 27, 34, 0.95);
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 10px;
                font-size: 12px;
                pointer-events: none;
                opacity: 0;
                max-width: 300px;
                z-index: 100;
            }}
            
            .node circle {{
                stroke-width: 2px;
                cursor: pointer;
                transition: all 0.2s;
            }}
            
            .node:hover circle {{
                stroke-width: 3px;
                filter: drop-shadow(0 0 8px currentColor);
            }}
            
            .node text {{
                font-size: 10px;
                fill: #8b949e;
                pointer-events: none;
            }}
            
            .link {{
                stroke-opacity: 0.4;
                fill: none;
            }}
            
            .link:hover {{
                stroke-opacity: 0.8;
            }}
            
            .activity-item {{
                display: flex;
                gap: 10px;
                padding: 8px 0;
                border-bottom: 1px solid #21262d;
                font-size: 12px;
            }}
            
            .activity-time {{
                color: #7d8590;
                min-width: 70px;
            }}
            
            .activity-tag {{
                padding: 2px 8px;
                border-radius: 999px;
                font-size: 10px;
                font-weight: 500;
            }}
            
            .activity-tag.fetch {{ background: #238636; color: #fff; }}
            .activity-tag.memo {{ background: #d29922; color: #fff; }}
            .activity-tag.graph {{ background: #1f6feb; color: #fff; }}
            .activity-tag.hyp {{ background: #da3633; color: #fff; }}
            .activity-tag.think {{ background: #8957e5; color: #fff; }}
            
            .activity-msg {{
                color: #e6edf3;
                flex: 1;
                word-break: break-word;
            }}
            
            .empty-state {{
                text-align: center;
                padding: 40px;
                color: #7d8590;
            }}
            
            .empty-state .icon {{
                font-size: 48px;
            }}
            
            /* Activity Stream Styles */
            .now-investigating {{
                background: linear-gradient(90deg, #1f6feb22 0%, #8957e522 100%);
                border: 1px solid #1f6feb44;
                padding: 12px 16px;
                margin: 0;
                font-size: 13px;
                color: #58a6ff;
                animation: pulse 2s ease-in-out infinite;
            }}
            
            @keyframes pulse {{
                0%, 100% {{ opacity: 1; }}
                50% {{ opacity: 0.7; }}
            }}
            
            .now-investigating.idle {{
                animation: none;
                opacity: 0.6;
                color: #7d8590;
            }}
            
            .activity-controls {{
                display: flex;
                gap: 8px;
                padding: 8px 12px;
                background: #21262d;
                border-bottom: 1px solid #30363d;
            }}
            
            .activity-controls button {{
                padding: 4px 12px;
                font-size: 11px;
            }}
            
            .activity-stream {{
                flex: 1;
                overflow-y: auto;
                padding: 8px 12px;
                max-height: 400px;
            }}
            
            .activity-event {{
                display: flex;
                gap: 8px;
                padding: 6px 8px;
                margin-bottom: 4px;
                background: #21262d;
                border-radius: 6px;
                font-size: 12px;
                align-items: flex-start;
            }}
            
            .activity-event.decision {{ border-left: 3px solid #238636; }}
            .activity-event.result {{ border-left: 3px solid #58a6ff; }}
            .activity-event.thought {{ border-left: 3px solid #8957e5; }}
            .activity-event.error {{ border-left: 3px solid #da3633; }}
            .activity-event.status {{ border-left: 3px solid #d29922; }}
            
            .event-time {{
                color: #7d8590;
                font-size: 10px;
                min-width: 55px;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .event-iteration {{
                background: #30363d;
                color: #8b949e;
                padding: 1px 6px;
                border-radius: 10px;
                font-size: 10px;
                min-width: 30px;
                text-align: center;
            }}
            
            .event-tag {{
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 10px;
                font-weight: 600;
                text-transform: uppercase;
                min-width: 70px;
                text-align: center;
            }}
            
            .event-tag.fetch {{ background: #23863633; color: #3fb950; }}
            .event-tag.memo {{ background: #d2992233; color: #d29922; }}
            .event-tag.graph {{ background: #1f6feb33; color: #58a6ff; }}
            .event-tag.hyp {{ background: #da363333; color: #f85149; }}
            .event-tag.think {{ background: #8957e533; color: #a371f7; }}
            .event-tag.status {{ background: #d2992233; color: #d29922; }}
            .event-tag.error {{ background: #da363333; color: #f85149; }}
            
            .event-content {{
                flex: 1;
                color: #c9d1d9;
                line-height: 1.4;
            }}
            
            .event-content .action {{ color: #58a6ff; font-weight: 500; }}
            .event-content .thought {{ color: #8b949e; font-style: italic; }}
            
            .ws-status {{
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 10px;
                display: flex;
                align-items: center;
                gap: 4px;
            }}
            
            .ws-status.connected {{ background: #23863633; color: #3fb950; }}
            .ws-status.disconnected {{ background: #da363333; color: #f85149; }}
            .ws-status .dot {{
                width: 6px;
                height: 6px;
                border-radius: 50%;
                background: currentColor;
            }}
            
            /* Usage Tab Styles */
            .usage-header {{
                padding: 12px 16px;
                border-bottom: 1px solid #30363d;
            }}
            
            .usage-header h3 {{
                margin: 0;
                font-size: 14px;
                color: #e6edf3;
            }}
            
            .usage-summary {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                padding: 16px;
                background: #0d1117;
                border-bottom: 1px solid #30363d;
            }}
            
            .usage-stat {{
                text-align: center;
                padding: 12px;
                background: #161b22;
                border-radius: 8px;
                border: 1px solid #30363d;
            }}
            
            .usage-stat.highlight {{
                background: linear-gradient(135deg, #238636 0%, #1f6feb 100%);
                border: none;
            }}
            
            .usage-value {{
                font-size: 20px;
                font-weight: 600;
                color: #e6edf3;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .usage-label {{
                font-size: 11px;
                color: #7d8590;
                margin-top: 4px;
                text-transform: uppercase;
            }}
            
            .usage-stat.highlight .usage-label {{
                color: rgba(255,255,255,0.8);
            }}
            
            .usage-breakdown, .model-usage, .pricing-info {{
                padding: 16px;
                border-bottom: 1px solid #21262d;
            }}
            
            .usage-breakdown h4, .model-usage h4, .pricing-info h4 {{
                font-size: 12px;
                color: #7d8590;
                margin: 0 0 12px 0;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            
            .token-row {{
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px solid #21262d;
            }}
            
            .token-row:last-child {{
                border-bottom: none;
            }}
            
            .token-label {{
                color: #7d8590;
            }}
            
            .token-value {{
                color: #e6edf3;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .model-item {{
                background: #21262d;
                border-radius: 6px;
                padding: 12px;
                margin-bottom: 8px;
            }}
            
            .model-name {{
                font-weight: 600;
                color: #e6edf3;
                font-size: 13px;
            }}
            
            .model-provider {{
                font-size: 11px;
                color: #7d8590;
                text-transform: uppercase;
                margin-top: 2px;
            }}
            
            .model-stats {{
                display: flex;
                gap: 16px;
                margin-top: 8px;
                font-size: 12px;
                color: #8b949e;
                font-family: 'JetBrains Mono', monospace;
            }}
            
            .pricing-table {{
                background: #21262d;
                border-radius: 6px;
                overflow: hidden;
            }}
            
            .pricing-row {{
                display: grid;
                grid-template-columns: 2fr 1fr 1fr;
                padding: 8px 12px;
                border-bottom: 1px solid #30363d;
                font-size: 12px;
            }}
            
            .pricing-row:last-child {{
                border-bottom: none;
            }}
            
            .pricing-row.header {{
                background: #161b22;
                font-weight: 600;
                color: #7d8590;
                text-transform: uppercase;
                font-size: 10px;
            }}
            
            .pricing-row span:not(:first-child) {{
                text-align: right;
                font-family: 'JetBrains Mono', monospace;
                color: #3fb950;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <a href="/admin/project/list" class="back-link">&larr; Back to Projects</a>
                <h1>🔍 {project.name}</h1>
            </div>
            <div style="display: flex; gap: 10px;">
                <button onclick="buildGraphs()">Build Graphs</button>
                <button class="primary" onclick="runAudit()">Run Audit</button>
            </div>
        </div>
        
        <div class="controls">
            <div class="control-group">
                <label>Graph</label>
                <select id="graph-selector" onchange="loadGraph(this.value)">
                    {''.join(f'<option value="{g.name}">{g.name}</option>' for g in graphs) if graphs else '<option value="">No graphs</option>'}
                </select>
            </div>
            <div class="control-group">
                <label>Node Filter</label>
                <select id="type-filter" onchange="filterNodes(this.value)">
                    <option value="all">All Types</option>
                </select>
            </div>
            <div class="control-group">
                <label>Layout</label>
                <select id="layout-selector" onchange="changeLayout(this.value)">
                    <option value="force">Force Directed</option>
                    <option value="hierarchical">Hierarchical</option>
                    <option value="circular">Circular</option>
                </select>
            </div>
            <button onclick="resetView()">Reset View</button>
            <button onclick="exportGraph()">Export PNG</button>
        </div>
        
        <div class="main-container">
            <div class="graph-container" id="graph-container">
                <div id="legend"></div>
                <div id="tooltip"></div>
            </div>
            
            <div class="sidebar">
                <div class="tabs">
                    <div class="tab active" data-tab="findings">Findings ({len(findings)})</div>
                    <div class="tab" data-tab="nodes">Node Info</div>
                    <div class="tab" data-tab="activity">Activity</div>
                    <div class="tab" data-tab="usage">Usage</div>
                </div>
                
                <div class="tab-content">
                    <div class="tab-pane active" id="findings-pane">
                        <div class="stats-grid">
                            <div class="stat-card">
                                <div class="stat-value">{len([f for f in findings if f.status == 'confirmed'])}</div>
                                <div class="stat-label">Confirmed</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value">{len([f for f in findings if f.severity in ['critical', 'high']])}</div>
                                <div class="stat-label">High+ Severity</div>
                            </div>
                        </div>
                        
                        <div id="findings-list">
                            {''.join(f'''
                            <div class="finding-item {f.status}" data-id="{f.hypothesis_id}" onclick="selectFinding('{f.hypothesis_id}')">
                                <div class="finding-header">
                                    <div class="finding-title">{f.title[:60]}{'...' if len(f.title) > 60 else ''}</div>
                                    <span class="badge {f.severity}">{f.severity}</span>
                                </div>
                                <div class="finding-meta">{f.vulnerability_type} • <span class="badge {f.status}">{f.status}</span></div>
                                <div class="confidence-bar"><div class="fill" style="width:{int(f.confidence * 100)}%"></div></div>
                                <div class="actions">
                                    <button class="confirm" onclick="event.stopPropagation(); confirmFinding('{f.hypothesis_id}')">Confirm</button>
                                    <button class="reject" onclick="event.stopPropagation(); rejectFinding('{f.hypothesis_id}')">Reject</button>
                                </div>
                            </div>
                            ''' for f in findings) if findings else '<div class="empty-state"><div class="icon">🔍</div><div>No findings yet. Run an audit to discover vulnerabilities.</div></div>'}
                        </div>
                    </div>
                    
                    <div class="tab-pane" id="nodes-pane">
                        <div id="node-details">
                            <div class="empty-state">
                                <div class="icon">📍</div>
                                <div>Click a node in the graph to see details</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-pane" id="activity-pane">
                        <div class="now-investigating idle" id="now-investigating">
                            🔍 Waiting for audit to start...
                        </div>
                        <div class="activity-controls">
                            <span class="ws-status disconnected" id="ws-status">
                                <span class="dot"></span>
                                <span>Disconnected</span>
                            </span>
                            <button onclick="connectToSession()">Connect</button>
                            <button onclick="clearActivity()">Clear</button>
                            <select id="session-selector" onchange="onSessionChange()">
                                <option value="">Select session...</option>
                                {''.join(f'<option value="{s.session_id}" {"selected" if active_session and s.session_id == active_session.session_id else ""}>{s.session_id[:12]}... ({s.status})</option>' for s in sessions) if sessions else ''}
                            </select>
                        </div>
                        <div class="activity-stream" id="activity-stream">
                            <div class="empty-state" id="activity-empty">
                                <div class="icon">📊</div>
                                <div>Activity will appear here during audits.<br>Select a session and click Connect.</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="tab-pane" id="usage-pane">
                        <div class="usage-header">
                            <h3>💰 Token Usage & Cost</h3>
                        </div>
                        <div class="usage-summary">
                            <div class="usage-stat">
                                <div class="usage-value" id="total-tokens">{total_tokens["total"]:,}</div>
                                <div class="usage-label">Total Tokens</div>
                            </div>
                            <div class="usage-stat">
                                <div class="usage-value" id="total-calls">{total_tokens["calls"]:,}</div>
                                <div class="usage-label">API Calls</div>
                            </div>
                            <div class="usage-stat highlight">
                                <div class="usage-value" id="estimated-cost">${estimated_cost:.4f}</div>
                                <div class="usage-label">Estimated Cost</div>
                            </div>
                        </div>
                        
                        <div class="usage-breakdown">
                            <h4>Token Breakdown</h4>
                            <div class="token-row">
                                <span class="token-label">Input Tokens:</span>
                                <span class="token-value">{total_tokens["input"]:,}</span>
                            </div>
                            <div class="token-row">
                                <span class="token-label">Output Tokens:</span>
                                <span class="token-value">{total_tokens["output"]:,}</span>
                            </div>
                        </div>
                        
                        <div class="model-usage">
                            <h4>By Model</h4>
                            <div id="model-usage-list">
                                {model_usage_html}
                            </div>
                        </div>
                        
                        <div class="pricing-info">
                            <h4>💡 Pricing Reference (per 1M tokens)</h4>
                            <div class="pricing-table">
                                <div class="pricing-row header">
                                    <span>Model</span>
                                    <span>Input</span>
                                    <span>Output</span>
                                </div>
                                <div class="pricing-row">
                                    <span>Claude Sonnet 4</span>
                                    <span>$3.00</span>
                                    <span>$15.00</span>
                                </div>
                                <div class="pricing-row">
                                    <span>GPT-4o</span>
                                    <span>$2.50</span>
                                    <span>$10.00</span>
                                </div>
                                <div class="pricing-row">
                                    <span>DeepSeek Chat</span>
                                    <span>$0.14</span>
                                    <span>$0.28</span>
                                </div>
                                <div class="pricing-row">
                                    <span>Gemini 2.0 Flash</span>
                                    <span>$0.10</span>
                                    <span>$0.40</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            // Data from server
            const projectId = {project_id};
            const projectName = "{project.name}";
            const allGraphs = {json.dumps(graphs_json)};
            const allSessions = {json.dumps(sessions_json)};
            const activeSessionId = "{active_session.session_id if active_session else ''}";
            const wsBase = "{ws_proto}://{host}";
            const allFindings = {json.dumps(findings_json)};
            const usageData = {json.dumps(usage_json)};
            
            // D3 visualization state
            let svg, simulation, g;
            let currentGraph = null;
            let currentNodes = [];
            let currentLinks = [];
            let selectedNode = null;
            
            // Color schemes
            const typeColors = {{
                'contract': '#30a14e',
                'interface': '#58a6ff',
                'library': '#a371f7',
                'function': '#56d364',
                'storage': '#f9826c',
                'event': '#79c0ff',
                'modifier': '#bc8cff',
                'external_actor': '#d29922',
                'role': '#ffa657',
                'code': '#30a14e',
                'concept': '#58a6ff',
                'invariant': '#f9826c',
                'observation': '#a371f7',
                'hypothesis': '#d29922',
                'issue': '#f85149',
                'pattern': '#56d364',
                'dataflow': '#79c0ff',
                'custom': '#8b949e'
            }};
            
            const edgeColors = {{
                'calls': '#30a14e',
                'contains': '#58a6ff',
                'depends_on': '#f9826c',
                'references': '#a371f7',
                'uses': '#79c0ff',
                'implements': '#56d364',
                'extends': '#bc8cff',
                'imports': '#d29922',
                'dataflow': '#ffa657',
                'reads': '#39d353',
                'writes': '#ff7b72',
                'custom': '#8b949e'
            }};
            
            function getNodeColor(type) {{
                return typeColors[type?.toLowerCase()] || typeColors.custom;
            }}
            
            function getEdgeColor(type) {{
                return edgeColors[type?.toLowerCase()] || edgeColors.custom;
            }}
            
            // Initialize
            function init() {{
                setupSvg();
                setupTabs();
                
                const graphNames = Object.keys(allGraphs);
                if (graphNames.length > 0) {{
                    loadGraph(graphNames[0]);
                }} else {{
                    showEmptyGraph();
                }}
            }}
            
            function setupSvg() {{
                const container = document.getElementById('graph-container');
                const width = container.clientWidth;
                const height = container.clientHeight;
                
                svg = d3.select('#graph-container')
                    .append('svg')
                    .attr('width', width)
                    .attr('height', height);
                
                // Add zoom behavior
                const zoom = d3.zoom()
                    .scaleExtent([0.1, 4])
                    .on('zoom', (event) => {{
                        g.attr('transform', event.transform);
                    }});
                
                svg.call(zoom);
                
                // Container for graph elements
                g = svg.append('g');
                
                // Arrow marker for edges
                svg.append('defs').append('marker')
                    .attr('id', 'arrowhead')
                    .attr('viewBox', '-0 -5 10 10')
                    .attr('refX', 20)
                    .attr('refY', 0)
                    .attr('orient', 'auto')
                    .attr('markerWidth', 6)
                    .attr('markerHeight', 6)
                    .append('path')
                    .attr('d', 'M 0,-5 L 10,0 L 0,5')
                    .attr('fill', '#8b949e');
            }}
            
            function setupTabs() {{
                document.querySelectorAll('.tab').forEach(tab => {{
                    tab.addEventListener('click', () => {{
                        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                        tab.classList.add('active');
                        document.getElementById(tab.dataset.tab + '-pane').classList.add('active');
                    }});
                }});
            }}
            
            function loadGraph(graphName) {{
                currentGraph = allGraphs[graphName];
                if (!currentGraph) {{
                    showEmptyGraph();
                    return;
                }}
                
                const nodes = currentGraph.nodes || [];
                const edges = currentGraph.edges || [];
                
                // Create node/link data
                currentNodes = nodes.map((n, i) => ({{
                    ...n,
                    id: n.id || n.node_id || `node_${{i}}`,
                    label: n.label || n.name || n.id || `Node ${{i}}`,
                    type: n.type || n.node_type || 'custom',
                    x: Math.random() * 800,
                    y: Math.random() * 600
                }}));
                
                const nodeMap = new Map(currentNodes.map(n => [n.id, n]));
                
                // Map edges - handle both source/target and source_id/target_id field names
                currentLinks = edges.map((e, i) => {{
                    const sourceId = e.source_id || e.source;
                    const targetId = e.target_id || e.target;
                    const sourceNode = nodeMap.get(sourceId);
                    const targetNode = nodeMap.get(targetId);
                    
                    return {{
                        ...e,
                        id: e.id || `edge_${{i}}`,
                        source: sourceNode,
                        target: targetNode,
                        type: e.type || e.label || 'references'
                    }};
                }}).filter(e => e.source && e.target);
                
                console.log('Loaded graph:', currentGraph.name || 'unnamed');
                console.log('Nodes:', currentNodes.length, 'Links:', currentLinks.length);
                
                updateTypeFilter();
                updateLegend();
                renderGraph();
            }}
            
            function showEmptyGraph() {{
                g.selectAll('*').remove();
                g.append('text')
                    .attr('x', svg.attr('width') / 2)
                    .attr('y', svg.attr('height') / 2)
                    .attr('text-anchor', 'middle')
                    .attr('fill', '#7d8590')
                    .text('No graph data. Build graphs first.');
            }}
            
            function renderGraph() {{
                g.selectAll('*').remove();
                
                if (currentNodes.length === 0) {{
                    showEmptyGraph();
                    return;
                }}
                
                const width = parseInt(svg.attr('width'));
                const height = parseInt(svg.attr('height'));
                
                // Create simulation
                simulation = d3.forceSimulation(currentNodes)
                    .force('link', d3.forceLink(currentLinks).id(d => d.id).distance(80))
                    .force('charge', d3.forceManyBody().strength(-200))
                    .force('center', d3.forceCenter(width / 2, height / 2))
                    .force('collision', d3.forceCollide().radius(30));
                
                // Draw edges
                const link = g.append('g')
                    .selectAll('line')
                    .data(currentLinks)
                    .enter()
                    .append('line')
                    .attr('class', 'link')
                    .attr('stroke', d => getEdgeColor(d.type))
                    .attr('stroke-width', 1.5)
                    .attr('marker-end', 'url(#arrowhead)');
                
                // Draw nodes
                const node = g.append('g')
                    .selectAll('.node')
                    .data(currentNodes)
                    .enter()
                    .append('g')
                    .attr('class', 'node')
                    .call(d3.drag()
                        .on('start', dragstarted)
                        .on('drag', dragged)
                        .on('end', dragended));
                
                node.append('circle')
                    .attr('r', d => Math.min(8 + (d.importance || 0) * 2, 20))
                    .attr('fill', d => getNodeColor(d.type))
                    .attr('stroke', d => d3.color(getNodeColor(d.type)).darker(0.5))
                    .on('click', (event, d) => selectNode(d))
                    .on('mouseover', (event, d) => showTooltip(event, d))
                    .on('mouseout', hideTooltip);
                
                node.append('text')
                    .attr('dx', 12)
                    .attr('dy', 4)
                    .text(d => d.label?.substring(0, 20) || '');
                
                // Simulation tick
                simulation.on('tick', () => {{
                    link
                        .attr('x1', d => d.source.x)
                        .attr('y1', d => d.source.y)
                        .attr('x2', d => d.target.x)
                        .attr('y2', d => d.target.y);
                    
                    node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
                }});
            }}
            
            function dragstarted(event, d) {{
                if (!event.active) simulation.alphaTarget(0.3).restart();
                d.fx = d.x;
                d.fy = d.y;
            }}
            
            function dragged(event, d) {{
                d.fx = event.x;
                d.fy = event.y;
            }}
            
            function dragended(event, d) {{
                if (!event.active) simulation.alphaTarget(0);
                d.fx = null;
                d.fy = null;
            }}
            
            function selectNode(node) {{
                selectedNode = node;
                
                // Switch to nodes tab
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                document.querySelector('[data-tab="nodes"]').classList.add('active');
                document.getElementById('nodes-pane').classList.add('active');
                
                // Display node details
                const details = document.getElementById('node-details');
                const content = node.content || node.description || node.summary || '';
                
                details.innerHTML = `
                    <div class="node-info">
                        <h4>${{node.label || node.id}}</h4>
                        <div class="detail"><strong>Type:</strong> ${{node.type || 'unknown'}}</div>
                        <div class="detail"><strong>ID:</strong> ${{node.id}}</div>
                        ${{node.file ? `<div class="detail"><strong>File:</strong> ${{node.file}}</div>` : ''}}
                        ${{node.line ? `<div class="detail"><strong>Line:</strong> ${{node.line}}</div>` : ''}}
                        ${{content ? `<code>${{escapeHtml(content.substring(0, 1000))}}</code>` : ''}}
                    </div>
                `;
                
                // Highlight related findings
                highlightRelatedFindings(node.id);
            }}
            
            function highlightRelatedFindings(nodeId) {{
                document.querySelectorAll('.finding-item').forEach(el => {{
                    el.style.borderColor = '#30363d';
                }});
                
                allFindings.forEach(f => {{
                    if (f.node_refs && f.node_refs.includes(nodeId)) {{
                        const el = document.querySelector(`[data-id="${{f.id}}"]`);
                        if (el) el.style.borderColor = '#30a14e';
                    }}
                }});
            }}
            
            function showTooltip(event, node) {{
                const tooltip = document.getElementById('tooltip');
                tooltip.innerHTML = `
                    <strong>${{node.label || node.id}}</strong><br>
                    <span style="color:#7d8590">Type:</span> ${{node.type || 'unknown'}}<br>
                    ${{node.file ? `<span style="color:#7d8590">File:</span> ${{node.file}}` : ''}}
                `;
                tooltip.style.left = (event.pageX + 10) + 'px';
                tooltip.style.top = (event.pageY - 10) + 'px';
                tooltip.style.opacity = 1;
            }}
            
            function hideTooltip() {{
                document.getElementById('tooltip').style.opacity = 0;
            }}
            
            function updateTypeFilter() {{
                const types = new Set(currentNodes.map(n => n.type).filter(Boolean));
                const select = document.getElementById('type-filter');
                select.innerHTML = '<option value="all">All Types</option>' +
                    Array.from(types).sort().map(t => `<option value="${{t}}">${{t}}</option>`).join('');
            }}
            
            function updateLegend() {{
                const types = new Set(currentNodes.map(n => n.type).filter(Boolean));
                const legend = document.getElementById('legend');
                
                legend.innerHTML = `
                    <h4>Node Types</h4>
                    ${{Array.from(types).slice(0, 8).map(t => `
                        <div class="legend-item">
                            <div class="legend-color" style="background:${{getNodeColor(t)}}"></div>
                            ${{t}}
                        </div>
                    `).join('')}}
                `;
            }}
            
            function filterNodes(type) {{
                if (type === 'all') {{
                    g.selectAll('.node').style('opacity', 1);
                }} else {{
                    g.selectAll('.node').style('opacity', d => d.type === type ? 1 : 0.2);
                }}
            }}
            
            function changeLayout(layout) {{
                if (!simulation || !currentNodes.length) return;
                
                const width = parseInt(svg.attr('width'));
                const height = parseInt(svg.attr('height'));
                
                if (layout === 'circular') {{
                    const angle = (2 * Math.PI) / currentNodes.length;
                    const radius = Math.min(width, height) / 3;
                    
                    currentNodes.forEach((n, i) => {{
                        n.fx = width/2 + radius * Math.cos(i * angle);
                        n.fy = height/2 + radius * Math.sin(i * angle);
                    }});
                    simulation.alpha(0.3).restart();
                    setTimeout(() => {{
                        currentNodes.forEach(n => {{ n.fx = null; n.fy = null; }});
                    }}, 1000);
                }} else if (layout === 'hierarchical') {{
                    // Simple hierarchical - group by type
                    const types = [...new Set(currentNodes.map(n => n.type))];
                    const typeIndex = new Map(types.map((t, i) => [t, i]));
                    
                    currentNodes.forEach(n => {{
                        n.fx = 100 + (typeIndex.get(n.type) || 0) * 150;
                        n.fy = 100 + Math.random() * (height - 200);
                    }});
                    simulation.alpha(0.3).restart();
                    setTimeout(() => {{
                        currentNodes.forEach(n => {{ n.fx = null; n.fy = null; }});
                    }}, 1000);
                }} else {{
                    // Force directed - release all fixed positions
                    currentNodes.forEach(n => {{ n.fx = null; n.fy = null; }});
                    simulation.alpha(1).restart();
                }}
            }}
            
            function resetView() {{
                svg.transition().duration(500).call(
                    d3.zoom().transform,
                    d3.zoomIdentity
                );
            }}
            
            function exportGraph() {{
                const svgEl = document.querySelector('#graph-container svg');
                const serializer = new XMLSerializer();
                const svgStr = serializer.serializeToString(svgEl);
                const canvas = document.createElement('canvas');
                canvas.width = svgEl.clientWidth * 2;
                canvas.height = svgEl.clientHeight * 2;
                const ctx = canvas.getContext('2d');
                const img = new Image();
                img.onload = function() {{
                    ctx.fillStyle = '#0d1117';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);
                    ctx.drawImage(img, 0, 0);
                    const link = document.createElement('a');
                    link.download = projectName + '_graph.png';
                    link.href = canvas.toDataURL('image/png');
                    link.click();
                }};
                img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgStr)));
            }}
            
            function selectFinding(id) {{
                const finding = allFindings.find(f => f.id === id);
                if (!finding) return;
                
                // Highlight nodes referenced by this finding
                if (finding.node_refs && finding.node_refs.length > 0) {{
                    g.selectAll('.node circle').style('stroke-width', d => 
                        finding.node_refs.includes(d.id) ? 4 : 2
                    ).style('filter', d =>
                        finding.node_refs.includes(d.id) ? 'drop-shadow(0 0 10px #30a14e)' : 'none'
                    );
                }}
            }}
            
            async function confirmFinding(id) {{
                await fetch(`/api/findings/${{id}}/status`, {{
                    method: 'PUT',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ status: 'confirmed' }})
                }});
                location.reload();
            }}
            
            async function rejectFinding(id) {{
                await fetch(`/api/findings/${{id}}/status`, {{
                    method: 'PUT',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ status: 'rejected' }})
                }});
                location.reload();
            }}
            
            async function buildGraphs() {{
                const resp = await fetch('/graphs/build', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        repo_url: "{project.git_url or ''}",
                        project_id: projectId,
                        num_graphs: 3,
                        init_only: false
                    }})
                }});
                const data = await resp.json();
                if (data.scan_id) {{
                    // Stay on dashboard and connect to activity stream
                    document.getElementById('session-selector').innerHTML += 
                        `<option value="${{data.scan_id}}" selected>${{data.scan_id.slice(0,12)}}... (building)</option>`;
                    connectToSession(data.scan_id);
                    showTab('activity');
                }}
            }}
            
            async function runAudit() {{
                const resp = await fetch('/audits/start', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{
                        repo_url: "{project.git_url or ''}",
                        project_id: projectId,
                        max_iterations: 50
                    }})
                }});
                const data = await resp.json();
                if (data.session_id) {{
                    // Stay on dashboard and connect to activity stream
                    document.getElementById('session-selector').innerHTML += 
                        `<option value="${{data.session_id}}" selected>${{data.session_id.slice(0,12)}}... (running)</option>`;
                    connectToSession(data.session_id);
                    showTab('activity');
                }}
            }}
            
            function escapeHtml(text) {{
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }}
            
            // ===================================
            // WebSocket Activity Streaming
            // ===================================
            
            let ws = null;
            let currentSessionId = null;
            let lastIteration = 0;
            const seenEvents = new Set();
            
            function showTab(tabName) {{
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                document.querySelector(`[data-tab="${{tabName}}"]`).classList.add('active');
                document.getElementById(tabName + '-pane').classList.add('active');
            }}
            
            function friendlyTag(action) {{
                const a = (action || '').toLowerCase();
                if (a === 'load_nodes' || a === 'load_node' || a === 'fetch_code') return {{ label: 'Fetch', cls: 'fetch' }};
                if (a === 'update_node') return {{ label: 'Memo', cls: 'memo' }};
                if (a === 'add_edge' || a === 'add_node') return {{ label: 'Graph', cls: 'graph' }};
                if (a === 'query_graph' || a === 'focus' || a === 'summarize') return {{ label: 'Graph', cls: 'graph' }};
                if (a === 'propose_hypothesis') return {{ label: 'Finding', cls: 'hyp' }};
                if (a === 'update_hypothesis') return {{ label: 'Update', cls: 'hyp' }};
                if (a === 'deep_think' || a === 'strategist') return {{ label: 'Think', cls: 'think' }};
                if (a === 'status' || a === 'thought') return {{ label: 'Status', cls: 'status' }};
                if (a === 'error') return {{ label: 'Error', cls: 'error' }};
                return {{ label: action || 'Act', cls: 'status' }};
            }}
            
            function dedupeKey(j) {{
                return `${{j.type||''}}|${{j.action||''}}|${{j.iteration||''}}|${{(j.message||'').slice(0,80)}}`;
            }}
            
            function handleActivityMessage(data) {{
                try {{
                    const j = JSON.parse(data);
                    
                    // Skip keepalive and connection messages
                    if (j.type === 'keepalive' || j.type === 'connected' || j.type === 'pong') return;
                    
                    // Dedupe
                    const key = dedupeKey(j);
                    if (seenEvents.has(key)) return;
                    seenEvents.add(key);
                    if (seenEvents.size > 500) {{
                        const first = seenEvents.values().next().value;
                        seenEvents.delete(first);
                    }}
                    
                    // Extract info
                    const ts = j.timestamp || j.ts ? new Date(j.timestamp || j.ts * 1000) : new Date();
                    const tstr = ts.toTimeString().split(' ')[0].slice(0, 5);
                    const iteration = j.iteration || lastIteration;
                    if (j.iteration) lastIteration = j.iteration;
                    
                    const action = j.action || j.type || '';
                    const tag = friendlyTag(action);
                    
                    // Build message
                    let text = '';
                    if (j.type === 'decision') {{
                        text = `<span class="action">${{tag.label}}: ${{j.action || 'thinking'}}</span>`;
                        if (j.reasoning) text += `<br><span class="thought">${{escapeHtml(j.reasoning.slice(0, 200))}}</span>`;
                    }} else if (j.type === 'thought') {{
                        text = `<span class="thought">${{escapeHtml(j.message || j.reasoning || '')}}</span>`;
                        updateNowInvestigating(j.message || j.reasoning || '');
                    }} else if (j.type === 'action_start') {{
                        text = `<span class="action">Starting: ${{j.action || 'action'}}</span>`;
                    }} else if (j.type === 'action_result' || j.type === 'result') {{
                        text = `<span class="action">Result:</span> ${{escapeHtml((j.message || j.result || '').slice(0, 300))}}`;
                    }} else if (j.type === 'status') {{
                        text = `<span class="action">Status: ${{j.status || j.message || ''}}</span>`;
                        if (j.status === 'completed' || j.status === 'failed') {{
                            updateNowInvestigating(j.status === 'completed' ? '✅ Audit completed' : '❌ Audit failed', true);
                        }}
                    }} else if (j.type === 'error') {{
                        text = `<span class="action">Error:</span> ${{escapeHtml(j.message || j.error || '')}}`;
                    }} else {{
                        text = escapeHtml(j.message || j.reasoning || JSON.stringify(j).slice(0, 200));
                    }}
                    
                    appendActivityEvent(tstr, iteration, tag, text, j.type);
                    
                }} catch (e) {{
                    // Plain text message
                    appendActivityEvent('', '', {{ label: 'Info', cls: 'status' }}, escapeHtml(data), 'info');
                }}
            }}
            
            function appendActivityEvent(time, iteration, tag, text, eventType) {{
                const stream = document.getElementById('activity-stream');
                const empty = document.getElementById('activity-empty');
                if (empty) empty.style.display = 'none';
                
                const div = document.createElement('div');
                div.className = `activity-event ${{eventType || ''}}`;
                div.innerHTML = `
                    <span class="event-time">${{time}}</span>
                    <span class="event-iteration">#${{iteration || '-'}}</span>
                    <span class="event-tag ${{tag.cls}}">${{tag.label}}</span>
                    <span class="event-content">${{text}}</span>
                `;
                
                stream.appendChild(div);
                stream.scrollTop = stream.scrollHeight;
            }}
            
            function updateNowInvestigating(text, idle = false) {{
                const el = document.getElementById('now-investigating');
                if (el) {{
                    el.textContent = idle ? text : `🔍 ${{text.slice(0, 100)}}`;
                    el.className = idle ? 'now-investigating idle' : 'now-investigating';
                }}
            }}
            
            function setWsStatus(connected) {{
                const el = document.getElementById('ws-status');
                if (el) {{
                    el.className = `ws-status ${{connected ? 'connected' : 'disconnected'}}`;
                    el.innerHTML = `<span class="dot"></span><span>${{connected ? 'Connected' : 'Disconnected'}}</span>`;
                }}
            }}
            
            function connectToSession(sessionId) {{
                if (!sessionId) {{
                    sessionId = document.getElementById('session-selector').value;
                }}
                if (!sessionId) {{
                    alert('Please select a session to connect to');
                    return;
                }}
                
                // Close existing connection
                if (ws) {{
                    ws.close();
                    ws = null;
                }}
                
                currentSessionId = sessionId;
                seenEvents.clear();
                lastIteration = 0;
                
                // Connect WebSocket
                const wsUrl = `${{wsBase}}/ws/sessions/${{sessionId}}`;
                console.log('Connecting to:', wsUrl);
                
                ws = new WebSocket(wsUrl);
                
                ws.onopen = () => {{
                    console.log('WebSocket connected');
                    setWsStatus(true);
                    updateNowInvestigating('Connected to audit stream...', false);
                }};
                
                ws.onmessage = (event) => {{
                    handleActivityMessage(event.data);
                }};
                
                ws.onerror = (error) => {{
                    console.error('WebSocket error:', error);
                    appendActivityEvent('', '', {{ label: 'Error', cls: 'error' }}, 'Connection error', 'error');
                }};
                
                ws.onclose = () => {{
                    console.log('WebSocket closed');
                    setWsStatus(false);
                    appendActivityEvent('', '', {{ label: 'Info', cls: 'status' }}, 'Connection closed', 'status');
                }};
                
                // Ping to keep alive
                setInterval(() => {{
                    if (ws && ws.readyState === WebSocket.OPEN) {{
                        ws.send('ping');
                    }}
                }}, 25000);
            }}
            
            function onSessionChange() {{
                const sessionId = document.getElementById('session-selector').value;
                if (sessionId) {{
                    connectToSession(sessionId);
                }}
            }}
            
            function clearActivity() {{
                const stream = document.getElementById('activity-stream');
                stream.innerHTML = `
                    <div class="empty-state" id="activity-empty">
                        <div class="icon">📊</div>
                        <div>Activity cleared. Connect to a session to see live updates.</div>
                    </div>
                `;
                seenEvents.clear();
                lastIteration = 0;
            }}
            
            // Auto-connect if there's an active session
            function autoConnect() {{
                if (activeSessionId) {{
                    setTimeout(() => {{
                        connectToSession(activeSessionId);
                        showTab('activity');
                    }}, 500);
                }}
            }}
            
            // Initialize on load
            document.addEventListener('DOMContentLoaded', () => {{
                init();
                autoConnect();
            }});
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/admin/progress/{session_id}", response_class=HTMLResponse)
async def admin_progress_viewer(session_id: str, request: Request, db: Session = Depends(get_db), _auth: bool = Depends(require_admin)):
    """
    Render a live progress viewer for audit/graph build sessions.
    Connects to WebSocket and shows real-time updates.
    """
    # Get session info
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
    session_info = {
        "id": session_id,
        "status": session.status if session else "unknown",
        "project": session.project.name if session and session.project else "N/A",
        "started": session.start_time.isoformat() if session and session.start_time else "N/A",
    }
    
    # Get the base URL for WebSocket
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    proto = request.headers.get("x-forwarded-proto", "http")
    ws_proto = "wss" if proto == "https" else "ws"
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Progress: {session_id}</title>
        <link rel="stylesheet" href="/admin/statics/css/tabler.min.css">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; padding: 20px; background: #1a1a2e; color: #eee; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
            .back-btn {{ color: #5c7cfa; text-decoration: none; }}
            .status {{ padding: 4px 12px; border-radius: 4px; font-weight: 500; }}
            .status.running {{ background: #3b82f6; }}
            .status.completed {{ background: #22c55e; }}
            .status.failed {{ background: #ef4444; }}
            .status.queued {{ background: #6b7280; }}
            .card {{ background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
            .card h3 {{ margin-top: 0; color: #5c7cfa; }}
            .log-container {{ background: #0f0f23; border-radius: 4px; padding: 15px; max-height: 500px; overflow-y: auto; font-family: monospace; font-size: 13px; }}
            .log-entry {{ padding: 4px 0; border-bottom: 1px solid #1a1a2e; }}
            .log-entry.decision {{ color: #fbbf24; }}
            .log-entry.thought {{ color: #a78bfa; }}
            .log-entry.action {{ color: #34d399; }}
            .log-entry.error {{ color: #f87171; }}
            .log-entry.status {{ color: #60a5fa; font-weight: bold; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }}
            .stat {{ background: #16213e; padding: 15px; border-radius: 8px; text-align: center; }}
            .stat-value {{ font-size: 24px; font-weight: bold; color: #5c7cfa; }}
            .stat-label {{ font-size: 12px; color: #9ca3af; margin-top: 5px; }}
            .connection {{ position: fixed; top: 10px; right: 10px; padding: 5px 10px; border-radius: 4px; font-size: 12px; }}
            .connection.connected {{ background: #22c55e; }}
            .connection.disconnected {{ background: #ef4444; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <a href="/admin/audit-session/list" class="back-btn">&larr; Back to Sessions</a>
                    <h1>Session Progress</h1>
                </div>
                <div>
                    <span class="status {session_info['status']}" id="status">{session_info['status'].upper()}</span>
                </div>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-value" id="iteration">0</div>
                    <div class="stat-label">Iteration</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="nodes">0</div>
                    <div class="stat-label">Nodes Loaded</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="hypotheses">0</div>
                    <div class="stat-label">Hypotheses</div>
                </div>
                <div class="stat">
                    <div class="stat-value" id="graphs">0</div>
                    <div class="stat-label">Graphs</div>
                </div>
            </div>
            
            <div class="card">
                <h3>Session Info</h3>
                <p><strong>Session ID:</strong> {session_id}</p>
                <p><strong>Project:</strong> {session_info['project']}</p>
                <p><strong>Started:</strong> {session_info['started']}</p>
            </div>
            
            <div class="card">
                <h3>Live Log</h3>
                <div class="log-container" id="log"></div>
            </div>
        </div>
        
        <div class="connection disconnected" id="connection">Disconnected</div>
        
        <script>
            const sessionId = "{session_id}";
            const wsUrl = "{ws_proto}://{host}/ws/sessions/" + sessionId;
            let ws;
            let reconnectAttempts = 0;
            
            function connect() {{
                ws = new WebSocket(wsUrl);
                
                ws.onopen = function() {{
                    document.getElementById('connection').className = 'connection connected';
                    document.getElementById('connection').textContent = 'Connected';
                    reconnectAttempts = 0;
                    addLog('Connected to session', 'status');
                }};
                
                ws.onmessage = function(event) {{
                    const data = JSON.parse(event.data);
                    handleMessage(data);
                }};
                
                ws.onclose = function() {{
                    document.getElementById('connection').className = 'connection disconnected';
                    document.getElementById('connection').textContent = 'Disconnected';
                    
                    // Reconnect with backoff
                    if (reconnectAttempts < 5) {{
                        reconnectAttempts++;
                        setTimeout(connect, 1000 * reconnectAttempts);
                    }}
                }};
                
                ws.onerror = function(error) {{
                    addLog('WebSocket error: ' + error.message, 'error');
                }};
            }}
            
            function handleMessage(data) {{
                const type = data.type || 'unknown';
                
                if (type === 'status') {{
                    document.getElementById('status').textContent = (data.status || 'unknown').toUpperCase();
                    document.getElementById('status').className = 'status ' + (data.status || '');
                    addLog('Status: ' + data.message, 'status');
                }}
                else if (type === 'progress') {{
                    if (data.data) {{
                        document.getElementById('iteration').textContent = data.data.iteration || 0;
                        document.getElementById('nodes').textContent = data.data.nodes_visited || 0;
                        document.getElementById('hypotheses').textContent = data.data.hypotheses_count || 0;
                        document.getElementById('graphs').textContent = data.data.graphs_loaded || 0;
                    }}
                }}
                else if (type === 'decision') {{
                    addLog('Decision: ' + data.action + ' - ' + (data.reasoning || '').substring(0, 100), 'decision');
                }}
                else if (type === 'thought') {{
                    addLog(data.thought || data.message || JSON.stringify(data), 'thought');
                }}
                else if (type === 'action_start') {{
                    addLog('Executing: ' + data.action, 'action');
                }}
                else if (type === 'action_result') {{
                    addLog('Result: ' + (data.result?.summary || data.result?.status || 'done'), 'action');
                }}
                else if (type === 'error') {{
                    addLog('Error: ' + data.message, 'error');
                }}
                else {{
                    addLog(JSON.stringify(data), 'thought');
                }}
            }}
            
            function addLog(message, type) {{
                const log = document.getElementById('log');
                const entry = document.createElement('div');
                entry.className = 'log-entry ' + type;
                entry.textContent = new Date().toLocaleTimeString() + ' | ' + message;
                log.appendChild(entry);
                log.scrollTop = log.scrollHeight;
            }}
            
            // Start connection
            connect();
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


# Pydantic models for request/response
class ProjectCreate(BaseModel):
    """Request model for creating a project."""

    name: str = Field(..., description="Project name")
    git_url: str | None = Field(None, description="Git repository URL")
    source_path: str | None = Field(None, description="Local source path")
    description: str | None = Field(None, description="Project description")


class ProjectResponse(BaseModel):
    """Response model for project data."""

    id: int
    name: str
    source_path: str | None
    git_url: str | None
    description: str | None
    status: str
    created_at: datetime
    last_accessed: datetime
    graphs_count: int = 0
    sessions_count: int = 0
    hypotheses_count: int = 0
    confirmed_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class SessionResponse(BaseModel):
    """Response model for session data."""

    id: int
    session_id: str
    status: str
    start_time: datetime
    end_time: datetime | None
    models: dict[str, Any] | None
    token_usage: dict[str, Any] | None
    coverage: dict[str, Any] | None
    investigations_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class GraphResponse(BaseModel):
    """Response model for graph data."""

    id: int
    name: str
    internal_name: str | None
    data: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(BaseModel):
    """Response model for hypothesis/finding data.

    Supports both deep-audit hypotheses (from Hypothesis table) and surface scan
    findings (from ScanExecution.findings JSONB).  Nullable fields accommodate
    surface scan findings which lack hypothesis-specific metadata.
    """

    id: int | None = None
    hypothesis_id: str | None = None
    title: str
    description: str
    vulnerability_type: str | None = None
    status: str = "confirmed"
    confidence: float
    severity: str
    node_refs: list[str] | None = None
    evidence: Any | None = None  # Can be dict or list
    reported_by_model: str | None = None
    junior_model: str | None = None
    senior_model: str | None = None
    project_id: int | None = None  # Explicit repo linkage
    pattern_id: str | None = None  # Surface scan pattern identifier
    location: str | None = None  # Code location from surface scan
    code_snippet: str | None = None  # Code snippet from surface scan
    source: str | None = None  # "surface" | "deep"
    user_notes: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ============================================================================
# Audit Control Request/Response Models
# ============================================================================

class AuditStartRequest(BaseModel):
    """Request model for starting a new audit."""
    
    repo_url: str = Field(..., description="Git repository URL or local path")
    tenant_id: int = Field(default=1, description="Tenant ID for multi-tenancy")
    project_id: int | None = Field(None, description="Link to existing project")
    max_iterations: int = Field(default=30, description="Maximum agent iterations per investigation")
    investigation_prompt: str | None = Field(None, description="Custom investigation prompt")
    installation_id: int | None = Field(None, description="GitHub App installation ID")
    pr_number: int | None = Field(None, description="PR number to post findings to")
    repo_full_name: str | None = Field(None, description="Repository full name (owner/repo)")
    time_limit_minutes: int = Field(default=120, description="Time limit for the entire audit in minutes")
    mode: Literal["sweep", "intuition", "auditor"] = Field(default="auditor", description="Audit mode: 'auditor' (default — Claude SingleAuditor + fp-check, firepan-8l1; the DeepSeek 'sweep' pipeline had a 0/13 TP rate so paid scan_type=deep now routes to auditor), 'sweep' (legacy DeepSeek broad coverage, opt-in), or 'intuition' (Phase 2 deep exploration)")
    plan_n: int = Field(default=5, description="Number of investigations to plan per batch")
    auto_create_fix_pr: bool = Field(default=False, description="Automatically create a PR with fixes for detected issues")
    base_branch: str = Field(default="main", description="Base branch for fix PR (default: main)")
    audit_branch: str | None = Field(default=None, description="Git ref (branch/tag/SHA) to audit; defaults to project default_branch", max_length=255)
    target_files: list[str] | None = Field(
        default=None,
        description=(
            "Optional list of repo-relative file paths to scope the deep audit to. "
            "Max 50 entries. Paid plans only — silently ignored for free-tier tenants. "
            "Leave unset to audit the whole repo."
        ),
        max_length=50,
    )


class AuditStartResponse(BaseModel):
    """Response model after starting an audit."""

    session_id: str = Field(..., description="Unique session ID for tracking")
    status: str = Field(default="queued", description="Current status")
    message: str = Field(..., description="Human-readable status message")
    websocket_url: str = Field(..., description="WebSocket URL for live progress")
    # firepan-sewd observability: surface the gate's mode decision so callers
    # can tell when their requested mode was silently downgraded (e.g.
    # auditor -> sweep for non-entitled tenants). All three are optional —
    # they're None on the early "already_processed" path where the gate
    # doesn't run, and otherwise reflect the request/gate outcome.
    requested_mode: str | None = Field(
        default=None,
        description="Mode requested by the caller (pre-gate)",
    )
    effective_mode: str | None = Field(
        default=None,
        description="Mode that will actually run after gate enforcement",
    )
    mode_downgrade_reason: str | None = Field(
        default=None,
        description=(
            "If set, identifies why effective_mode differs from requested_mode "
            "(e.g. 'claude_audit_not_entitled' for the firepan-sewd gate)."
        ),
    )
    # firepan-bug-sweep: coverage ratchet. The worker records chunks_processed
    # / chunks_total when the audit completes (or partially completes). Surfaced
    # here only for /audits/{session_id}/status responses; on the initial
    # /audits/start dispatch both are None because the audit has not run yet.
    coverage_chunks_processed: int | None = Field(
        default=None,
        description="Chunks processed by the auditor. None until the audit terminates.",
    )
    coverage_chunks_total: int | None = Field(
        default=None,
        description="Total chunks the auditor planned. None until the audit terminates.",
    )


class AuditStatusResponse(BaseModel):
    """Response model for audit status check."""

    session_id: str
    status: str
    progress: dict[str, Any] | None = None
    findings_count: int = 0
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    # firepan-bug-sweep: coverage ratchet. Populated by the worker when an audit
    # terminates (in_review / completed / failed). `None` while the audit is
    # still running; once present, callers SHOULD show a partial-run banner
    # when coverage_ratio < 1.0 so a budget-truncated run isn't mistaken for
    # full coverage.
    coverage_chunks_processed: int | None = None
    coverage_chunks_total: int | None = None
    coverage_ratio: float | None = None
    # firepan-bug-sweep: curator state. When audit_context.scope_files was set
    # on dispatch, the worker runs the post-auditor curator. This flag tells
    # callers whether it completed; consumers shipping reports under
    # audit_context SHOULD refuse to export when curator_applied is False.
    curator_applied: bool | None = None
    curator_summary: dict[str, int] | None = None
    curator_error: str | None = None


# ============================================================================
# Audit Control Endpoints - THE CRITICAL WIRING
# ============================================================================

@app.post("/audits/start", response_model=AuditStartResponse)
async def start_audit(
    request_body: AuditStartRequest,
    request: Request,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    _: None = Depends(reject_preview_writes),
    __: None = Depends(require_verified_email),
):
    """
    Start a new security audit (async, returns immediately).
    PAID: $5.00 via x402 for AI agent customers.
    SaaS subscribers bypass x402 (they pay via Stripe).

    This endpoint:
    1. Validates project ownership (if project_id provided)
    2. Checks x402 payment gate (skipped for SaaS subscribers)
    3. Enforces audit quota for SaaS subscribers
    4. Creates an AuditSession record with status "queued"
    5. Creates a ScanExecution row (dashboard path only)
    6. Dispatches work to the Celery worker queue
    7. Returns immediately with a session_id for tracking

    The actual audit runs in a background Celery worker. Connect to the
    WebSocket endpoint to receive real-time progress updates.
    """
    from server.x402_deps import PaymentGate, create_paid_job, mark_job_failed, require_payment

    # Step 1: Validate project ownership (if project_id provided)
    project = None
    if request_body.project_id:
        project = db.query(Project).filter(
            Project.id == request_body.project_id,
            Project.tenant_id == tenant_id,
        ).first()
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

    # Step 2: SaaS bypass for x402 — SaaS subscribers pay via Stripe, not x402
    tenant = project.tenant if project else db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        tenant = Tenant(name="default")
        db.add(tenant)
        db.commit()

    # firepan-bv21: pre-flight auth check for private repos. Without this the
    # worker falls through to an unauthenticated `git clone` and the user sees
    # a raw `terminal prompts disabled` error (mezher-profi / GneralyFulldestroyer
    # 2026-05-14). Run before quota burn / session row insertion so a 403
    # doesn't leave orphan AuditSession + ScanExecution rows.
    if project and project.is_private:
        has_install = bool(getattr(project, "installation_id", None)) or bool(
            getattr(tenant, "installation_id", None)
        )
        if not has_install:
            try:
                audit_user = await _get_current_user_with_token(request, db)
            except HTTPException:
                # No user context (agent x402 path) — refuse cleanly.
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "insufficient_github_scope",
                        "message": "Private repo audit requires GitHub App installation or repo-scoped OAuth.",
                    },
                )
            _check_private_repo_access(project, audit_user)

    from server.tier_enforcement import claude_audit_allowed, has_paid_subscription
    has_saas_sub = has_paid_subscription(tenant)

    # firepan-sewd: Claude SingleAuditor (mode=auditor) is gated to genuinely
    # Stripe-paid tenants or an explicit per-tenant allowlist flag. Auto-trial
    # tenants are NOT grandfathered in. Any other tenant requesting auditor is
    # downgraded to the DeepSeek 'sweep' pipeline here, at the single dispatch
    # chokepoint (request-model default stays 'auditor'; policy enforced with
    # the tenant in hand). Admin force-run is a separate handler and bypasses
    # this by design (explicit-provision mechanism).
    effective_mode = request_body.mode
    mode_downgrade_reason: str | None = None
    if effective_mode == "auditor" and not claude_audit_allowed(tenant):
        logger.info(
            "claude_audit gate: tenant=%s not entitled, downgrading mode "
            "auditor->sweep (firepan-sewd)",
            tenant_id,
        )
        effective_mode = "sweep"
        mode_downgrade_reason = "claude_audit_not_entitled"

    gate = PaymentGate(enabled=False, status="disabled")

    if has_saas_sub:
        # SaaS tenant — enforce audit quota via tier enforcement
        from server.tier_enforcement import _check_sync
        _check_sync(tenant_id, "audit", db)  # Raises 403 if over quota

        # Require project_id for SaaS tenants (dashboard path)
        if not request_body.project_id:
            raise HTTPException(
                status_code=422,
                detail="project_id is required for SaaS subscribers",
            )
    else:
        # Agent customer — require x402 payment
        gate_fn = require_payment("POST /audits/start")
        gate = await gate_fn(request=request, tenant_id=tenant_id, db=db)

        if gate.status == "already_processed":
            return AuditStartResponse(
                session_id=gate.job_id or "",
                status="already_processed",
                message="Already processed",
                websocket_url=f"/ws/sessions/{gate.job_id}",
            )

    # firepan-nxf: scope handling. Paid plans (SaaS + active trial) honor
    # target_files; free-tier tenants silently drop it so the UX doesn't 403
    # unexpectedly from a form that may render the field for all users.
    scoped_target_files = None
    if request_body.target_files is not None:
        validated = _validate_target_files(request_body.target_files)
        if not has_saas_sub:
            if validated:
                logger.info(
                    "target_files ignored: tier=free tenant=%s count=%d",
                    tenant_id, len(validated),
                )
        else:
            scoped_target_files = validated
            if scoped_target_files and project is not None:
                resolved, missing = _check_target_files_exist_on_disk(
                    getattr(project, "source_path", None),
                    scoped_target_files,
                )
                if resolved or missing:  # check actually ran
                    if not resolved:
                        raise HTTPException(
                            status_code=422,
                            detail={
                                "error": "scoped_audit_no_files_match",
                                "missing": missing,
                                "message": (
                                    "None of the requested target_files exist in "
                                    "the cached clone. Check paths and branch."
                                ),
                            },
                        )

    # Import worker tasks (done here to avoid circular imports)
    try:
        from worker.tasks import execute_audit_task
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {e}. Is Celery configured?"
        )

    # Resolve branch: explicit user pick > project default_branch > "main".
    # Validation enforces no shell metacharacters before we hand it to git clone.
    requested_audit_branch = _validate_ref(request_body.audit_branch)
    resolved_audit_branch = (
        requested_audit_branch
        or (project.default_branch if project else None)
        or "main"
    )

    # Generate unique session ID
    session_id = f"audit_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    # Build session_metadata for scoped audits (firepan-nxf).
    session_metadata_dict: dict = {}
    if scoped_target_files:
        session_metadata_dict["target_files"] = scoped_target_files

    # Create AuditSession record with status "queued"
    audit_session = AuditSession(
        session_id=session_id,
        project_id=request_body.project_id,
        status="queued",
        start_time=datetime.now(timezone.utc),
        models={"max_iterations": request_body.max_iterations},
        session_metadata=session_metadata_dict or None,
    )
    db.add(audit_session)
    db.commit()

    # Create ScanExecution so deep audit appears in scan history (dashboard path only)
    if project:
        from database.models import ScanExecution as ScanExecutionModel

        scan_config_dict: dict = {
            "scan_type": "deep",
            "mode": effective_mode,  # firepan-sewd: gated (auditor->sweep if not entitled)
            "branch": resolved_audit_branch,
        }
        if scoped_target_files:
            scan_config_dict["target_files"] = scoped_target_files

        deep_scan = ScanExecutionModel(
            execution_id=session_id,
            project_id=request_body.project_id,
            tenant_id=tenant_id,
            repo_url=request_body.repo_url,
            repo_name=project.name,
            status="queued",
            started_at=datetime.now(timezone.utc),
            scan_config=scan_config_dict,
        )
        db.add(deep_scan)
        db.commit()

    logger.info(f"Created audit session {session_id} for {request_body.repo_url}")

    # Link payment to job
    if gate.enabled and gate.payment_log_id:
        try:
            create_paid_job(db, gate.payment_log_id, session_id)
        except Exception as e:
            logger.error(f"Failed to link payment to audit job: {e}")
            mark_job_failed(db, gate.payment_log_id)

    # Resolve installation_id: prefer request, fall back to project, then tenant.
    # firepan-bv21: include tenant.installation_id as a final fallback so that
    # repos added before the webhook bridge fix (project.installation_id NULL)
    # can still authenticate via the tenant's install. Without this, every
    # pre-fix orphan would need a manual project-row backfill before scans work.
    resolved_installation_id = request_body.installation_id
    if not resolved_installation_id and project and getattr(project, "installation_id", None):
        resolved_installation_id = project.installation_id
    if not resolved_installation_id and tenant and getattr(tenant, "installation_id", None):
        resolved_installation_id = tenant.installation_id

    # Dispatch to Celery worker queue (async - returns immediately!)
    task = execute_audit_task.delay(
        repo_url=request_body.repo_url,
        scan_id=session_id,
        tenant_id=tenant.id,
        project_id=request_body.project_id,
        max_iterations=request_body.max_iterations,
        investigation_prompt=request_body.investigation_prompt,
        installation_id=resolved_installation_id,
        pr_number=request_body.pr_number,
        repo_full_name=request_body.repo_full_name,
        time_limit_minutes=request_body.time_limit_minutes,
        mode=effective_mode,  # firepan-sewd: gated
        plan_n=request_body.plan_n,
        branch=resolved_audit_branch,
        target_files=scoped_target_files,
    )

    logger.info(f"Dispatched audit task {task.id} for session {session_id}")

    # Send Telegram notification for deep audit start (fire-and-forget)
    try:
        await notify_deep_audit_started(
            repo_url=request_body.repo_url,
            session_id=session_id,
            tenant_id=tenant.id,
            project_name=project.name if project else None,
            mode=effective_mode,  # firepan-sewd: gated
            requested_mode=request_body.mode,
            mode_downgrade_reason=mode_downgrade_reason,
        )
    except Exception:
        pass  # non-critical

    return AuditStartResponse(
        session_id=session_id,
        status="queued",
        message=f"Audit queued successfully. Task ID: {task.id}",
        websocket_url=f"/ws/sessions/{session_id}",
        requested_mode=request_body.mode,
        effective_mode=effective_mode,
        mode_downgrade_reason=mode_downgrade_reason,
    )


@app.get("/audits/{session_id}/status", response_model=AuditStatusResponse)
async def get_audit_status(
    session_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """
    Get the current status of an audit.

    Returns the current status, progress information, and findings count.
    """
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Audit session not found")

    # Verify tenant ownership via project
    if session.project_id:
        project = db.query(Project).filter(Project.id == session.project_id).first()
        if not project or project.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Audit session not found")

    # Count findings
    findings_count = 0
    if session.project_id:
        findings_count = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == session.project_id)
            .count()
        )

    # Read error_message from ScanExecution if available (dashboard-linked audits)
    error_message = None
    scan_exec = db.query(ScanExecution).filter_by(execution_id=session_id).first()
    if scan_exec and scan_exec.error_message:
        error_message = scan_exec.error_message

    # firepan-bug-sweep: surface coverage ratchet. Worker writes
    # AuditSession.coverage = {"chunks_processed": X, "chunks_total": Y,
    # "coverage_ratio": Z, ...} when the audit terminates. None during run.
    cov = session.coverage or {}
    cov_processed = cov.get("chunks_processed") if isinstance(cov, dict) else None
    cov_total = cov.get("chunks_total") if isinstance(cov, dict) else None
    cov_ratio = cov.get("coverage_ratio") if isinstance(cov, dict) else None

    # firepan-bug-sweep: surface curator state from session_metadata. Set by
    # worker/tasks.py after the curator runs (or fails). Three states:
    #   - None: no audit_context was provided on dispatch (no curator expected)
    #   - True: curator applied successfully; summary contains category counts
    #   - False: audit_context provided but curator failed; error in curator_error
    meta = session.session_metadata or {}
    cstate = meta.get("curator") if isinstance(meta, dict) else None
    curator_applied = None
    curator_summary = None
    curator_error = None
    if isinstance(cstate, dict):
        curator_applied = cstate.get("applied")
        curator_summary = cstate.get("summary")
        curator_error = cstate.get("error")

    return AuditStatusResponse(
        session_id=session.session_id,
        status=session.status,
        progress=session.token_usage,  # Contains progress info
        findings_count=findings_count,
        error_message=error_message,
        started_at=session.start_time,
        completed_at=session.end_time,
        coverage_chunks_processed=cov_processed,
        coverage_chunks_total=cov_total,
        coverage_ratio=cov_ratio,
        curator_applied=curator_applied,
        curator_summary=curator_summary,
        curator_error=curator_error,
    )


# ============================================================================
# Auto-Fix PR Creation Endpoint
# ============================================================================

class AutoFixPRRequest(BaseModel):
    """Request model for creating auto-fix PR."""
    
    installation_id: int = Field(..., description="GitHub App installation ID")
    repo_full_name: str = Field(..., description="Repository full name (owner/repo)")
    session_id: str | None = Field(None, description="Audit session ID to get findings from")
    findings: list[dict[str, Any]] | None = Field(None, description="Manual list of findings to fix")
    base_branch: str = Field(default="main", description="Base branch for PR (default: main)")
    auto_merge: bool = Field(default=False, description="Enable auto-merge if checks pass")


class AutoFixPRResponse(BaseModel):
    """Response model for auto-fix PR creation."""
    
    success: bool
    pr_number: int | None = None
    pr_url: str | None = None
    branch_name: str | None = None
    fixes_applied: int = 0
    fixes_failed: int = 0
    errors: list[str] = []


@app.post("/audits/{session_id}/create-fix-pr", response_model=AutoFixPRResponse)
async def create_auto_fix_pr(
    session_id: str,
    request: AutoFixPRRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Create a PR with automatic fixes for detected security issues.
    
    This endpoint:
    1. Retrieves findings from the audit session
    2. Generates fixes for fixable vulnerabilities
    3. Creates a new branch with the fixes
    4. Opens a pull request with detailed descriptions
    
    Example:
        POST /audits/audit_abc123/create-fix-pr
        {
            "installation_id": 12345,
            "repo_full_name": "owner/repo",
            "base_branch": "main",
            "auto_merge": false
        }
    """
    from integrations.auto_pr_fixer import create_fix_pr_for_findings
    
    # Get findings from session or use provided findings
    findings = request.findings
    
    if not findings and session_id:
        # Retrieve findings from database
        session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
        
        if not session:
            raise HTTPException(status_code=404, detail="Audit session not found")
        
        if not session.project_id:
            raise HTTPException(
                status_code=400,
                detail="Session has no associated project to retrieve findings from"
            )
        
        # Get hypotheses (findings) from the project
        hypotheses = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == session.project_id)
            .filter(Hypothesis.confidence > 0.5)  # Only high-confidence findings
            .all()
        )
        
        # Convert to finding format
        findings = []
        for hyp in hypotheses:
            finding = {
                "pattern_id": hyp.type or "UNKNOWN",
                "title": hyp.title,
                "severity": hyp.severity or "medium",
                "location": f"{hyp.file_path}:{hyp.line_number}" if hyp.file_path else "",
                "description": hyp.description,
                "confidence": hyp.confidence,
            }
            findings.append(finding)
    
    if not findings:
        raise HTTPException(
            status_code=400,
            detail="No findings provided and none found in session"
        )
    
    logger.info(f"Creating fix PR for {len(findings)} findings in {request.repo_full_name}")
    
    # Create fix PR
    try:
        result = create_fix_pr_for_findings(
            installation_id=request.installation_id,
            repo_full_name=request.repo_full_name,
            findings=findings,
            scan_id=session_id,
            base_branch=request.base_branch,
            auto_merge=request.auto_merge,
        )
        
        return AutoFixPRResponse(**result)
        
    except Exception as e:
        logger.exception(f"Failed to create fix PR: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create fix PR: {str(e)}")


@app.post("/github/create-fix-pr", response_model=AutoFixPRResponse)
async def create_fix_pr_standalone(
    request: AutoFixPRRequest,
    _: None = Depends(require_admin),
):
    """
    Create a fix PR without an audit session (standalone).
    
    Use this endpoint when you have findings from another source
    or want to create a fix PR manually.
    
    Example:
        POST /github/create-fix-pr
        {
            "installation_id": 12345,
            "repo_full_name": "owner/repo",
            "findings": [
                {
                    "pattern_id": "REENTRANCY-001",
                    "title": "Reentrancy vulnerability",
                    "severity": "high",
                    "location": "contracts/Token.sol:42",
                    "description": "External call before state update"
                }
            ]
        }
    """
    from integrations.auto_pr_fixer import create_fix_pr_for_findings
    
    if not request.findings:
        raise HTTPException(status_code=400, detail="No findings provided")
    
    logger.info(f"Creating standalone fix PR for {len(request.findings)} findings")
    
    try:
        result = create_fix_pr_for_findings(
            installation_id=request.installation_id,
            repo_full_name=request.repo_full_name,
            findings=request.findings,
            scan_id=request.session_id,
            base_branch=request.base_branch,
            auto_merge=request.auto_merge,
        )
        
        return AutoFixPRResponse(**result)
        
    except Exception as e:
        logger.exception(f"Failed to create fix PR: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create fix PR: {str(e)}")


# ============================================================================
# Graph Building Endpoint - BUILD GRAPHS BEFORE AUDIT
# ============================================================================

class GraphBuildRequest(BaseModel):
    """Request model for building graphs."""
    repo_url: str = Field(..., description="Git repository URL or local path")
    tenant_id: int | None = Field(None, description="Tenant ID")
    project_id: int | None = Field(None, description="Project ID to link graphs to")
    max_iterations: int = Field(3, description="Max graph refinement iterations")
    num_graphs: int = Field(2, description="Number of graphs to build")
    init_only: bool = Field(False, description="Only build SystemArchitecture graph")
    installation_id: int | None = Field(None, description="GitHub App installation ID")


class GraphBuildResponse(BaseModel):
    """Response model for graph build."""
    scan_id: str
    status: str
    message: str
    websocket_url: str


@app.post("/graphs/build", response_model=GraphBuildResponse)
async def build_graphs(
    request: GraphBuildRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Build knowledge graphs for a repository (async, returns immediately).
    
    This is a prerequisite step before running a full audit. It:
    1. Clones/accesses the repository
    2. Creates a manifest of all source files
    3. Bundles code for analysis
    4. Uses LLM to build knowledge graphs
    
    Connect to the WebSocket endpoint to receive real-time progress updates.
    
    Example:
        POST /graphs/build
        {
            "repo_url": "https://github.com/owner/repo",
            "project_id": 1,
            "init_only": true  // For quick initial graph
        }
    """
    try:
        from worker.tasks import build_graphs_task
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {e}. Is Celery configured?"
        )
    
    # Generate unique scan ID
    scan_id = f"graphs_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
    
    # Get or create tenant
    tenant = db.query(Tenant).filter(Tenant.id == request.tenant_id).first()
    if not tenant:
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
    
    logger.info(f"Starting graph build {scan_id} for {request.repo_url}")
    
    # Dispatch to Celery worker queue
    task = build_graphs_task.delay(
        repo_url=request.repo_url,
        scan_id=scan_id,
        tenant_id=tenant.id,
        project_id=request.project_id,
        max_iterations=request.max_iterations,
        num_graphs=request.num_graphs,
        init_only=request.init_only,
        installation_id=request.installation_id,
    )
    
    logger.info(f"Dispatched graph build task {task.id} for scan {scan_id}")
    
    return GraphBuildResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Graph build queued successfully. Task ID: {task.id}",
        websocket_url=f"/ws/sessions/{scan_id}",
    )


@app.get("/projects/{project_id}/graphs")
async def get_project_graphs(
    project_id: int,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Get all graphs for a project.

    Returns a list of graphs with their metadata (excludes full graph data).
    """
    # Verify project belongs to tenant
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project or project.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Project not found")

    graphs = db.query(Graph).filter(Graph.project_id == project_id).all()
    
    return [
        {
            "id": g.id,
            "name": g.name,
            "internal_name": g.internal_name,
            "created_at": g.created_at.isoformat(),
            "updated_at": g.updated_at.isoformat(),
            "node_count": len(g.data.get("nodes", [])) if g.data else 0,
            "edge_count": len(g.data.get("edges", [])) if g.data else 0,
        }
        for g in graphs
    ]


@app.get("/graphs/{graph_id}")
async def get_graph(
    graph_id: int,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Get a specific graph with full data.
    """
    graph = db.query(Graph).filter(Graph.id == graph_id).first()
    if not graph:
        raise HTTPException(status_code=404, detail="Graph not found")
    project = db.query(Project).filter(Project.id == graph.project_id).first()
    if not project or project.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Graph not found")
    
    return {
        "id": graph.id,
        "project_id": graph.project_id,
        "name": graph.name,
        "internal_name": graph.internal_name,
        "data": graph.data,
        "created_at": graph.created_at.isoformat(),
        "updated_at": graph.updated_at.isoformat(),
    }


# ============================================================================
# SYNCHRONOUS GRAPH BUILDING AND AUDIT - FOR SAAS WITHOUT CELERY
# ============================================================================

class SyncGraphBuildRequest(BaseModel):
    """Request model for synchronous graph building."""
    project_id: int = Field(..., description="Project ID to build graphs for")
    num_graphs: int = Field(4, description="Number of graphs to build (1-10)")
    init_only: bool = Field(False, description="Only build SystemArchitecture graph (faster)")
    max_iterations: int = Field(3, description="Max refinement iterations per graph")


class SyncGraphBuildResponse(BaseModel):
    """Response model for synchronous graph build."""
    success: bool
    message: str
    graphs_built: int
    graphs: list[dict[str, Any]]
    total_nodes: int
    total_edges: int
    duration_seconds: float


@app.post("/graphs/build-sync", response_model=SyncGraphBuildResponse)
async def build_graphs_sync(
    request: SyncGraphBuildRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Build knowledge graphs SYNCHRONOUSLY (blocking call).
    
    This is the simple SaaS-friendly version that doesn't require Celery/Redis.
    Use this for single-tenant setups or when you want immediate results.
    
    The graphs are saved directly to the database for viewing in the admin panel.
    
    Example:
        POST /graphs/build-sync
        {
            "project_id": 1,
            "num_graphs": 4,
            "init_only": false
        }
    
    Returns when complete (may take 1-10 minutes depending on codebase size).
    """
    import tempfile
    import time
    from pathlib import Path
    
    start_time = time.time()
    
    # Get project
    project = db.query(Project).filter(Project.id == request.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail=f"Project {request.project_id} not found")
    
    # Determine source path
    source_path = project.source_path
    if not source_path:
        if project.git_url:
            # Clone to temp directory
            import subprocess
            temp_dir = tempfile.mkdtemp(prefix="hound_")
            source_path = temp_dir
            logger.info(f"Cloning {project.git_url} to {temp_dir}")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", project.git_url, temp_dir],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                raise HTTPException(status_code=500, detail=f"Git clone failed: {result.stderr}")
        else:
            raise HTTPException(status_code=400, detail="Project has no source_path or git_url")
    
    source_path = Path(source_path)
    if not source_path.exists():
        raise HTTPException(status_code=400, detail=f"Source path does not exist: {source_path}")
    
    logger.info(f"Building graphs for project {project.id} ({project.name}) from {source_path}")
    
    try:
        # Load config (using active config profile)
        config = get_active_config()
        
        # Create manifest using RepositoryManifest class
        from ingest.bundles import AdaptiveBundler
        from ingest.manifest import RepositoryManifest
        
        with tempfile.TemporaryDirectory(prefix="hound_manifest_") as manifest_dir:
            manifest_path = Path(manifest_dir)
            
            # Create manifest
            logger.info("Creating manifest...")
            manifest = RepositoryManifest(str(source_path), config, file_filter=None)
            cards, files = manifest.walk_repository()
            manifest.save_manifest(manifest_path)
            logger.info(f"Ingested {len(files)} files → {len(cards)} cards")
            
            # Create bundles (cards)
            logger.info("Creating code bundles...")
            bundler = AdaptiveBundler(cards, files, config)
            bundles = bundler.create_bundles()
            bundler.save_bundles(manifest_path)
            logger.info(f"Created {len(bundles)} bundles")
            
            # Build graphs
            logger.info(f"Building {request.num_graphs if not request.init_only else 1} graphs...")
            from analysis.graph_builder import GraphBuilder
            
            builder = GraphBuilder(config, debug=False)
            
            # Determine number of graphs
            num_graphs = 1 if request.init_only else request.num_graphs
            
            # Build graphs - note: repo_root is not a param, it's read from manifest
            builder.build(
                manifest_dir=manifest_path,
                output_dir=manifest_path / "graphs",
                max_iterations=request.max_iterations,
                max_graphs=num_graphs,
            )
            
            # Save graphs to database
            graphs_created = []
            total_nodes = 0
            total_edges = 0
            
            for graph_name, graph in builder.graphs.items():
                graph_data = graph.to_dict()
                
                # Check if graph already exists for this project
                existing = db.query(Graph).filter(
                    Graph.project_id == project.id,
                    Graph.name == graph_name
                ).first()
                
                if existing:
                    # Update existing graph
                    existing.data = graph_data
                    existing.updated_at = datetime.now(timezone.utc)
                    db_graph = existing
                else:
                    # Create new graph
                    db_graph = Graph(
                        project_id=project.id,
                        name=graph_name,
                        internal_name=graph_data.get("internal_name", graph_name),
                        data=graph_data,
                    )
                    db.add(db_graph)
                
                db.commit()
                db.refresh(db_graph)
                
                node_count = len(graph_data.get("nodes", []))
                edge_count = len(graph_data.get("edges", []))
                total_nodes += node_count
                total_edges += edge_count
                
                graphs_created.append({
                    "id": db_graph.id,
                    "name": graph_name,
                    "node_count": node_count,
                    "edge_count": edge_count,
                })
                
                logger.info(f"Saved graph '{graph_name}': {node_count} nodes, {edge_count} edges")
            
            duration = time.time() - start_time
            
            return SyncGraphBuildResponse(
                success=True,
                message=f"Built {len(graphs_created)} graphs for project '{project.name}'",
                graphs_built=len(graphs_created),
                graphs=graphs_created,
                total_nodes=total_nodes,
                total_edges=total_edges,
                duration_seconds=round(duration, 2),
            )
            
    except Exception as e:
        logger.exception(f"Graph build failed: {e}")
        raise HTTPException(status_code=500, detail=f"Graph build failed: {str(e)}")


class SyncAuditRequest(BaseModel):
    """Request model for synchronous audit execution."""
    project_id: int = Field(..., description="Project ID to audit")
    max_investigations: int = Field(20, description="Maximum investigations (1-100)")
    time_limit_minutes: int = Field(30, description="Time limit in minutes (1-120)")


class SyncAuditResponse(BaseModel):
    """Response model for synchronous audit."""
    success: bool
    message: str
    session_id: str
    hypotheses_found: int
    confirmed_count: int
    findings: list[dict[str, Any]]
    duration_seconds: float
    report_path: str | None = None
    report_url: str | None = None


@app.post("/audits/run-sync", response_model=SyncAuditResponse)
async def run_audit_sync(
    request: SyncAuditRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Run a security audit SYNCHRONOUSLY (blocking call).
    
    This is the simple SaaS-friendly version that doesn't require Celery/Redis.
    Requires graphs to be built first via /graphs/build-sync.
    
    The audit results (hypotheses) are saved directly to the database.
    
    Example:
        POST /audits/run-sync
        {
            "project_id": 1,
            "max_investigations": 20,
            "time_limit_minutes": 30
        }
    
    Returns when complete (may take 5-60 minutes depending on settings).
    """
    import tempfile
    import time
    from pathlib import Path
    
    start_time = time.time()
    
    # Get project
    project = db.query(Project).filter(Project.id == request.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail=f"Project {request.project_id} not found")
    
    # Check if project has graphs
    graphs = db.query(Graph).filter(Graph.project_id == request.project_id).all()
    if not graphs:
        raise HTTPException(
            status_code=400, 
            detail="No graphs found for this project. Build graphs first using /graphs/build-sync"
        )
    
    logger.info(f"Starting audit for project {project.id} ({project.name}) with {len(graphs)} graphs")
    
    # Generate session ID
    session_id = f"audit_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
    
    # Create audit session record
    audit_session = AuditSession(
        session_id=session_id,
        project_id=project.id,
        status="running",
        start_time=datetime.now(timezone.utc),
        models={"trigger": "api_sync"},
    )
    db.add(audit_session)
    db.commit()
    
    try:
        # Load config
        config = get_active_config()
        
        # Determine source path
        source_path = project.source_path
        if not source_path or not Path(source_path).exists():
            if project.git_url:
                import subprocess
                temp_dir = tempfile.mkdtemp(prefix="hound_audit_")
                source_path = temp_dir
                subprocess.run(
                    ["git", "clone", "--depth", "1", project.git_url, temp_dir],
                    capture_output=True, text=True, timeout=300
                )
            else:
                raise HTTPException(status_code=400, detail="Project source not available")
        
        source_path = Path(source_path)
        
        # Create temporary directory for audit artifacts
        with tempfile.TemporaryDirectory(prefix="hound_audit_") as temp_dir:
            temp_path = Path(temp_dir)
            graphs_dir = temp_path / "graphs"
            graphs_dir.mkdir()
            manifest_dir = temp_path / "manifest"
            manifest_dir.mkdir()
            
            # Write graphs to temp files (agent expects filesystem graphs)
            graphs_paths = {}
            for graph in graphs:
                graph_file = graphs_dir / f"graph_{graph.name}.json"
                import json
                with open(graph_file, "w") as f:
                    json.dump(graph.data, f, indent=2)
                # Build path entry for metadata (relative to graphs dir)
                graphs_paths[graph.name] = str(graph_file)
            
            # Write graphs metadata file in the format agent expects
            # Format: {"graphs": {"GraphName": "/path/to/graph.json"}}
            graphs_metadata_file = graphs_dir / "graphs_metadata.json"
            with open(graphs_metadata_file, "w") as f:
                json.dump({"graphs": graphs_paths}, f, indent=2)
            
            # Create manifest with source files (needed for code lookup)
            # First, try to load existing manifest from CLI if available
            cli_manifest_path = Path.home() / ".hound" / "projects" / project.name / "manifest" / "manifest.json"
            cli_cards_path = Path.home() / ".hound" / "projects" / project.name / "manifest" / "cards.json"
            
            manifest_data = {"repo_path": str(source_path), "num_files": 0, "files": []}
            cards_data = []
            
            if cli_manifest_path.exists():
                try:
                    with open(cli_manifest_path) as f:
                        manifest_data = json.load(f)
                    logger.info(f"Loaded existing manifest with {manifest_data.get('num_files', 0)} files")
                except Exception as e:
                    logger.warning(f"Failed to load CLI manifest: {e}")
            
            if cli_cards_path.exists():
                try:
                    with open(cli_cards_path) as f:
                        cards_data = json.load(f)
                    logger.info(f"Loaded {len(cards_data)} cards from CLI")
                except Exception as e:
                    logger.warning(f"Failed to load CLI cards: {e}")
            
            # Write manifest files
            manifest_file = manifest_dir / "manifest.json"
            with open(manifest_file, "w") as f:
                json.dump(manifest_data, f, indent=2)
            
            cards_file = manifest_dir / "cards.json"
            with open(cards_file, "w") as f:
                json.dump(cards_data, f, indent=2)
            
            logger.info(f"Prepared {len(graphs)} graphs in {graphs_dir}")
            
            # Run the agent
            from analysis.agent_core import AutonomousAgent
            
            # Calculate token budget - be generous for sync mode (no Celery overhead)
            # Use 500K tokens as default, or unlimited if time_limit is high
            token_budget = max(500000, request.time_limit_minutes * 60 * 500)
            
            agent = AutonomousAgent(
                graphs_metadata_path=graphs_metadata_file,
                manifest_path=manifest_dir,
                agent_id=session_id,
                config=config,
                debug=False,
                session_id=session_id,
                budget_limit=token_budget,
                budget_type='tokens',
            )
            
            # Create investigation prompt
            investigation_prompt = """Perform a comprehensive security audit of this codebase.
Focus on identifying:
1. Critical vulnerabilities (reentrancy, access control, overflow)
2. Logic bugs and edge cases
3. Economic exploits (flash loans, price manipulation)
4. Integration risks

Analyze the loaded graphs systematically and form hypotheses for any potential issues."""

            # Run investigation
            results = agent.investigate(
                prompt=investigation_prompt,
                max_iterations=request.max_investigations,
            )
            
            # Get hypotheses from the agent's hypothesis store
            hypotheses = agent.hypothesis_store.list_all()
            
            # Save hypotheses to database
            hypotheses_saved = []
            confirmed_count = 0
            
            for hyp in hypotheses:
                # Create unique hypothesis ID
                hyp_id = hyp.get("id") or f"hyp_{uuid.uuid4().hex[:12]}"
                
                # Check if already exists
                existing = db.query(Hypothesis).filter(
                    Hypothesis.hypothesis_id == hyp_id
                ).first()
                
                if existing:
                    continue
                
                db_hyp = Hypothesis(
                    project_id=project.id,
                    hypothesis_id=hyp_id,
                    title=hyp.get("title", "Untitled"),
                    description=hyp.get("description", ""),
                    vulnerability_type=hyp.get("vulnerability_type", "unknown"),
                    status=hyp.get("status", "proposed"),
                    confidence=hyp.get("confidence", 0.5),
                    severity=hyp.get("severity", "medium"),
                    node_refs=hyp.get("node_refs", []),
                    evidence=hyp.get("evidence", {}),
                    reported_by_model=hyp.get("reported_by_model"),
                )
                db.add(db_hyp)
                db.commit()
                db.refresh(db_hyp)
                
                if db_hyp.status == "confirmed":
                    confirmed_count += 1
                
                hypotheses_saved.append({
                    "id": db_hyp.id,
                    "hypothesis_id": db_hyp.hypothesis_id,
                    "title": db_hyp.title,
                    "severity": db_hyp.severity,
                    "confidence": db_hyp.confidence,
                    "status": db_hyp.status,
                })
            
            # Update session status
            audit_session.status = "completed"
            audit_session.end_time = datetime.now(timezone.utc)
            db.commit()
            
            # Auto-generate report if enabled (default: true for sync audits)
            auto_generate_report = os.environ.get("AUTO_GENERATE_REPORT", "true").lower() == "true"
            report_path = None
            
            if auto_generate_report and confirmed_count > 0:
                try:
                    logger.info(f"Auto-generating report for session {session_id}...")
                    import tempfile

                    from analysis.report_generator import ReportGenerator
                    
                    # Create temporary project directory for report
                    with tempfile.TemporaryDirectory(prefix="hound_report_") as report_temp_dir:
                        report_temp_path = Path(report_temp_dir)
                        
                        # Create graphs directory
                        report_graphs_dir = report_temp_path / "graphs"
                        report_graphs_dir.mkdir()
                        
                        # Write knowledge_graphs.json
                        kg_data = {
                            "manifest": {"repo_path": str(source_path) if source_path else None},
                            "card_store_path": None
                        }
                        with open(report_graphs_dir / "knowledge_graphs.json", "w") as f:
                            json.dump(kg_data, f)
                        
                        # Write minimal graph file
                        with open(report_graphs_dir / "graph_analysis.json", "w") as f:
                            json.dump({"nodes": [], "edges": []}, f)
                        
                        # Build hypotheses dict
                        hyp_dict = {}
                        for h in hypotheses_saved:
                            hyp_dict[h["hypothesis_id"]] = {
                                "title": h["title"],
                                "description": "",
                                "vulnerability_type": "",
                                "status": h["status"],
                                "confidence": h["confidence"],
                                "severity": h["severity"],
                                "node_refs": [],
                                "evidence": {},
                                "annotations": [],
                                "reasoning": "",
                            }
                        
                        # Write hypotheses.json
                        hyp_data = {
                            "hypotheses": hyp_dict,
                            "metadata": {"source": "database", "project_name": project.name}
                        }
                        with open(report_temp_path / "hypotheses.json", "w") as f:
                            json.dump(hyp_data, f)
                        
                        # Create reports directory
                        (report_temp_path / "reports").mkdir(exist_ok=True)
                        
                        # Generate report
                        generator = ReportGenerator(
                            project_dir=report_temp_path,
                            config=config,
                            debug=False,
                            include_all=False
                        )
                        
                        report_html = generator.generate(
                            project_name=project.name,
                            project_source=str(source_path) if source_path else None,
                            title=f"Security Audit Report: {project.name}",
                            auditors=["Security Team"],
                            format="html",
                            progress_callback=None
                        )
                        
                        # Save report
                        user_reports_dir = Path.home() / ".hound" / "reports" / project.name
                        user_reports_dir.mkdir(parents=True, exist_ok=True)
                        
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        report_path = user_reports_dir / f"audit_report_{timestamp}.html"
                        
                        with open(report_path, 'w') as f:
                            f.write(report_html)
                        
                        logger.info(f"Auto-generated report saved to: {report_path}")
                        
                except Exception as report_err:
                    logger.warning(f"Failed to auto-generate report: {report_err}")
                    # Don't fail the audit if report generation fails
            
            duration = time.time() - start_time
            
            response_data = {
                "success": True,
                "message": f"Audit completed for project '{project.name}'",
                "session_id": session_id,
                "hypotheses_found": len(hypotheses_saved),
                "confirmed_count": confirmed_count,
                "findings": hypotheses_saved,
                "duration_seconds": round(duration, 2),
            }
            
            if report_path:
                response_data["report_path"] = str(report_path)
                response_data["report_url"] = f"/reports/{project.name}/{report_path.name}"
            
            return SyncAuditResponse(**response_data)
            
    except Exception as e:
        logger.exception(f"Audit failed: {e}")
        
        # Try to capture any hypotheses that were formed before the error
        hypotheses_saved = []
        try:
            if 'agent' in locals() and hasattr(agent, 'hypothesis_store'):
                hypotheses = agent.hypothesis_store.list_all()
                logger.info(f"Captured {len(hypotheses)} hypotheses despite error")
                
                for hyp in hypotheses:
                    hyp_id = hyp.get("id") or f"hyp_{uuid.uuid4().hex[:12]}"
                    existing = db.query(Hypothesis).filter(Hypothesis.hypothesis_id == hyp_id).first()
                    if existing:
                        continue
                    
                    db_hyp = Hypothesis(
                        project_id=project.id,
                        hypothesis_id=hyp_id,
                        title=hyp.get("title", "Untitled"),
                        description=hyp.get("description", ""),
                        vulnerability_type=hyp.get("vulnerability_type", "unknown"),
                        status=hyp.get("status", "proposed"),
                        confidence=hyp.get("confidence", 0.5),
                        severity=hyp.get("severity", "medium"),
                        node_refs=hyp.get("node_refs", []),
                        evidence=hyp.get("evidence", {}),
                        reported_by_model=hyp.get("reported_by_model"),
                    )
                    db.add(db_hyp)
                    db.commit()
                    hypotheses_saved.append({"id": db_hyp.id, "title": db_hyp.title})
        except Exception as capture_err:
            logger.warning(f"Failed to capture hypotheses on error: {capture_err}")
        
        # Update session status
        audit_session.status = "failed" if not hypotheses_saved else "partial"
        audit_session.end_time = datetime.now(timezone.utc)
        db.commit()
        
        # If we captured hypotheses, return a partial success
        if hypotheses_saved:
            duration = time.time() - start_time
            return SyncAuditResponse(
                success=True,
                message=f"Audit partially completed (budget exceeded) for project '{project.name}' - captured {len(hypotheses_saved)} findings",
                session_id=session_id,
                hypotheses_found=len(hypotheses_saved),
                confirmed_count=0,
                findings=hypotheses_saved,
                duration_seconds=round(duration, 2),
            )
        
        raise HTTPException(status_code=500, detail=f"Audit failed: {str(e)}")


# ============================================================================
# GitHub Webhook Endpoint - HANDLES INCOMING GITHUB EVENTS
# ============================================================================

# GitHub webhook secret (must match the secret configured in GitHub App)
GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")


def verify_github_signature(payload: bytes, signature: str) -> bool:
    """Verify GitHub webhook signature using HMAC-SHA256."""
    if not GITHUB_WEBHOOK_SECRET:
        logger.warning("GITHUB_WEBHOOK_SECRET not set - skipping signature verification")
        return True  # Skip verification if no secret configured (dev mode)
    
    if not signature or not signature.startswith("sha256="):
        return False
    
    expected_sig = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected_sig}", signature)


@app.post("/webhooks/github")
async def handle_github_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handle GitHub App webhook events.
    
    This endpoint receives events from GitHub when:
    - App is installed on a repository
    - A pull request is opened or updated
    - A push is made to a monitored branch
    
    For pull_request events, it automatically triggers a security audit
    and posts findings as PR comments.
    
    Security:
        Verifies the X-Hub-Signature-256 header using GITHUB_WEBHOOK_SECRET.
    """
    # Get raw body for signature verification
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    
    if not verify_github_signature(body, signature):
        logger.warning("Invalid GitHub webhook signature")
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # Parse payload
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    event_type = request.headers.get("X-GitHub-Event", "")
    logger.info(f"Received GitHub webhook: {event_type}")
    
    # Handle installation events
    if event_type == "installation":
        action = payload.get("action")
        installation = payload.get("installation", {})
        installation_id = installation.get("id")
        account = installation.get("account", {})
        account_login = account.get("login", "")
        account_type = account.get("type", "User")
        sender = payload.get("sender", {}) or {}
        sender_github_id = sender.get("id")
        sender_login = sender.get("login", "")
        logger.info(
            f"Installation event: {action} for {installation_id} ({account_login}) by sender={sender_login}({sender_github_id})"
        )

        if action == "created" and installation_id:
            # firepan-bv21: the user who clicked Install may already exist in our
            # DB (they signed in via OAuth before installing the App). If so,
            # attach the installation to THEIR tenant rather than minting a
            # parallel orphan tenant. This is the root cause of the mezher-profi
            # / GneralyFulldestroyer split on 2026-05-14: webhook minted tenant
            # 78 for the org while user mezher-profi sat on tenant 77 with no
            # installation_id, so their private-repo scans failed without auth.
            tenant = db.query(Tenant).filter(Tenant.installation_id == installation_id).first()
            if not tenant and sender_github_id:
                sender_user = db.query(User).filter(User.github_id == sender_github_id).first()
                if sender_user and sender_user.tenant_id:
                    user_tenant = db.query(Tenant).filter(Tenant.id == sender_user.tenant_id).first()
                    if user_tenant and not user_tenant.installation_id:
                        user_tenant.installation_id = installation_id
                        user_tenant.github_account_login = (
                            user_tenant.github_account_login or account_login or None
                        )
                        user_tenant.github_account_type = (
                            user_tenant.github_account_type or account_type or None
                        )
                        if user_tenant.status == "pending":
                            user_tenant.status = "active"
                        db.commit()
                        db.refresh(user_tenant)
                        tenant = user_tenant
                        logger.info(
                            "Linked installation %s to existing tenant %s (user %s)",
                            installation_id, tenant.id, sender_login,
                        )
            if not tenant:
                tenant_name = f"github_{account_login}" if account_login else f"installation_{installation_id}"
                tenant = db.query(Tenant).filter(Tenant.name == tenant_name).first()
                if tenant:
                    # Reinstall: update installation_id on existing tenant
                    tenant.installation_id = installation_id
                    tenant.github_account_login = account_login or tenant.github_account_login
                    tenant.github_account_type = account_type or tenant.github_account_type
                    db.commit()
                    db.refresh(tenant)
                else:
                    # New install: create tenant
                    try:
                        tenant = Tenant(
                            name=tenant_name,
                            installation_id=installation_id,
                            status="pending",
                            github_account_login=account_login or None,
                            github_account_type=account_type or None,
                        )
                        db.add(tenant)
                        db.commit()
                        db.refresh(tenant)
                    except IntegrityError:
                        db.rollback()
                        # Race condition: another request created it first
                        tenant = db.query(Tenant).filter(Tenant.installation_id == installation_id).first()

            # firepan-l57m: heal already-connected projects. A repo connected
            # via the dashboard BEFORE the App was installed has
            # installation_id=NULL; without this the next scan can't resolve an
            # installation token (RAAC needed a manual UPDATE). Backfill the
            # tenant's NULL-installation projects — but CONSTRAINED BY GITHUB
            # OWNER (full_name "account_login/..."), not tenant alone:
            # Tenant.installation_id is unique 1:1 (models.py:83), yet a
            # tenant's Project rows are not owner-scoped, so an unconstrained
            # backfill could stamp the wrong install onto repos from another
            # owner. Owner-match prevents that cross-contamination.
            if tenant is not None and account_login:
                try:
                    healed = (
                        db.query(Project)
                        .filter(
                            Project.tenant_id == tenant.id,
                            Project.installation_id.is_(None),
                            Project.full_name.ilike(f"{account_login}/%"),
                        )
                        .update(
                            {"installation_id": installation_id},
                            synchronize_session=False,
                        )
                    )
                    if healed:
                        db.commit()
                        logger.info(
                            "Backfilled installation %s onto %d existing %s/* "
                            "project(s) for tenant %s (firepan-l57m)",
                            installation_id, healed, account_login, tenant.id,
                        )
                except Exception:
                    db.rollback()
                    logger.exception(
                        "Project installation_id backfill failed for tenant=%s "
                        "installation=%s",
                        tenant.id if tenant else None, installation_id,
                    )

            # Send notification (fire-and-forget)
            try:
                await notify_app_installed(
                    github_account=account_login or f"installation_{installation_id}",
                    account_type=account_type,
                    tenant_id=tenant.id if tenant else None,
                    installation_id=installation_id,
                )
            except Exception:
                pass  # non-critical

            return {
                "status": "ok",
                "event": "installation",
                "action": action,
                "tenant_id": tenant.id if tenant else None,
            }

        elif action == "deleted":
            logger.info(f"GitHub App uninstalled by {account_login} (installation {installation_id}) - tenant preserved")

        return {"status": "ok", "event": "installation", "action": action}
    
    # Handle pull request events — trigger surface scan + PR comment
    if event_type == "pull_request":
        action = payload.get("action")

        # Only scan on PR open or synchronize (new commits pushed)
        if action not in ("opened", "synchronize", "reopened"):
            return {"status": "ok", "event": "pull_request", "action": action, "skipped": True}

        pr = payload.get("pull_request", {})
        repo = payload.get("repository", {})
        installation = payload.get("installation", {})

        pr_number = pr.get("number")
        repo_full_name = repo.get("full_name")
        clone_url = repo.get("clone_url")
        pr_installation_id = installation.get("id")
        head_sha = pr.get("head", {}).get("sha", "")
        github_repo_id = repo.get("id")

        if not all([pr_number, repo_full_name, clone_url, pr_installation_id]):
            logger.warning("Missing required fields in PR webhook payload")
            return {"status": "error", "message": "Missing required fields"}

        # Look up project to check pr_comments_enabled
        project = db.query(Project).filter(Project.github_repo_id == github_repo_id).first() if github_repo_id else None

        # Check pr_comments_enabled guard
        if project and hasattr(project, 'pr_comments_enabled') and not project.pr_comments_enabled:
            logger.info(f"PR comments disabled for {repo_full_name}, skipping")
            return {"status": "ok", "event": "pull_request", "skipped": True, "reason": "PR comments disabled"}

        # Look up tenant via installation_id
        tenant = db.query(Tenant).filter(Tenant.installation_id == pr_installation_id).first()
        if not tenant and project:
            tenant = db.query(Tenant).filter(Tenant.id == project.tenant_id).first()
        if not tenant:
            tenant = db.query(Tenant).first()
        if not tenant:
            logger.warning(f"No tenant found for PR webhook from {repo_full_name}")
            return {"status": "error", "message": "No tenant found"}

        logger.info(f"Triggering surface scan for PR #{pr_number} on {repo_full_name}")

        # Tier enforcement: check plan limits before scanning
        uses_credit = False
        try:
            from server.tier_enforcement import _check_sync
            allowance = _check_sync(tenant.id, "scan", db)
            uses_credit = allowance.get("uses_credit", False)
        except HTTPException:
            logger.info(f"Scan limit reached for tenant {tenant.id} ({tenant.name}), skipping PR scan for {repo_full_name}")
            return {"status": "ok", "event": "pull_request", "skipped": True, "reason": "scan_limit_reached"}

        # Redis dedup: per PR + head SHA
        dedup_key = f"pr:scan:{project.id if project else 0}:{pr_number}:{head_sha}"
        try:
            import redis as redis_lib
            redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
            r = redis_lib.from_url(redis_url)
            acquired = r.set(dedup_key, "1", ex=300, nx=True)
        except Exception:
            acquired = True  # fail open

        if not acquired:
            logger.info(f"Duplicate PR scan for {repo_full_name}#{pr_number}@{head_sha[:8]}, skipping")
            return {"status": "ok", "event": "pull_request", "skipped": True, "reason": "Duplicate"}

        # Import and dispatch surface scan task
        try:
            from worker.tasks import execute_scan_task
        except ImportError as e:
            logger.error(f"Worker module not available: {e}")
            return {"status": "error", "message": "Worker not available"}

        # Create ScanExecution record
        timestamp = int(datetime.now(timezone.utc).timestamp())
        execution_id = f"scan_{uuid.uuid4().hex[:12]}_{timestamp}"

        scan_execution = ScanExecution(
            execution_id=execution_id,
            project_id=project.id if project else None,
            tenant_id=tenant.id,
            repo_url=clone_url,
            repo_name=repo_full_name,
            status="pending",
            scan_config={"trigger_source": "pr", "pr_number": pr_number, "head_sha": head_sha, "scan_type": "surface", "uses_credit": uses_credit},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(scan_execution)
        db.commit()

        # Dispatch surface scan with PR params
        task = execute_scan_task.delay(
            repo_url=clone_url,
            scan_id=execution_id,
            tenant_id=tenant.id,
            llm_budget=5,
            pr_number=pr_number,
            repo_full_name=repo_full_name,
            installation_id=pr_installation_id,
        )

        logger.info(f"Dispatched PR scan task {task.id} for {execution_id}")

        return {
            "status": "ok",
            "event": "pull_request",
            "action": action,
            "execution_id": execution_id,
            "task_id": task.id,
        }
    
    # Handle push events — trigger surface scan on contract changes
    if event_type == "push":
        ref = payload.get("ref", "")
        repo = payload.get("repository", {})
        installation = payload.get("installation", {})

        # Only trigger on default branch pushes
        default_branch = repo.get("default_branch", "main")
        if ref not in (f"refs/heads/{default_branch}", "refs/heads/main", "refs/heads/master"):
            return {"status": "ok", "event": "push", "skipped": True, "reason": "Not default branch"}

        github_repo_id = repo.get("id")
        repo_full_name = repo.get("full_name", "")
        clone_url = repo.get("clone_url", "")
        push_installation_id = installation.get("id")
        head_commit = payload.get("head_commit", {})
        commit_sha = head_commit.get("id", payload.get("after", ""))

        # Look up project by github_repo_id
        project = db.query(Project).filter(Project.github_repo_id == github_repo_id).first()
        if not project:
            logger.info(f"Push to {repo_full_name}: no matching project, skipping")
            return {"status": "ok", "event": "push", "skipped": True, "reason": "No matching project"}

        if project.status != "active":
            logger.info(f"Push to {repo_full_name}: project not active, skipping")
            return {"status": "ok", "event": "push", "skipped": True, "reason": "Project not active"}

        if not project.tenant_id:
            logger.warning(f"Push to {repo_full_name}: project has no tenant_id")
            return {"status": "error", "message": "Project has no tenant"}

        # Dispatch scan via audit_trigger
        from integrations.audit_trigger import run_audit_task
        execution_id = run_audit_task(
            project_id=project.id,
            project_name=repo_full_name,
            commit_sha=commit_sha,
            repo_url=clone_url,
            tenant_id=project.tenant_id,
            installation_id=push_installation_id,
            payload=payload,
        )

        if execution_id:
            return {"status": "ok", "event": "push", "execution_id": execution_id}
        else:
            return {"status": "ok", "event": "push", "skipped": True, "reason": "No contract changes or duplicate"}
    
    # Unknown event type
    return {"status": "ok", "event": event_type, "handled": False}


# ============================================================================
# Original API Endpoints
# ============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Hound Dashboard API",
        "version": "1.0.0",
        "endpoints": {
            "projects": "/projects",
            "create_project": "POST /projects",
            "sessions": "/projects/{id}/sessions",
            "graph": "/sessions/{id}/graph",
            "findings": "/sessions/{id}/findings",
            "websocket": "/ws/sessions/{id}",
            "start_audit": "POST /audits/start",
            "audit_status": "GET /audits/{session_id}/status",
            "github_webhook": "POST /webhooks/github",
            "user_profile": "GET /users/me",
            "organization": "GET /organizations/{id}",
            "organization_members": "GET /organizations/{id}/members",
            "subscription": "GET /subscriptions/current",
            "usage": "GET /usage/current-month",
            "repositories": "GET /repositories",
            "trigger_scan": "POST /repositories/{id}/scan",
            "repository_scans": "GET /repositories/{id}/scans",
            "all_findings": "GET /findings",
            "findings_stats": "GET /findings/stats",
            "surface_scans": "GET /surface/scans",
        },
    }


@app.get("/projects", response_model=list[ProjectResponse])
async def list_projects(
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    List all projects for the authenticated tenant.

    Returns project metadata with statistics including:
    - Number of graphs
    - Number of sessions
    - Number of hypotheses
    - Number of confirmed hypotheses
    """
    projects = db.query(Project).filter(Project.tenant_id == tenant_id).all()

    response = []
    for project in projects:
        # Count related items
        graphs_count = db.query(Graph).filter(Graph.project_id == project.id).count()
        sessions_count = db.query(AuditSession).filter(AuditSession.project_id == project.id).count()
        hypotheses_count = db.query(Hypothesis).filter(Hypothesis.project_id == project.id).count()
        confirmed_count = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == project.id, Hypothesis.status == "confirmed")
            .count()
        )

        response.append(
            ProjectResponse(
                id=project.id,
                name=project.name,
                source_path=project.source_path,
                git_url=project.git_url,
                description=project.description,
                status=project.status,
                created_at=project.created_at,
                last_accessed=project.last_accessed,
                graphs_count=graphs_count,
                sessions_count=sessions_count,
                hypotheses_count=hypotheses_count,
                confirmed_count=confirmed_count,
            )
        )

    return response


@app.post("/projects", response_model=ProjectResponse)
async def create_project(
    project_data: ProjectCreate,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Create a new project for manual git URLs or source paths.

    Accepts either git_url or source_path. Creates the project using
    the ProjectManager and stores it in the database.

    Note: If git_url is provided without source_path, the repository
    should be cloned first. This is currently a placeholder for future
    git clone functionality.
    """
    # Path traversal validation
    if ".." in project_data.name:
        raise HTTPException(status_code=400, detail="Invalid project name: path traversal not allowed")
    if project_data.source_path and ".." in project_data.source_path:
        raise HTTPException(status_code=400, detail="Invalid source_path: path traversal not allowed")

    # Validate that at least one source is provided
    if not project_data.git_url and not project_data.source_path:
        raise HTTPException(
            status_code=400, detail="Either git_url or source_path must be provided"
        )

    # Use ProjectManager to create the project
    manager = ProjectManager()

    try:
        # For now, require source_path for actual project creation
        # TODO: Add git clone functionality for git_url
        source = project_data.source_path
        if not source:
            # Placeholder: git_url should trigger clone to temp directory
            raise HTTPException(
                status_code=400, 
                detail="source_path is required. Git URL cloning not yet implemented."
            )

        # Create project using ProjectManager
        project_config = manager.create_project(
            name=project_data.name,
            source_path=source,
            description=project_data.description,
        )

        # Also create database entry
        # First, get or create default tenant
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        # Create database project entry with error handling for datetime parsing
        try:
            created_at = datetime.fromisoformat(project_config["created_at"])
            last_accessed = datetime.fromisoformat(project_config["last_accessed"])
        except (ValueError, KeyError) as e:
            logger.warning(f"Failed to parse datetime from project config: {e}")
            # Fallback to current time
            created_at = datetime.now(timezone.utc)
            last_accessed = datetime.now(timezone.utc)
        
        db_project = Project(
            tenant_id=tenant.id,
            name=project_data.name,
            source_path=project_data.source_path,
            git_url=project_data.git_url,
            description=project_data.description or project_config.get("description"),
            status="active",
            created_at=created_at,
            last_accessed=last_accessed,
        )
        db.add(db_project)
        db.commit()
        db.refresh(db_project)

        return ProjectResponse(
            id=db_project.id,
            name=db_project.name,
            source_path=db_project.source_path,
            git_url=db_project.git_url,
            description=db_project.description,
            status=db_project.status,
            created_at=db_project.created_at,
            last_accessed=db_project.last_accessed,
            graphs_count=0,
            sessions_count=0,
            hypotheses_count=0,
            confirmed_count=0,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")


@app.get("/projects/{project_id}/sessions", response_model=list[SessionResponse])
async def list_project_sessions(
    project_id: int,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    List all audit sessions for a project.

    Returns session metadata including:
    - Session ID and status
    - Start and end times
    - Models used
    - Token usage statistics
    - Coverage information
    - Number of investigations
    """
    # Verify project exists and belongs to tenant
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project or project.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Project not found")

    # Query sessions for the project
    sessions = (
        db.query(AuditSession)
        .filter(AuditSession.project_id == project_id)
        .order_by(AuditSession.start_time.desc())
        .all()
    )

    response = []
    for session in sessions:
        investigations_count = len(session.investigations or [])

        response.append(
            SessionResponse(
                id=session.id,
                session_id=session.session_id,
                status=session.status,
                start_time=session.start_time,
                end_time=session.end_time,
                models=session.models,
                token_usage=session.token_usage,
                coverage=session.coverage,
                investigations_count=investigations_count,
            )
        )

    return response


@app.get("/sessions/{session_id}/graph")
async def get_session_graph(
    session_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Return the system_graph JSON for visualization.

    This endpoint retrieves the graph data associated with a session.
    If the session has a project, it returns the SystemArchitecture graph
    for that project.
    """
    # First, try to get the session from the database
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get the project's graphs and verify tenant ownership
    project = db.query(Project).filter(Project.id == session.project_id).first()
    if not project or project.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Project not found for session")

    # Try to get SystemArchitecture graph from database
    system_graph = (
        db.query(Graph)
        .filter(
            Graph.project_id == project.id,
            Graph.internal_name == "SystemArchitecture",
        )
        .first()
    )

    if system_graph:
        return system_graph.data

    # No filesystem fallback — all graphs must come from the database.
    raise HTTPException(status_code=404, detail="System graph not found")


@app.get("/projects/{project_id}/hypotheses", response_model=list[FindingResponse])
async def get_project_hypotheses(
    project_id: int,
    status: str | None = None,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Return all hypotheses for a project, optionally filtered by status.

    Query params:
        - status: Filter by status (proposed, investigating, confirmed, rejected, resolved)
    """
    # Verify project exists and belongs to tenant
    project = db.query(Project).filter(
        Project.id == project_id,
        Project.tenant_id == tenant_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Build query
    query = db.query(Hypothesis).filter(Hypothesis.project_id == project_id)
    
    if status:
        query = query.filter(Hypothesis.status == status)
    
    hypotheses = query.order_by(Hypothesis.created_at.desc()).all()

    response = []
    for hypothesis in hypotheses:
        response.append(
            FindingResponse(
                id=hypothesis.id,
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                description=hypothesis.description,
                vulnerability_type=hypothesis.vulnerability_type,
                status=hypothesis.status,
                confidence=hypothesis.confidence,
                severity=hypothesis.severity,
                node_refs=hypothesis.node_refs,
                evidence=hypothesis.evidence,
                reported_by_model=hypothesis.reported_by_model,
                junior_model=hypothesis.junior_model,
                senior_model=hypothesis.senior_model,
                user_notes=hypothesis.user_notes,
                created_at=hypothesis.created_at,
                updated_at=hypothesis.updated_at,
            )
        )

    return response


@app.get("/sessions/{session_id}/findings", response_model=list[FindingResponse])
async def get_session_findings(
    session_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """
    Return the list of confirmed hypotheses (findings).

    This endpoint retrieves all confirmed hypotheses/findings for a project
    associated with the given session.
    """
    # Get the session
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Verify tenant ownership via project
    if session.project_id:
        project = db.query(Project).filter(Project.id == session.project_id).first()
        if not project or project.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Session not found")

    # Get confirmed hypotheses for the project
    hypotheses = (
        db.query(Hypothesis)
        .filter(
            Hypothesis.project_id == session.project_id,
            Hypothesis.status == "confirmed",
        )
        .order_by(Hypothesis.confidence.desc())
        .all()
    )

    response = []
    for hypothesis in hypotheses:
        response.append(
            FindingResponse(
                id=hypothesis.id,
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                description=hypothesis.description,
                vulnerability_type=hypothesis.vulnerability_type,
                status=hypothesis.status,
                confidence=hypothesis.confidence,
                severity=hypothesis.severity,
                node_refs=hypothesis.node_refs,
                evidence=hypothesis.evidence,
                reported_by_model=hypothesis.reported_by_model,
                junior_model=hypothesis.junior_model,
                senior_model=hypothesis.senior_model,
                user_notes=hypothesis.user_notes,
                created_at=hypothesis.created_at,
                updated_at=hypothesis.updated_at,
            )
        )

    return response


class FindingTriageUpdate(BaseModel):
    """Request model for triaging a finding (status change and/or notes)."""

    status: str | None = Field(None, description="New status (proposed, investigating, confirmed, rejected, resolved)")
    user_notes: str | None = Field(None, description="User triage notes / reasoning")


class FindingStatusUpdate(BaseModel):
    """Request model for updating finding status."""

    status: str = Field(..., description="New status (proposed, investigating, confirmed, rejected, resolved)")


@app.patch("/findings/{finding_id}/triage")
async def triage_finding(
    finding_id: str,
    triage: FindingTriageUpdate,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    _: None = Depends(reject_preview_writes),
):
    """
    Triage a finding: update status and/or add user notes.

    JWT-authenticated, tenant-scoped. Supports both hypothesis_id strings
    and integer DB IDs.
    """
    if triage.status is None and triage.user_notes is None:
        raise HTTPException(status_code=400, detail="Must provide status or user_notes")

    valid_statuses = ["proposed", "investigating", "confirmed", "rejected", "resolved"]
    if triage.status is not None and triage.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Look up by hypothesis_id string first, then integer ID
    finding = (
        db.query(Hypothesis)
        .join(Project, Hypothesis.project_id == Project.id)
        .filter(Hypothesis.hypothesis_id == finding_id, Project.tenant_id == tenant_id)
        .first()
    )
    if not finding:
        try:
            int_id = int(finding_id)
            finding = (
                db.query(Hypothesis)
                .join(Project, Hypothesis.project_id == Project.id)
                .filter(Hypothesis.id == int_id, Project.tenant_id == tenant_id)
                .first()
            )
        except ValueError:
            pass

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if triage.status is not None:
        finding.status = triage.status
        if triage.status == "confirmed":
            finding.confidence = 1.0
        elif triage.status == "rejected":
            finding.confidence = 0.0

    if triage.user_notes is not None:
        finding.user_notes = triage.user_notes

    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    return FindingResponse(
        id=finding.id,
        hypothesis_id=finding.hypothesis_id,
        title=finding.title,
        description=finding.description,
        vulnerability_type=finding.vulnerability_type,
        status=finding.status,
        confidence=finding.confidence,
        severity=finding.severity,
        node_refs=finding.node_refs,
        evidence=finding.evidence,
        reported_by_model=finding.reported_by_model,
        junior_model=finding.junior_model,
        senior_model=finding.senior_model,
        project_id=finding.project_id,
        user_notes=finding.user_notes,
        source=_hypothesis_source(finding),
        created_at=finding.created_at,
        updated_at=finding.updated_at,
    )


@app.post("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: int,
    status_update: FindingStatusUpdate,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Update the status of a finding (hypothesis) by database ID.

    This endpoint allows users to confirm or reject findings from the UI.
    Valid statuses are: proposed, investigating, confirmed, rejected, resolved.
    """
    # Validate status
    valid_statuses = ["proposed", "investigating", "confirmed", "rejected", "resolved"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Get the finding
    finding = db.query(Hypothesis).filter(Hypothesis.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update status
    finding.status = status_update.status
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "hypothesis_id": finding.hypothesis_id,
        "status": finding.status,
        "updated_at": finding.updated_at.isoformat(),
    }


@app.put("/api/findings/{finding_id}/status")
async def update_finding_status_by_hyp_id(
    finding_id: str,
    status_update: FindingStatusUpdate,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Update the status of a finding (hypothesis) by hypothesis_id string.

    This endpoint is used by the admin dashboard.
    Valid statuses are: proposed, investigating, confirmed, rejected, resolved.
    """
    # Validate status
    valid_statuses = ["proposed", "investigating", "confirmed", "rejected", "resolved"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Try to find by hypothesis_id string first, then by integer ID
    finding = db.query(Hypothesis).filter(Hypothesis.hypothesis_id == finding_id).first()
    
    if not finding:
        # Try as integer ID
        try:
            int_id = int(finding_id)
            finding = db.query(Hypothesis).filter(Hypothesis.id == int_id).first()
        except ValueError:
            pass

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update status and confidence based on status
    finding.status = status_update.status
    if status_update.status == "confirmed":
        finding.confidence = 1.0
    elif status_update.status == "rejected":
        finding.confidence = 0.0
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "hypothesis_id": finding.hypothesis_id,
        "status": finding.status,
        "confidence": finding.confidence,
        "updated_at": finding.updated_at.isoformat(),
    }


# ============================================================================
# Dashboard API Endpoints - Users, Organizations, Repositories, Findings
# ============================================================================

# -------------------- Response Models --------------------

class UserProfileResponse(BaseModel):
    """Response model for user profile."""
    id: int
    name: str
    email: str | None
    org_id: int
    org_name: str
    org_type: str  # "User" or "Organization"
    role: str = "member"  # For future role-based access control
    suggested_email: str | None = None  # Best-guess email for verification pre-fill

    model_config = ConfigDict(from_attributes=True)


class UserProfileUpdateRequest(BaseModel):
    """Request model for updating user profile."""
    email: str | None = None


class OrganizationResponse(BaseModel):
    """Response model for organization details."""
    id: int
    name: str
    github_account_login: str | None
    github_account_type: str | None
    status: str
    contact_email: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrganizationMemberResponse(BaseModel):
    """Response model for organization member."""
    id: int
    name: str
    email: str | None
    role: str = "member"

    model_config = ConfigDict(from_attributes=True)


class SubscriptionResponse(BaseModel):
    """Response model for subscription details."""
    tenant_id: int
    org_name: str
    plan: str = "free"  # free, starter, professional, enterprise
    status: str  # active, pending, suspended
    created_at: datetime
    plan_limits: dict = {}  # { repos, audits_per_month, scans_per_month }
    usage_this_month: dict = {}  # { scans_used, audits_used, repos_count }
    can_scan: bool = False
    can_view_details: bool = False
    scan_credits: int = 0
    stripe_customer_id: str | None = None
    trial_ends_at: datetime | None = None
    trial_plan: str | None = None
    is_trial: bool = False
    email_verified: bool = False
    contact_email: str | None = None

    model_config = ConfigDict(from_attributes=True)


class UsageStatsResponse(BaseModel):
    """Response model for usage statistics."""
    tenant_id: int
    period: str  # e.g., "2024-02"
    scans_count: int
    findings_count: int
    total_cost_usd: float
    token_usage: dict[str, Any]

    model_config = ConfigDict(from_attributes=True)


class RepositoryResponse(BaseModel):
    """Response model for repository details."""
    id: int
    name: str
    full_name: str | None = None
    git_url: str | None = None
    github_repo_id: int | None = None
    description: str | None = None
    is_private: bool = False
    default_branch: str | None = None
    status: str = "active"
    last_scan_at: datetime | None = None
    scans_count: int = 0
    findings_count: int = 0
    tenant_id: int | None = None
    created_at: datetime
    updated_at: datetime | None = None
    initial_scan_id: str | None = None

    model_config = ConfigDict(from_attributes=True)


class RepositoryListResponse(BaseModel):
    """Response model for paginated repository list."""
    repositories: list[RepositoryResponse]
    total: int
    page: int
    page_size: int


class RepositoryCreateRequest(BaseModel):
    """Request model for adding a new repository."""
    github_repo_id: int | None = None
    installation_id: int | None = None
    name: str
    full_name: str
    git_url: str
    default_branch: str = "main"
    description: str | None = None
    is_private: bool = False


class GitHubRepoItem(BaseModel):
    """A single GitHub repository from the user's account."""
    id: int
    name: str
    full_name: str
    description: str | None = None
    private: bool = False
    default_branch: str | None = "main"
    html_url: str
    language: str | None = None
    updated_at: str | None = None
    already_added: bool = False


class GitHubRepoListResponse(BaseModel):
    """Paginated list of GitHub repositories."""
    repos: list[GitHubRepoItem]
    total_count: int
    page: int
    per_page: int


class GitHubStatusResponse(BaseModel):
    """GitHub connection status."""
    connected: bool
    username: str | None = None
    avatar_url: str | None = None
    scopes: list[str] = []
    connected_at: str | None = None
    has_repo_scope: bool = False


class ScanHistoryItem(BaseModel):
    """Response model for scan history item."""
    execution_id: str
    status: str
    risk_score: int | None
    risk_level: str | None
    findings_count: int
    started_at: datetime | None
    completed_at: datetime | None
    scan_type: str = "surface"
    error_message: str | None = None
    # Branch this scan ran against. Falls back to project default_branch when
    # legacy rows have no branch in scan_config.
    branch: str | None = None
    # Deep audit curated fields (None for surface scans)
    assessment_level: str | None = None
    credible_findings_count: int | None = None
    # firepan-oi4: gates rendering of assessment_level/risk_score until a human
    # or stronger-model verifier signs off. Missing key on legacy rows = False.
    admin_verified: bool = False
    # firepan-ygy: set by the finalize step when the confirmed findings look like a
    # template-FP storm (e.g. yieldnest-style >10 access-control FPs). Surfaced so
    # the dashboard/admin UI can render a louder "don't just verify this" banner.
    needs_manual_review: bool = False
    review_reason: str | None = None
    # firepan-nxf: repo-relative paths the deep audit was scoped to, if any.
    # None = whole-repo run. Legacy rows without the key also surface as None.
    # Sourced from scan_config["target_files"].
    target_files: list[str] | None = None

    model_config = ConfigDict(from_attributes=True)


class ScanHistoryResponse(BaseModel):
    """Response model for scan history."""
    repository_id: int
    scans: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int


class FindingStatsResponse(BaseModel):
    """Response model for finding statistics."""
    total: int
    by_severity: dict[str, int]  # critical, high, medium, low
    by_status: dict[str, int]  # proposed, investigating, confirmed, rejected, resolved
    by_repository: dict[str, int]  # repo_name -> count


class FindingListResponse(BaseModel):
    """Response model for paginated findings list."""
    findings: list[FindingResponse]
    total: int
    page: int
    page_size: int


# -------------------- Endpoints --------------------

@app.get("/users/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Get current user profile from JWT token.

    Returns user information including organization details.
    Requires JWT authentication via Authorization header.
    """
    tenant = db.query(Tenant).filter(Tenant.id == user.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="User/Organization not found")

    # Best-guess email for verification dialog pre-fill
    suggested = user.email or getattr(user, "google_email", None) or None

    return UserProfileResponse(
        id=tenant.id,
        name=tenant.github_account_login or tenant.name,
        email=tenant.contact_email,
        org_id=tenant.id,
        org_name=tenant.name,
        org_type=tenant.github_account_type or "User",
        role="admin",  # In current model, installation owner is admin
        suggested_email=suggested,
    )


@app.patch("/users/me")
async def update_user_profile(
    body: UserProfileUpdateRequest,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """Update current user profile (contact email)."""
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="User not found")
    was_empty = not tenant.contact_email
    if body.email is not None:
        new_email = body.email.strip()
        # If email changed, reset verification
        if new_email.lower() != (tenant.contact_email or "").lower():
            tenant.email_verified = False
            tenant.email_verified_at = None
        tenant.contact_email = new_email
    db.commit()
    # Notify team when a user first provides contact email
    if was_empty and tenant.contact_email:
        try:
            from integrations.telegram import notify_contact_captured
            await notify_contact_captured(
                tenant_id=tenant_id,
                tenant_name=tenant.github_account_login or tenant.name,
                email=tenant.contact_email,
            )
        except Exception:
            pass
    return {"email": tenant.contact_email}


@app.get("/organizations/{org_id}", response_model=OrganizationResponse)
async def get_organization(
    org_id: int,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Get organization details by ID.

    Returns organization metadata including GitHub account information.
    """
    if org_id != tenant_id:
        raise HTTPException(status_code=404, detail="Organization not found")
    org = db.query(Tenant).filter(Tenant.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return OrganizationResponse(
        id=org.id,
        name=org.name,
        github_account_login=org.github_account_login,
        github_account_type=org.github_account_type,
        status=org.status,
        contact_email=org.contact_email,
        created_at=org.created_at,
        updated_at=org.updated_at,
    )


@app.get("/organizations/{org_id}/members", response_model=list[OrganizationMemberResponse])
async def list_organization_members(
    org_id: int,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    List members of an organization.

    Note: In the current GitHub App installation model, we don't track individual members.
    This returns the organization itself as a single member. Future enhancement could
    integrate with GitHub API to fetch actual org members.
    """
    if org_id != tenant_id:
        raise HTTPException(status_code=404, detail="Organization not found")
    org = db.query(Tenant).filter(Tenant.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Return org owner as single member (current architecture limitation)
    return [
        OrganizationMemberResponse(
            id=org.id,
            name=org.github_account_login or org.name,
            email=org.contact_email,
            role="owner",
        )
    ]


@app.get("/subscriptions/current", response_model=SubscriptionResponse)
async def get_current_subscription(
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get current subscription for user/organization.

    Returns subscription plan, limits, usage, and billing status.
    """
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    subscription_status = "active" if tenant.status == "active" else "pending"
    from server.tier_enforcement import get_effective_plan, has_paid_subscription, is_trial_active

    plan = get_effective_plan(tenant)
    has_stripe_paid_plan = bool(tenant.stripe_subscription_id) and tenant.plan not in (None, "free")
    is_trial = is_trial_active(tenant) and not has_stripe_paid_plan

    # Load plan limits
    import json
    from pathlib import Path
    config_path = Path(__file__).parent.parent / "config" / "stripe_plans.json"
    try:
        with open(config_path) as f:
            plans_config = json.load(f)
        plan_data = plans_config["plans"].get(plan, plans_config.get("free", {}))
        plan_limits = plan_data.get("limits", {})
    except (FileNotFoundError, KeyError):
        plan_limits = {"repos": 999, "audits_per_month": 0, "scans_per_month": 0}

    # Calculate usage this month
    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    scans_used = db.query(ScanExecution).filter(
        ScanExecution.tenant_id == tenant_id,
        ScanExecution.created_at >= month_start,
        ScanExecution.status.notin_(["failed", "error"]),
    ).count()

    repos_count = db.query(Project).filter(
        Project.tenant_id == tenant_id,
        Project.status == "active",
    ).count()

    tenant_project_ids = db.query(Project.id).filter(Project.tenant_id == tenant_id).subquery()
    audits_used = db.query(AuditSession).filter(
        AuditSession.project_id.in_(tenant_project_ids),
        AuditSession.start_time >= month_start,
    ).count()

    usage = {
        "scans_used": scans_used,
        "repos_count": repos_count,
        "audits_used": audits_used,
    }

    # Can scan: within plan limit OR has credits
    scans_limit = plan_limits.get("scans_per_month", 0)
    can_scan = scans_used < scans_limit or (tenant.scan_credits or 0) > 0

    can_view_details = has_paid_subscription(tenant)
    return SubscriptionResponse(
        tenant_id=tenant.id,
        org_name=tenant.name,
        plan=plan,
        status=subscription_status,
        created_at=tenant.created_at,
        plan_limits=plan_limits,
        usage_this_month=usage,
        can_scan=can_scan,
        can_view_details=can_view_details,
        scan_credits=tenant.scan_credits or 0,
        stripe_customer_id=tenant.stripe_customer_id,
        trial_ends_at=tenant.trial_ends_at,
        trial_plan=tenant.trial_plan,
        is_trial=is_trial,
        email_verified=tenant.email_verified if tenant.email_verified is not None else False,
        contact_email=tenant.contact_email,
    )


ALLOWED_ANALYTICS_EVENTS = {
    "scan_completed",
    "paywall_viewed",
    "upgrade_clicked",
    "checkout_started",
    "checkout_completed",
    "checkout_canceled",
}


class AnalyticsEventRequest(BaseModel):
    event: str
    properties: dict = {}


@app.post("/events", status_code=204)
async def track_event(
    body: AnalyticsEventRequest,
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """Track a funnel analytics event. Whitelisted event names only."""
    if body.event not in ALLOWED_ANALYTICS_EVENTS:
        raise HTTPException(400, f"Unknown event: {body.event}")

    # Cap payload size
    import json as _json
    if len(body.properties) > 10 or len(_json.dumps(body.properties)) > 4096:
        raise HTTPException(400, "Properties too large (max 10 keys, 4KB)")

    from database.models import AnalyticsEvent
    event = AnalyticsEvent(
        tenant_id=tenant_id,
        event=body.event,
        properties=body.properties,
    )
    db.add(event)
    db.commit()


@app.get("/usage/current-month", response_model=UsageStatsResponse)
async def get_current_month_usage(
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """
    Get usage and billing statistics for current billing period.
    
    Returns scan counts, finding counts, and token usage costs for the current month.
    """
    from database.models import TokenUsageLog
    
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    
    # Get current month start
    now = datetime.now(timezone.utc)
    month_start = datetime(now.year, now.month, 1, tzinfo=timezone.utc)
    
    # Count scans for this tenant in current month
    scans_count = db.query(func.count(ScanExecution.id)).filter(
        ScanExecution.tenant_id == tenant_id,
        ScanExecution.created_at >= month_start
    ).scalar() or 0
    
    # Count findings (hypotheses from projects belonging to tenant)
    findings_count = db.query(func.count(Hypothesis.id)).join(
        Project, Hypothesis.project_id == Project.id
    ).filter(
        Project.tenant_id == tenant_id,
        Hypothesis.created_at >= month_start
    ).scalar() or 0
    
    # Get token usage and cost
    token_stats = db.query(
        func.sum(TokenUsageLog.input_tokens).label('input_tokens'),
        func.sum(TokenUsageLog.output_tokens).label('output_tokens'),
        func.sum(TokenUsageLog.cost_usd).label('total_cost')
    ).filter(
        TokenUsageLog.tenant_id == tenant_id,
        TokenUsageLog.created_at >= month_start
    ).first()
    
    input_tokens = int(token_stats.input_tokens or 0)
    output_tokens = int(token_stats.output_tokens or 0)
    total_cost = float(token_stats.total_cost or 0.0)
    
    return UsageStatsResponse(
        tenant_id=tenant_id,
        period=now.strftime("%Y-%m"),
        scans_count=scans_count,
        findings_count=findings_count,
        total_cost_usd=total_cost,
        token_usage={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        }
    )


def _hypothesis_source(h: "Hypothesis") -> str:
    """Return the source tag ("deep" | "surface") for a Hypothesis row.

    INVARIANT: every row in the hypotheses table originates from a deep audit
    (pipeline-produced or manually inserted from a human review). Surface-scan
    findings live in ScanExecution.findings JSONB and reach the API response
    through a separate code path (see list_all_findings — the surface-findings
    loop). If the hypotheses table ever starts storing non-deep content,
    revisit this helper and classify per-row (e.g. by reported_by_model or a
    new scan_execution_id FK — see firepan-dar).
    """
    return "deep"


def _latest_scan_by_type(db: Session, project_id: int, scan_type: str):
    """Get the latest completed scan of a given type for a project.

    Filters in Python (not SQL) because scan_config is JSONB on Postgres
    but plain JSON on SQLite (tests), and JSONB path operators like
    ['scan_type'].astext don't work on SQLite.
    """
    scans = db.query(ScanExecution).filter(
        ScanExecution.project_id == project_id,
        ScanExecution.status.in_(["completed", "in_review"]),
        ScanExecution.findings.isnot(None),
    ).order_by(ScanExecution.created_at.desc()).all()

    for scan in scans:
        cfg = scan.scan_config or {}
        actual_type = cfg.get("scan_type", "surface") if isinstance(cfg, dict) else "surface"
        if actual_type == scan_type:
            return scan
    return None


def _count_findings_for_project(db: Session, project_id: int) -> int:
    """Count current findings for a project.

    Uses the LATEST completed scan per type (surface + deep separately)
    to avoid deep audits eclipsing surface findings or vice versa.
    """
    count = 0

    # Latest completed surface scan findings
    latest_surface = _latest_scan_by_type(db, project_id, "surface")
    if latest_surface and latest_surface.findings:
        count += len(latest_surface.findings)

    # Latest completed deep audit findings (from ScanExecution, not Hypothesis table)
    # Prefer curated credible count from deep_audit_overview when available
    latest_deep = _latest_scan_by_type(db, project_id, "deep")
    if latest_deep and latest_deep.findings:
        overview = latest_deep.deep_audit_overview if hasattr(latest_deep, 'deep_audit_overview') else None
        if isinstance(overview, dict) and "credible_findings_count" in overview:
            count += overview["credible_findings_count"]
        else:
            count += len(latest_deep.findings)

    # Deep audit hypotheses not backed by a ScanExecution (CLI/agent path)
    if not latest_deep:
        deep_findings = db.query(func.count(Hypothesis.id)).filter(
            Hypothesis.project_id == project_id
        ).scalar() or 0
        count += deep_findings

    return count


@app.get("/repositories", response_model=RepositoryListResponse)
async def list_repositories(
    tenant_id: int = Depends(get_current_tenant_id),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str | None = Query(None, description="Search repository name"),
    db: Session = Depends(get_db)
):
    """
    List all connected GitHub repositories for tenant/user.

    Returns paginated list of repositories (projects) with scan statistics.
    Redacts scan stats for unverified tenants.
    """
    # Check email verification for stats redaction
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    verified = tenant.email_verified if tenant else False

    query = db.query(Project).filter(
        Project.tenant_id == tenant_id,
        Project.status != "removed",
    )

    # Apply search filter
    if search:
        query = query.filter(Project.name.ilike(f"%{search}%"))

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * page_size
    projects = query.order_by(Project.created_at.desc()).offset(offset).limit(page_size).all()

    # Build response with statistics
    repositories = []
    for project in projects:
        if verified:
            last_scan = db.query(ScanExecution).filter(
                ScanExecution.project_id == project.id
            ).order_by(ScanExecution.created_at.desc()).first()
            last_scan_at = last_scan.created_at if last_scan else None
            scans_count = db.query(func.count(ScanExecution.id)).filter(
                ScanExecution.project_id == project.id
            ).scalar() or 0
            findings_count = _count_findings_for_project(db, project.id)
        else:
            last_scan_at = None
            scans_count = 0
            findings_count = 0

        repositories.append(RepositoryResponse(
            id=project.id,
            name=project.name,
            full_name=project.full_name,
            git_url=project.git_url,
            github_repo_id=project.github_repo_id,
            description=project.description,
            is_private=project.is_private,
            default_branch=project.default_branch,
            status=project.status,
            last_scan_at=last_scan_at,
            scans_count=scans_count,
            findings_count=findings_count,
            tenant_id=project.tenant_id,
            created_at=project.created_at,
            updated_at=project.last_accessed,
        ))
    
    return RepositoryListResponse(
        repositories=repositories,
        total=total,
        page=page,
        page_size=page_size,
    )



# ---------------------------------------------------------------------------
# GitHub Integration & Repository Management endpoints
# ---------------------------------------------------------------------------


async def _get_current_user_with_token(
    request: Request, db: Session
) -> User:
    """
    Resolve the current user from the JWT and ensure a GitHub token exists.

    Returns the SQLAlchemy User object.
    Raises HTTPException 401 if no valid token is available.
    """
    from server.auth_routes import get_token_from_header
    from server.auth_utils import get_current_user_from_token

    token = get_token_from_header(request)
    try:
        payload = get_current_user_from_token(token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired token. Please log in again.")
    user = db.query(User).filter(User.id == payload["user_id"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.github_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub token expired. Please reconnect your GitHub account.",
        )
    return user


def _try_resolve_user_no_token(request: Request, db: Session) -> User | None:
    """Resolve the User from the JWT WITHOUT requiring a valid GitHub token.

    firepan-l57m review F1: an authenticated user with a missing/expired
    GitHub token is the exact silent-bad-path population. _get_current_user_
    with_token() 401s for them (it requires github_token_encrypted), so we
    couldn't run the private-repo gate against them. This resolves just the
    User row so the gate can see github_token_encrypted/has_repo_scope and
    hard-fail with a guided 403. Returns None only if there is genuinely no
    valid session user (truly anonymous).
    """
    from server.auth_routes import get_token_from_header
    from server.auth_utils import get_current_user_from_token

    try:
        token = get_token_from_header(request)
        payload = get_current_user_from_token(token)
        return db.query(User).filter(User.id == payload["user_id"]).first()
    except Exception:
        return None


def _check_private_repo_access(project: Project, user: User):
    """Raise 403 if private repo lacks both installation token and repo-scoped OAuth.

    Best-effort gate: trusts stored scopes without a live GitHub API check.
    If the token is actually revoked, the worker catches it and refunds credits.
    """
    if not project.is_private:
        return
    if project.installation_id:
        return
    if not user.github_token_encrypted:
        raise HTTPException(403, detail={
            "error": "insufficient_github_scope",
            "message": "Private repo scanning requires GitHub authentication",
        })
    if not user.has_repo_scope:
        raise HTTPException(403, detail={
            "error": "insufficient_github_scope",
            "message": "Private repo scanning requires additional GitHub permissions or GitHub App installation",
        })


async def _resolve_repo_privacy(
    git_url: str,
    user: User | None,
    tenant: Tenant | None,
    client_is_private: bool,
) -> bool:
    """Resolve a repo's true private/public status server-side (firepan-l57m).

    The manual-add path historically omitted `is_private`, so the backend
    defaulted it to False and the private-repo access gate became a no-op —
    silently connecting unscannable private repos. This resolves the truth from
    GitHub instead of trusting the client.

    FAIL-SAFE policy (revised after review of PR #64 — findings F1/F2/F3):
    the old code returned the permissive client hint whenever it could NOT
    positively determine privacy (no/expired token, 401, unexpected error),
    which reopened the original silent-bad-path: an authenticated user with an
    expired GitHub token could manual-add a private repo as `is_private=False`,
    skip the gate, and persist it. We now fail SAFE — when we cannot prove the
    repo is public-and-scannable, resolve to private so the access gate
    hard-fails (or so the worker uses an installation token).

      - 200 + `.private`                 -> that boolean (authoritative).
      - GitHub auth failure (401/403)
        OR httpx 401 not mapped by
        github_service                   -> private (gate hard-fails / install
                                            token resolves it).
      - 404 AND tenant has App install   -> VERIFY with the install token (the
                                            token that would actually scan it).
                                            Visible -> its `.private`. Still
                                            404 -> genuine typo, raise 404
                                            (no junk row — review F3 hardened).
      - 404 AND no App install           -> raise 404
                                            `repo_not_found_or_inaccessible`
                                            (caller must NOT persist; covers
                                            typoed manual URLs — review F3).
      - no user context AT ALL           -> only here do we trust the hint:
                                            picker / installation paths carry
                                            their own auth; pure no-user with
                                            no install is not a real manual-add.
      - unexpected/transient error       -> private (fail safe), not the hint.

    Returns the resolved `is_private`. Raises HTTPException(404) for the
    not-found-without-install case so the caller rejects before persistence.
    """
    import httpx

    from server.services.github_service import GitHubService, parse_github_url

    tenant_has_install = bool(tenant and tenant.installation_id)

    if user is None:
        # No authenticated user object at all. Picker / installation-backed
        # paths carry their own auth and pass a real is_private; trust the
        # hint here (this is NOT the manual-add-with-expired-token case —
        # that user IS present, just token-less, handled below as private).
        return bool(client_is_private)

    if not user.github_token_encrypted:
        # Authenticated user but no usable GitHub token (expired/revoked).
        # This is exactly the silent-bad-path from review F1. Fail SAFE:
        # treat as private so the access gate hard-fails with a guided 403
        # (unless an App install will resolve it, which the gate also checks).
        return True

    try:
        owner, repo = parse_github_url(git_url)
    except ValueError:
        # URL shape validated upstream; if we somehow can't parse, fail safe.
        return True

    try:
        token = decrypt_token(user.github_token_encrypted)
        details = await GitHubService(token).get_repo_details(owner, repo)
        return bool(details.get("private", True))  # absent -> assume private
    except HTTPException as e:
        if e.status_code == 404:
            def _reject_not_found() -> None:
                raise HTTPException(
                    status_code=404,
                    detail={
                        "error": "repo_not_found_or_inaccessible",
                        "message": (
                            "Repository not found, or not accessible with "
                            "your GitHub account. Check the URL, or install "
                            "the FirePan GitHub App on the owning "
                            "organization for private repos."
                        ),
                    },
                )

            if not tenant_has_install:
                _reject_not_found()

            # Tenant has an App install. The OAuth token's 404 may just mean
            # "this token can't see a private repo the install token can."
            # VERIFY with the install token (the token that would actually
            # scan it) so a genuine typo cannot land a junk project row
            # (review F3 — makes "no junk row on typo" literally true).
            try:
                from integrations.github_auth import get_installation_token

                inst_token = get_installation_token(tenant.installation_id)
                inst_details = await GitHubService(
                    inst_token
                ).get_repo_details(owner, repo)
                # Install token CAN see it -> real repo. Its .private is
                # authoritative; the gate passes via installation_id.
                return bool(inst_details.get("private", True))
            except HTTPException as ie:
                if ie.status_code == 404:
                    # Neither OAuth nor install token can see it -> genuine
                    # typo / nonexistent. Reject; do NOT persist a junk row.
                    _reject_not_found()
                # Install token exists but 401/403 on this repo -> repo is
                # real but out of the install's scope -> private, gate decides.
                return True
            except Exception:
                # Install-token mint/probe failed transiently. Fail safe:
                # private (gate / worker re-resolve), not a junk public row.
                logger.warning(
                    "Install-token verify failed for %s; failing safe (private)",
                    git_url,
                )
                return True
        # 401/403 (or anything else github_service mapped): repo exists but
        # this token can't read it -> private; let the gate hard-fail.
        return True
    except httpx.HTTPStatusError:
        # github_service only maps 404/403 to HTTPException; a 401 reaches
        # here via raise_for_status (review F2). Fail safe -> private.
        return True
    except Exception:
        logger.warning(
            "Privacy resolution failed for %s; failing safe (private)",
            git_url,
        )
        return True


@app.get("/github/repos", response_model=GitHubRepoListResponse, tags=["github"])
async def list_github_repos(
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(30, ge=1, le=100, description="Results per page"),
    search: str | None = Query(None, description="Filter repos by name"),
    sort: str = Query("updated", description="Sort field: updated, name, created"),
    db: Session = Depends(get_db),
):
    """
    List the authenticated user's GitHub repositories.

    Uses the stored GitHub OAuth token to call the GitHub API.
    Powers the repo-picker UI where users select repos to monitor.
    """
    user = await _get_current_user_with_token(request, db)

    try:
        github_token = decrypt_token(user.github_token_encrypted)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="GitHub token expired. Please reconnect your GitHub account.",
        )

    # Map sort parameter to GitHub API values
    gh_sort_map = {"updated": "updated", "name": "full_name", "created": "created"}
    gh_sort = gh_sort_map.get(sort, "updated")
    gh_direction = "desc" if gh_sort != "full_name" else "asc"

    # When searching, we need to fetch more repos and filter server-side
    # because GitHub /user/repos doesn't support name substring search.
    if search:
        fetch_per_page = 100
        fetch_page = 1
        all_repos: list[dict] = []
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient(timeout=30) as client:
            # Fetch pages until we have enough filtered results or exhaust repos
            while True:
                resp = await client.get(
                    "https://api.github.com/user/repos",
                    params={
                        "sort": gh_sort,
                        "direction": gh_direction,
                        "per_page": fetch_per_page,
                        "page": fetch_page,
                        "type": "all",
                    },
                    headers=headers,
                )
                if resp.status_code == 401:
                    raise HTTPException(
                        status_code=401,
                        detail="GitHub token expired. Please reconnect your GitHub account.",
                    )
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break
                # Filter by search term (case-insensitive contains)
                search_lower = search.lower()
                for repo in batch:
                    if search_lower in repo.get("name", "").lower():
                        all_repos.append(repo)
                # If GitHub returned less than a full page, no more pages
                if len(batch) < fetch_per_page:
                    break
                fetch_page += 1
                # Safety: don't fetch more than 10 pages when searching
                if fetch_page > 10:
                    break

        total_count = len(all_repos)
        start = (page - 1) * per_page
        repos_page = all_repos[start : start + per_page]
    else:
        # Direct passthrough to GitHub API with pagination
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                "https://api.github.com/user/repos",
                params={
                    "sort": gh_sort,
                    "direction": gh_direction,
                    "per_page": per_page,
                    "page": page,
                    "type": "all",
                },
                headers=headers,
            )
            if resp.status_code == 401:
                raise HTTPException(
                    status_code=401,
                    detail="GitHub token expired. Please reconnect your GitHub account.",
                )
            resp.raise_for_status()
            repos_page = resp.json()

        # GitHub doesn't return total_count for /user/repos; approximate from
        # the number of results on this page.
        total_count = len(repos_page) + (page - 1) * per_page
        if len(repos_page) == per_page:
            # There are likely more pages
            total_count += 1  # signals "at least one more page"

    # Build set of already-added github_repo_ids for this tenant
    added_ids: set[int] = set()
    existing = (
        db.query(Project.github_repo_id)
        .filter(
            Project.tenant_id == tenant_id,
            Project.github_repo_id.isnot(None),
            Project.status != "removed",
        )
        .all()
    )
    for (repo_id,) in existing:
        added_ids.add(repo_id)

    items = []
    for repo in repos_page:
        items.append(
            GitHubRepoItem(
                id=repo["id"],
                name=repo.get("name", ""),
                full_name=repo.get("full_name", ""),
                description=repo.get("description"),
                private=repo.get("private", False),
                default_branch=repo.get("default_branch", "main"),
                html_url=repo.get("html_url", ""),
                language=repo.get("language"),
                updated_at=repo.get("updated_at"),
                already_added=repo["id"] in added_ids,
            )
        )

    return GitHubRepoListResponse(
        repos=items,
        total_count=total_count,
        page=page,
        per_page=per_page,
    )


@app.get("/github/installation-repos", response_model=GitHubRepoListResponse, tags=["github"])
async def list_installation_repos(
    tenant_id: int = Depends(get_current_tenant_id),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(30, ge=1, le=100, description="Results per page"),
    search: str | None = Query(None, description="Filter repos by name"),
    db: Session = Depends(get_db),
):
    """List repositories available to the tenant's GitHub App installation."""
    from integrations.github_auth import get_installation_token

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant or not tenant.installation_id:
        raise HTTPException(404, "No GitHub App installation for this tenant")

    try:
        installation_token = get_installation_token(tenant.installation_id)
    except Exception as exc:
        raise HTTPException(502, f"Failed to get installation token: {exc}") from exc

    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    added_ids = {
        repo_id
        for (repo_id,) in db.query(Project.github_repo_id).filter(
            Project.tenant_id == tenant_id,
            Project.github_repo_id.isnot(None),
            Project.status != "removed",
        ).all()
    }

    async with httpx.AsyncClient(timeout=30) as client:
        if search:
            fetch_page = 1
            all_repos: list[dict] = []
            search_lower = search.lower()
            while True:
                resp = await client.get(
                    "https://api.github.com/installation/repositories",
                    params={"per_page": 100, "page": fetch_page},
                    headers=headers,
                )
                if resp.status_code != 200:
                    raise HTTPException(502, "Failed to list installation repos")
                data = resp.json()
                batch = data.get("repositories", [])
                if not batch:
                    break
                all_repos.extend(
                    repo for repo in batch if search_lower in repo.get("name", "").lower()
                )
                if len(batch) < 100:
                    break
                fetch_page += 1
            total_count = len(all_repos)
            start = (page - 1) * per_page
            repos_page = all_repos[start : start + per_page]
        else:
            resp = await client.get(
                "https://api.github.com/installation/repositories",
                params={"per_page": per_page, "page": page},
                headers=headers,
            )
            if resp.status_code != 200:
                raise HTTPException(502, "Failed to list installation repos")
            data = resp.json()
            repos_page = data.get("repositories", [])
            total_count = data.get("total_count", len(repos_page))

    items = [
        GitHubRepoItem(
            id=repo["id"],
            name=repo.get("name", ""),
            full_name=repo.get("full_name", ""),
            description=repo.get("description"),
            private=repo.get("private", False),
            default_branch=repo.get("default_branch", "main"),
            html_url=repo.get("html_url", ""),
            language=repo.get("language"),
            updated_at=repo.get("updated_at"),
            already_added=repo["id"] in added_ids,
        )
        for repo in repos_page
    ]

    return GitHubRepoListResponse(
        repos=items,
        total_count=total_count,
        page=page,
        per_page=per_page,
    )


@app.post("/repositories", status_code=201, response_model=RepositoryResponse, tags=["repositories"])
async def create_repository(
    body: RepositoryCreateRequest,
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
    __: None = Depends(require_verified_email),
):
    """
    Add a GitHub repository to the tenant's monitored repositories.

    Can be called from the repo picker (with github_repo_id) or from
    manual URL input (with git_url).
    """
    import re

    # Validate git_url format
    git_url_pattern = re.compile(
        r"^https?://[a-zA-Z0-9._-]+(:[0-9]+)?/[a-zA-Z0-9._/-]+(\.git)?/?$"
    )
    if not git_url_pattern.match(body.git_url):
        raise HTTPException(status_code=400, detail="Invalid repository URL")

    # Check for duplicates (github_repo_id OR git_url within tenant, excluding removed)
    dup_query = db.query(Project).filter(
        Project.tenant_id == tenant_id,
        Project.status != "removed",
    )
    if body.github_repo_id:
        existing = dup_query.filter(
            Project.github_repo_id == body.github_repo_id
        ).first()
        if existing:
            raise HTTPException(status_code=409, detail="Repository already added")

    existing_url = dup_query.filter(Project.git_url == body.git_url).first()
    if existing_url:
        raise HTTPException(status_code=409, detail="Repository already added")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()

    # firepan-l57m: resolve the acting user + true repo privacy BEFORE
    # persisting, so an inaccessible private repo (or a 404 typo) never
    # creates a junk project row and never returns a fake "success".
    #
    # Review F1: resolve the User object INDEPENDENT of token validity. The
    # silent-bad-path population is precisely the authenticated user whose
    # GitHub token is missing/expired — _get_current_user_with_token() 401s
    # for them, so keying the gate off "did we get an acting_user" let them
    # skip it. We need the User row (token or not) so the gate can evaluate
    # has_repo_scope / github_token_encrypted and hard-fail correctly.
    acting_user: User | None = None
    try:
        acting_user = await _get_current_user_with_token(request, db)
    except HTTPException:
        acting_user = _try_resolve_user_no_token(request, db)

    resolved_is_private = await _resolve_repo_privacy(
        body.git_url, acting_user, tenant, body.is_private
    )  # raises 404 repo_not_found_or_inaccessible -> caller never persists

    now = datetime.now(timezone.utc)
    project = Project(
        tenant_id=tenant_id,
        name=body.name,
        full_name=body.full_name,
        git_url=body.git_url,
        github_repo_id=body.github_repo_id,
        installation_id=body.installation_id or (tenant.installation_id if tenant else None),
        default_branch=body.default_branch,
        description=body.description,
        is_private=resolved_is_private,
        status="active",
        created_at=now,
        last_accessed=now,
    )

    # Hard-fail BEFORE persistence if this is a private repo we cannot scan.
    # Returns 403 insufficient_github_scope, which the current dashboard
    # already surfaces as an error — no silent failure, no junk row.
    # (firepan-l57m bleed-stop.)
    #
    # Review F1: the gate runs whenever the repo resolved private and there
    # is no installation coverage — NOT only "if we have a user". A private
    # repo with no acting user and no install is unscannable and must be
    # rejected, never persisted as a fake success.
    if project.is_private and not project.installation_id:
        if acting_user is None:
            raise HTTPException(403, detail={
                "error": "insufficient_github_scope",
                "message": "Private repo scanning requires GitHub authentication or the FirePan GitHub App.",
            })
        _check_private_repo_access(project, acting_user)

    db.add(project)
    db.commit()
    db.refresh(project)

    # Lifecycle: stamp first_repo_connected_at + last_activity_at (dashboard path).
    # The GitHub App webhook path in integrations/github_app.py does the same.
    try:
        if tenant is not None:
            if tenant.first_repo_connected_at is None:
                tenant.first_repo_connected_at = now
            tenant.last_activity_at = now
            db.commit()
    except Exception:
        logger.exception("Lifecycle stamp (first_repo_connected_at) failed for tenant=%s", tenant_id)

    # Send Telegram notification for new repo (fire-and-forget)
    try:
        await notify_repo_added(
            repo_name=project.name,
            repo_url=project.git_url or "",
            github_account=tenant.github_account_login if tenant else None,
            tenant_id=tenant_id,
            full_name=project.full_name,
        )
    except Exception:
        pass  # non-critical

    # Auto-trigger initial surface scan (fire-and-forget)
    initial_execution_id = None
    if project.git_url:
        try:
            # firepan-l57m: privacy resolution + the private-repo access gate
            # already ran (and hard-failed with 403) BEFORE persistence above.
            # Reuse the resolved acting user; this block is now genuinely
            # fire-and-forget (tier limits / enqueue only) — the bare except
            # below no longer hides an access failure.
            github_user_id = (
                acting_user.id
                if (acting_user is not None and not project.installation_id)
                else None
            )

            # Tier enforcement: check plan limits before auto-scanning
            from server.tier_enforcement import _check_sync
            auto_scan_uses_credit = False
            try:
                allowance = _check_sync(tenant_id, "scan", db)
                auto_scan_uses_credit = allowance.get("uses_credit", False)
            except HTTPException:
                logger.info(f"Scan limit reached for tenant {tenant_id}, skipping auto-scan for {project.name}")
                raise  # caught by outer except — repo add still succeeds

            from worker.tasks import execute_scan_task
            initial_execution_id = f"scan_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"
            initial_scan = ScanExecution(
                execution_id=initial_execution_id,
                project_id=project.id,
                tenant_id=tenant_id,
                repo_name=project.name,
                repo_url=project.git_url,
                status="pending",
                scan_config={"trigger_source": "repo_added", "scan_type": "surface", "uses_credit": auto_scan_uses_credit},
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(initial_scan)
            db.commit()
            execute_scan_task.delay(
                repo_url=project.git_url,
                scan_id=initial_execution_id,
                tenant_id=tenant_id,
                installation_id=project.installation_id,
                github_user_id=github_user_id,
            )
            logger.info(f"Auto-triggered initial scan {initial_execution_id} for new repo {project.name}")
        except Exception as e:
            logger.warning(f"Failed to auto-trigger initial scan for {project.name}: {e}")

    return RepositoryResponse(
        id=project.id,
        name=project.name,
        full_name=project.full_name,
        git_url=project.git_url,
        github_repo_id=project.github_repo_id,
        description=project.description,
        is_private=project.is_private,
        default_branch=project.default_branch,
        status=project.status,
        last_scan_at=None,
        scans_count=0,
        findings_count=0,
        tenant_id=project.tenant_id,
        created_at=project.created_at,
        updated_at=project.last_accessed,
        initial_scan_id=initial_execution_id,
    )


@app.get("/repositories/{repository_id}", response_model=RepositoryResponse, tags=["repositories"])
async def get_repository(
    repository_id: int,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Get details for a single repository by ID.

    Returns repository info with scan statistics.
    Redacts scan stats for unverified tenants.
    """
    project = (
        db.query(Project)
        .filter(
            Project.id == repository_id,
            Project.tenant_id == tenant_id,
            Project.status != "removed",
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Check email verification for stats redaction
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    verified = tenant.email_verified if tenant else False

    if verified:
        last_scan = db.query(ScanExecution).filter(
            ScanExecution.project_id == project.id
        ).order_by(ScanExecution.created_at.desc()).first()
        last_scan_at = last_scan.created_at if last_scan else None
        scans_count = db.query(func.count(ScanExecution.id)).filter(
            ScanExecution.project_id == project.id
        ).scalar() or 0
        findings_count = _count_findings_for_project(db, project.id)
    else:
        last_scan_at = None
        scans_count = 0
        findings_count = 0

    return RepositoryResponse(
        id=project.id,
        name=project.name,
        full_name=project.full_name,
        git_url=project.git_url,
        github_repo_id=project.github_repo_id,
        description=project.description,
        is_private=project.is_private,
        default_branch=project.default_branch,
        status=project.status,
        last_scan_at=last_scan_at,
        scans_count=scans_count,
        findings_count=findings_count,
        tenant_id=project.tenant_id,
        created_at=project.created_at,
        updated_at=project.last_accessed,
    )


@app.delete("/repositories/{repository_id}", status_code=204, tags=["repositories"])
async def delete_repository(
    repository_id: int,
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """
    Remove a repository from monitoring (soft delete).

    Sets the repository status to 'removed'. Scan history and findings
    are preserved for the audit trail.
    """
    project = (
        db.query(Project)
        .filter(
            Project.id == repository_id,
            Project.tenant_id == tenant_id,
            Project.status != "removed",
        )
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Repository not found")

    project.status = "removed"
    project.last_accessed = datetime.now(timezone.utc)
    db.commit()

    return Response(status_code=204)


# ============================================================================
# Team Endpoints - Team-based access control
# ============================================================================

async def _sync_repo_collaborators(
    db: Session,
    project: "Project",
    actor: "User",
    github_token: str,
) -> dict:
    """Fetch GitHub collaborators for `project` and upsert into its per-repo Team.

    Used by both /repositories/{id}/sync-team (single-repo, admin-triggered)
    and /team/sync-from-github (tenant-wide fan-out).

    Returns {team_id, team_name, github_repo_name, members_count, members[]}
    on success. Raises HTTPException on auth/access errors so the single-repo
    endpoint can surface them; the tenant-wide endpoint catches and records
    them per-repo.

    Flushes but does NOT commit — the caller decides transaction boundaries.
    """
    from server.services.github_service import GitHubService, parse_github_url

    try:
        owner, repo_name = parse_github_url(project.git_url or "")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    github = GitHubService(github_token)
    try:
        user_has_access = await github.check_user_access(owner, repo_name, actor.github_login)
        if not user_has_access:
            raise HTTPException(
                status_code=403,
                detail=f"You don't have access to {owner}/{repo_name}",
            )
        repo_data = await github.get_repo_details(owner, repo_name)
        collaborators = await github.get_repo_collaborators(owner, repo_name)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub API error: {str(e)}")

    # Create or update per-repo Team
    team = db.query(Team).filter_by(github_repo_id=repo_data["id"]).first()
    if not team:
        team = Team(
            name=f"{owner}/{repo_name} Team",
            github_repo_id=repo_data["id"],
            github_repo_name=f"{owner}/{repo_name}",
            last_synced_at=datetime.now(timezone.utc),
        )
        db.add(team)
        db.flush()
    else:
        team.last_synced_at = datetime.now(timezone.utc)

    if project.team_id != team.id:
        project.team_id = team.id

    existing_user_ids = {
        m.user_id for m in db.query(TeamMember).filter_by(team_id=team.id).all()
    }

    synced_members = []
    for collab in collaborators:
        github_login = collab["login"]
        user = db.query(User).filter_by(github_login=github_login).first()
        if not user:
            # Create stub user; they'll hydrate on first login
            user = User(
                github_id=collab["id"],
                github_login=github_login,
                avatar_url=collab.get("avatar_url"),
                tenant_id=actor.tenant_id,
            )
            db.add(user)
            db.flush()

        if user.id not in existing_user_ids:
            role = "admin" if collab.get("permissions", {}).get("admin") else "member"
            db.add(TeamMember(team_id=team.id, user_id=user.id, role=role))

        synced_members.append({
            "github_login": github_login,
            "avatar_url": collab.get("avatar_url"),
            "role": "admin" if collab.get("permissions", {}).get("admin") else "member",
        })

    return {
        "team_id": team.id,
        "team_name": team.name,
        "github_repo_name": team.github_repo_name,
        "members_count": len(synced_members),
        "members": synced_members,
    }


@app.post("/repositories/{repo_id}/sync-team", tags=["teams"])
async def sync_team_from_github(
    repo_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _: None = Depends(reject_preview_writes),
):
    """
    Sync team members from GitHub repository collaborators.

    - Fetches all collaborators from GitHub API
    - Creates or updates per-repo Team record
    - Adds/updates TeamMember records for each collaborator
    - Links repository to team

    Returns team info with member list.
    """
    repo = db.query(Project).filter_by(id=repo_id).first()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    if not current_user.github_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub access token not found. Please re-authenticate.",
        )

    try:
        _gh_token = decrypt_token(current_user.github_token_encrypted)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="GitHub token expired. Please reconnect your GitHub account.",
        )

    result = await _sync_repo_collaborators(db, repo, current_user, _gh_token)
    db.commit()
    return result


@app.get("/teams/{team_id}/members", tags=["teams"])
async def get_team_members(
    team_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all members of a team.
    
    User must be a member of the team to view members.
    """
    team = db.query(Team).filter_by(id=team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    
    # Verify user is a member
    is_member = db.query(TeamMember).filter_by(
        team_id=team_id,
        user_id=current_user.id
    ).first()
    
    if not is_member:
        raise HTTPException(status_code=403, detail="You are not a member of this team")
    
    members = db.query(TeamMember).filter_by(team_id=team_id).all()
    
    return {
        "team": {
            "id": team.id,
            "name": team.name,
            "github_repo_name": team.github_repo_name,
            "last_synced_at": team.last_synced_at.isoformat() if team.last_synced_at else None
        },
        "members": [
            {
                "id": m.id,
                "user_id": m.user_id,
                "github_login": m.user.github_login,
                "github_avatar_url": m.user.avatar_url,
                "email": m.user.email,
                "role": m.role,
                "joined_at": m.joined_at.isoformat()
            }
            for m in members
        ]
    }


# ============================================================================
# Tenant-wide team endpoints (firepan-5o8)
#
# Distinct from the per-repo /teams/{team_id}/members endpoint above.
# The dashboard's Settings > Team page uses these; per-repo team cards still
# use the per-repo endpoint and its response shape.
# ============================================================================


class _TenantTeamMemberDTO(BaseModel):
    id: int
    user_id: int
    display_name: str
    primary_provider: str  # "github" | "google"
    github_login: str | None = None
    github_avatar_url: str | None = None
    google_name: str | None = None
    google_avatar_url: str | None = None
    email: str | None = None
    role: str  # "admin" | "member" | "viewer"
    joined_at: str  # ISO 8601


class _TenantTeamResponse(BaseModel):
    team: dict  # {id, name}
    members: list[_TenantTeamMemberDTO]
    viewer_role: str  # role of the caller; drives UI gating


class _UpdateMemberRoleRequest(BaseModel):
    role: str  # "admin" | "member" | "viewer"


def _member_to_dto(m: TeamMember) -> dict:
    """Serialise a TeamMember row to the tenant-team DTO shape.

    Tolerates Google-only users (no github_login). Picks avatar from the
    user's primary_provider first, then falls back to the other provider.
    """
    u = m.user
    gh_avatar = u.avatar_url  # historically the GitHub avatar
    return {
        "id": m.id,
        "user_id": u.id,
        "display_name": u.display_name,
        "primary_provider": u.primary_provider,
        "github_login": u.github_login,
        "github_avatar_url": gh_avatar if u.has_github else None,
        "google_name": u.google_name,
        "google_avatar_url": u.google_avatar_url,
        "email": u.email or u.google_email,
        "role": m.role,
        "joined_at": m.joined_at.isoformat(),
    }


@app.get("/team", tags=["teams"])
async def get_my_team(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return the caller's tenant-wide team + members + viewer's role."""
    tenant = db.query(Tenant).filter(Tenant.id == current_user.tenant_id).first()
    if not tenant or not tenant.team_id:
        raise HTTPException(status_code=404, detail="Tenant team not found")

    team = db.query(Team).filter(Team.id == tenant.team_id).first()
    members = db.query(TeamMember).filter(TeamMember.team_id == tenant.team_id).all()
    viewer = next((m for m in members if m.user_id == current_user.id), None)
    if not viewer:
        # Caller is in the tenant but not yet a team member. Surface as member
        # with empty perms; admin gating will fail gracefully downstream.
        viewer_role = "member"
    else:
        viewer_role = viewer.role

    return {
        "team": {"id": team.id, "name": team.name},
        "members": [_member_to_dto(m) for m in members],
        "viewer_role": viewer_role,
    }


@app.post("/team/sync-from-github", tags=["teams"])
async def tenant_sync_from_github(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    admin_member: TeamMember = Depends(require_team_admin),
    _: None = Depends(reject_preview_writes),
):
    """Refresh per-repo collaborators across all connected repos, then merge
    unique users into the tenant team as role="member" (never admin).

    Phase 1: for each Project in the tenant, call _sync_repo_collaborators.
    Per-repo errors are captured and continue — one bad repo doesn't abort.

    Phase 2: collect the union of distinct user_ids across all per-repo Teams,
    then for each user: skip if their User.tenant_id differs (report in
    cross_tenant_conflicts), no-op if already a tenant-team member, else
    insert TeamMember with role="member".
    """
    if not current_user.github_token_encrypted:
        raise HTTPException(
            status_code=401,
            detail="GitHub access token not found. Please re-authenticate.",
        )

    try:
        _gh_token = decrypt_token(current_user.github_token_encrypted)
    except ValueError:
        raise HTTPException(
            status_code=401,
            detail="GitHub token expired. Please reconnect your GitHub account.",
        )

    tenant_id = current_user.tenant_id
    projects = (
        db.query(Project)
        .filter(Project.tenant_id == tenant_id)
        .filter(Project.git_url.isnot(None))
        .all()
    )

    # Phase 1: refresh each repo's per-repo team
    repo_syncs = []
    for project in projects:
        try:
            result = await _sync_repo_collaborators(db, project, current_user, _gh_token)
            repo_syncs.append({
                "repo_name": result["github_repo_name"],
                "synced_count": result["members_count"],
                "error": None,
            })
        except HTTPException as e:
            repo_syncs.append({
                "repo_name": project.name or project.git_url or f"project-{project.id}",
                "synced_count": 0,
                "error": f"{e.status_code}: {e.detail}",
            })
        except Exception as e:
            logger.exception("Tenant sync: unexpected error for project=%s", project.id)
            repo_syncs.append({
                "repo_name": project.name or project.git_url or f"project-{project.id}",
                "synced_count": 0,
                "error": f"unexpected: {str(e)[:200]}",
            })

    db.flush()  # Ensure phase 1 writes are visible to phase 2 queries

    # Phase 2: merge unique users into the tenant team
    per_repo_team_ids = [
        p.team_id for p in projects if p.team_id is not None
    ]
    tenant_team_id = admin_member.team_id

    already_members = {
        m.user_id for m in db.query(TeamMember).filter(TeamMember.team_id == tenant_team_id).all()
    }

    candidate_user_ids = set()
    if per_repo_team_ids:
        rows = db.query(TeamMember.user_id).filter(TeamMember.team_id.in_(per_repo_team_ids)).all()
        candidate_user_ids = {r[0] for r in rows}

    added_count = 0
    skipped_already_member = 0
    cross_tenant_conflicts = []

    for uid in candidate_user_ids:
        if uid in already_members:
            skipped_already_member += 1
            continue
        user = db.query(User).filter(User.id == uid).first()
        if not user:
            continue
        if user.tenant_id != tenant_id:
            cross_tenant_conflicts.append({
                "github_login": user.github_login,
                "display_name": user.display_name,
                "current_tenant_id": user.tenant_id,
            })
            continue
        db.add(TeamMember(team_id=tenant_team_id, user_id=uid, role="member"))
        added_count += 1

    db.commit()

    return {
        "repo_syncs": repo_syncs,
        "added_count": added_count,
        "skipped_already_member": skipped_already_member,
        "cross_tenant_conflicts": cross_tenant_conflicts,
    }


_VALID_ROLES = {"admin", "member", "viewer"}


@app.patch("/team/members/{member_id}", tags=["teams"])
async def update_tenant_team_member_role(
    member_id: int,
    body: _UpdateMemberRoleRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    admin_member: TeamMember = Depends(require_team_admin),
    _: None = Depends(reject_preview_writes),
):
    """Change a tenant-team member's role. Admin-only.

    Rejects:
    - 400: invalid role value
    - 404: member_id not in caller's tenant team
    - 409: self-role change (admins can't demote themselves)
    - 409: demoting the last admin
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"role must be one of {_VALID_ROLES}")

    target = (
        db.query(TeamMember)
        .filter(TeamMember.id == member_id, TeamMember.team_id == admin_member.team_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Team member not found")

    if target.user_id == current_user.id:
        raise HTTPException(status_code=409, detail="Cannot change your own role")

    if target.role == "admin" and body.role != "admin":
        admin_count = (
            db.query(TeamMember)
            .filter(TeamMember.team_id == admin_member.team_id, TeamMember.role == "admin")
            .count()
        )
        if admin_count <= 1:
            raise HTTPException(status_code=409, detail="Cannot demote the last admin")

    target.role = body.role
    db.commit()
    db.refresh(target)
    return _member_to_dto(target)


@app.delete("/team/members/{member_id}", tags=["teams"])
async def remove_tenant_team_member(
    member_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    admin_member: TeamMember = Depends(require_team_admin),
    _: None = Depends(reject_preview_writes),
):
    """Remove a member from the tenant team. Admin-only.

    Only deletes the TeamMember row. User.tenant_id is untouched (the user
    stays in the tenant, they just no longer appear on the team page).

    Rejects:
    - 404: member_id not in caller's tenant team
    - 409: self-removal
    - 409: removing the last admin
    """
    target = (
        db.query(TeamMember)
        .filter(TeamMember.id == member_id, TeamMember.team_id == admin_member.team_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Team member not found")

    if target.user_id == current_user.id:
        raise HTTPException(status_code=409, detail="Cannot remove yourself")

    if target.role == "admin":
        admin_count = (
            db.query(TeamMember)
            .filter(TeamMember.team_id == admin_member.team_id, TeamMember.role == "admin")
            .count()
        )
        if admin_count <= 1:
            raise HTTPException(status_code=409, detail="Cannot remove the last admin")

    db.delete(target)
    db.commit()
    return Response(status_code=204)


@app.get("/github/status", response_model=GitHubStatusResponse, tags=["github"])
async def github_status(
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Check if the user's GitHub connection is still valid.

    Makes a test call to the GitHub API to verify the stored token.
    Used on the profile/settings page.
    """
    from server.auth_routes import get_token_from_header
    from server.auth_utils import get_current_user_from_token

    try:
        token = get_token_from_header(request)
        payload = get_current_user_from_token(token)
    except (HTTPException, ValueError):
        return GitHubStatusResponse(connected=False)

    user = db.query(User).filter(User.id == payload.get("user_id")).first()
    if not user or not user.github_token_encrypted:
        return GitHubStatusResponse(connected=False)

    try:
        github_token = decrypt_token(user.github_token_encrypted)
    except ValueError:
        return GitHubStatusResponse(connected=False)

    # Validate token against GitHub API
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )

    if resp.status_code != 200:
        # Token is revoked or invalid — clear it from the database
        user.github_token_encrypted = None
        user.github_connected_at = None
        user.github_token_scopes = None
        db.commit()
        return GitHubStatusResponse(connected=False)

    github_user = resp.json()
    scopes = [s.strip() for s in resp.headers.get("X-OAuth-Scopes", "").split(",") if s.strip()]

    # Opportunistic backfill: populate stored scopes from live header
    if scopes and not user.github_token_scopes:
        user.github_token_scopes = ",".join(scopes)
        db.commit()

    connected_at = (
        user.github_connected_at.isoformat() + "Z"
        if user.github_connected_at
        else None
    )

    return GitHubStatusResponse(
        connected=True,
        username=github_user.get("login"),
        avatar_url=github_user.get("avatar_url"),
        scopes=scopes,
        connected_at=connected_at,
        has_repo_scope="repo" in scopes,
    )


class TriggerScanRequest(BaseModel):
    """Request body for POST /repositories/{id}/scan."""
    branch: str | None = Field(
        default=None,
        description="Git ref (branch/tag/SHA) to scan; defaults to project default_branch",
        max_length=255,
    )

    model_config = ConfigDict(extra="ignore")


def _validate_ref(value: str | None) -> str | None:
    """Sanitize a user-supplied git ref. Returns trimmed value or None."""
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    # Argv-passed (no shell), but reject control chars + obvious shell metas
    # as defence in depth — also rejects refs git itself would refuse.
    forbidden = set("\x00\n\r\t ;|&`$<>\"'\\")
    if any(ch in forbidden for ch in cleaned):
        raise HTTPException(status_code=400, detail="Invalid branch name")
    return cleaned


# firepan-nxf: syntactic + on-disk validation for file-scoped deep audits.
# Two helpers because the checks have different failure modes: bad syntax is
# always rejected at the API boundary; on-disk existence is best-effort at
# the API (clone may not be present on the API host) and authoritative at
# the worker (where the clone definitely exists).

_TARGET_FILES_MAX = 50
# Shell/control chars that must never reach RepositoryManifest / git invocations.
# Intentionally stricter than _validate_ref — these are file paths, not refs,
# so glob characters also get rejected to keep the whitelist unambiguous.
_TARGET_FILE_FORBIDDEN = set("\x00\n\r\t;|&`$<>\"'\\*?[]")


def _validate_target_files(value: list[str] | None) -> list[str] | None:
    """Sanitize a user-supplied file whitelist for a scoped deep audit.

    Returns a cleaned list of repo-relative paths, or None when the input is
    effectively empty (None, [], or all-blank). Pure syntactic check — does
    NOT touch the filesystem. Callers may additionally run
    _check_target_files_exist_on_disk() when a clone is available.
    """
    if value is None:
        return None
    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail="target_files must be a list of strings")
    if len(value) > _TARGET_FILES_MAX:
        raise HTTPException(
            status_code=422,
            detail=f"target_files exceeds max of {_TARGET_FILES_MAX} entries",
        )
    cleaned: list[str] = []
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, str):
            raise HTTPException(status_code=422, detail="target_files entries must be strings")
        trimmed = entry.strip()
        if not trimmed:
            continue
        if trimmed.startswith("/"):
            raise HTTPException(
                status_code=422,
                detail=f"target_files entry must be repo-relative (no leading slash): {entry!r}",
            )
        # Reject traversal anywhere in the path — leading, middle, or bare ".."
        parts = trimmed.replace("\\", "/").split("/")
        if any(p == ".." for p in parts):
            raise HTTPException(
                status_code=422,
                detail=f"target_files entry contains path traversal: {entry!r}",
            )
        if any(ch in _TARGET_FILE_FORBIDDEN for ch in trimmed):
            raise HTTPException(
                status_code=422,
                detail=f"target_files entry contains forbidden character: {entry!r}",
            )
        if trimmed in seen:
            continue
        seen.add(trimmed)
        cleaned.append(trimmed)
    return cleaned or None


def _check_target_files_exist_on_disk(
    source_path: str | None,
    target_files: list[str] | None,
) -> tuple[list[str], list[str]]:
    """Best-effort existence check against a cached clone.

    Returns (resolved, missing). When source_path is missing/empty or the
    directory does not exist on this host (typical in containerized prod
    where only the worker has the clone), returns ([], []) so the caller
    knows to defer to worker-time validation.
    """
    if not target_files:
        return ([], [])
    if not source_path:
        return ([], [])
    from pathlib import Path
    root = Path(source_path)
    if not root.is_dir():
        return ([], [])
    resolved: list[str] = []
    missing: list[str] = []
    for rel in target_files:
        full = root / rel
        try:
            # Resolve symlinks but keep the comparison under `root` — defence
            # against a symlinked `contracts/x.vy → /etc/passwd` in a repo.
            full_resolved = full.resolve()
            full_resolved.relative_to(root.resolve())
        except (ValueError, OSError):
            missing.append(rel)
            continue
        if full_resolved.is_file():
            resolved.append(rel)
        else:
            missing.append(rel)
    return (resolved, missing)


@app.post("/repositories/{repository_id}/scan")
async def trigger_repository_scan(
    repository_id: int,
    request: Request,
    body: TriggerScanRequest | None = Body(default=None),
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
    current_user: User = Depends(require_github_linked),
    ___: None = Depends(require_verified_email),
):
    """
    Trigger a new scan for a repository.

    Creates a surface scan execution for the specified repository.
    Checks plan limits before allowing the scan.
    Returns the execution ID for tracking.
    """
    # 1. Ownership check FIRST — before any credit consumption
    project = db.query(Project).filter(
        Project.id == repository_id,
        Project.tenant_id == tenant_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Repository not found")

    # 2. Private repo access check — before tier enforcement so no credits consumed
    _check_private_repo_access(project, current_user)

    # 3. Tier enforcement — only after we know the repo is theirs and accessible
    from server.tier_enforcement import require_plan_allowance
    tier_check = require_plan_allowance("scan")
    allowance = await tier_check(request)

    # Resolve branch: explicit user pick > project default_branch > "main"
    requested_branch = _validate_ref(body.branch if body else None)
    resolved_branch = requested_branch or project.default_branch or "main"

    # Generate scan execution ID
    execution_id = f"scan_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    # Create scan execution
    scan = ScanExecution(
        execution_id=execution_id,
        project_id=project.id,
        tenant_id=project.tenant_id,
        repo_name=project.name,
        repo_url=project.git_url,
        status="pending",
        scan_config={"scan_type": "surface", "branch": resolved_branch},
        created_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Dispatch to Celery worker (async — returns immediately)
    try:
        from worker.tasks import execute_scan_task
        execute_scan_task.delay(
            repo_url=project.git_url,
            scan_id=execution_id,
            tenant_id=project.tenant_id,
            installation_id=project.installation_id,
            github_user_id=current_user.id,
            branch=resolved_branch,
        )
    except Exception as e:
        # Mark scan as failed — don't leave it stuck "pending"
        scan.status = "failed"
        scan.error_message = f"Failed to dispatch scan: {e}"
        db.commit()

        # Refund credit if one was consumed by tier enforcement
        if allowance.get("uses_credit"):
            try:
                from server.tier_enforcement import refund_scan_credit
                refund_scan_credit(db, project.tenant_id, execution_id)
            except Exception as refund_err:
                logger.error("Failed to refund scan credit: %s", refund_err)

        logger.error("Failed to dispatch scan task: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {e}. Is Celery configured?"
        )

    return {
        "execution_id": execution_id,
        "repository_id": repository_id,
        "status": "pending",
        "message": "Scan queued successfully",
        "uses_credit": allowance.get("uses_credit", False),
    }


@app.get("/repositories/{repository_id}/scans", response_model=ScanHistoryResponse)
async def list_repository_scans(
    repository_id: int,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """
    List scan history for a repository.

    Returns paginated list of all scan executions for the specified repository.
    """
    # Verify repository exists and belongs to tenant
    project = db.query(Project).filter(
        Project.id == repository_id,
        Project.tenant_id == tenant_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Repository not found")
    
    # Query scans for this repository
    query = db.query(ScanExecution).filter(ScanExecution.project_id == repository_id)
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    scans = query.order_by(ScanExecution.created_at.desc()).offset(offset).limit(page_size).all()
    
    # Build response
    scan_items = []
    for scan in scans:
        findings_count = len(scan.findings) if scan.findings else 0
        # Extract curated fields from deep_audit_overview if present
        overview = scan.deep_audit_overview if hasattr(scan, 'deep_audit_overview') else None
        assessment_level = None
        credible_findings_count = None
        admin_verified = False
        needs_manual_review = False
        review_reason = None
        if isinstance(overview, dict):
            assessment_level = overview.get("assessment_level")
            credible_findings_count = overview.get("credible_findings_count")
            admin_verified = bool(overview.get("admin_verified", False))
            needs_manual_review = bool(overview.get("needs_manual_review", False))
            review_reason = overview.get("review_reason")
        cfg = scan.scan_config or {}
        scan_branch = cfg.get("branch") or project.default_branch
        # firepan-nxf: surface scope. Defensive coercion — scan_config is JSONB,
        # malformed values (dicts, strings) should not break history rendering.
        raw_target_files = cfg.get("target_files") if isinstance(cfg, dict) else None
        scoped_target_files: list[str] | None = None
        if isinstance(raw_target_files, list) and all(isinstance(t, str) for t in raw_target_files):
            scoped_target_files = raw_target_files or None
        scan_items.append(ScanHistoryItem(
            execution_id=scan.execution_id,
            status=scan.status,
            risk_score=scan.risk_score,
            risk_level=scan.risk_level,
            findings_count=findings_count,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            scan_type=cfg.get("scan_type", "surface"),
            error_message=scan.error_message,
            branch=scan_branch,
            assessment_level=assessment_level,
            credible_findings_count=credible_findings_count,
            admin_verified=admin_verified,
            needs_manual_review=needs_manual_review,
            review_reason=review_reason,
            target_files=scoped_target_files,
        ))
    
    return ScanHistoryResponse(
        repository_id=repository_id,
        scans=scan_items,
        total=total,
        page=page,
        page_size=page_size,
    )


# ---------------------------------------------------------------------------
# Branch listing for the per-scan branch picker (firepan-6dx)
# ---------------------------------------------------------------------------

class BranchInfo(BaseModel):
    name: str
    is_default: bool = False
    protected: bool = False
    commit_sha: str | None = None

    model_config = ConfigDict(extra="ignore")


class BranchesResponse(BaseModel):
    repository_id: int
    default_branch: str | None
    branches: list[BranchInfo]
    truncated: bool = False


@app.get("/repositories/{repository_id}/branches", response_model=BranchesResponse)
async def list_repository_branches(
    repository_id: int,
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """List GitHub branches for a repository so the dashboard can offer a picker.

    Token resolution priority (most reliable first):
    1. Project's GitHub App installation token (works for private + public).
    2. Caller's user OAuth token (works for any repo they can see).
    3. Unauthenticated GitHub API (public repos only, 60/hr per IP).
    """
    from urllib.parse import urlparse

    project = db.query(Project).filter(
        Project.id == repository_id,
        Project.tenant_id == tenant_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Repository not found")

    parsed = urlparse(project.git_url or "")
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2 or "github.com" not in (parsed.netloc or ""):
        raise HTTPException(status_code=400, detail="Repository is not a GitHub repo")
    owner, repo = parts[0], parts[1].removesuffix(".git")

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if project.installation_id:
        try:
            from integrations.github_auth import get_installation_token
            headers["Authorization"] = f"Bearer {get_installation_token(project.installation_id)}"
        except Exception as exc:
            logger.warning(
                "branches: installation token failed for project %s: %s",
                repository_id,
                exc,
            )
    if "Authorization" not in headers:
        try:
            user = await _get_current_user_with_token(request, db)
            headers["Authorization"] = f"Bearer {decrypt_token(user.github_token_encrypted)}"
        except Exception:
            pass  # public-repo fallback; GitHub will 404 private repos

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/branches",
            params={"per_page": 100},
            headers=headers,
        )
        if resp.status_code == 404:
            raise HTTPException(status_code=404, detail="Repository not accessible")
        if resp.status_code in (401, 403):
            raise HTTPException(status_code=403, detail="GitHub API rejected request")
        resp.raise_for_status()
        raw = resp.json() or []

    out: list[BranchInfo] = [
        BranchInfo(
            name=b.get("name", ""),
            is_default=(b.get("name") == project.default_branch),
            protected=bool(b.get("protected", False)),
            commit_sha=(b.get("commit") or {}).get("sha"),
        )
        for b in raw
        if b.get("name")
    ]
    out.sort(key=lambda b: (not b.is_default, b.name.lower()))

    return BranchesResponse(
        repository_id=repository_id,
        default_branch=project.default_branch,
        branches=out,
        truncated=len(raw) >= 100,
    )


@app.get("/findings", response_model=FindingListResponse)
async def list_all_findings(
    tenant_id: int = Depends(get_current_tenant_id),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(None, description="Filter by severity (critical, high, medium, low)"),
    status: str | None = Query(None, description="Filter by status"),
    repository_id: int | None = Query(None, description="Filter by repository ID"),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """
    List all findings for a tenant: deep-audit hypotheses + surface scan findings.

    Surface scan findings are a current-state view (latest completed scan per
    project only).  Deep-audit hypotheses include all linked findings.
    Supports filtering by severity, status, and repository.
    Returns paginated list with full finding details.
    """
    # Query all hypothesis findings for tenant (pagination applied after
    # combining with surface scan findings below).
    query = db.query(Hypothesis).join(
        Project, Hypothesis.project_id == Project.id
    ).filter(Project.tenant_id == tenant_id)

    # Apply filters
    if severity:
        query = query.filter(Hypothesis.severity == severity)
    if status:
        query = query.filter(Hypothesis.status == status)
    if repository_id:
        query = query.filter(Hypothesis.project_id == repository_id)

    findings = query.order_by(Hypothesis.created_at.desc()).all()

    # Build hypothesis findings.  Source classification is centralised in
    # _hypothesis_source() so that this endpoint and the triage endpoint
    # always return the same tag for the same row.  See firepan-dar.
    hypothesis_findings = []
    for h in findings:
        hypothesis_findings.append(FindingResponse(
            id=h.id,
            hypothesis_id=h.hypothesis_id,
            title=h.title,
            description=h.description,
            vulnerability_type=h.vulnerability_type,
            status=h.status,
            confidence=h.confidence,
            severity=h.severity,
            node_refs=h.node_refs,
            evidence=h.evidence,
            reported_by_model=h.reported_by_model,
            junior_model=h.junior_model,
            senior_model=h.senior_model,
            project_id=h.project_id,
            user_notes=h.user_notes,
            source=_hypothesis_source(h),
            created_at=h.created_at,
            updated_at=h.updated_at,
        ))

    # Include scan findings (latest completed scan per type per project).
    # Surface and deep scans are independent analyses — both contribute.
    # This is a current-state view: the most recent completed scan of each
    # type per project is included.  Historical scan data is available via
    # /repositories/{id}/scans.
    tenant_projects = db.query(Project.id, Project.name).filter(
        Project.tenant_id == tenant_id,
        Project.status != "removed",
    ).all()

    surface_findings: list[FindingResponse] = []
    for proj_id, proj_name in tenant_projects:
        # Apply repository_id filter early if set
        if repository_id and proj_id != repository_id:
            continue

        # Deep findings come from Hypothesis table (above). Only surface from JSONB.
        scans_to_include = []
        scan = _latest_scan_by_type(db, proj_id, "surface")
        if scan and scan.findings:
            scans_to_include.append(scan)

        for latest_scan in scans_to_include:
            scan_ts = latest_scan.completed_at or latest_scan.created_at
            for sf in latest_scan.findings:
                if not isinstance(sf, dict):
                    continue
                sf_severity = sf.get("severity", "medium")
                sf_status = "scanner_detected"
                # Apply severity/status filters
                if severity and sf_severity != severity:
                    continue
                if status and sf_status != status:
                    continue
                surface_findings.append(FindingResponse(
                    id=None,
                    hypothesis_id=None,
                    pattern_id=sf.get("pattern_id"),
                    title=sf.get("title", "Untitled"),
                    description=sf.get("description", ""),
                    vulnerability_type=sf.get("category"),
                    status=sf_status,
                    confidence=sf.get("confidence", 0.5),
                    severity=sf_severity,
                    node_refs=None,
                    evidence={"scan_execution_id": latest_scan.execution_id},
                    location=sf.get("location"),
                    code_snippet=sf.get("code_snippet"),
                    project_id=proj_id,
                    source="surface",
                    created_at=scan_ts,
                    updated_at=scan_ts,
                ))

    # Combine, sort by created_at descending, then paginate in-memory.
    # Acceptable at current scale (tens to low hundreds per tenant).
    # TODO: optimise with SQL UNION when finding volume grows.
    combined = hypothesis_findings + surface_findings
    combined.sort(key=lambda f: f.created_at, reverse=True)
    total = len(combined)
    offset = (page - 1) * page_size
    page_items = combined[offset : offset + page_size]

    return FindingListResponse(
        findings=page_items,
        total=total,
        page=page,
        page_size=page_size,
    )


@app.get("/findings/stats", response_model=FindingStatsResponse)
async def get_findings_statistics(
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """
    Get summary statistics for findings.
    
    Returns aggregate counts by severity, status, and repository.
    """
    from sqlalchemy.orm import joinedload
    
    # Get all findings for tenant with project data eagerly loaded
    findings = db.query(Hypothesis).join(
        Project, Hypothesis.project_id == Project.id
    ).options(joinedload(Hypothesis.project)).filter(
        Project.tenant_id == tenant_id
    ).all()
    
    # Calculate statistics
    total = len(findings)
    
    by_severity = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    
    by_status = {
        "proposed": 0,
        "investigating": 0,
        "confirmed": 0,
        "rejected": 0,
        "resolved": 0,
        "scanner_detected": 0,
    }
    
    by_repository = {}
    
    for finding in findings:
        # Count by severity
        if finding.severity in by_severity:
            by_severity[finding.severity] += 1
        
        # Count by status
        if finding.status in by_status:
            by_status[finding.status] += 1
        
        # Count by repository (project is now eagerly loaded)
        if finding.project:
            repo_name = finding.project.name
            by_repository[repo_name] = by_repository.get(repo_name, 0) + 1

    # Also include scan findings (latest scan per type per project)
    tenant_projects = db.query(Project.id, Project.name).filter(
        Project.tenant_id == tenant_id,
        Project.status != "removed",
    ).all()

    for proj_id, proj_name in tenant_projects:
        # Deep findings come from Hypothesis table (above). Only surface from JSONB.
        latest_scan = _latest_scan_by_type(db, proj_id, "surface")
        if not latest_scan or not latest_scan.findings:
            continue

        for finding in latest_scan.findings:
            total += 1
            sev = finding.get("severity", "low") if isinstance(finding, dict) else "low"
            if sev in by_severity:
                by_severity[sev] += 1
            by_status["scanner_detected"] += 1
            by_repository[proj_name] = by_repository.get(proj_name, 0) + 1

    return FindingStatsResponse(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        by_repository=by_repository,
    )


# ============================================================================
# QA Finalization Endpoint - LLM-based hypothesis review
# ============================================================================

class QAFinalizeRequest(BaseModel):
    """Request model for QA finalization."""
    threshold: float = Field(default=0.5, description="Confidence threshold (0.0-1.0)")
    include_below_threshold: bool = Field(default=False, description="Include pending hypotheses below threshold")
    max_hypotheses: int = Field(default=10, description="Maximum hypotheses to review in one call")


class QAReviewResult(BaseModel):
    """Result of reviewing a single hypothesis."""
    hypothesis_id: str
    title: str
    original_confidence: float
    verdict: str  # confirmed, rejected, uncertain
    reasoning: str
    new_confidence: float


class QAFinalizeResponse(BaseModel):
    """Response from QA finalization."""
    session_id: str
    total_reviewed: int
    confirmed: int
    rejected: int
    uncertain: int
    results: list[QAReviewResult]


@app.post("/sessions/{session_id}/finalize", response_model=QAFinalizeResponse)
async def finalize_session_hypotheses(
    session_id: str,
    request: QAFinalizeRequest,
    background_tasks: BackgroundTasks,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """
    Run QA finalization on hypotheses from a session.

    Uses an LLM to review hypotheses above the confidence threshold
    and confirm/reject them based on source code analysis.
    """
    # Get the session
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get the project — verify tenant ownership
    project = db.query(Project).filter(
        Project.id == session.project_id,
        Project.tenant_id == tenant_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get hypotheses for this project
    query = db.query(Hypothesis).filter(
        Hypothesis.project_id == session.project_id,
        Hypothesis.status.notin_(["confirmed", "rejected"])  # Only pending
    )
    
    if not request.include_below_threshold:
        query = query.filter(Hypothesis.confidence >= request.threshold)
    
    hypotheses = query.order_by(Hypothesis.confidence.desc()).limit(request.max_hypotheses).all()
    
    if not hypotheses:
        return QAFinalizeResponse(
            session_id=session_id,
            total_reviewed=0,
            confirmed=0,
            rejected=0,
            uncertain=0,
            results=[]
        )
    
    # Load config for LLM
    config_path = Path(__file__).parent.parent / "config.yaml"
    config = {}
    if config_path.exists():
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    
    # Initialize LLM for finalization - handle missing API keys
    try:
        from llm.unified_client import UnifiedLLMClient
        llm = UnifiedLLMClient(cfg=config, profile="finalize")
    except ValueError as e:
        if "API key not found" in str(e):
            raise HTTPException(
                status_code=503,
                detail=f"LLM not configured: {str(e)}. Set the required API key environment variable."
            )
        raise
    
    # Get repo path for source code access - check multiple sources
    repo_root = None
    
    # Try 1: project.source_path
    if project.source_path:
        candidate = Path(project.source_path)
        if candidate.exists():
            repo_root = candidate
    
    # Try 2: Look for cloned repo in /tmp based on git_url
    if not repo_root and project.git_url:
        # Extract repo name from URL
        repo_name = project.git_url.rstrip('/').split('/')[-1].replace('.git', '')
        for tmp_dir in [Path('/tmp'), Path('/workspaces')]:
            candidate = tmp_dir / repo_name
            if candidate.exists() and (candidate / '.git').exists():
                repo_root = candidate
                break
            # Also check with owner prefix
            if '/' in project.git_url:
                parts = project.git_url.rstrip('/').split('/')
                if len(parts) >= 2:
                    owner_repo = f"{parts[-2]}_{parts[-1].replace('.git', '')}"
                    candidate = tmp_dir / owner_repo
                    if candidate.exists():
                        repo_root = candidate
                        break
    
    # Try 3: Check audit session for repo path in metadata
    if not repo_root:
        # The audit task clones to /tmp/{repo_name}
        if project.git_url:
            repo_name = project.git_url.rstrip('/').split('/')[-1].replace('.git', '')
            candidate = Path(f'/tmp/{repo_name}')
            if candidate.exists():
                repo_root = candidate
    
    # Try 4: Clone the repo if we have a git_url but no local copy
    temp_clone_dir = None
    if not repo_root and project.git_url:
        import subprocess
        import tempfile
        try:
            temp_clone_dir = tempfile.mkdtemp(prefix="hound_qa_")
            repo_path = Path(temp_clone_dir) / "repo"
            result = subprocess.run(
                ["git", "clone", "--depth", "1", project.git_url, str(repo_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0 and repo_path.exists():
                repo_root = repo_path
        except Exception:
            pass  # Continue without source code if clone fails
    
    # Review each hypothesis
    results = []
    confirmed_count = 0
    rejected_count = 0
    uncertain_count = 0
    
    for hypothesis in hypotheses:
        try:
            # Load source code - use guess_relpaths like CLI does
            source_code = {}
            source_files = []
            
            # Get source files from node_refs
            if hypothesis.node_refs:
                for node_ref in hypothesis.node_refs:
                    if isinstance(node_ref, str):
                        source_files.append(node_ref)
            
            # Use guess_relpaths to find file paths from hypothesis text
            if repo_root:
                try:
                    from analysis.path_utils import guess_relpaths
                    extra_texts = [
                        hypothesis.title or '',
                        hypothesis.description or '',
                    ]
                    # Add evidence items
                    evidence = hypothesis.evidence or {}
                    for item in evidence.get('items', []):
                        if isinstance(item, str):
                            extra_texts.append(item)
                        elif isinstance(item, dict):
                            extra_texts.append(item.get('description', ''))
                    
                    guessed = guess_relpaths(
                        "\n".join([t for t in extra_texts if t]), 
                        repo_root
                    )
                    for rel in guessed:
                        if rel not in source_files:
                            source_files.append(rel)
                except Exception:
                    pass
            
            # Load actual source code files
            if source_files and repo_root:
                for file_path in source_files[:10]:  # Limit to 10 files
                    try:
                        full_path = repo_root / file_path
                        if full_path.exists() and full_path.is_file():
                            with open(full_path) as f:
                                content = f.read()
                                # Limit file size to avoid huge prompts
                                if len(content) < 50000:
                                    source_code[file_path] = content
                    except Exception:
                        pass
            
            # Build review prompt
            review_prompt = f"""You are a security expert performing final review of a vulnerability hypothesis.

=== HYPOTHESIS UNDER REVIEW ===
Title: {hypothesis.title}
Type: {hypothesis.vulnerability_type}
Severity: {hypothesis.severity}
Confidence: {hypothesis.confidence:.0%}
Description: {hypothesis.description}

=== SOURCE CODE ===
"""
            if source_code:
                for file_path, code in source_code.items():
                    review_prompt += f"\n--- File: {file_path} ---\n{code}\n"
            else:
                # Include evidence if no source code
                evidence = hypothesis.evidence or {}
                if evidence.get("items"):
                    review_prompt += "\n--- Evidence ---\n"
                    for item in evidence["items"][:5]:
                        review_prompt += f"• {item}\n"
                else:
                    review_prompt += "No source code or evidence available.\n"
            
            review_prompt += """
=== YOUR TASK ===
Review the available information to determine if this hypothesis represents a REAL vulnerability.

Provide your determination in this EXACT JSON format:
{
    "verdict": "confirmed" or "rejected" or "uncertain",
    "reasoning": "A detailed one-paragraph explanation (50-150 words) explaining your verdict.",
    "confidence": 0.0 to 1.0
}

Rules:
- "confirmed" = Vulnerability clearly exists with exploitable path
- "rejected" = This is a false positive or mitigated
- "uncertain" = Need more context to determine

Be conservative - only confirm if evidence clearly shows the vulnerability.
"""
            
            # Get LLM verdict
            try:
                response_text = llm.raw(
                    system="You are a security expert. Respond only with valid JSON.",
                    user=review_prompt
                )
                from utils.json_utils import extract_json_object
                response = extract_json_object(response_text)
                
                if isinstance(response, dict):
                    verdict = response.get('verdict', 'uncertain')
                    reasoning = response.get('reasoning', 'No reasoning provided')
                    new_confidence = float(response.get('confidence', hypothesis.confidence))
                else:
                    verdict = 'uncertain'
                    reasoning = 'Failed to parse LLM response'
                    new_confidence = hypothesis.confidence
            except Exception as e:
                verdict = 'uncertain'
                reasoning = f'LLM error: {str(e)}'
                new_confidence = hypothesis.confidence
            
            # Update hypothesis in database
            original_confidence = hypothesis.confidence
            
            if verdict == "confirmed":
                hypothesis.status = "confirmed"
                hypothesis.confidence = 1.0
                confirmed_count += 1
            elif verdict == "rejected":
                hypothesis.status = "rejected"
                hypothesis.confidence = 0.0
                rejected_count += 1
            else:
                uncertain_count += 1
                # Update confidence if LLM provided one
                if new_confidence != hypothesis.confidence:
                    hypothesis.confidence = new_confidence
            
            # Store reasoning in evidence
            if hypothesis.evidence is None:
                hypothesis.evidence = {}
            # Create a new dict to ensure SQLAlchemy detects the change
            new_evidence = dict(hypothesis.evidence)
            new_evidence["qa_reasoning"] = reasoning
            new_evidence["qa_verdict"] = verdict
            hypothesis.evidence = new_evidence
            hypothesis.updated_at = datetime.now(timezone.utc)
            
            # Mark the JSON field as modified for SQLAlchemy
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(hypothesis, "evidence")
            
            results.append(QAReviewResult(
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                original_confidence=original_confidence,
                verdict=verdict,
                reasoning=reasoning,
                new_confidence=hypothesis.confidence
            ))
            
        except Exception as e:
            uncertain_count += 1
            results.append(QAReviewResult(
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                original_confidence=hypothesis.confidence,
                verdict="uncertain",
                reasoning=f"Error during review: {str(e)}",
                new_confidence=hypothesis.confidence
            ))
    
    # Commit all changes
    db.commit()
    
    # Cleanup temp clone directory if we created one
    if temp_clone_dir:
        import shutil
        try:
            shutil.rmtree(temp_clone_dir, ignore_errors=True)
        except Exception:
            pass
    
    return QAFinalizeResponse(
        session_id=session_id,
        total_reviewed=len(hypotheses),
        confirmed=confirmed_count,
        rejected=rejected_count,
        uncertain=uncertain_count,
        results=results
    )


# ============================================================================
# PoC Generation Endpoint - Generate proof-of-concept prompts
# ============================================================================

class PoCGenerateRequest(BaseModel):
    """Request model for PoC prompt generation."""
    hypothesis_id: str | None = Field(None, description="Specific hypothesis ID to generate PoC for")
    max_hypotheses: int = Field(default=10, description="Maximum hypotheses to process")
    min_confidence: float = Field(default=0.7, description="Minimum confidence threshold")


class PoCPromptResult(BaseModel):
    """Result of generating a PoC prompt for a hypothesis."""
    hypothesis_id: str
    title: str
    vulnerability_type: str
    severity: str
    affected_files: list[str]
    prompt: str
    output_path: str


class PoCGenerateResponse(BaseModel):
    """Response from PoC generation."""
    session_id: str
    project_name: str
    total_generated: int
    results: list[PoCPromptResult]


@app.post("/sessions/{session_id}/poc", response_model=PoCGenerateResponse)
async def generate_poc_prompts(
    session_id: str,
    request: PoCGenerateRequest,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """
    Generate proof-of-concept prompts for hypotheses from a session.

    Uses an LLM strategist to generate detailed PoC prompts that can be
    given to a coding agent to create actual exploit code.
    """
    # Get the session
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get the project — verify tenant ownership
    project = db.query(Project).filter(
        Project.id == session.project_id,
        Project.tenant_id == tenant_id,
    ).first()
    if not project:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Get hypotheses for this project
    query = db.query(Hypothesis).filter(
        Hypothesis.project_id == session.project_id,
    )
    
    # Filter by specific hypothesis or by confidence/status
    if request.hypothesis_id:
        query = query.filter(Hypothesis.hypothesis_id == request.hypothesis_id)
    else:
        query = query.filter(
            (Hypothesis.status == "confirmed") | 
            (Hypothesis.confidence >= request.min_confidence)
        )
    
    hypotheses = query.order_by(Hypothesis.confidence.desc()).limit(request.max_hypotheses).all()
    
    if not hypotheses:
        return PoCGenerateResponse(
            session_id=session_id,
            project_name=project.name,
            total_generated=0,
            results=[]
        )
    
    # Load config for LLM
    config_path = Path(__file__).parent.parent / "config.yaml"
    config = {}
    if config_path.exists():
        import yaml
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    
    # Initialize LLM for strategist - handle missing API keys
    try:
        from llm.unified_client import UnifiedLLMClient
        UnifiedLLMClient(cfg=config, profile="strategist")
    except ValueError as e:
        if "API key not found" in str(e):
            raise HTTPException(
                status_code=503,
                detail=f"LLM not configured: {str(e)}. Set the required API key environment variable."
            )
        raise
    
    # Get repo path for source code access
    repo_root = None
    temp_clone_dir = None
    
    # Try to find or clone the repo
    if project.source_path:
        candidate = Path(project.source_path)
        if candidate.exists():
            repo_root = candidate
    
    if not repo_root and project.git_url:
        # Extract repo name from URL
        repo_name = project.git_url.rstrip('/').split('/')[-1].replace('.git', '')
        
        # Check common locations
        for base in [Path('/tmp'), Path('/workspaces')]:
            candidate = base / repo_name
            if candidate.exists():
                repo_root = candidate
                break
        
        # Clone if not found
        if not repo_root:
            import subprocess
            import tempfile
            try:
                temp_clone_dir = tempfile.mkdtemp(prefix="hound_poc_")
                repo_path = Path(temp_clone_dir) / "repo"
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", project.git_url, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0 and repo_path.exists():
                    repo_root = repo_path
            except Exception:
                pass
    
    # Import PoC generation utilities
    from commands.poc import PoCContext, generate_poc_with_strategist, load_affected_files
    
    # Create output directory
    output_dir = Path.home() / f".hound/poc_prompts/{project.name}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate prompts for each hypothesis
    results = []
    
    for hypothesis in hypotheses:
        try:
            # Convert DB hypothesis to dict format expected by load_affected_files
            hyp_dict = {
                'title': hypothesis.title,
                'description': hypothesis.description,
                'vulnerability_type': hypothesis.vulnerability_type,
                'severity': hypothesis.severity,
                'confidence': hypothesis.confidence,
                'node_refs': hypothesis.node_refs or [],
                'evidence': hypothesis.evidence or {},
                'annotations': [],
                'locations': [],
                'reasoning': hypothesis.description,  # Use description as reasoning
            }
            
            # Convert node_refs to annotations format
            if hypothesis.node_refs:
                for ref in hypothesis.node_refs:
                    if isinstance(ref, str) and ':' in ref:
                        parts = ref.split(':')
                        file_path = parts[0]
                        line = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                        hyp_dict['annotations'].append({'file_path': file_path, 'line': line})
                    elif isinstance(ref, str):
                        hyp_dict['annotations'].append({'file_path': ref})
            
            # Load affected files
            affected_files = load_affected_files(hyp_dict, {}, repo_root)
            
            # Create context
            context = PoCContext(
                project_name=project.name,
                hypothesis=hyp_dict,
                affected_files=affected_files,
                manifest_data={},
                repo_root=repo_root
            )
            
            # Generate prompt using strategist
            prompt = generate_poc_with_strategist(context, config)
            
            # Save prompt to file
            output_file = output_dir / f"{hypothesis.hypothesis_id}_poc_prompt.md"
            with open(output_file, 'w') as f:
                f.write(f"# PoC Generation Prompt for {hypothesis.hypothesis_id}\n\n")
                f.write(f"**Project:** {project.name}\n")
                f.write(f"**Vulnerability:** {hypothesis.title}\n")
                f.write(f"**Type:** {hypothesis.vulnerability_type}\n")
                f.write(f"**Severity:** {hypothesis.severity}\n\n")
                f.write("---\n\n")
                f.write(prompt)
            
            results.append(PoCPromptResult(
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                vulnerability_type=hypothesis.vulnerability_type or "unknown",
                severity=hypothesis.severity or "unknown",
                affected_files=list(affected_files.keys()),
                prompt=prompt,
                output_path=str(output_file)
            ))
            
        except Exception as e:
            # Log error but continue with other hypotheses
            logger.error(f"Error generating PoC for {hypothesis.hypothesis_id}: {e}")
            results.append(PoCPromptResult(
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                vulnerability_type=hypothesis.vulnerability_type or "unknown",
                severity=hypothesis.severity or "unknown",
                affected_files=[],
                prompt=f"Error generating PoC: {str(e)}",
                output_path=""
            ))
    
    # Cleanup temp clone directory if we created one
    if temp_clone_dir:
        import shutil
        try:
            shutil.rmtree(temp_clone_dir, ignore_errors=True)
        except Exception:
            pass
    
    return PoCGenerateResponse(
        session_id=session_id,
        project_name=project.name,
        total_generated=len([r for r in results if r.output_path]),
        results=results
    )


# ============================================================================
# Report Generation Endpoint - Generate security audit reports
# ============================================================================

class ReportGenerateRequest(BaseModel):
    """Request model for report generation."""
    format: str = Field(default="html", description="Report format: html, markdown, or pdf")
    title: str | None = Field(None, description="Custom report title")
    auditors: str = Field(default="Security Team", description="Comma-separated auditor names")
    include_all: bool = Field(default=False, description="Include all hypotheses, not just confirmed")


class ReportGenerateResponse(BaseModel):
    """Response from report generation."""
    session_id: str
    project_name: str
    format: str
    total_findings: int
    output_path: str
    report_url: str | None = None


@app.post("/sessions/{session_id}/report", response_model=ReportGenerateResponse)
async def generate_report(
    session_id: str,
    request: ReportGenerateRequest,
    db: Session = Depends(get_db),
    tenant_id: int | None = Depends(require_tenant_or_admin),
    _: None = Depends(reject_preview_writes),
):
    """
    Generate a security audit report for a session's findings.

    Creates a professional HTML or Markdown report with:
    - Executive summary (AI-generated)
    - Vulnerability findings with severity ratings
    - Code snippets and remediation advice
    - Testing methodology

    This endpoint uses LLM to generate executive summary and takes 30-60 seconds.

    Auth: tenant JWT (ownership check) OR X-Admin-Key header (admin bypass).
    """
    import re
    import subprocess
    import tempfile
    import traceback
    from datetime import datetime

    logger.info(f"Starting report generation for session {session_id}")

    try:
        # Get the session
        session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()
        if not session:
            logger.error(f"Session not found: {session_id}")
            raise HTTPException(status_code=404, detail="Session not found")

        # Get the project
        project = db.query(Project).filter(Project.id == session.project_id).first()
        if not project:
            logger.error(f"Project not found for session {session_id}")
            raise HTTPException(status_code=404, detail="Session not found")

        # Tenant callers must own the session; admin callers skip ownership check
        if tenant_id is not None and project.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="Session not found")

        logger.info(f"Generating report for project: {project.name}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in report generation setup: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Setup error: {str(e)}")
    
    # Determine repo root
    repo_root = None
    temp_clone_dir = None
    
    if project.source_path:
        candidate = Path(project.source_path)
        if candidate.exists():
            repo_root = candidate
    
    if not repo_root and project.git_url:
        repo_name = project.git_url.rstrip('/').split('/')[-1].replace('.git', '')
        for base in [Path('/tmp'), Path('/workspaces')]:
            candidate = base / repo_name
            if candidate.exists():
                repo_root = candidate
                break
        
        if not repo_root:
            try:
                temp_clone_dir = tempfile.mkdtemp(prefix="hound_report_clone_")
                repo_path = Path(temp_clone_dir) / "repo"
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", project.git_url, str(repo_path)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0 and repo_path.exists():
                    repo_root = repo_path
            except Exception:
                pass
    
    # Helper function to extract file paths from hypothesis text
    def _extract_source_files(title: str, description: str) -> list[str]:
        if not repo_root:
            return []
        
        source_files = []
        combined = f"{title} {description}".lower()
        
        identifiers = set(re.findall(
            r'\b([A-Za-z][a-zA-Z0-9]*(?:[A-Z][a-zA-Z0-9]*)+)\b', 
            f"{title} {description}"
        ))
        
        keywords = set()
        for word in re.findall(r'\b([a-zA-Z]{4,20})\b', combined):
            if word not in {'this', 'that', 'with', 'from', 'allows', 'which', 'could', 
                          'would', 'should', 'using', 'funds', 'tokens', 'called', 'function',
                          'contract', 'address', 'operator', 'manager', 'admin', 'oracle'}:
                keywords.add(word)
        
        contracts_dir = repo_root / 'contracts'
        if contracts_dir.exists():
            for sol_file in contracts_dir.glob('**/*.sol'):
                file_lower = sol_file.stem.lower()
                for kw in keywords | {i.lower() for i in identifiers}:
                    if kw in file_lower or file_lower in kw:
                        rel_path = str(sol_file.relative_to(repo_root))
                        if rel_path not in source_files:
                            source_files.append(rel_path)
                        break
        
        return source_files
    
    # Get hypotheses
    query = db.query(Hypothesis).filter(Hypothesis.project_id == session.project_id)
    
    if not request.include_all:
        query = query.filter(
            (Hypothesis.status == "confirmed") | 
            (Hypothesis.confidence >= 0.7)
        )
    
    hypotheses = query.order_by(Hypothesis.confidence.desc()).all()
    
    # Create temporary project directory for ReportGenerator
    temp_project_dir = Path(tempfile.mkdtemp(prefix="hound_report_"))
    
    try:
        # Create graphs directory
        graphs_dir = temp_project_dir / "graphs"
        graphs_dir.mkdir(parents=True, exist_ok=True)
        
        # Create knowledge_graphs.json with repo root
        import json
        kg_data = {
            "manifest": {"repo_path": str(repo_root) if repo_root else None},
            "card_store_path": None
        }
        with open(graphs_dir / "knowledge_graphs.json", "w") as f:
            json.dump(kg_data, f)
        
        # Create minimal graph file
        with open(graphs_dir / "graph_analysis.json", "w") as f:
            json.dump({"nodes": [], "edges": []}, f)
        
        # Build hypotheses dict with source files
        hyp_dict = {}
        for h in hypotheses:
            source_files = _extract_source_files(h.title, h.description)
            effective_node_refs = h.node_refs or []
            if not effective_node_refs and source_files:
                effective_node_refs = source_files
            
            hyp_dict[h.hypothesis_id] = {
                'title': h.title,
                'description': h.description,
                'vulnerability_type': h.vulnerability_type,
                'status': h.status,
                'confidence': h.confidence,
                'severity': h.severity,
                'node_refs': effective_node_refs,
                'evidence': h.evidence or {},
                'annotations': [],
                'reasoning': h.description,
                'properties': {'source_files': source_files}
            }
            
            for ref in effective_node_refs:
                if isinstance(ref, str) and ':' in ref:
                    parts = ref.split(':')
                    hyp_dict[h.hypothesis_id]['annotations'].append({
                        'file_path': parts[0],
                        'line': int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
                    })
                elif isinstance(ref, str):
                    hyp_dict[h.hypothesis_id]['annotations'].append({'file_path': ref})
        
        # Create hypotheses.json
        hyp_data = {
            "hypotheses": hyp_dict,
            "metadata": {"source": "database", "project_name": project.name}
        }
        with open(temp_project_dir / "hypotheses.json", "w") as f:
            json.dump(hyp_data, f)
        
        # Create reports directory
        (temp_project_dir / "reports").mkdir(exist_ok=True)
        
        # Load config for LLM
        logger.info("Loading configuration for LLM...")
        config = None
        try:
            config = get_active_config()
            logger.info(f"Config loaded: {list(config.get('models', {}).keys())}")
        except Exception as config_err:
            logger.warning(f"Failed to load config: {config_err}")
            # Try fallback config
            config_path = Path(__file__).parent.parent / "config.yaml"
            if config_path.exists():
                import yaml
                with open(config_path) as f:
                    config = yaml.safe_load(f) or {}
                logger.info("Loaded config from config.yaml")
            else:
                logger.error("No configuration found - report may fail")
                config = {}
        
        if not hypotheses:
            logger.warning(f"No hypotheses found for session {session_id}")
            raise HTTPException(status_code=400, detail="No findings to include in report")
        
        # Initialize report generator
        logger.info(f"Initializing report generator with {len(hypotheses)} hypotheses...")
        from analysis.report_generator import ReportGenerator
        
        generator = ReportGenerator(
            project_dir=temp_project_dir,
            config=config,
            debug=True,  # Enable debug for better error messages
            include_all=request.include_all
        )
        
        # Generate report (this calls LLM for executive summary)
        logger.info("Generating report... This will take 30-60 seconds as AI compiles the analysis...")
        try:
            report_data = generator.generate(
                project_name=project.name,
                project_source=str(repo_root) if repo_root else None,
                title=request.title or f"Security Audit Report: {project.name}",
                auditors=request.auditors.split(','),
                format=request.format,
                progress_callback=lambda msg: logger.info(f"Report progress: {msg}")
            )
            logger.info(f"Report generated successfully: {len(report_data)} bytes")
        except Exception as gen_err:
            logger.error(f"Report generation failed: {gen_err}")
            logger.error(traceback.format_exc())
            raise HTTPException(status_code=500, detail=f"Report generation failed: {str(gen_err)}")
        
        # Save report to user's home directory
        user_reports_dir = Path.home() / f".hound/reports/{project.name}"
        user_reports_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "html" if request.format == "pdf" else request.format
        output_path = user_reports_dir / f"audit_report_{timestamp}.{ext}"
        
        with open(output_path, 'w') as f:
            f.write(report_data)
        
        # Count confirmed findings
        confirmed_count = len([h for h in hypotheses if h.status == "confirmed"])
        
        # Generate accessible URL
        report_url = f"/reports/{project.name}/{output_path.name}"
        
        logger.info(f"Report saved to: {output_path}")
        logger.info(f"Report URL: {report_url}")
        
        return ReportGenerateResponse(
            session_id=session_id,
            project_name=project.name,
            format=request.format,
            total_findings=confirmed_count if not request.include_all else len(hypotheses),
            output_path=str(output_path),
            report_url=report_url
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in report generation: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
    finally:
        # Cleanup temp directories
        import shutil
        try:
            if 'temp_project_dir' in locals():
                shutil.rmtree(temp_project_dir, ignore_errors=True)
        except Exception:
            pass
        
        if temp_clone_dir:
            try:
                shutil.rmtree(temp_clone_dir, ignore_errors=True)
            except Exception:
                pass


# ============================================================================
# Surface Scan Endpoints - Lightweight security analysis for lead generation
# ============================================================================

class SurfaceScanRequest(BaseModel):
    """Request model for surface scan."""
    target: str = Field(default=None, description="GitHub URL or repository path to scan")
    repo_url: str = Field(default=None, description="Alias for target - GitHub URL to scan")
    llm_budget: int = Field(default=5, description="Maximum LLM calls per scan (0 to disable)")
    model: str | None = Field(default=None, description="Override LLM model")
    
    @model_validator(mode='after')
    def validate_target_or_repo_url(self):
        """Ensure either target or repo_url is provided."""
        if not self.target and not self.repo_url:
            raise ValueError("Either 'target' or 'repo_url' must be provided")
        # Use repo_url if target not provided
        if not self.target and self.repo_url:
            self.target = self.repo_url
        return self


class SurfaceFinding(BaseModel):
    """A vulnerability or quality finding from surface scan."""
    pattern_id: str
    title: str
    severity: str
    category: str
    confidence: float
    location: str
    code_snippet: str
    description: str
    llm_verified: bool = False
    llm_notes: str | None = None


class SurfaceQualityMetrics(BaseModel):
    """Code quality metrics from surface scan."""
    solidity_version: str | None = None
    vyper_version: str | None = None
    has_tests: bool = False
    test_count: int = 0
    has_natspec: bool = False
    contract_count: int = 0
    total_loc: int = 0
    has_events: bool = False
    uses_safemath: bool = False
    has_access_control: bool = False


class SurfaceScanResponse(BaseModel):
    """Response from surface scan."""
    execution_id: str
    repo_url: str | None = None
    repo_name: str
    risk_score: int
    risk_level: str
    findings: list[SurfaceFinding]
    quality_metrics: SurfaceQualityMetrics
    contracts_scanned: int
    llm_calls_used: int
    scan_duration_seconds: float
    summary: str
    error: str | None = None
    scan_log: str | None = None
    scan_type: str = "surface"
    # Branch this scan ran against (None for legacy rows scanned before per-branch picker shipped).
    branch: str | None = None
    # Deep audit curated assessment (None for surface scans)
    deep_audit_overview: dict | None = None
    # firepan-nxf: scope (deep scans only). None for whole-repo or legacy rows.
    target_files: list[str] | None = None


class SurfaceScanListItem(BaseModel):
    """Summary item for scan listing."""
    execution_id: str
    repo_name: str
    repo_url: str | None = None
    risk_score: int
    risk_level: str
    finding_count: int
    contracts_scanned: int
    status: str
    created_at: datetime
    summary: str | None = None


class SurfaceScanListResponse(BaseModel):
    """Response for listing surface scans."""
    scans: list[SurfaceScanListItem]
    total: int
    page: int
    page_size: int


@app.post("/surface/scan", response_model=SurfaceScanResponse)
async def run_surface_scan(
    request: SurfaceScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Run a lightweight surface scan on a repository.
    
    This is designed for lead generation - quickly identifying potential
    security issues that warrant a full audit. Results are saved to the
    database for the admin panel.
    
    Cost: ~$0.05 per scan with LLM verification
    Time: ~2-10 seconds depending on repo size
    """
    from analysis.surface import SurfaceScanner
    
    # Load active config profile
    config = get_active_config()
    
    # Initialize scanner
    scanner = SurfaceScanner(
        config=config,
        llm_budget=request.llm_budget,
        model=request.model,
        quiet=True,
    )
    
    # Run scan
    result = scanner.scan(request.target)
    
    # Generate unique execution ID
    execution_id = f"scan_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    # Generate executive summary overview
    overview = None
    if result.findings and not result.error:
        try:
            from worker.tasks import _compute_surface_scan_overview
            overview = _compute_surface_scan_overview(
                findings=[f.model_dump() for f in result.findings],
                quality_metrics=result.quality_metrics.model_dump(),
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                repo_name=result.repo_name,
            )
        except Exception as e:
            logger.warning(f"Surface scan overview generation failed: {e}")

    # Save to database
    try:
        # Get or create default tenant
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="Default", slug="default")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        scan_exec = ScanExecution(
            execution_id=execution_id,
            tenant_id=tenant.id,
            repo_url=result.repo_url,
            repo_name=result.repo_name,
            status="completed" if not result.error else "failed",
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            findings=[f.model_dump() for f in result.findings],
            quality_metrics=result.quality_metrics.model_dump(),
            summary=result.summary,
            scan_config={
                "llm_budget": request.llm_budget,
                "model": request.model,
                "scan_type": "surface",
            },
            llm_calls_made=result.llm_calls_used,
            contracts_scanned=result.contracts_scanned,
            contracts_total=result.contracts_total,
            error_message=result.error,
            scan_log=result.scan_log,
            started_at=result.scan_timestamp,
            completed_at=datetime.now(),
            deep_audit_overview=overview,
        )

        db.add(scan_exec)
        db.commit()
    except Exception as e:
        logger.warning(f"Failed to save scan to database: {e}")

    # Build response
    return SurfaceScanResponse(
        execution_id=execution_id,
        repo_url=result.repo_url,
        repo_name=result.repo_name,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        findings=[
            SurfaceFinding(
                pattern_id=f.pattern_id,
                title=f.title,
                severity=f.severity,
                category=f.category,
                confidence=f.confidence,
                location=f.location,
                code_snippet=f.code_snippet,
                description=f.description,
                llm_verified=f.llm_verified,
                llm_notes=f.llm_notes,
            )
            for f in result.findings
        ],
        quality_metrics=SurfaceQualityMetrics(
            solidity_version=result.quality_metrics.solidity_version,
            vyper_version=result.quality_metrics.vyper_version,
            has_tests=result.quality_metrics.has_tests,
            test_count=result.quality_metrics.test_count,
            has_natspec=result.quality_metrics.has_natspec,
            contract_count=result.quality_metrics.contract_count,
            total_loc=result.quality_metrics.total_loc,
            has_events=result.quality_metrics.has_events,
            uses_safemath=result.quality_metrics.uses_safemath,
            has_access_control=result.quality_metrics.has_access_control,
        ),
        contracts_scanned=result.contracts_scanned,
        llm_calls_used=result.llm_calls_used,
        scan_duration_seconds=result.scan_duration_seconds,
        summary=result.summary,
        error=result.error,
        scan_log=result.scan_log,
        deep_audit_overview=overview,
    )


# =============================================================================
# x402 PAID ENDPOINTS
# =============================================================================

@app.post("/surface/scan/full", response_model=SurfaceScanResponse)
async def run_full_surface_scan(
    request_body: SurfaceScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    tenant_id: int = Depends(get_current_tenant_id),
    _: None = Depends(reject_preview_writes),
):
    """
    Run a full vulnerability surface scan (PAID: $0.50 via x402).

    Returns complete vulnerability findings with details.
    When x402 is disabled, works identically to /surface/scan (no paywall).
    """
    from server.x402_deps import create_paid_job, mark_job_failed, require_payment

    # Run payment gate manually (can't use Depends with dynamic factory easily here)
    gate_fn = require_payment("POST /surface/scan/full")
    gate = await gate_fn(request=request, tenant_id=tenant_id, db=db)

    if gate.status == "already_processed":
        return {"execution_id": gate.job_id, "status": "already_processed", "message": "Already processed"}

    from analysis.surface import SurfaceScanner

    config = get_active_config()
    scanner = SurfaceScanner(
        config=config,
        llm_budget=request_body.llm_budget,
        model=request_body.model,
        quiet=True,
    )

    result = scanner.scan(request_body.target)
    execution_id = f"scan_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    # Generate executive summary overview
    overview = None
    if result.findings and not result.error:
        try:
            from worker.tasks import _compute_surface_scan_overview
            overview = _compute_surface_scan_overview(
                findings=[f.model_dump() for f in result.findings],
                quality_metrics=result.quality_metrics.model_dump(),
                risk_score=result.risk_score,
                risk_level=result.risk_level,
                repo_name=result.repo_name,
            )
        except Exception as e:
            logger.warning(f"Surface scan overview generation failed: {e}")

    try:
        scan_exec = ScanExecution(
            execution_id=execution_id,
            tenant_id=tenant_id,
            repo_url=result.repo_url,
            repo_name=result.repo_name,
            status="completed" if not result.error else "failed",
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            findings=[f.model_dump() for f in result.findings],
            quality_metrics=result.quality_metrics.model_dump(),
            summary=result.summary,
            scan_config={
                "llm_budget": request_body.llm_budget,
                "model": request_body.model,
                "paid": True,
                "scan_type": "surface",
            },
            llm_calls_made=result.llm_calls_used,
            contracts_scanned=result.contracts_scanned,
            contracts_total=result.contracts_total,
            error_message=result.error,
            scan_log=result.scan_log,
            started_at=result.scan_timestamp,
            completed_at=datetime.now(),
            deep_audit_overview=overview,
        )
        db.add(scan_exec)
        db.commit()

        if gate.enabled and gate.payment_log_id:
            try:
                create_paid_job(db, gate.payment_log_id, execution_id)
            except Exception as e:
                logger.error(f"Failed to link payment to job: {e}")
                mark_job_failed(db, gate.payment_log_id)
    except Exception as e:
        logger.warning(f"Failed to save paid scan to database: {e}")
        if gate.enabled and gate.payment_log_id:
            mark_job_failed(db, gate.payment_log_id)

    return SurfaceScanResponse(
        execution_id=execution_id,
        repo_url=result.repo_url,
        repo_name=result.repo_name,
        risk_score=result.risk_score,
        risk_level=result.risk_level,
        findings=[
            SurfaceFinding(
                pattern_id=f.pattern_id,
                title=f.title,
                severity=f.severity,
                category=f.category,
                confidence=f.confidence,
                location=f.location,
                code_snippet=f.code_snippet,
                description=f.description,
                llm_verified=f.llm_verified,
                llm_notes=f.llm_notes,
            )
            for f in result.findings
        ],
        quality_metrics=SurfaceQualityMetrics(
            solidity_version=result.quality_metrics.solidity_version,
            vyper_version=result.quality_metrics.vyper_version,
            has_tests=result.quality_metrics.has_tests,
            test_count=result.quality_metrics.test_count,
            has_natspec=result.quality_metrics.has_natspec,
            contract_count=result.quality_metrics.contract_count,
            total_loc=result.quality_metrics.total_loc,
            has_events=result.quality_metrics.has_events,
            uses_safemath=result.quality_metrics.uses_safemath,
            has_access_control=result.quality_metrics.has_access_control,
        ),
        contracts_scanned=result.contracts_scanned,
        llm_calls_used=result.llm_calls_used,
        scan_duration_seconds=result.scan_duration_seconds,
        summary=result.summary,
        error=result.error,
        scan_log=result.scan_log,
        deep_audit_overview=overview,
    )


class PaymentLookupResponse(BaseModel):
    """Response for payment lookup."""
    id: int
    payment_id: str | None
    endpoint: str
    status: str
    amount_usd: float
    payer_address: str | None
    tx_hash: str | None
    network: str
    job_id: str | None
    created_at: datetime
    settled_at: datetime | None


@app.get("/payments/{payment_id}")
@limiter.limit("30/minute", key_func=rate_limit_key_tenant_or_ip)
async def get_payment(
    payment_id: str,
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
):
    """
    Look up a payment by payment_id. Requires auth + ownership check.
    Returns 404 (not 403) if payment belongs to a different tenant.
    """
    request.state.tenant_id = tenant_id

    log = db.query(PaymentLog).filter(PaymentLog.payment_id == payment_id).first()
    if not log or log.tenant_id != tenant_id:
        raise HTTPException(404, "Payment not found")

    return PaymentLookupResponse(
        id=log.id,
        payment_id=log.payment_id,
        endpoint=log.endpoint,
        status=log.status,
        amount_usd=float(log.amount_usd) if log.amount_usd else 0.0,
        payer_address=log.payer_address,
        tx_hash=log.tx_hash,
        network=log.network,
        job_id=log.job_id,
        created_at=log.created_at,
        settled_at=log.settled_at,
    )


@app.get("/surface/scans", response_model=SurfaceScanListResponse)
async def list_surface_scans(
    tenant_id: int = Depends(get_current_tenant_id),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    risk_level: str | None = Query(None, description="Filter by risk level"),
    status: str | None = Query(None, description="Filter by status"),
    search: str | None = Query(None, description="Search repo name"),
    db: Session = Depends(get_db)
):
    """
    List all surface scans for the authenticated user.
    
    Requires JWT authentication. Returns only scans for the authenticated user's tenant.
    Supports pagination and filtering by risk level, status, and repo name.
    """
    query = db.query(ScanExecution)
    
    # Apply tenant filter from JWT token
    query = query.filter(ScanExecution.tenant_id == tenant_id)
    
    # Apply additional filters
    if risk_level:
        query = query.filter(ScanExecution.risk_level == risk_level)
    if status:
        query = query.filter(ScanExecution.status == status)
    if search:
        query = query.filter(ScanExecution.repo_name.ilike(f"%{search}%"))
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * page_size
    scans = query.order_by(ScanExecution.created_at.desc()).offset(offset).limit(page_size).all()
    
    # Build response
    return SurfaceScanListResponse(
        scans=[
            SurfaceScanListItem(
                execution_id=s.execution_id,
                repo_name=s.repo_name,
                repo_url=s.repo_url,
                risk_score=s.risk_score or 0,
                risk_level=s.risk_level or "unknown",
                finding_count=len(s.findings) if s.findings else 0,
                contracts_scanned=s.contracts_scanned,
                status=s.status,
                created_at=s.created_at,
                summary=s.summary[:200] if s.summary else None,
            )
            for s in scans
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@app.get("/surface/scans/{execution_id}", response_model=SurfaceScanResponse)
async def get_surface_scan(
    execution_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(require_verified_email),
):
    """
    Get details of a specific surface scan.

    Returns full scan results including all findings and quality metrics.
    """
    scan = db.query(ScanExecution).filter(
        ScanExecution.execution_id == execution_id,
        ScanExecution.tenant_id == tenant_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Parse findings from JSON
    findings = []
    if scan.findings:
        for f in scan.findings:
            findings.append(SurfaceFinding(
                pattern_id=f.get("pattern_id", ""),
                title=f.get("title", ""),
                severity=f.get("severity", "medium"),
                category=f.get("category", "vulnerability"),
                confidence=f.get("confidence", 0.5),
                location=f.get("location", ""),
                code_snippet=f.get("code_snippet", ""),
                description=f.get("description", ""),
                llm_verified=f.get("llm_verified", False),
                llm_notes=f.get("llm_notes"),
            ))
    
    # Parse quality metrics
    qm = scan.quality_metrics or {}
    quality_metrics = SurfaceQualityMetrics(
        solidity_version=qm.get("solidity_version"),
        vyper_version=qm.get("vyper_version"),
        has_tests=qm.get("has_tests", False),
        test_count=qm.get("test_count", 0),
        has_natspec=qm.get("has_natspec", False),
        contract_count=qm.get("contract_count", 0),
        total_loc=qm.get("total_loc", 0),
        has_events=qm.get("has_events", False),
        uses_safemath=qm.get("uses_safemath", False),
        has_access_control=qm.get("has_access_control", False),
    )
    
    # Calculate scan duration
    duration = 0.0
    if scan.started_at and scan.completed_at:
        duration = (scan.completed_at - scan.started_at).total_seconds()
    
    # Include deep_audit_overview if present
    overview = scan.deep_audit_overview if hasattr(scan, 'deep_audit_overview') else None

    cfg = scan.scan_config or {}
    project_for_branch = db.query(Project).filter(Project.id == scan.project_id).first()
    scan_branch = cfg.get("branch") or (project_for_branch.default_branch if project_for_branch else None)
    # firepan-nxf: scope readback, defensive against malformed JSONB.
    raw_tf = cfg.get("target_files") if isinstance(cfg, dict) else None
    scoped_tf: list[str] | None = None
    if isinstance(raw_tf, list) and all(isinstance(t, str) for t in raw_tf):
        scoped_tf = raw_tf or None
    return SurfaceScanResponse(
        execution_id=scan.execution_id,
        repo_url=scan.repo_url,
        repo_name=scan.repo_name,
        risk_score=scan.risk_score or 0,
        risk_level=scan.risk_level or "unknown",
        findings=findings,
        quality_metrics=quality_metrics,
        contracts_scanned=scan.contracts_scanned,
        llm_calls_used=scan.llm_calls_made,
        scan_duration_seconds=duration,
        summary=scan.summary or "",
        error=scan.error_message,
        scan_log=scan.scan_log,
        scan_type=cfg.get("scan_type", "surface"),
        branch=scan_branch,
        deep_audit_overview=overview if isinstance(overview, dict) else None,
        target_files=scoped_tf,
    )


@app.delete("/surface/scans/{execution_id}")
async def delete_surface_scan(
    execution_id: str,
    request: Request,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """
    Delete a surface scan from the database.
    """
    scan = db.query(ScanExecution).filter(
        ScanExecution.execution_id == execution_id,
        ScanExecution.tenant_id == tenant_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    db.delete(scan)
    db.commit()
    
    return {"status": "deleted", "execution_id": execution_id}


@app.post("/surface/scans/{execution_id}/finalize")
async def finalize_scan(
    execution_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Finalize an in_review scan to completed. Admin only."""
    if not _verify_explicit_admin_header(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    scan = db.query(ScanExecution).filter(
        ScanExecution.execution_id == execution_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "in_review":
        raise HTTPException(status_code=400, detail=f"Cannot finalize: status is {scan.status}")
    scan.status = "completed"
    session = db.query(AuditSession).filter_by(session_id=execution_id).first()
    if session:
        session.status = "completed"
    db.commit()
    # Publish WebSocket event for live UI update
    try:
        from worker.redis_publisher import RedisPublisher
        publisher = RedisPublisher(execution_id)
        publisher.publish_status("completed", "Audit finalized")
        publisher.close()
    except Exception:
        pass
    return {"status": "completed", "execution_id": execution_id}


# firepan-oi4: admin-only flag flip for the model-written deep_audit_overview.
# Defaults to unverified on every new deep audit; these endpoints let an admin
# sign off after reviewing the findings. Stamps verified_at + verified_by into
# the JSONB so there's a trail. Reassigns the whole dict because JSONType has
# no MutableDict hook — in-place mutation would be invisible to SQLAlchemy.
@app.post("/admin/scans/{execution_id}/verify-overview")
async def verify_deep_audit_overview(
    execution_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Flip deep_audit_overview.admin_verified = True. Admin only."""
    if not _verify_explicit_admin_header(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    scan = db.query(ScanExecution).filter(
        ScanExecution.execution_id == execution_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    overview = scan.deep_audit_overview
    if not isinstance(overview, dict):
        raise HTTPException(
            status_code=400,
            detail="Scan has no deep_audit_overview to verify",
        )
    updated = dict(overview)
    updated["admin_verified"] = True
    updated["verified_at"] = datetime.now(timezone.utc).isoformat()
    updated["verified_by"] = "admin"
    scan.deep_audit_overview = updated
    db.commit()
    return {
        "execution_id": execution_id,
        "admin_verified": True,
        "verified_at": updated["verified_at"],
    }


@app.post("/admin/scans/{execution_id}/unverify-overview")
async def unverify_deep_audit_overview(
    execution_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Flip deep_audit_overview.admin_verified = False. Admin only. Idempotent."""
    if not _verify_explicit_admin_header(request):
        raise HTTPException(status_code=403, detail="Admin access required")
    scan = db.query(ScanExecution).filter(
        ScanExecution.execution_id == execution_id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    overview = scan.deep_audit_overview
    if not isinstance(overview, dict):
        raise HTTPException(
            status_code=400,
            detail="Scan has no deep_audit_overview to unverify",
        )
    updated = dict(overview)
    updated["admin_verified"] = False
    updated.pop("verified_at", None)
    updated.pop("verified_by", None)
    scan.deep_audit_overview = updated
    db.commit()
    return {"execution_id": execution_id, "admin_verified": False}


# firepan-1bg: admin-only deep-audit force-run + refund helpers.
# Mirrors the verify-overview pattern above: X-Admin-Key header ONLY, no JWT,
# no session cookies, no query-param auth. Bypasses tenant quota
# (tier_enforcement._check_sync bypass_quota=True) and x402 gates entirely —
# admin is authoritative. Motivated by Egorov 2026-04-23 FeeDistributor thread:
# running repeat deep audits on behalf of paying-but-curious customers should
# not burn the admin's own monthly quota, and the manual-refund workflow for
# failed audits (CLAUDE.md #46) should be a single call, not SQLAdmin clicks.


class AdminAuditForceRunRequest(BaseModel):
    """Request body for POST /admin/audits/force-run.

    Admin callers specify tenant_id explicitly because there's no JWT.
    project_id is required — whole-tenant sweeps are not this endpoint's job.
    """

    project_id: int = Field(..., description="Project to audit (admin confirms ownership)")
    tenant_id: int | None = Field(
        None,
        description="Tenant to attribute the audit to. If omitted, derives from project.",
    )
    repo_url: str | None = Field(
        None,
        description="Override repo URL. If omitted, uses project.git_url or project.source_path.",
    )
    max_iterations: int = Field(default=30, ge=1, le=200)
    investigation_prompt: str | None = None
    time_limit_minutes: int = Field(default=120, ge=1, le=600)
    mode: Literal["sweep", "intuition", "auditor", "verify"] = Field(default="auditor", description="Audit mode: 'auditor' (default — Claude SingleAuditor, firepan-8l1), 'sweep' (legacy DeepSeek, opt-in), 'intuition', or 'verify' (firepan-bump-verify — runs the Bump Sheet phases against a finding from a prior auditor run)")
    # firepan-bump-verify: when mode='verify', the worker pulls these
    # parameters out of scan_config_dict["bump_verify"] and runs phases 1-4
    # against the named finding. All optional fields default such that
    # dry-run (scaffold-only) mode works without external RPC.
    verify_finding_id: str | None = Field(
        default=None,
        description=(
            "Hypothesis ID (e.g. hyp_abc123) of the finding to verify. "
            "Required when mode='verify'."
        ),
    )
    verify_rpc_url: str | None = Field(
        default=None,
        description=(
            "Archive RPC URL for fork-based verification. When None, the "
            "verifier runs in dry-run mode and emits scaffolded artifacts."
        ),
    )
    verify_fork_block: int | None = Field(
        default=None,
        description="Block height to fork at. None ⇒ dry-run scaffold only.",
    )
    plan_n: int = Field(default=5, ge=1, le=20)
    audit_branch: str | None = Field(default=None, max_length=255)
    target_files: list[str] | None = Field(
        default=None,
        description=(
            "Optional list of repo-relative file paths to scope the deep audit to. "
            "Max 50 entries. Admin bypasses tier gating but NOT existence validation."
        ),
        max_length=50,
    )
    audit_context: dict | None = Field(
        default=None,
        description=(
            "Per-engagement curation context (firepan-curator). Threaded through "
            "to the worker's post-auditor curation pass via scan_config['audit_context']. "
            "Keys: scope_files (list[str], hard-enforced — findings outside are relabeled "
            "out_of_scope), dead_code_paths (list[{file, function}]), trusted_roles "
            "(list[str] like ['onlyOwner', 'onlyStrategy']; trust-boundary heuristic "
            "downgrades findings whose exploitation requires only a trusted role), "
            "deployed_contracts (dict[name, address] — chain-of-custody only), and "
            "out_of_scope_action ('downgrade' or 'drop')."
        ),
    )


@app.post("/admin/audits/force-run", response_model=AuditStartResponse)
async def admin_force_run_audit(
    payload: AdminAuditForceRunRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Dispatch a deep audit as admin, bypassing tenant quota and x402 gates.

    Admin only. Creates the same AuditSession + ScanExecution rows as
    /audits/start so the dashboard/websocket progress path is unchanged;
    the only difference is the quota/payment check is skipped.
    """
    if not _verify_explicit_admin_header(request):
        raise HTTPException(status_code=403, detail="Admin access required")

    project = db.query(Project).filter(Project.id == payload.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    tenant_id = payload.tenant_id or project.tenant_id
    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="tenant_id required (project has no tenant_id set)",
        )
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Explicit bypass marker — call _check_sync with bypass_quota=True so the
    # side-effects (tenant lookup) still run but no limit is enforced. This
    # lets us keep the single code path for tenant resolution.
    from server.tier_enforcement import _check_sync as _tier_check
    _tier_check(tenant_id, "audit", db, bypass_quota=True)

    # firepan-nxf: scope validation. Admin bypasses the tier gate but NOT the
    # existence check — the on-disk check is best-effort (worker is authoritative).
    scoped_target_files = _validate_target_files(payload.target_files)
    if scoped_target_files:
        resolved, missing = _check_target_files_exist_on_disk(
            getattr(project, "source_path", None),
            scoped_target_files,
        )
        if resolved or missing:  # check actually ran (clone was available)
            if not resolved:
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "scoped_audit_no_files_match",
                        "missing": missing,
                        "message": (
                            "None of the requested target_files exist in the cached clone. "
                            "Check paths and branch."
                        ),
                    },
                )

    try:
        from worker.tasks import execute_audit_task
    except ImportError as e:
        raise HTTPException(
            status_code=500,
            detail=f"Worker module not available: {e}. Is Celery configured?",
        )

    requested_audit_branch = _validate_ref(payload.audit_branch)
    resolved_audit_branch = (
        requested_audit_branch
        or (project.default_branch if project else None)
        or "main"
    )
    resolved_repo_url = (
        payload.repo_url
        or getattr(project, "git_url", None)
        or getattr(project, "source_path", None)
        or ""
    )
    if not resolved_repo_url:
        raise HTTPException(
            status_code=400,
            detail="Cannot resolve repo_url (pass explicitly or set project.git_url)",
        )

    session_id = f"audit_{uuid.uuid4().hex[:12]}_{int(datetime.now().timestamp())}"

    session_models: dict = {
        "max_iterations": payload.max_iterations,
        "admin_forced": True,
    }
    session_metadata: dict = {}
    if scoped_target_files:
        session_metadata["target_files"] = scoped_target_files

    audit_session = AuditSession(
        session_id=session_id,
        project_id=project.id,
        status="queued",
        start_time=datetime.now(timezone.utc),
        models=session_models,
        session_metadata=session_metadata or None,
    )
    db.add(audit_session)
    db.commit()

    from database.models import ScanExecution as ScanExecutionModel
    scan_config_dict: dict = {
        "scan_type": "deep",
        "mode": payload.mode,
        "branch": resolved_audit_branch,
        "admin_forced": True,
    }
    if scoped_target_files:
        scan_config_dict["target_files"] = scoped_target_files
    # firepan-curator: thread the curator context to the worker. The worker
    # reads it from scan_config["audit_context"] after the auditor returns.
    if payload.audit_context:
        scan_config_dict["audit_context"] = payload.audit_context

    # firepan-bump-verify: when mode='verify', thread the bump-verifier
    # parameters through. The worker reads them from scan_config["bump_verify"]
    # and instantiates analysis.bump_verifier.BumpVerifier accordingly.
    if payload.mode == "verify":
        if not payload.verify_finding_id:
            raise HTTPException(
                status_code=422,
                detail="verify_finding_id required when mode='verify'",
            )
        scan_config_dict["bump_verify"] = {
            "finding_id": payload.verify_finding_id,
            "rpc_url": payload.verify_rpc_url,
            "fork_block": payload.verify_fork_block,
        }

    deep_scan = ScanExecutionModel(
        execution_id=session_id,
        project_id=project.id,
        tenant_id=tenant_id,
        repo_url=resolved_repo_url,
        repo_name=project.name,
        status="queued",
        started_at=datetime.now(timezone.utc),
        scan_config=scan_config_dict,
    )
    db.add(deep_scan)
    db.commit()

    resolved_installation_id = getattr(project, "installation_id", None)

    task = execute_audit_task.delay(
        repo_url=resolved_repo_url,
        scan_id=session_id,
        tenant_id=tenant_id,
        project_id=project.id,
        max_iterations=payload.max_iterations,
        investigation_prompt=payload.investigation_prompt,
        installation_id=resolved_installation_id,
        pr_number=None,
        repo_full_name=None,
        time_limit_minutes=payload.time_limit_minutes,
        mode=payload.mode,
        plan_n=payload.plan_n,
        branch=resolved_audit_branch,
        target_files=scoped_target_files,
    )

    logger.info(
        "Admin force-run deep audit session=%s project=%s tenant=%s task=%s scoped=%s",
        session_id, project.id, tenant_id, task.id, bool(scoped_target_files),
    )

    return AuditStartResponse(
        session_id=session_id,
        status="queued",
        message=f"Admin-forced deep audit queued. Task ID: {task.id}",
        websocket_url=f"/ws/sessions/{session_id}",
    )


@app.post("/admin/audits/{session_id}/refund")
async def admin_refund_audit(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Delete AuditSession + matching ScanExecution so the tenant's monthly
    quota releases the slot. Admin only.

    Replaces the manual SQLAdmin workflow called out in CLAUDE.md #46: failed
    or stalled deep audits still count against quota until the row is gone,
    and there was no helper endpoint. Idempotent — returns 404 only if neither
    row exists; if just one exists the other is a no-op.
    """
    if not _verify_explicit_admin_header(request):
        raise HTTPException(status_code=403, detail="Admin access required")

    audit_session = db.query(AuditSession).filter(
        AuditSession.session_id == session_id,
    ).first()
    scan = db.query(ScanExecution).filter(
        ScanExecution.execution_id == session_id,
    ).first()

    if not audit_session and not scan:
        raise HTTPException(status_code=404, detail="No audit session or scan with that id")

    deleted = {"audit_session": False, "scan_execution": False}
    if audit_session:
        db.delete(audit_session)
        deleted["audit_session"] = True
    if scan:
        db.delete(scan)
        deleted["scan_execution"] = True
    db.commit()

    logger.info("Admin refunded audit session=%s deleted=%s", session_id, deleted)
    return {"session_id": session_id, "deleted": deleted}


@app.get("/surface/stats")
async def get_surface_scan_stats(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Get statistics for surface scans - useful for admin dashboard.
    
    Returns counts by risk level, status, and recent activity.
    """
    from sqlalchemy import func
    
    # Count by risk level
    risk_counts = db.query(
        ScanExecution.risk_level,
        func.count(ScanExecution.id)
    ).group_by(ScanExecution.risk_level).all()
    
    # Count by status
    status_counts = db.query(
        ScanExecution.status,
        func.count(ScanExecution.id)
    ).group_by(ScanExecution.status).all()
    
    # Total scans
    total = db.query(func.count(ScanExecution.id)).scalar()
    
    # Recent scans (last 7 days)
    week_ago = datetime.now() - timedelta(days=7)
    recent_count = db.query(func.count(ScanExecution.id)).filter(
        ScanExecution.created_at >= week_ago
    ).scalar()
    
    # Average risk score
    avg_risk = db.query(func.avg(ScanExecution.risk_score)).filter(
        ScanExecution.risk_score.isnot(None)
    ).scalar()
    
    return {
        "total_scans": total or 0,
        "recent_scans_7d": recent_count or 0,
        "average_risk_score": round(avg_risk or 0, 1),
        "by_risk_level": {r[0]: r[1] for r in risk_counts if r[0]},
        "by_status": {s[0]: s[1] for s in status_counts if s[0]},
    }


# ============================================================================
# Token Usage & Cost Tracking Endpoints
# ============================================================================

@app.get("/admin/token-stats")
async def get_token_usage_stats(
    request: Request,
    project_id: int | None = Query(None, description="Filter by project ID"),
    days: int = Query(30, description="Number of days to look back"),
    db: Session = Depends(get_db),
    _auth: bool = Depends(require_admin)
):
    """
    Get token usage and cost statistics for the admin dashboard.
    
    Returns aggregated statistics by model, provider, profile, and project.
    """
    from sqlalchemy import func

    from database.models import TokenUsageLog
    
    # Date filter
    since = datetime.now() - timedelta(days=days)
    
    # Base query
    query = db.query(TokenUsageLog).filter(TokenUsageLog.created_at >= since)
    if project_id:
        query = query.filter(TokenUsageLog.project_id == project_id)
    
    # Total stats
    total_tokens = db.query(func.sum(TokenUsageLog.total_tokens)).filter(
        TokenUsageLog.created_at >= since
    )
    if project_id:
        total_tokens = total_tokens.filter(TokenUsageLog.project_id == project_id)
    total_tokens = total_tokens.scalar() or 0
    
    total_cost = db.query(func.sum(TokenUsageLog.cost_usd)).filter(
        TokenUsageLog.created_at >= since
    )
    if project_id:
        total_cost = total_cost.filter(TokenUsageLog.project_id == project_id)
    total_cost = total_cost.scalar() or 0
    
    total_calls = db.query(func.count(TokenUsageLog.id)).filter(
        TokenUsageLog.created_at >= since
    )
    if project_id:
        total_calls = total_calls.filter(TokenUsageLog.project_id == project_id)
    total_calls = total_calls.scalar() or 0
    
    # By model
    by_model_query = db.query(
        TokenUsageLog.model,
        func.sum(TokenUsageLog.total_tokens).label('tokens'),
        func.sum(TokenUsageLog.cost_usd).label('cost'),
        func.count(TokenUsageLog.id).label('calls')
    ).filter(TokenUsageLog.created_at >= since)
    
    if project_id:
        by_model_query = by_model_query.filter(TokenUsageLog.project_id == project_id)
    
    by_model = by_model_query.group_by(TokenUsageLog.model).all()
    
    # By provider
    by_provider_query = db.query(
        TokenUsageLog.provider,
        func.sum(TokenUsageLog.total_tokens).label('tokens'),
        func.sum(TokenUsageLog.cost_usd).label('cost'),
        func.count(TokenUsageLog.id).label('calls')
    ).filter(TokenUsageLog.created_at >= since)
    
    if project_id:
        by_provider_query = by_provider_query.filter(TokenUsageLog.project_id == project_id)
    
    by_provider = by_provider_query.group_by(TokenUsageLog.provider).all()
    
    # By profile
    by_profile_query = db.query(
        TokenUsageLog.profile,
        func.sum(TokenUsageLog.total_tokens).label('tokens'),
        func.sum(TokenUsageLog.cost_usd).label('cost'),
        func.count(TokenUsageLog.id).label('calls')
    ).filter(TokenUsageLog.created_at >= since, TokenUsageLog.profile.isnot(None))
    
    if project_id:
        by_profile_query = by_profile_query.filter(TokenUsageLog.project_id == project_id)
    
    by_profile = by_profile_query.group_by(TokenUsageLog.profile).all()
    
    # By project (top 10)
    by_project_query = db.query(
        TokenUsageLog.project_id,
        Project.name,
        func.sum(TokenUsageLog.total_tokens).label('tokens'),
        func.sum(TokenUsageLog.cost_usd).label('cost'),
        func.count(TokenUsageLog.id).label('calls')
    ).join(Project, TokenUsageLog.project_id == Project.id, isouter=True)\
     .filter(TokenUsageLog.created_at >= since, TokenUsageLog.project_id.isnot(None))
    
    if project_id:
        by_project_query = by_project_query.filter(TokenUsageLog.project_id == project_id)
    
    by_project = by_project_query.group_by(TokenUsageLog.project_id, Project.name)\
                                 .order_by(func.sum(TokenUsageLog.cost_usd).desc())\
                                 .limit(10).all()
    
    # Daily trend (last N days)
    daily_query = db.query(
        func.date_trunc('day', TokenUsageLog.created_at).label('day'),
        func.sum(TokenUsageLog.total_tokens).label('tokens'),
        func.sum(TokenUsageLog.cost_usd).label('cost'),
        func.count(TokenUsageLog.id).label('calls')
    ).filter(TokenUsageLog.created_at >= since)
    
    if project_id:
        daily_query = daily_query.filter(TokenUsageLog.project_id == project_id)
    
    daily = daily_query.group_by('day').order_by('day').all()
    
    return {
        "period_days": days,
        "project_id": project_id,
        "totals": {
            "tokens": int(total_tokens),
            "cost_usd": round(float(total_cost), 4),
            "calls": int(total_calls),
            "avg_cost_per_call": round(float(total_cost) / max(total_calls, 1), 4)
        },
        "by_model": [
            {
                "model": row[0],
                "tokens": int(row[1] or 0),
                "cost_usd": round(float(row[2] or 0), 4),
                "calls": int(row[3] or 0)
            }
            for row in by_model
        ],
        "by_provider": [
            {
                "provider": row[0],
                "tokens": int(row[1] or 0),
                "cost_usd": round(float(row[2] or 0), 4),
                "calls": int(row[3] or 0)
            }
            for row in by_provider
        ],
        "by_profile": [
            {
                "profile": row[0] or "unknown",
                "tokens": int(row[1] or 0),
                "cost_usd": round(float(row[2] or 0), 4),
                "calls": int(row[3] or 0)
            }
            for row in by_profile
        ],
        "by_project": [
            {
                "project_id": row[0],
                "project_name": row[1] or "Unknown",
                "tokens": int(row[2] or 0),
                "cost_usd": round(float(row[3] or 0), 4),
                "calls": int(row[4] or 0)
            }
            for row in by_project
        ],
        "daily_trend": [
            {
                "date": row[0].isoformat() if row[0] else None,
                "tokens": int(row[1] or 0),
                "cost_usd": round(float(row[2] or 0), 4),
                "calls": int(row[3] or 0)
            }
            for row in daily
        ]
    }


@app.get("/admin/cost-dashboard", response_class=HTMLResponse)
def cost_dashboard(request: Request, db: Session = Depends(get_db), _auth: bool = Depends(require_admin)):
    """
    Cost tracking dashboard page for the admin panel.
    
    Shows token usage and cost statistics with charts and breakdowns.
    """
    from sqlalchemy import func

    from database.models import TokenUsageLog
    
    # Get stats for last 30 days
    since = datetime.now() - timedelta(days=30)
    
    total_cost = db.query(func.sum(TokenUsageLog.cost_usd)).filter(
        TokenUsageLog.created_at >= since
    ).scalar() or 0
    
    total_tokens = db.query(func.sum(TokenUsageLog.total_tokens)).filter(
        TokenUsageLog.created_at >= since
    ).scalar() or 0
    
    total_calls = db.query(func.count(TokenUsageLog.id)).filter(
        TokenUsageLog.created_at >= since
    ).scalar() or 0
    
    # By model (top 5)
    by_model = db.query(
        TokenUsageLog.model,
        func.sum(TokenUsageLog.cost_usd).label('cost')
    ).filter(TokenUsageLog.created_at >= since)\
     .group_by(TokenUsageLog.model)\
     .order_by(func.sum(TokenUsageLog.cost_usd).desc())\
     .limit(5).all()
    
    model_chart_data = [{"name": row[0], "value": float(row[1] or 0)} for row in by_model]
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cost Dashboard - Hound Admin</title>
        <style>
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 1400px;
                margin: 0 auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 12px;
                margin-bottom: 20px;
            }}
            .back-link {{
                color: white;
                text-decoration: none;
                opacity: 0.8;
            }}
            .back-link:hover {{ opacity: 1; }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: white;
                padding: 25px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .stat-value {{
                font-size: 36px;
                font-weight: bold;
                color: #667eea;
                margin: 10px 0;
            }}
            .stat-label {{
                color: #666;
                font-size: 14px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
            .card {{
                background: white;
                padding: 25px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #eee;
            }}
            th {{
                background: #f8f9fa;
                font-weight: 600;
            }}
            .cost {{
                color: #28a745;
                font-weight: bold;
            }}
            .btn {{
                display: inline-block;
                padding: 10px 20px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 6px;
                margin: 4px;
            }}
            .btn:hover {{ background: #5a67d8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <a href="/admin" class="back-link">← Back to Admin</a>
            <h1 style="margin: 12px 0 0 0;">💰 Cost Dashboard</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9;">LLM Token Usage & Cost Tracking (Last 30 Days)</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Cost</div>
                <div class="stat-value">${total_cost:.2f}</div>
                <div style="color: #666; font-size: 12px;">Last 30 days</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Total Tokens</div>
                <div class="stat-value">{total_tokens:,}</div>
                <div style="color: #666; font-size: 12px;">{total_calls:,} API calls</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Avg Cost/Call</div>
                <div class="stat-value">${(total_cost / max(total_calls, 1)):.4f}</div>
                <div style="color: #666; font-size: 12px;">Per API request</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Top Models by Cost</h2>
            <table>
                <thead>
                    <tr>
                        <th>Model</th>
                        <th>Cost (USD)</th>
                        <th>% of Total</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join([
                        f'<tr><td>{row["name"]}</td><td class="cost">${row["value"]:.4f}</td><td>{(row["value"] / max(total_cost, 0.0001) * 100):.1f}%</td></tr>'
                        for row in model_chart_data
                    ])}
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <h2>Quick Actions</h2>
            <a href="/admin/token-usage-log/list" class="btn">View All Token Logs</a>
            <a href="/admin/token-stats?days=30" class="btn">API Stats (JSON)</a>
            <a href="/admin/project/list" class="btn">View Projects</a>
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


@app.get("/admin/scan-findings/{scan_id}", response_class=HTMLResponse)
def view_scan_findings(scan_id: int, request: Request, db: Session = Depends(get_db), _auth: bool = Depends(require_admin)):
    """
    View scan findings in a detailed HTML page.
    
    This is linked from the admin panel to show full finding details.
    """
    scan = db.query(ScanExecution).filter(ScanExecution.id == scan_id).first()
    if not scan:
        return HTMLResponse(content="<h1>Scan not found</h1>", status_code=404)
    
    # Handle findings - support both flat list and severity-grouped dict structure
    findings_list = []
    if scan.findings:
        if isinstance(scan.findings, list):
            # Old format: flat list
            findings_list = scan.findings
        elif isinstance(scan.findings, dict):
            # New format: grouped by severity
            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity in scan.findings:
                    for finding in scan.findings[severity]:
                        if isinstance(finding, dict):
                            # Ensure severity is set
                            finding['severity'] = severity
                            findings_list.append(finding)
    
    # Build HTML for findings
    findings_html = ""
    for i, finding in enumerate(findings_list, 1):
        severity = finding.get("severity", "info")
        severity_color = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107", 
            "low": "#17a2b8",
            "info": "#6c757d",
        }.get(severity, "#6c757d")
        
        findings_html += f"""
        <div style="border: 1px solid #ddd; border-left: 4px solid {severity_color}; 
                    border-radius: 4px; padding: 16px; margin: 12px 0;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h3 style="margin: 0; color: #333;">{i}. {finding.get('title', 'Untitled')}</h3>
                <span style="background: {severity_color}; color: white; padding: 4px 12px; 
                            border-radius: 4px; font-weight: bold; text-transform: uppercase;">
                    {severity}
                </span>
            </div>
            <p style="margin: 12px 0; color: #666;">{finding.get('description', '')}</p>
            <div style="background: #f8f9fa; padding: 12px; border-radius: 4px; margin: 8px 0;">
                <strong>Location:</strong> <code>{finding.get('contract', finding.get('location', 'N/A'))}</code>
                {f" - Line {finding.get('line')}" if finding.get('line') else ""}
            </div>
            <div style="margin-top: 8px;">
                <strong>Recommendation:</strong> {finding.get('recommendation', finding.get('impact', 'N/A'))}
            </div>
            <div style="margin-top: 8px;">
                <strong>ID:</strong> {finding.get('id', finding.get('category', 'N/A'))}
            </div>
            <div style="margin-top: 8px;">
                <strong>Confidence:</strong> {finding.get('confidence', 0) * 100:.0f}%
            </div>
        </div>
        """
    
    if not findings_html:
        findings_html = "<p style='color: #666; font-style: italic;'>No findings recorded for this scan.</p>"
    
    # Quality metrics
    qm = scan.quality_metrics or {}
    quality_html = ""
    if qm:
        quality_html = f"""
        <div style="background: #e9ecef; padding: 16px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin: 0 0 12px 0;">Quality Metrics</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 12px;">
                <div><strong>Contracts Analyzed:</strong> {qm.get('contracts_analyzed', 0)}</div>
                <div><strong>Functions Analyzed:</strong> {qm.get('functions_analyzed', 0)}</div>
                <div><strong>Total Lines:</strong> {qm.get('total_lines', 0)}</div>
                <div><strong>Has Tests:</strong> {'✅' if qm.get('has_tests') else '❌'}</div>
                <div><strong>Has Docs:</strong> {'✅' if qm.get('has_documentation') else '❌'}</div>
                <div><strong>Language:</strong> {qm.get('primary_language', 'Unknown')}</div>
            </div>
        </div>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Scan Findings - {scan.repo_name}</title>
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 1200px; 
                margin: 0 auto; 
                padding: 20px;
                background: #f5f5f5;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 12px;
                margin-bottom: 20px;
            }}
            .back-link {{
                color: white;
                text-decoration: none;
                opacity: 0.8;
            }}
            .back-link:hover {{ opacity: 1; }}
            .card {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
                gap: 16px;
                margin: 20px 0;
            }}
            .stat-box {{
                background: white;
                padding: 20px;
                border-radius: 8px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .stat-value {{ font-size: 32px; font-weight: bold; color: #333; }}
            .stat-label {{ color: #666; margin-top: 4px; }}
            code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
            .action-btn {{
                display: inline-block;
                padding: 10px 20px;
                background: #667eea;
                color: white;
                text-decoration: none;
                border-radius: 6px;
                margin: 4px;
            }}
            .action-btn:hover {{ background: #5a67d8; }}
            .action-btn.success {{ background: #28a745; }}
            .action-btn.success:hover {{ background: #218838; }}
        </style>
    </head>
    <body>
        <div class="header">
            <a href="/admin/scan-execution/list" class="back-link">← Back to Scans</a>
            <h1 style="margin: 12px 0 0 0;">{scan.repo_name}</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9;">
                {scan.repo_url or 'No URL'} • 
                Scanned {scan.created_at.strftime('%Y-%m-%d %H:%M') if scan.created_at else 'N/A'}
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value" style="color: {'#dc3545' if (scan.risk_score or 0) >= 70 else '#ffc107' if (scan.risk_score or 0) >= 40 else '#28a745'};">
                    {scan.risk_score or 0}
                </div>
                <div class="stat-label">Risk Score</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(scan.findings or [])}</div>
                <div class="stat-label">Findings</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{scan.contracts_scanned or 0}</div>
                <div class="stat-label">Contracts Scanned</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{scan.risk_level or 'N/A'}</div>
                <div class="stat-label">Risk Level</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Summary</h2>
            <p>{scan.summary or 'No summary available.'}</p>
            {quality_html}
        </div>
        
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <h2 style="margin: 0;">Findings ({len(scan.findings or [])})</h2>
                <div>
                    <a href="/admin/scan-execution/details/{scan.id}" class="action-btn">View in Admin</a>
                    {'<a href="/admin/project/details/' + str(scan.project_id) + '" class="action-btn success">View Project</a>' if scan.project_id else '<a href="/admin/scan-execution/list?pks=' + str(scan.id) + '&action=convert_to_project" class="action-btn success">Convert to Project</a>'}
                </div>
            </div>
            {findings_html}
        </div>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


# WebSocket endpoint for live audit logs
class ConnectionManager:
    """Manage WebSocket connections for live audit log streaming."""

    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str):
        """Accept a new WebSocket connection for a session."""
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)

    def disconnect(self, websocket: WebSocket, session_id: str):
        """Remove a WebSocket connection."""
        if session_id in self.active_connections:
            self.active_connections[session_id].remove(websocket)
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]

    async def send_message(self, message: str, session_id: str):
        """Send a message to all connections for a session."""
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                await connection.send_text(message)

    async def broadcast(self, message: dict, session_id: str):
        """Broadcast a JSON message to all connections for a session."""
        if session_id in self.active_connections:
            message_text = json.dumps(message)
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_text(message_text)
                except Exception:
                    pass  # Connection closed, will be cleaned up


manager_ws = ConnectionManager()

# Redis configuration
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


async def redis_subscriber(websocket: WebSocket, session_id: str):
    """
    Subscribe to Redis Pub/Sub channel and forward messages to WebSocket.
    
    This runs as a background task that listens to the Redis channel
    for this session and forwards all messages to the WebSocket client.
    """
    try:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        pubsub = redis_client.pubsub()
        
        # Subscribe to the session channel (matches worker/redis_publisher.py)
        # Publisher uses both updates and status channels
        channel_updates = f"audit:updates:{session_id}"
        channel_status = f"audit:status:{session_id}"
        
        await pubsub.subscribe(channel_updates, channel_status)
        
        logger.info(f"Subscribed to Redis channels: {channel_updates}, {channel_status}")
        
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                except json.JSONDecodeError:
                    # Forward raw message if not JSON
                    await websocket.send_text(message["data"])
                except Exception as e:
                    logger.error(f"Error sending to WebSocket: {e}")
                    break
                    
    except Exception as e:
        logger.error(f"Redis subscriber error for {session_id}: {e}")
    finally:
        try:
            await pubsub.unsubscribe(channel_updates, channel_status)
            await redis_client.close()
        except Exception:
            pass


@app.websocket("/ws/sessions/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for streaming live audit progress.
    
    This endpoint:
    1. Accepts a WebSocket connection
    2. Subscribes to the Redis Pub/Sub channel for this session
    3. Forwards all messages from the worker to the client in real-time
    
    The worker (worker/tasks.py) publishes progress updates to Redis
    using the RedisPublisher class. This endpoint acts as a bridge
    between Redis and the browser.
    
    Message types (from RedisPublisher):
        - status: Overall audit status (queued, running, completed, failed)
        - thought: Agent's current thinking/analysis
        - decision: Agent's action decision
        - action_start: Action execution started
        - action_result: Action execution completed
        - error: Error occurred
        
    Example client usage:
        const ws = new WebSocket('ws://localhost:8000/ws/sessions/abc123');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            console.log(data.type, data.message);
        };
    """
    await manager_ws.connect(websocket, session_id)
    redis_task = None

    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "session_id": session_id,
            "message": "WebSocket connection established. Subscribing to audit updates...",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Start Redis subscriber as a background task
        redis_task = asyncio.create_task(redis_subscriber(websocket, session_id))
        
        # Keep connection alive - listen for client pings/messages
        while True:
            try:
                # Wait for client messages (ping/pong or commands)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                
                # Handle ping
                if data == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    
            except asyncio.TimeoutError:
                # Send keepalive ping
                try:
                    await websocket.send_json({
                        "type": "keepalive",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                except Exception:
                    break

    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error for session {session_id}: {e}")
    finally:
        # Clean up
        if redis_task:
            redis_task.cancel()
            try:
                await redis_task
            except asyncio.CancelledError:
                pass
        manager_ws.disconnect(websocket, session_id)


# ============================================================================
# CONFIG PROFILE MANAGEMENT
# ============================================================================

# Global active config profile (can be overridden per-tenant in future)
_active_config_profile: str = "default"
_config_cache: dict = {}

def get_available_config_profiles() -> list[dict]:
    """Get list of available config profiles."""
    from pathlib import Path

    import yaml
    
    hound_dir = Path(__file__).parent.parent
    profiles = []
    
    # Look for config files
    config_files = [
        ("default", "config.yaml", "Default configuration"),
        ("deepseek", "config.deepseek.yaml", "DeepSeek only - 95% cost savings"),
        ("premium", "config.premium.yaml", "Premium models - best quality"),
        ("example", "config.yaml.example", "Example configuration template"),
    ]
    
    for profile_id, filename, description in config_files:
        config_path = hound_dir / filename
        if config_path.exists():
            try:
                with open(config_path) as f:
                    cfg = yaml.safe_load(f) or {}
                
                # Extract model info
                models = cfg.get("models", {})
                model_summary = {}
                for profile_name, settings in models.items():
                    provider = settings.get("provider", "unknown")
                    model = settings.get("model", "unknown")
                    model_summary[profile_name] = f"{provider}/{model}"
                
                profiles.append({
                    "id": profile_id,
                    "filename": filename,
                    "description": description,
                    "path": str(config_path),
                    "models": model_summary,
                    "exists": True
                })
            except Exception as e:
                profiles.append({
                    "id": profile_id,
                    "filename": filename,
                    "description": description,
                    "path": str(config_path),
                    "error": str(e),
                    "exists": True
                })
    
    return profiles


def load_config_profile(profile_id: str) -> dict:
    """Load a specific config profile."""
    from pathlib import Path

    import yaml
    
    # Check cache
    if profile_id in _config_cache:
        return _config_cache[profile_id]
    
    hound_dir = Path(__file__).parent.parent
    
    profile_files = {
        "default": "config.yaml",
        "deepseek": "config.deepseek.yaml",
        "premium": "config.premium.yaml",
        "example": "config.yaml.example",
    }
    
    filename = profile_files.get(profile_id, f"config.{profile_id}.yaml")
    config_path = hound_dir / filename
    
    # Fallback chain
    if not config_path.exists():
        # Try default config.yaml
        config_path = hound_dir / "config.yaml"
    if not config_path.exists():
        # Try example
        config_path = hound_dir / "config.yaml.example"
    if not config_path.exists():
        return {}
    
    with open(config_path) as f:
        config = yaml.safe_load(f) or {}
    
    _config_cache[profile_id] = config
    return config


def get_active_config() -> dict:
    """Get the currently active config."""
    return load_config_profile(_active_config_profile)


@app.get("/config/profiles")
async def list_config_profiles():
    """
    List available LLM configuration profiles.
    
    Returns all config profiles with their model configurations.
    Use this to see what profiles are available and switch between them.
    """
    global _active_config_profile
    
    profiles = get_available_config_profiles()
    
    return {
        "active_profile": _active_config_profile,
        "profiles": profiles
    }


@app.post("/config/profiles/{profile_id}/activate")
async def activate_config_profile(profile_id: str):
    """
    Activate a specific config profile for all API operations.
    
    This changes which LLM models are used for scans, graph building, and audits.
    
    Available profiles:
    - default: Your main config.yaml
    - deepseek: Cost-effective DeepSeek models (~95% savings)
    - premium: Best quality models (GPT-5, Claude, Gemini)
    """
    global _active_config_profile, _config_cache
    
    profiles = get_available_config_profiles()
    profile_ids = [p["id"] for p in profiles]
    
    if profile_id not in profile_ids:
        raise HTTPException(
            status_code=404,
            detail=f"Profile '{profile_id}' not found. Available: {profile_ids}"
        )
    
    # Clear cache to reload config
    _config_cache.clear()
    _active_config_profile = profile_id
    
    # Load and return the new config summary
    config = load_config_profile(profile_id)
    models = config.get("models", {})
    
    return {
        "status": "success",
        "active_profile": profile_id,
        "models": {
            name: f"{cfg.get('provider', 'unknown')}/{cfg.get('model', 'unknown')}"
            for name, cfg in models.items()
        }
    }


@app.get("/config/active")
async def get_active_config_info():
    """
    Get the currently active configuration profile and its settings.
    """
    global _active_config_profile
    
    config = get_active_config()
    models = config.get("models", {})
    
    return {
        "active_profile": _active_config_profile,
        "models": {
            name: {
                "provider": cfg.get("provider", "unknown"),
                "model": cfg.get("model", "unknown"),
                "max_context": cfg.get("max_context"),
                "temperature": cfg.get("temperature")
            }
            for name, cfg in models.items()
        },
        "context": config.get("context", {}),
        "timeouts": config.get("timeouts", {}),
        "retries": config.get("retries", {})
    }


# ============================================================================
# AUTH ENDPOINTS - GitHub App Waitlist Flow
# ============================================================================


class AuthStartRequest(BaseModel):
    """Request model for starting OAuth flow."""
    email: str | None = None


class AuthStartResponse(BaseModel):
    """Response model for auth start endpoint."""
    state_token: str
    install_url: str


class AuthCompleteRequest(BaseModel):
    """Request model for completing OAuth flow."""
    installation_id: int
    state_token: str


class AuthCompleteResponse(BaseModel):
    """Response model for auth complete endpoint."""
    success: bool
    tenant_id: int
    message: str


def get_auth_redis_client():
    """Get async Redis client for state token storage."""
    return aioredis.from_url(REDIS_URL, decode_responses=True)


@app.post("/auth/start", response_model=AuthStartResponse)
@limiter.limit("20/minute")
async def auth_start(request: Request, body: AuthStartRequest):
    """
    Start the GitHub App installation flow.

    Generates a state token and stores the optional email in Redis.
    Returns the state token and GitHub App install URL.

    The frontend should redirect the user to the install_url.
    """
    # Generate opaque state token
    state_token = secrets.token_urlsafe(32)

    # Store in Redis with 10 minute TTL
    redis_client = get_auth_redis_client()
    try:
        state_data = json.dumps({
            "email": body.email,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        await redis_client.setex(f"auth_state:{state_token}", 600, state_data)
        logger.info(f"AUTH_START: Generated token={state_token[:20]}... email={body.email}")
    finally:
        await redis_client.aclose()

    # Build GitHub App install URL with state
    install_url = f"https://github.com/apps/{GITHUB_APP_SLUG}/installations/new?state={state_token}"

    return AuthStartResponse(
        state_token=state_token,
        install_url=install_url,
    )


@app.post("/auth/complete", response_model=AuthCompleteResponse)
@limiter.limit("10/minute")
async def auth_complete(request: Request, body: AuthCompleteRequest, db: Session = Depends(get_db)):
    """
    Complete the GitHub App installation flow.

    Called by the frontend after GitHub redirects back with installation_id.
    Validates the state token, creates or updates the Tenant, and stores the email.

    Security:
    - State token is one-time use (deleted after validation)
    - Rate limited to 10 requests/minute per IP
    """
    # Lookup and validate state token in Redis
    logger.info(f"AUTH_COMPLETE: Received token={body.state_token[:20]}... installation_id={body.installation_id}")
    redis_client = get_auth_redis_client()
    try:
        state_key = f"auth_state:{body.state_token}"
        state_data_raw = await redis_client.get(state_key)

        if not state_data_raw:
            logger.warning(f"AUTH_COMPLETE: Token NOT FOUND in Redis: {body.state_token[:20]}...")
            raise HTTPException(status_code=400, detail="Invalid or expired state token")

        # Delete token immediately (one-time use, prevent replay)
        await redis_client.delete(state_key)

        state_data = json.loads(state_data_raw)
        email = state_data.get("email")
    finally:
        await redis_client.aclose()

    # Fetch installation details from GitHub API to verify it exists
    repos_list = []
    try:
        from integrations.github_app import get_github_app_integration
        integration = get_github_app_integration()
        # Use get_app_installation() with installation ID
        installation = integration.get_app_installation(body.installation_id)
        account_login = installation.account.login
        account_type = installation.account.type

        # Fetch repos (limit to first 10 for notification)
        try:
            import requests
            access_token = integration.get_access_token(body.installation_id)
            headers = {"Authorization": f"Bearer {access_token.token}", "Accept": "application/vnd.github+json"}
            response = requests.get("https://api.github.com/installation/repositories", headers=headers)
            data = response.json()
            total_count = data.get("total_count", 0)
            for i, repo in enumerate(data.get("repositories", [])):
                if i >= 10:
                    repos_list.append(f"... and {total_count - 10} more")
                    break
                repos_list.append(repo["full_name"])
        except Exception as repo_err:
            logger.warning(f"Failed to fetch repos for installation {body.installation_id}: {repo_err}")
    except Exception as e:
        logger.warning(f"Failed to fetch installation {body.installation_id}: {e}")
        # Installation might exist but we can't verify - proceed with limited info
        account_login = f"installation_{body.installation_id}"
        account_type = "Unknown"

    # firepan-bv21: if the caller is a logged-in OAuth user, prefer attaching
    # the installation to THEIR tenant. This catches the case where webhook
    # ordering or a Webhook delivery failure left tenant 78 (org) orphaned
    # while tenant 77 (user) had no installation_id. Belt-and-suspenders to
    # the sender-based webhook bridge above.
    jwt_user_tenant: Tenant | None = None
    try:
        from server.auth_routes import get_token_from_header
        from server.auth_utils import get_current_user_from_token
        token = get_token_from_header(request)
        if token:
            payload = get_current_user_from_token(token)
            jwt_tenant_id = payload.get("tenant_id")
            if jwt_tenant_id:
                jwt_user_tenant = db.query(Tenant).filter(Tenant.id == jwt_tenant_id).first()
    except Exception:
        # No JWT or invalid token — fall through to webhook-style resolution.
        jwt_user_tenant = None

    # Find or create Tenant (webhook may have already created it)
    # Check by installation_id first, then by account name (handles reinstalls with new installation_id)
    tenant = db.query(Tenant).filter_by(installation_id=body.installation_id).first()

    # firepan-bv21: if the JWT user's tenant exists and has no install yet,
    # bridge here even if the webhook already minted a separate orphan tenant.
    # Mark the orphan as merged so it doesn't accumulate state.
    if jwt_user_tenant and not jwt_user_tenant.installation_id:
        orphan = tenant if tenant and tenant.id != jwt_user_tenant.id else None
        jwt_user_tenant.installation_id = body.installation_id
        if account_login and not account_login.startswith("installation_"):
            jwt_user_tenant.github_account_login = (
                jwt_user_tenant.github_account_login or account_login
            )
            jwt_user_tenant.github_account_type = (
                jwt_user_tenant.github_account_type or account_type
            )
        if jwt_user_tenant.status == "pending":
            jwt_user_tenant.status = "active"
        if orphan:
            # Strip installation_id from the orphan so future queries route to
            # the JWT user's tenant. Leave status untouched — changing it can
            # cascade to billing/tier_enforcement; clearing the install is
            # sufficient to make this row inert for new scans.
            orphan.installation_id = None
            logger.info(
                "Bridged installation %s from orphan tenant %s to user tenant %s via JWT",
                body.installation_id, orphan.id, jwt_user_tenant.id,
            )
        tenant = jwt_user_tenant

    if not tenant and account_login and not account_login.startswith("installation_"):
        # Check if tenant exists by name (reinstall case - new installation_id for same account)
        tenant = db.query(Tenant).filter_by(name=f"github_{account_login}").first()
        if tenant:
            # Update installation_id to the new one
            tenant.installation_id = body.installation_id
            logger.info(f"Updated tenant {tenant.id} with new installation_id {body.installation_id}")

    if not tenant:
        # Create new tenant
        tenant = Tenant(
            name=f"github_{account_login}",
            installation_id=body.installation_id,
            status="pending",
            github_account_login=account_login,
            github_account_type=account_type,
        )
        db.add(tenant)
        db.flush()
        logger.info(f"Created pending tenant {tenant.id} for installation {body.installation_id}")
    else:
        # Update GitHub account info if we have better data
        if account_login and not account_login.startswith("installation_"):
            tenant.github_account_login = account_login
            tenant.github_account_type = account_type
        logger.info(f"Found existing tenant {tenant.id} for installation {body.installation_id}")

    # Update contact email if provided
    if email:
        tenant.contact_email = email

    db.commit()

    # Send Telegram notification (fire-and-forget, don't block response)
    try:
        await notify_new_repo_synced(
            github_account=tenant.github_account_login or f"installation_{body.installation_id}",
            account_type=tenant.github_account_type or "Unknown",
            email=email,
            tenant_id=tenant.id,
            installation_id=body.installation_id,
            repos=repos_list,
        )
    except Exception as e:
        # Don't fail the request if notification fails
        logger.warning(f"Failed to send Telegram notification: {e}")

    return AuthCompleteResponse(
        success=True,
        tenant_id=tenant.id,
        message="You're on the waitlist! We'll review your application and be in touch.",
    )


# --------------------------------------------------------------------------
# Page view beacon (funnel analytics)
# --------------------------------------------------------------------------
@app.post("/t", status_code=204)
@limiter.limit("20/minute")
async def track_page_view(request: Request, db: Session = Depends(get_db)):
    """Lightweight page view beacon. No auth required."""
    # Origin check: strict hostname match
    origin = request.headers.get("origin", "")
    if origin:
        try:
            from urllib.parse import urlparse
            host = urlparse(origin).hostname or ""
            if host != "firepan.com" and not host.endswith(".firepan.com"):
                return Response(status_code=204)
        except Exception:
            return Response(status_code=204)

    try:
        body = await request.json()
    except Exception:
        return Response(status_code=204)

    path = str(body.get("p", ""))[:500]
    if not path.startswith("/"):
        return Response(status_code=204)

    vid = str(body.get("v", ""))[:64]
    if vid and (len(vid) < 20 or not all(c.isalnum() or c == '-' for c in vid)):
        vid = None

    page_view = PageView(
        path=path,
        referrer=str(body.get("r", ""))[:1000] or None,
        user_agent=str(request.headers.get("user-agent", ""))[:500] or None,
        visitor_id=vid or None,
    )
    db.add(page_view)
    db.commit()
    return Response(status_code=204)


# Stripe webhook health check
@app.get("/health/stripe")
async def stripe_webhook_health(db: Session = Depends(get_db)):
    """Check Stripe webhook configuration and last processed event."""
    from server.stripe_routes import STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET

    issues = []
    if not STRIPE_WEBHOOK_SECRET:
        issues.append("STRIPE_WEBHOOK_SECRET not configured")
    if not STRIPE_SECRET_KEY:
        issues.append("STRIPE_SECRET_KEY not configured")

    raw_latest = db.execute(text(
        "SELECT MAX(processed_at) FROM stripe_processed_events"
    )).scalar()

    # Parse timestamp — Postgres returns datetime, SQLite returns string
    latest = None
    if raw_latest is not None:
        if isinstance(raw_latest, str):
            latest = datetime.fromisoformat(raw_latest)
        else:
            latest = raw_latest
        if latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)

    # Live probe: POST to the webhook endpoint with a dummy payload.
    # A healthy webhook returns 400 "Invalid Stripe signature" (signature check active).
    # Anything else (404, 500, crash) means the endpoint is broken.
    webhook_probe = {"status": "unknown", "detail": "not tested"}
    try:
        from starlette.testclient import TestClient
        probe_client = TestClient(app, raise_server_exceptions=False)
        probe_resp = probe_client.post(
            "/webhooks/stripe",
            content=b'{"type":"health_probe"}',
            headers={"Content-Type": "application/json", "Stripe-Signature": "t=0,v1=probe"},
        )
        if probe_resp.status_code == 400 and "signature" in probe_resp.text.lower():
            webhook_probe = {"status": "ok", "detail": "Signature verification active"}
        else:
            webhook_probe = {
                "status": "error",
                "detail": f"Unexpected response: {probe_resp.status_code} {probe_resp.text[:200]}",
            }
            issues.append(f"Webhook probe returned {probe_resp.status_code} instead of 400")
    except Exception as e:
        webhook_probe = {"status": "error", "detail": str(e)[:200]}
        issues.append(f"Webhook probe failed: {e}")

    result = {
        "config_ok": len(issues) == 0,
        "issues": issues,
        "webhook_probe": webhook_probe,
        "last_event_processed": latest.isoformat() if latest else None,
    }

    if latest:
        age_days = (datetime.now(timezone.utc) - latest).days
        result["last_event_days_ago"] = age_days

    return result


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint.

    Returns the current server status and timestamp. Used by load balancers
    and monitoring systems to verify the server is running and responsive.

    Returns:
        dict: Status and UTC timestamp
    """
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.get("/health/db")
async def database_health(db: Session = Depends(get_db)):
    """
    Check database connection.
    
    Returns the database connection status. Used to verify that the database
    is accessible and queries can be executed.
    
    Returns:
        dict: Status and database connection state
    """
    try:
        # Try a simple query
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        # Log the full exception but return generic message to client
        logger.error(f"Database health check failed: {str(e)}")
        return {"status": "unhealthy", "database": "connection_failed"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
