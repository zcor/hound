"""
Tier enforcement dependency for FastAPI endpoints.

Checks plan limits before allowing scan/audit operations.
Uses atomic SQL operations to prevent race conditions on credit consumption.

Usage:
    @app.post("/repositories/{repository_id}/scan")
    async def trigger_scan(
        ...,
        allowance: dict = Depends(require_plan_allowance("scan")),
    ):
        # allowance = {"uses_credit": bool}
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from database.models import ScanExecution, Tenant

logger = logging.getLogger(__name__)


def _as_utc(dt: datetime) -> datetime:
    """Normalize naive DB timestamps to UTC for safe comparisons."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_trial_active(tenant: Tenant) -> bool:
    """Return True when a tenant has an unexpired active trial."""
    if tenant.trial_ends_at and tenant.trial_plan:
        return datetime.now(timezone.utc) < _as_utc(tenant.trial_ends_at)
    return False


def get_effective_plan(tenant: Tenant) -> str:
    """Return the effective plan. Precedence: paid > active trial > free."""
    if tenant.stripe_subscription_id and tenant.plan not in (None, "free"):
        return tenant.plan
    if is_trial_active(tenant):
        return tenant.trial_plan or "free"
    return tenant.plan or "free"


def has_paid_subscription(tenant: Tenant) -> bool:
    """Canonical check: does this tenant have an active paid subscription or trial?"""
    if tenant.stripe_subscription_id and tenant.plan not in (None, "free"):
        return True
    return is_trial_active(tenant)


def is_genuinely_paid(tenant: Tenant) -> bool:
    """True ONLY for a real Stripe-paid subscription — NOT auto-trials.

    Distinct from has_paid_subscription(), which counts active trials. The
    auto-14-day-starter-trial granted on every signup makes has_paid_subscription
    True for ~every fresh tenant; this excludes that so trial users do NOT get
    the (expensive) Claude SingleAuditor pipeline. See firepan-sewd.
    """
    return bool(tenant.stripe_subscription_id) and tenant.plan not in (None, "free")


def claude_audit_allowed(tenant: Tenant) -> bool:
    """Entitlement gate for the Claude SingleAuditor (mode=auditor) pipeline.

    Policy (firepan-sewd, Gerrit 2026-05-19): Claude deep audits are gated to
    genuinely-Stripe-paid tenants OR an explicit per-tenant allowlist flag.
    Auto-trial tenants are NOT grandfathered in. Everyone else is downgraded
    to the DeepSeek 'sweep' pipeline at the dispatch chokepoint. The admin
    force-run path bypasses this entirely (explicit-provision mechanism).
    """
    if getattr(tenant, "claude_audit_enabled", False):
        return True
    return is_genuinely_paid(tenant)
def _load_plans() -> dict:
    """Load plan config from stripe_plans.json."""
    config_path = Path(__file__).parent.parent / "config" / "stripe_plans.json"
    with open(config_path) as f:
        data = json.load(f)
    # Merge plans + free into a flat dict keyed by plan name
    result = {}
    for key, plan in data["plans"].items():
        result[key] = plan
    result["free"] = data["free"]
    return result


def require_plan_allowance(operation: str):
    """
    FastAPI dependency factory that checks plan limits.

    Args:
        operation: "scan" or "audit"

    Returns:
        A dependency function returning {"uses_credit": bool}
    """
    async def _check(
        request: Request,
        db: Session = Depends(lambda: None),  # Placeholder — overridden below
    ) -> dict:
        from server.api import get_current_tenant_id as _get_tid, get_db as _get_db

        tenant_id = await _get_tid(request)

        # Get a proper DB session
        engine_db = next(_get_db())
        try:
            return _check_sync(tenant_id, operation, engine_db)
        finally:
            engine_db.close()

    # Use proper FastAPI DI instead of manual session management
    async def _check_with_di(
        request: Request,
    ) -> dict:
        from server.api import get_current_tenant_id as _get_tid, get_engine

        tenant_id = await _get_tid(request)

        from database.models import create_db_session
        engine = get_engine()
        db = create_db_session(engine)
        try:
            return _check_sync(tenant_id, operation, db)
        finally:
            db.close()

    return _check_with_di


def _check_sync(
    tenant_id: int,
    operation: str,
    db: Session,
    *,
    bypass_quota: bool = False,
) -> dict:
    """Synchronous plan check with atomic credit reservation.

    bypass_quota=True skips both monthly-limit and scan-credit enforcement.
    Reserved for admin-authenticated callers (firepan-1bg) — never reachable
    from tenant-facing paths.
    """
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(404, "Tenant not found")

    if bypass_quota:
        return {"uses_credit": False, "admin_bypass": True}

    plans = _load_plans()
    effective_plan = get_effective_plan(tenant)
    plan_config = plans.get(effective_plan, plans["free"])
    limits = plan_config.get("limits", {})

    if operation == "scan":
        # Use timezone-aware month boundary
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Count non-failed scans this month
        scan_count = db.query(ScanExecution).filter(
            ScanExecution.tenant_id == tenant_id,
            ScanExecution.created_at >= month_start,
            ScanExecution.status.notin_(["failed", "error"]),
        ).count()

        base_limit = limits.get("scans_per_month", 0)

        if scan_count < base_limit:
            return {"uses_credit": False}

        # Over base limit — try consuming a credit atomically
        rows = db.execute(
            text("UPDATE tenants SET scan_credits = scan_credits - 1 WHERE id = :tid AND scan_credits > 0"),
            {"tid": tenant_id},
        )
        db.commit()

        if rows.rowcount == 0:
            raise HTTPException(403, {
                "error": "scan_limit_reached",
                "limit": base_limit,
                "credits_remaining": 0,
                "message": "Upgrade your plan or purchase credits to continue scanning",
            })
        return {"uses_credit": True}

    elif operation == "audit":
        from database.models import AuditSession, Project
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Tenant-scoped: only count successful audits (failed/error don't consume quota)
        tenant_project_ids = db.query(Project.id).filter(Project.tenant_id == tenant_id).subquery()
        audit_count = db.query(AuditSession).filter(
            AuditSession.project_id.in_(tenant_project_ids),
            AuditSession.start_time >= month_start,
            AuditSession.status.notin_(["failed", "error"]),
        ).count()

        base_limit = limits.get("audits_per_month", 0)

        if audit_count >= base_limit:
            raise HTTPException(403, {
                "error": "audit_limit_reached",
                "limit": base_limit,
                "message": "Upgrade your plan to run more audits",
            })
        return {"uses_credit": False}

    return {"uses_credit": False}


def refund_scan_credit(db: Session, tenant_id: int, scan_execution_id: str):
    """
    Refund a credit exactly once, tied to a specific failed scan execution.

    Uses INSERT ... ON CONFLICT DO NOTHING as the concurrency gate.
    Only the INSERT winner proceeds to refund — losers get rowcount=0.
    """
    result = db.execute(
        text("""
            INSERT INTO credit_refunds (scan_execution_id, tenant_id)
            VALUES (:sid, :tid)
            ON CONFLICT (scan_execution_id) DO NOTHING
        """),
        {"sid": scan_execution_id, "tid": tenant_id},
    )
    if result.rowcount == 0:
        return  # Already refunded

    db.execute(
        text("UPDATE tenants SET scan_credits = scan_credits + 1 WHERE id = :tid"),
        {"tid": tenant_id},
    )
    db.commit()
    logger.info("Refunded scan credit for tenant %d (scan %s)", tenant_id, scan_execution_id)
