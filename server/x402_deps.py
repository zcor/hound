"""
x402 payment dependency for FastAPI endpoints.

Used as a library dependency (NOT middleware) to guarantee auth (401) runs
before payment (402). The x402 SDK is called directly for verify/settle.

Usage in endpoints:
    @app.post("/surface/scan/full")
    async def full_scan(
        ...,
        gate: PaymentGate = Depends(require_payment("POST /surface/scan/full")),
    ):
        if gate.status == "already_processed":
            return {"job_id": gate.job_id, "status": "already_processed"}
        job = await run_full_scan(...)
        if gate.enabled and gate.payment_log_id:
            create_paid_job(db, gate.payment_log_id, job.id)
        return {"job_id": job.id}
"""

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal

from fastapi import Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database.models import PaymentLog
from server.x402_config import get_config, x402_enabled

logger = logging.getLogger(__name__)


# =============================================================================
# Payment State Machine
# =============================================================================

class PaymentStatus:
    RESERVED = "reserved"
    PAID = "paid"
    JOB_CREATED = "job_created"
    JOB_FAILED = "job_failed"
    EXPIRED = "expired"


LEGAL_TRANSITIONS = {
    PaymentStatus.RESERVED: {PaymentStatus.PAID, PaymentStatus.EXPIRED},
    PaymentStatus.EXPIRED: {PaymentStatus.RESERVED},
    PaymentStatus.PAID: {PaymentStatus.JOB_CREATED, PaymentStatus.JOB_FAILED},
    PaymentStatus.JOB_FAILED: {PaymentStatus.PAID},
}


def transition(log: PaymentLog, new_status: str, db: Session):
    """Enforce legal status transitions. Raises ValueError on illegal transition."""
    allowed = LEGAL_TRANSITIONS.get(log.status, set())
    if new_status not in allowed:
        raise ValueError(f"Illegal transition: {log.status} -> {new_status}")
    log.status = new_status
    db.commit()


# =============================================================================
# PaymentGate — result type from require_payment dependency
# =============================================================================

@dataclass
class PaymentGate:
    """Result from require_payment dependency. Always present, even when x402 is off."""
    enabled: bool
    status: str  # "disabled", "entitled", "paid", "already_processed"
    payment_log_id: int | None = None
    job_id: str | None = None
    resource_id: str | None = None


# =============================================================================
# Helpers
# =============================================================================

def canonical_request_hash(body: bytes) -> str:
    """SHA-256 of canonicalized JSON body."""
    try:
        parsed = json.loads(body)
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    except (json.JSONDecodeError, TypeError):
        canonical = body.decode("utf-8", errors="replace")
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_402_headers(config, endpoint: str, resource_id: str | None) -> dict[str, str]:
    """Build 402 Payment Required response headers per x402 v2 spec."""
    route_config = config.route_pricing.get(endpoint)
    if not route_config:
        return {}

    # Build PaymentRequirements from RouteConfig
    requirements = config.server.build_payment_requirements(route_config)
    payment_required = config.server.create_payment_required_response(requirements)

    return {
        "X-Payment-Requirements": payment_required.model_dump_json(),
        "Content-Type": "application/json",
    }


# =============================================================================
# Core Payment Gate Logic
# =============================================================================

async def process_payment_gate(
    tenant_id: int,
    endpoint: str,
    resource_id: str | None,
    idempotency_key: str,
    request_hash: str,
    request: Request,
    db: Session,
) -> PaymentGate:
    """
    Payment gate state machine: Reserve -> Verify -> return PaymentGate.
    Does NOT create jobs. Endpoint calls create_paid_job() for that.
    """
    config = get_config()
    if config is None:
        return PaymentGate(enabled=False, status="disabled")

    # -- STEP 1: Check for existing entitlement (report routes) --
    if resource_id:
        existing_entitlement = db.query(PaymentLog).filter(
            PaymentLog.tenant_id == tenant_id,
            PaymentLog.endpoint == endpoint,
            PaymentLog.resource_id == resource_id,
            PaymentLog.status == PaymentStatus.JOB_CREATED,
            PaymentLog.created_at >= datetime.utcnow() - timedelta(days=30),
        ).first()
        if existing_entitlement:
            return PaymentGate(enabled=True, status="entitled", resource_id=resource_id)

    # -- STEP 2: Reserve (atomic INSERT, prevents concurrent double-charge) --
    log = None
    try:
        log = PaymentLog(
            idempotency_key=idempotency_key if idempotency_key else None,
            request_hash=request_hash,
            resource_id=resource_id,
            tenant_id=tenant_id,
            endpoint=endpoint,
            status=PaymentStatus.RESERVED,
            payment_id=None,
            amount_atomic=0,
            amount_usd=Decimal("0"),
            payer_address=None,
            tx_hash=None,
            network=config.network,
        )
        db.add(log)
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(PaymentLog).filter_by(
            tenant_id=tenant_id,
            endpoint=endpoint,
            idempotency_key=idempotency_key if idempotency_key else None,
        ).first()

        if existing is None:
            raise HTTPException(500, "Payment reservation conflict but no existing row found")

        if existing.request_hash != request_hash:
            raise HTTPException(409, "Idempotency-Key reused with different request body")

        if existing.status == PaymentStatus.JOB_CREATED and existing.job_id:
            return PaymentGate(
                enabled=True,
                status="already_processed",
                payment_log_id=existing.id,
                job_id=existing.job_id,
            )

        if existing.status == PaymentStatus.RESERVED:
            age = datetime.utcnow() - existing.created_at
            if age > timedelta(minutes=5):
                transition(existing, PaymentStatus.EXPIRED, db)
                transition(existing, PaymentStatus.RESERVED, db)
                existing.created_at = datetime.utcnow()
                db.commit()
                log = existing
            else:
                raise HTTPException(409, "Request is being processed, retry shortly")

        elif existing.status == PaymentStatus.EXPIRED:
            transition(existing, PaymentStatus.RESERVED, db)
            existing.created_at = datetime.utcnow()
            db.commit()
            log = existing

        elif existing.status == PaymentStatus.PAID:
            raise HTTPException(409, "Payment settled, job creation in progress")

        elif existing.status == PaymentStatus.JOB_FAILED:
            transition(existing, PaymentStatus.PAID, db)
            return PaymentGate(
                enabled=True,
                status="paid",
                payment_log_id=existing.id,
            )

        else:
            raise HTTPException(500, f"Unexpected payment status: {existing.status}")

    # -- STEP 3: Verify payment (only reservation owner reaches here) --
    payment_header = (
        request.headers.get("X-PAYMENT")
        or request.headers.get("PAYMENT-SIGNATURE")
    )
    if not payment_header:
        transition(log, PaymentStatus.EXPIRED, db)
        headers = build_402_headers(config, endpoint, resource_id)
        raise HTTPException(status_code=402, detail="Payment required", headers=headers)

    # Parse payment payload and verify via facilitator
    from x402.schemas import PaymentPayload

    try:
        payload = PaymentPayload.model_validate_json(payment_header)
    except Exception:
        transition(log, PaymentStatus.EXPIRED, db)
        headers = build_402_headers(config, endpoint, resource_id)
        raise HTTPException(status_code=402, detail="Invalid payment payload", headers=headers)

    # Get the route's requirements for verification
    route_config = config.route_pricing.get(endpoint)
    if not route_config:
        transition(log, PaymentStatus.EXPIRED, db)
        raise HTTPException(500, f"No pricing configured for {endpoint}")

    requirements_list = config.server.build_payment_requirements(route_config)
    matched_req = config.server.find_matching_requirements(requirements_list, payload)
    if not matched_req:
        transition(log, PaymentStatus.EXPIRED, db)
        headers = build_402_headers(config, endpoint, resource_id)
        raise HTTPException(status_code=402, detail="Payment does not match requirements")

    # Verify via facilitator
    verify_result = await config.server.verify_payment(payload, matched_req)
    if not verify_result.is_valid:
        transition(log, PaymentStatus.EXPIRED, db)
        headers = build_402_headers(config, endpoint, resource_id)
        raise HTTPException(
            status_code=402,
            detail=f"Payment invalid: {verify_result.invalid_reason}",
            headers=headers,
        )

    # Settle payment
    settle_result = await config.server.settle_payment(payload, matched_req)
    if not settle_result.success:
        transition(log, PaymentStatus.EXPIRED, db)
        raise HTTPException(
            status_code=402,
            detail=f"Settlement failed: {settle_result.error_reason}",
        )

    # Bind payment proof — replay protection via unique index on payment_id
    try:
        # Extract amount from the matched requirements
        amount_atomic = int(matched_req.amount) if matched_req.amount else 0
        log.payment_id = settle_result.transaction  # tx hash as unique payment ID
        log.amount_atomic = amount_atomic
        log.amount_usd = Decimal(amount_atomic) / Decimal(10**6)
        log.payer_address = settle_result.payer or verify_result.payer
        log.tx_hash = settle_result.transaction
        log.settled_at = datetime.utcnow()
        transition(log, PaymentStatus.PAID, db)
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Payment proof already used (replay rejected)")

    return PaymentGate(enabled=True, status="paid", payment_log_id=log.id)


# =============================================================================
# Job lifecycle helpers
# =============================================================================

def create_paid_job(db: Session, payment_log_id: int, job_id: str):
    """Link a job to a paid PaymentLog row. Enforces paid -> job_created transition."""
    log = db.get(PaymentLog, payment_log_id)
    if not log:
        raise ValueError(f"PaymentLog {payment_log_id} not found")
    log.job_id = job_id
    transition(log, PaymentStatus.JOB_CREATED, db)


def mark_job_failed(db: Session, payment_log_id: int):
    """Mark a paid request's job creation as failed. Enforces paid -> job_failed."""
    log = db.get(PaymentLog, payment_log_id)
    if not log:
        raise ValueError(f"PaymentLog {payment_log_id} not found")
    transition(log, PaymentStatus.JOB_FAILED, db)


# =============================================================================
# Dependency Factory
# =============================================================================

def require_payment(route_key: str, resource_extractor: Callable | None = None):
    """
    Dependency factory. Returns a callable suitable for Depends().

    route_key must match a key in x402_pricing.json (e.g., "POST /surface/scan/full").

    Handles: auth (401) -> idempotency-key validation (400) -> reservation ->
    payment verification (402) -> returns PaymentGate.
    """
    # Import here to avoid circular dependency
    from server.api import get_current_tenant_id, get_db

    async def _dependency(
        request: Request,
        tenant_id: int = Depends(get_current_tenant_id),
        db: Session = Depends(get_db),
    ) -> PaymentGate:
        if not x402_enabled():
            return PaymentGate(enabled=False, status="disabled")

        # Store tenant_id on request.state for rate limiter keying
        request.state.tenant_id = tenant_id

        # Idempotency-Key required on paid POST endpoints
        is_post = request.method == "POST"
        idempotency_key = request.headers.get("Idempotency-Key", "").strip()
        if is_post and not idempotency_key:
            raise HTTPException(400, "Idempotency-Key header is required for paid POST endpoints")

        resource_id = resource_extractor(request) if resource_extractor else None
        body = await request.body()
        req_hash = canonical_request_hash(body)

        return await process_payment_gate(
            tenant_id=tenant_id,
            endpoint=route_key,
            resource_id=resource_id,
            idempotency_key=idempotency_key,
            request_hash=req_hash,
            request=request,
            db=db,
        )

    return _dependency
