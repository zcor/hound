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
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal

from fastapi import Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database.models import PaymentLog, TenantDiscount, X402Discount
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


def cents_to_usd_string(cents: int) -> str:
    """Convert cents to USD string for x402 SDK. 1 -> '$0.01', 50 -> '$0.50'."""
    dollars = cents / 100
    return f"${dollars:.2f}"


def _usd_string_to_cents(usd_str: str) -> int:
    """Convert USD string like '$0.50' to cents (50). Inverse of cents_to_usd_string."""
    return int(Decimal(usd_str.replace("$", "")) * 100)


def _lookup_tenant_discount(
    db: Session, tenant_id: int, endpoint: str, base_price_cents: int,
) -> tuple[int | None, str | None]:
    """Find best active discount for tenant+endpoint. Returns (price_cents, code) or (None, None).

    base_price_cents: the route's base price in cents (e.g. 50 for $0.50).

    Precedence (when multiple active discounts exist):
      1. Endpoint-specific over global
      2. Fixed-price over percentage
      3. Most recently redeemed
    """
    from sqlalchemy import func as sa_func, or_

    td = db.query(TenantDiscount).join(X402Discount).filter(
        TenantDiscount.tenant_id == tenant_id,
        X402Discount.active == True,  # noqa: E712
        or_(X402Discount.expires_at == None, X402Discount.expires_at > sa_func.now()),  # noqa: E711
        or_(X402Discount.endpoint == None, X402Discount.endpoint == endpoint),  # noqa: E711
    ).order_by(
        # 1. endpoint-specific first (NULL sorts last)
        X402Discount.endpoint.is_(None).asc(),
        # 2. fixed_price_cents first (non-NULL before NULL)
        X402Discount.fixed_price_cents.is_(None).asc(),
        # 3. newest redemption first
        TenantDiscount.redeemed_at.desc(),
    ).first()

    if not td:
        return None, None

    # Lock the discount row to prevent race on usage counters
    discount = db.query(X402Discount).with_for_update().filter(
        X402Discount.id == td.discount_id,
    ).one_or_none()

    if not discount:
        return None, None

    # Check global usage limit
    if discount.max_uses is not None and discount.current_uses >= discount.max_uses:
        return None, None

    # Lock tenant_discount row too for per-tenant limit check (reviewer note #1)
    td_locked = db.query(TenantDiscount).with_for_update().filter(
        TenantDiscount.id == td.id,
    ).one_or_none()

    if not td_locked:
        return None, None

    # Check per-tenant usage limit
    if discount.max_uses_per_tenant is not None and td_locked.uses >= discount.max_uses_per_tenant:
        return None, None

    if discount.fixed_price_cents is not None:
        return discount.fixed_price_cents, discount.code

    if discount.percentage_off is not None:
        discounted = max(1, base_price_cents * (100 - discount.percentage_off) // 100)
        return discounted, discount.code

    return None, None


def _consume_discount(db: Session, tenant_id: int, discount_code: str):
    """Atomically increment usage counters. Called after settlement. Commits.

    Uses WHERE guards to prevent exceeding limits even under concurrency.
    """
    from sqlalchemy import text

    # Atomic global counter increment with WHERE guard
    result = db.execute(text(
        "UPDATE x402_discounts SET current_uses = current_uses + 1 "
        "WHERE code = :code AND (max_uses IS NULL OR current_uses < max_uses)"
    ), {"code": discount_code})

    if result.rowcount == 0:
        db.commit()
        return  # Limit hit between lookup and settlement — benign race

    # Atomic per-tenant counter with WHERE guard (reviewer note #1)
    db.execute(text(
        "UPDATE tenant_discounts SET uses = uses + 1 "
        "FROM x402_discounts "
        "WHERE tenant_discounts.discount_id = x402_discounts.id "
        "AND tenant_discounts.tenant_id = :tid AND x402_discounts.code = :code "
        "AND (x402_discounts.max_uses_per_tenant IS NULL OR tenant_discounts.uses < x402_discounts.max_uses_per_tenant)"
    ), {"tid": tenant_id, "code": discount_code})

    db.commit()


def _get_resource_config(config, endpoint: str, tenant_id: int | None = None, db: Session | None = None):
    """Get a ResourceConfig for the given endpoint, applying discount if applicable.

    Returns (ResourceConfig, discount_code | None) tuple.
    When tenant_id/db are provided, looks up discount and returns discounted price.
    """
    from x402.schemas.config import ResourceConfig

    route_config = config.route_pricing.get(endpoint)
    if not route_config:
        return None, None

    # RouteConfig.accepts is a PaymentOption with scheme, pay_to, price, network
    option = route_config.accepts
    if isinstance(option, list):
        option = option[0]

    base_price = option.price
    discount_code = None
    resolved_price_cents = _usd_string_to_cents(base_price)

    # Look up tenant discount if context is available
    if tenant_id is not None and db is not None:
        discounted_cents, code = _lookup_tenant_discount(db, tenant_id, endpoint, resolved_price_cents)
        if discounted_cents is not None:
            resolved_price_cents = discounted_cents
            base_price = cents_to_usd_string(discounted_cents)
            discount_code = code

    rc = ResourceConfig(
        scheme=option.scheme,
        pay_to=option.pay_to,
        price=base_price,
        network=option.network,
        max_timeout_seconds=option.max_timeout_seconds,
    )
    return rc, discount_code


def build_402_headers(
    config, endpoint: str, resource_id: str | None,
    tenant_id: int | None = None, db: Session | None = None,
) -> tuple[dict[str, str], str | None]:
    """Build 402 Payment Required response headers per x402 v2 spec.

    Returns (headers_dict, discount_code | None).
    """
    rc, discount_code = _get_resource_config(config, endpoint, tenant_id=tenant_id, db=db)
    if not rc:
        return {}, None

    requirements = config.server.build_payment_requirements(rc)
    payment_required = config.server.create_payment_required_response(requirements)

    headers = {
        "X-Payment-Requirements": payment_required.model_dump_json(),
        "Content-Type": "application/json",
    }
    return headers, discount_code


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

    # -- STEP 2.5: Resolve discount ONCE at reservation time --
    rc, discount_code = _get_resource_config(config, endpoint, tenant_id=tenant_id, db=db)
    if not rc:
        transition(log, PaymentStatus.EXPIRED, db)
        raise HTTPException(500, f"No pricing configured for {endpoint}")

    # Persist the resolved price on the PaymentLog (reviewer note #2)
    resolved_cents = _usd_string_to_cents(rc.price)
    log.discount_code = discount_code
    log.resolved_price_cents = resolved_cents
    db.commit()

    # -- STEP 3: Verify payment (only reservation owner reaches here) --
    payment_header = (
        request.headers.get("X-PAYMENT")
        or request.headers.get("PAYMENT-SIGNATURE")
    )
    if not payment_header:
        transition(log, PaymentStatus.EXPIRED, db)
        # Use the same rc for 402 headers (identical price path)
        requirements = config.server.build_payment_requirements(rc)
        payment_required = config.server.create_payment_required_response(requirements)
        headers = {
            "X-Payment-Requirements": payment_required.model_dump_json(),
            "Content-Type": "application/json",
        }
        raise HTTPException(status_code=402, detail="Payment required", headers=headers)

    # Parse payment payload and verify via facilitator
    from x402.schemas import PaymentPayload

    try:
        payload = PaymentPayload.model_validate_json(payment_header)
    except Exception:
        transition(log, PaymentStatus.EXPIRED, db)
        requirements = config.server.build_payment_requirements(rc)
        payment_required = config.server.create_payment_required_response(requirements)
        headers = {
            "X-Payment-Requirements": payment_required.model_dump_json(),
            "Content-Type": "application/json",
        }
        raise HTTPException(status_code=402, detail="Invalid payment payload", headers=headers)

    # Use the SAME rc for verification (identical price path — Fix #5)
    requirements_list = config.server.build_payment_requirements(rc)
    matched_req = config.server.find_matching_requirements(requirements_list, payload)
    if not matched_req:
        transition(log, PaymentStatus.EXPIRED, db)
        requirements = config.server.build_payment_requirements(rc)
        payment_required = config.server.create_payment_required_response(requirements)
        headers = {
            "X-Payment-Requirements": payment_required.model_dump_json(),
            "Content-Type": "application/json",
        }
        raise HTTPException(status_code=402, detail="Payment does not match requirements")

    # Verify via facilitator
    verify_result = await config.server.verify_payment(payload, matched_req)
    if not verify_result.is_valid:
        transition(log, PaymentStatus.EXPIRED, db)
        requirements = config.server.build_payment_requirements(rc)
        payment_required = config.server.create_payment_required_response(requirements)
        headers = {
            "X-Payment-Requirements": payment_required.model_dump_json(),
            "Content-Type": "application/json",
        }
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

    # Consume discount usage after successful settlement
    if discount_code:
        _consume_discount(db, tenant_id, discount_code)

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
