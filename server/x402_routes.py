"""
x402 discount/coupon endpoints for agent payments.

Separate from stripe_routes.py to keep Stripe and x402 concerns isolated.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database.models import TenantDiscount, X402Discount

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/x402", tags=["x402"])


# ---------------------------------------------------------------------------
# Shared DB dependency (runtime import to avoid circular imports)
# ---------------------------------------------------------------------------
def get_db():
    from server.api import get_db as api_get_db
    yield from api_get_db()


# ---------------------------------------------------------------------------
# Request/Response schemas
# ---------------------------------------------------------------------------
class RedeemCouponRequest(BaseModel):
    code: str


class RedeemCouponResponse(BaseModel):
    code: str
    discount_type: str  # "fixed_price" or "percentage"
    value: int  # cents for fixed, percentage for percentage_off
    endpoint: str | None


class DiscountInfo(BaseModel):
    code: str
    discount_type: str
    value: int
    endpoint: str | None
    uses: int
    max_uses_per_tenant: int | None
    redeemed_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.post("/redeem-coupon", response_model=RedeemCouponResponse)
async def redeem_coupon(
    body: RedeemCouponRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Redeem a discount code for x402 payments."""
    from server.api import get_current_tenant_id
    tenant_id = await get_current_tenant_id(request)

    discount = db.query(X402Discount).filter(
        X402Discount.code == body.code,
        X402Discount.active == True,  # noqa: E712
    ).first()

    if not discount:
        raise HTTPException(404, "Invalid or inactive discount code")

    # Check expiration
    if discount.expires_at and discount.expires_at < datetime.now(timezone.utc):
        raise HTTPException(410, "Discount code has expired")

    # Check global usage limit
    if discount.max_uses is not None and discount.current_uses >= discount.max_uses:
        raise HTTPException(410, "Discount code has reached its usage limit")

    # Check if already redeemed (idempotent)
    existing = db.query(TenantDiscount).filter(
        TenantDiscount.tenant_id == tenant_id,
        TenantDiscount.discount_id == discount.id,
    ).first()

    if not existing:
        td = TenantDiscount(
            tenant_id=tenant_id,
            discount_id=discount.id,
            uses=0,
        )
        db.add(td)
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise HTTPException(409, "Failed to redeem coupon")

    # Determine discount type for response
    if discount.fixed_price_cents is not None:
        dtype = "fixed_price"
        value = discount.fixed_price_cents
    elif discount.percentage_off is not None:
        dtype = "percentage"
        value = discount.percentage_off
    else:
        dtype = "unknown"
        value = 0

    return RedeemCouponResponse(
        code=discount.code,
        discount_type=dtype,
        value=value,
        endpoint=discount.endpoint,
    )


@router.get("/my-discounts", response_model=list[DiscountInfo])
async def get_my_discounts(
    request: Request,
    db: Session = Depends(get_db),
):
    """List active x402 discounts for the current tenant."""
    from sqlalchemy import or_, func as sa_func
    from server.api import get_current_tenant_id
    tenant_id = await get_current_tenant_id(request)

    rows = db.query(TenantDiscount, X402Discount).join(X402Discount).filter(
        TenantDiscount.tenant_id == tenant_id,
        X402Discount.active == True,  # noqa: E712
        or_(
            X402Discount.expires_at == None,  # noqa: E711
            X402Discount.expires_at > sa_func.now(),
        ),
    ).all()

    results = []
    for td, disc in rows:
        if disc.fixed_price_cents is not None:
            dtype = "fixed_price"
            value = disc.fixed_price_cents
        elif disc.percentage_off is not None:
            dtype = "percentage"
            value = disc.percentage_off
        else:
            dtype = "unknown"
            value = 0

        results.append(DiscountInfo(
            code=disc.code,
            discount_type=dtype,
            value=value,
            endpoint=disc.endpoint,
            uses=td.uses,
            max_uses_per_tenant=disc.max_uses_per_tenant,
            redeemed_at=td.redeemed_at.isoformat() if td.redeemed_at else "",
        ))

    return results
