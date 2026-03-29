"""
Stripe billing routes for FirePan subscriptions and credit purchases.

Two routers:
  - router (prefix=/billing): authenticated endpoints for checkout, portal, plans
  - webhook_router (prefix=/webhooks): unauthenticated Stripe webhook (signature-verified)
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

import stripe
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from database.models import Tenant
from integrations.telegram import notify_payment_event
from server.auth_utils import reject_preview_writes

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Stripe key configuration with live-key safety guard
# ---------------------------------------------------------------------------
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

if not STRIPE_SECRET_KEY:
    logger.critical(
        "STRIPE_SECRET_KEY is empty — ALL outgoing Stripe API calls will fail. "
        "Billing checkout, portal, and plan queries are broken. "
        "Set in docker-compose.yml AND .env."
    )
if not STRIPE_WEBHOOK_SECRET:
    logger.critical(
        "STRIPE_WEBHOOK_SECRET is empty — ALL Stripe webhooks will fail "
        "signature verification (400). Subscription events, payment notifications, "
        "and invoice updates will be silently dropped. "
        "Set in docker-compose.yml AND .env."
    )

if STRIPE_SECRET_KEY.startswith("sk_live_") and os.environ.get("STRIPE_LIVE_CONFIRMED") != "true":
    raise RuntimeError(
        "STRIPE_SECRET_KEY is a live key but STRIPE_LIVE_CONFIRMED is not set. "
        "Set STRIPE_LIVE_CONFIRMED=true in production to confirm live key usage."
    )

stripe.api_key = STRIPE_SECRET_KEY

FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://app.firepan.com").rstrip("/")


# ---------------------------------------------------------------------------
# Plan config loader
# ---------------------------------------------------------------------------
def load_stripe_plans() -> dict:
    """Load plan configuration from config/stripe_plans.json."""
    config_path = Path(__file__).parent.parent / "config" / "stripe_plans.json"
    with open(config_path) as f:
        return json.load(f)


VALID_PLANS = {"test", "starter", "professional", "enterprise"}
VALID_PERIODS = {"monthly", "annual"}


# ---------------------------------------------------------------------------
# Shared DB dependency (imported at runtime to avoid circular imports)
# ---------------------------------------------------------------------------
def get_db():
    from server.api import get_db as api_get_db
    yield from api_get_db()


def get_current_tenant_id(request: Request) -> int:
    from server.api import get_current_tenant_id as api_get_tenant
    import asyncio
    loop = asyncio.get_event_loop()
    if loop.is_running():
        import concurrent.futures
        # We're in an async context; this dependency is called by FastAPI's DI
        # which handles the coroutine for us. Just raise to let FastAPI handle it.
        raise RuntimeError("Use Depends() — do not call directly")
    return loop.run_until_complete(api_get_tenant(request))


# ---------------------------------------------------------------------------
# Request/Response models
# ---------------------------------------------------------------------------
class CheckoutRequest(BaseModel):
    plan: str  # starter, professional, enterprise
    period: str  # monthly, annual
    return_path: str | None = None  # optional path to redirect after checkout


class CheckoutResponse(BaseModel):
    checkout_url: str


class PortalResponse(BaseModel):
    portal_url: str


class PlanInfo(BaseModel):
    name: str
    monthly_amount_cents: int | None = None
    annual_amount_cents: int | None = None
    limits: dict
    features: list[str]


class PlansResponse(BaseModel):
    plans: dict[str, PlanInfo]
    credit_tranche: dict


# ---------------------------------------------------------------------------
# Authenticated billing router
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/billing", tags=["billing"])


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout_session(
    body: CheckoutRequest,
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """Create a Stripe Checkout Session for a subscription."""
    from server.api import get_current_tenant_id as _get_tid
    tenant_id = await _get_tid(request)

    if body.plan not in VALID_PLANS:
        raise HTTPException(400, f"Invalid plan: {body.plan}. Must be one of {VALID_PLANS}")
    if body.period not in VALID_PERIODS:
        raise HTTPException(400, f"Invalid period: {body.period}. Must be one of {VALID_PERIODS}")

    config = load_stripe_plans()
    plan_config = config["plans"][body.plan]
    price_id = plan_config[f"{body.period}_price_id"]

    if not price_id or price_id.startswith("REPLACE"):
        raise HTTPException(503, "Stripe price IDs not yet configured. Contact support.")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(404, "Tenant not found")

    # Create or reuse Stripe customer
    if not tenant.stripe_customer_id:
        customer = stripe.Customer.create(
            metadata={"tenant_id": str(tenant.id), "github_login": tenant.github_account_login or ""},
            email=tenant.contact_email or None,
        )
        tenant.stripe_customer_id = customer.id
        db.commit()

    # Build return URLs — default to billing page, allow override via return_path
    return_base = "/settings/billing"
    if body.return_path:
        rp = body.return_path
        if not rp.startswith("/") or "://" in rp or "//" in rp or "\n" in rp or "\r" in rp:
            raise HTTPException(400, "Invalid return_path")
        return_base = rp

    success_url = f"{FRONTEND_URL}{return_base}{'&' if '?' in return_base else '?'}success=true"
    cancel_url = f"{FRONTEND_URL}{return_base}{'&' if '?' in return_base else '?'}canceled=true"

    session = stripe.checkout.Session.create(
        customer=tenant.stripe_customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        allow_promotion_codes=True,
        metadata={"tenant_id": str(tenant.id), "plan": body.plan, "period": body.period},
    )

    return CheckoutResponse(checkout_url=session.url)


@router.post("/buy-credits", response_model=CheckoutResponse)
async def buy_credits(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """Create a Stripe Checkout Session for a one-time credit tranche purchase."""
    from server.api import get_current_tenant_id as _get_tid
    tenant_id = await _get_tid(request)

    config = load_stripe_plans()
    tranche = config["credit_tranche"]
    price_id = tranche["price_id"]

    if not price_id or price_id.startswith("REPLACE"):
        raise HTTPException(503, "Credit tranche price ID not yet configured. Contact support.")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(404, "Tenant not found")

    if not tenant.stripe_customer_id:
        customer = stripe.Customer.create(
            metadata={"tenant_id": str(tenant.id), "github_login": tenant.github_account_login or ""},
            email=tenant.contact_email or None,
        )
        tenant.stripe_customer_id = customer.id
        db.commit()

    session = stripe.checkout.Session.create(
        customer=tenant.stripe_customer_id,
        mode="payment",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=f"{FRONTEND_URL}/settings/billing?credits=true",
        cancel_url=f"{FRONTEND_URL}/settings/billing?canceled=true",
        metadata={"tenant_id": str(tenant.id), "type": "credit_tranche"},
    )

    return CheckoutResponse(checkout_url=session.url)


@router.post("/portal", response_model=PortalResponse)
async def create_billing_portal(
    request: Request,
    db: Session = Depends(get_db),
    _: None = Depends(reject_preview_writes),
):
    """Create a Stripe Billing Portal session for plan management."""
    from server.api import get_current_tenant_id as _get_tid
    tenant_id = await _get_tid(request)

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant or not tenant.stripe_customer_id:
        raise HTTPException(400, "No billing account found. Subscribe to a plan first.")

    session = stripe.billing_portal.Session.create(
        customer=tenant.stripe_customer_id,
        return_url=f"{FRONTEND_URL}/settings/billing",
    )

    return PortalResponse(portal_url=session.url)


@router.get("/plans", response_model=PlansResponse)
async def get_plans():
    """Get available plans with pricing. No auth required."""
    config = load_stripe_plans()
    plans = {}
    for key, plan in config["plans"].items():
        plans[key] = PlanInfo(
            name=plan["name"],
            monthly_amount_cents=plan.get("monthly_amount_cents"),
            annual_amount_cents=plan.get("annual_amount_cents"),
            limits=plan["limits"],
            features=plan["features"],
        )
    # Include free tier
    free = config["free"]
    plans["free"] = PlanInfo(
        name=free["name"],
        limits=free["limits"],
        features=[],
    )
    return PlansResponse(
        plans=plans,
        credit_tranche={
            "name": config["credit_tranche"]["name"],
            "amount_cents": config["credit_tranche"]["amount_cents"],
            "scans_granted": config["credit_tranche"]["scans_granted"],
        },
    )


# ---------------------------------------------------------------------------
# Unauthenticated webhook router (Stripe signature verification only)
# ---------------------------------------------------------------------------
webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@webhook_router.post("/stripe")
async def handle_stripe_webhook(request: Request, db: Session = Depends(get_db)):
    """
    Handle Stripe webhook events.

    Auth: Stripe signature verification only — NO JWT.
    Idempotency: crash-safe two-phase INSERT/UPDATE pattern.
    """
    body = await request.body()
    sig = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(body, sig, STRIPE_WEBHOOK_SECRET)
    except stripe.SignatureVerificationError:
        raise HTTPException(400, "Invalid Stripe signature")
    except Exception as e:
        logger.error("Stripe webhook error: %s", e)
        raise HTTPException(400, f"Webhook error: {e}")

    # Phase 1: Claim the event (idempotency gate)
    result = db.execute(
        text("""
            INSERT INTO stripe_processed_events (event_id, status)
            VALUES (:eid, 'processing')
            ON CONFLICT (event_id) DO NOTHING
        """),
        {"eid": event.id},
    )
    db.commit()

    if result.rowcount == 0:
        # Row already exists — check if already processed
        existing = db.execute(
            text("SELECT status FROM stripe_processed_events WHERE event_id = :eid FOR UPDATE"),
            {"eid": event.id},
        ).first()
        if existing and existing.status == "processed":
            return Response(status_code=200)
        # status == "processing" — previous attempt may have crashed. Re-process.

    # Phase 2: Business logic
    notification = None
    try:
        notification = _handle_event(event, db)

        # Phase 3: Mark done
        db.execute(
            text("""
                UPDATE stripe_processed_events
                SET status = 'processed', processed_at = NOW()
                WHERE event_id = :eid
            """),
            {"eid": event.id},
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Stripe webhook processing failed for event %s", event.id)
        raise

    # Fire-and-forget Telegram alert — outside the webhook try/except
    if notification:
        try:
            await notify_payment_event(event_id=event.id, **notification)
        except Exception as e:
            logger.warning("Telegram payment notification failed: %s", e)

    return Response(status_code=200)


def _handle_event(event: stripe.Event, db: Session) -> dict | None:
    """Route Stripe events to handlers. Returns notification dict or None."""
    etype = event.type

    if etype == "checkout.session.completed":
        return _handle_checkout_completed(event.data.object, db)
    elif etype == "customer.subscription.updated":
        return _handle_subscription_updated(event.data.object, db)
    elif etype == "customer.subscription.deleted":
        return _handle_subscription_deleted(event.data.object, db)
    elif etype == "invoice.payment_failed":
        return _handle_payment_failed(event.data.object, db)
    else:
        logger.info("Ignoring Stripe event type: %s", etype)
        return None


def _find_tenant_by_metadata(metadata: dict, db: Session) -> Tenant | None:
    """Find tenant from Stripe event metadata."""
    tenant_id = metadata.get("tenant_id")
    if tenant_id:
        return db.query(Tenant).filter(Tenant.id == int(tenant_id)).first()
    return None


def _find_tenant_by_customer(customer_id: str, db: Session) -> Tenant | None:
    """Find tenant by Stripe customer ID."""
    return db.query(Tenant).filter(Tenant.stripe_customer_id == customer_id).first()


def _handle_checkout_completed(session, db: Session) -> dict | None:
    """Handle checkout.session.completed — route by session mode."""
    metadata = session.get("metadata", {})
    tenant = _find_tenant_by_metadata(metadata, db)

    if not tenant:
        # Fallback: find by customer ID
        customer_id = session.get("customer")
        if customer_id:
            tenant = _find_tenant_by_customer(customer_id, db)

    if not tenant:
        logger.error("Checkout completed but tenant not found. metadata=%s", metadata)
        return None

    mode = session.get("mode")

    if mode == "subscription":
        plan = metadata.get("plan", "starter")
        period = metadata.get("period", "monthly")
        subscription_id = session.get("subscription")
        customer_id = session.get("customer")

        tenant.plan = plan
        tenant.plan_period = period
        tenant.plan_updated_at = datetime.now(timezone.utc)
        if not tenant.first_paid_at:
            tenant.first_paid_at = datetime.now(timezone.utc)
        if subscription_id:
            tenant.stripe_subscription_id = subscription_id
        if customer_id and not tenant.stripe_customer_id:
            tenant.stripe_customer_id = customer_id
        db.commit()
        logger.info("Tenant %d upgraded to plan=%s period=%s", tenant.id, plan, period)
        return {
            "event_type": "subscription_created",
            "tenant_name": tenant.name,
            "tenant_id": tenant.id,
            "customer_id": customer_id or tenant.stripe_customer_id,
            "plan": plan,
            "period": period,
        }

    elif mode == "payment":
        event_type = metadata.get("type")
        if event_type == "credit_tranche":
            config = load_stripe_plans()
            scans_granted = config["credit_tranche"]["scans_granted"]
            db.execute(
                text("UPDATE tenants SET scan_credits = scan_credits + :n WHERE id = :tid"),
                {"n": scans_granted, "tid": tenant.id},
            )
            db.commit()
            logger.info("Tenant %d purchased credit tranche: +%d scans", tenant.id, scans_granted)
            return {
                "event_type": "credit_purchase",
                "tenant_name": tenant.name,
                "tenant_id": tenant.id,
                "customer_id": session.get("customer") or tenant.stripe_customer_id,
                "scans_granted": scans_granted,
            }

    return None


def _handle_subscription_updated(subscription, db: Session) -> dict | None:
    """Handle plan changes via Stripe portal."""
    customer_id = subscription.get("customer")
    tenant = _find_tenant_by_customer(customer_id, db)
    if not tenant:
        logger.warning("subscription.updated for unknown customer %s", customer_id)
        return None

    # Check if plan changed via price lookup
    new_plan = None
    new_period = None
    items = subscription.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")
        config = load_stripe_plans()
        for plan_key, plan_config in config["plans"].items():
            if price_id in (plan_config.get("monthly_price_id"), plan_config.get("annual_price_id")):
                new_plan = plan_key
                new_period = "annual" if price_id == plan_config.get("annual_price_id") else "monthly"
                tenant.plan = new_plan
                tenant.plan_period = new_period
                tenant.plan_updated_at = datetime.now(timezone.utc)
                break

    tenant.stripe_subscription_id = subscription.get("id")
    db.commit()
    return {
        "event_type": "subscription_updated",
        "tenant_name": tenant.name,
        "tenant_id": tenant.id,
        "customer_id": customer_id,
        "plan": new_plan or tenant.plan,
        "period": new_period or tenant.plan_period,
    }


def _handle_subscription_deleted(subscription, db: Session) -> dict | None:
    """Handle subscription cancellation."""
    customer_id = subscription.get("customer")
    tenant = _find_tenant_by_customer(customer_id, db)
    if not tenant:
        logger.warning("subscription.deleted for unknown customer %s", customer_id)
        return None

    tenant.plan = "free"
    tenant.plan_period = None
    tenant.stripe_subscription_id = None
    tenant.plan_updated_at = datetime.now(timezone.utc)
    db.commit()
    logger.info("Tenant %d subscription canceled, reverted to free", tenant.id)
    return {
        "event_type": "subscription_deleted",
        "tenant_name": tenant.name,
        "tenant_id": tenant.id,
        "customer_id": customer_id,
    }


def _handle_payment_failed(invoice, db: Session) -> dict | None:
    """Log payment failure — don't immediately downgrade."""
    customer_id = invoice.get("customer")
    tenant = _find_tenant_by_customer(customer_id, db)
    tenant_info = f"tenant_id={tenant.id}" if tenant else f"customer={customer_id}"
    logger.warning("Payment failed for %s. Invoice: %s", tenant_info, invoice.get("id"))
    return {
        "event_type": "payment_failed",
        "tenant_name": tenant.name if tenant else None,
        "tenant_id": tenant.id if tenant else None,
        "customer_id": customer_id,
        "invoice_id": invoice.get("id"),
    }
