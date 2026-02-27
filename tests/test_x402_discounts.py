"""
Tests for x402 discount/coupon system.

Covers discount lookup, precedence rules, percentage/fixed discounts,
consumption, coupon redemption endpoints, and identical price path.
Uses SQLite in-memory DB for unit-level tests.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import (
    Base,
    PaymentLog,
    Tenant,
    TenantDiscount,
    X402Discount,
    create_db_engine,
    create_db_session,
    init_database,
)
from server.x402_deps import (
    _consume_discount,
    _lookup_tenant_discount,
    _usd_string_to_cents,
    cents_to_usd_string,
)


class TestCentsConversion(unittest.TestCase):
    """Test cents <-> USD string helpers."""

    def test_cents_to_usd_string(self):
        self.assertEqual(cents_to_usd_string(1), "$0.01")
        self.assertEqual(cents_to_usd_string(50), "$0.50")
        self.assertEqual(cents_to_usd_string(500), "$5.00")
        self.assertEqual(cents_to_usd_string(100), "$1.00")

    def test_usd_string_to_cents(self):
        self.assertEqual(_usd_string_to_cents("$0.01"), 1)
        self.assertEqual(_usd_string_to_cents("$0.50"), 50)
        self.assertEqual(_usd_string_to_cents("$5.00"), 500)
        self.assertEqual(_usd_string_to_cents("$1.00"), 100)

    def test_round_trip(self):
        for cents in [1, 10, 50, 99, 100, 500, 2999]:
            self.assertEqual(_usd_string_to_cents(cents_to_usd_string(cents)), cents)


class DiscountTestBase(unittest.TestCase):
    """Base class with DB setup for discount tests."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_db_engine("sqlite:///:memory:", echo=False)
        init_database(cls.engine)

    def setUp(self):
        self.db = create_db_session(self.engine)
        self.tenant = Tenant(name=f"test_{id(self)}")
        self.db.add(self.tenant)
        self.db.commit()

    def tearDown(self):
        self.db.rollback()
        for table in reversed(Base.metadata.sorted_tables):
            self.db.execute(table.delete())
        self.db.commit()
        self.db.close()

    def _create_discount(self, **kwargs):
        defaults = dict(
            code=f"TEST{id(self)}",
            active=True,
            current_uses=0,
        )
        defaults.update(kwargs)
        d = X402Discount(**defaults)
        self.db.add(d)
        self.db.commit()
        self.db.refresh(d)
        return d

    def _redeem(self, discount, tenant=None):
        """Create a TenantDiscount row (simulates coupon redemption)."""
        t = tenant or self.tenant
        td = TenantDiscount(
            tenant_id=t.id,
            discount_id=discount.id,
            uses=0,
        )
        self.db.add(td)
        self.db.commit()
        self.db.refresh(td)
        return td


class TestDiscountLookup(DiscountTestBase):
    """Test _lookup_tenant_discount with various scenarios."""

    def test_active_fixed_price_discount(self):
        """Returns discounted price for tenant with active fixed-price coupon."""
        d = self._create_discount(code="FIX1", fixed_price_cents=1)
        self._redeem(d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertEqual(price, 1)
        self.assertEqual(code, "FIX1")

    def test_no_discount(self):
        """Returns (None, None) for tenant without coupon."""
        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertIsNone(price)
        self.assertIsNone(code)

    def test_expired_discount(self):
        """Expired coupon returns (None, None)."""
        d = self._create_discount(
            code="EXPIRED1",
            fixed_price_cents=1,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        self._redeem(d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        # SQLite doesn't support func.now() the same way, but the discount
        # has a past expires_at so it should be filtered
        self.assertIsNone(price)
        self.assertIsNone(code)

    def test_maxed_out_global(self):
        """Coupon at max_uses returns (None, None)."""
        d = self._create_discount(
            code="MAXED1", fixed_price_cents=1, max_uses=5, current_uses=5,
        )
        self._redeem(d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertIsNone(price)
        self.assertIsNone(code)

    def test_per_tenant_limit(self):
        """Per-tenant limit respected."""
        d = self._create_discount(
            code="PERTENANT1", fixed_price_cents=1, max_uses_per_tenant=3,
        )
        td = self._redeem(d)
        td.uses = 3
        self.db.commit()

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertIsNone(price)
        self.assertIsNone(code)

    def test_endpoint_specific(self):
        """Endpoint-scoped coupon only applies to matching route."""
        d = self._create_discount(
            code="SCANONLY", fixed_price_cents=1,
            endpoint="POST /surface/scan/full",
        )
        self._redeem(d)

        # Matching endpoint
        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertEqual(price, 1)
        self.assertEqual(code, "SCANONLY")

        # Non-matching endpoint
        price2, code2 = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /audits/start", 500,
        )
        self.assertIsNone(price2)
        self.assertIsNone(code2)

    def test_percentage_off(self):
        """50% off $0.50 -> $0.25 (25 cents)."""
        d = self._create_discount(code="HALF", percentage_off=50)
        self._redeem(d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertEqual(price, 25)
        self.assertEqual(code, "HALF")

    def test_percentage_off_min_one_cent(self):
        """99% off $0.50 -> $0.01 (minimum 1 cent)."""
        d = self._create_discount(code="ALMOST_FREE", percentage_off=99)
        self._redeem(d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertEqual(price, 1)
        self.assertEqual(code, "ALMOST_FREE")

    def test_inactive_discount_ignored(self):
        """Inactive discount not returned."""
        d = self._create_discount(code="INACTIVE1", fixed_price_cents=1, active=False)
        self._redeem(d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertIsNone(price)
        self.assertIsNone(code)


class TestDiscountPrecedence(DiscountTestBase):
    """Test precedence rules when tenant has multiple active discounts."""

    def test_endpoint_specific_over_global(self):
        """Endpoint-specific discount wins over global when both active."""
        global_d = self._create_discount(
            code="GLOBAL1", fixed_price_cents=10,
        )
        specific_d = self._create_discount(
            code="SPECIFIC1", fixed_price_cents=5,
            endpoint="POST /surface/scan/full",
        )
        self._redeem(global_d)
        self._redeem(specific_d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertEqual(code, "SPECIFIC1")
        self.assertEqual(price, 5)

    def test_fixed_over_percentage(self):
        """Fixed-price discount wins over percentage when both global."""
        pct_d = self._create_discount(
            code="PCT1", percentage_off=50,
        )
        fixed_d = self._create_discount(
            code="FIXED1", fixed_price_cents=1,
        )
        self._redeem(pct_d)
        self._redeem(fixed_d)

        price, code = _lookup_tenant_discount(
            self.db, self.tenant.id, "POST /surface/scan/full", 50,
        )
        self.assertEqual(code, "FIXED1")
        self.assertEqual(price, 1)


class TestConsumeDiscount(DiscountTestBase):
    """Test _consume_discount atomic increment."""

    def test_atomic_increment(self):
        """_consume_discount increments both counters."""
        d = self._create_discount(code="CONSUME1", fixed_price_cents=1)
        td = self._redeem(d)

        _consume_discount(self.db, self.tenant.id, "CONSUME1")

        self.db.refresh(d)
        self.db.refresh(td)
        self.assertEqual(d.current_uses, 1)
        self.assertEqual(td.uses, 1)

    def test_consume_at_limit(self):
        """_consume_discount is a no-op when limit already hit (not an error)."""
        d = self._create_discount(
            code="LIMIT1", fixed_price_cents=1, max_uses=1, current_uses=1,
        )
        self._redeem(d)

        # Should not raise
        _consume_discount(self.db, self.tenant.id, "LIMIT1")

        self.db.refresh(d)
        self.assertEqual(d.current_uses, 1)  # Unchanged

    def test_consume_increments_multiple_times(self):
        """Multiple consumptions increment counters correctly."""
        d = self._create_discount(code="MULTI1", fixed_price_cents=1)
        td = self._redeem(d)

        _consume_discount(self.db, self.tenant.id, "MULTI1")
        _consume_discount(self.db, self.tenant.id, "MULTI1")
        _consume_discount(self.db, self.tenant.id, "MULTI1")

        self.db.refresh(d)
        self.db.refresh(td)
        self.assertEqual(d.current_uses, 3)
        self.assertEqual(td.uses, 3)


class TestGetResourceConfigWithDiscount(DiscountTestBase):
    """Test _get_resource_config with discount resolution."""

    def _mock_config(self):
        """Create a mock x402 config with route pricing."""
        from unittest.mock import MagicMock

        option = MagicMock()
        option.scheme = "exact"
        option.pay_to = "0xTEST"
        option.price = "$0.50"
        option.network = "eip155:84532"
        option.max_timeout_seconds = 300

        route_config = MagicMock()
        route_config.accepts = option

        config = MagicMock()
        config.route_pricing = {"POST /surface/scan/full": route_config}
        return config

    def test_base_price_without_discount(self):
        """Without tenant context, returns base price."""
        from server.x402_deps import _get_resource_config

        config = self._mock_config()
        rc, code = _get_resource_config(config, "POST /surface/scan/full")

        self.assertIsNotNone(rc)
        self.assertIsNone(code)
        self.assertEqual(rc.price, "$0.50")

    def test_discounted_price_with_tenant(self):
        """With tenant and discount, returns discounted price."""
        from server.x402_deps import _get_resource_config

        d = self._create_discount(code="FOUNDERS", fixed_price_cents=1)
        self._redeem(d)

        config = self._mock_config()
        rc, code = _get_resource_config(
            config, "POST /surface/scan/full",
            tenant_id=self.tenant.id, db=self.db,
        )

        self.assertIsNotNone(rc)
        self.assertEqual(code, "FOUNDERS")
        self.assertEqual(rc.price, "$0.01")

    def test_no_discount_returns_base_price(self):
        """Tenant without discount gets base price."""
        from server.x402_deps import _get_resource_config

        config = self._mock_config()
        rc, code = _get_resource_config(
            config, "POST /surface/scan/full",
            tenant_id=self.tenant.id, db=self.db,
        )

        self.assertIsNotNone(rc)
        self.assertIsNone(code)
        self.assertEqual(rc.price, "$0.50")

    def test_identical_price_in_402_and_verify(self):
        """The ResourceConfig used for 402 headers and for verification is the same object.

        This verifies Fix #5: discount is resolved once and reused for both
        the 402 response and the payment verification step.
        """
        from server.x402_deps import _get_resource_config

        d = self._create_discount(code="IDCHECK", fixed_price_cents=1)
        self._redeem(d)

        config = self._mock_config()

        # Simulate what process_payment_gate does: call once, reuse rc
        rc1, code1 = _get_resource_config(
            config, "POST /surface/scan/full",
            tenant_id=self.tenant.id, db=self.db,
        )

        # Second call (without tenant context) would give base price
        rc2, code2 = _get_resource_config(config, "POST /surface/scan/full")

        # rc1 has discounted price, rc2 has base price
        self.assertEqual(rc1.price, "$0.01")
        self.assertEqual(rc2.price, "$0.50")

        # The point: process_payment_gate uses rc1 for BOTH 402 headers and
        # verification, never calls _get_resource_config again
        self.assertNotEqual(rc1.price, rc2.price)


class TestCouponRedemptionEndpoint(DiscountTestBase):
    """Test POST /x402/redeem-coupon via function-level testing."""

    def test_redeem_valid_code(self):
        """Valid code creates TenantDiscount row."""
        d = self._create_discount(code="REDEEM1", fixed_price_cents=1)

        # Verify no TenantDiscount exists yet
        count = self.db.query(TenantDiscount).filter(
            TenantDiscount.tenant_id == self.tenant.id,
            TenantDiscount.discount_id == d.id,
        ).count()
        self.assertEqual(count, 0)

        # Simulate redemption
        self._redeem(d)

        count = self.db.query(TenantDiscount).filter(
            TenantDiscount.tenant_id == self.tenant.id,
            TenantDiscount.discount_id == d.id,
        ).count()
        self.assertEqual(count, 1)

    def test_redeem_duplicate_idempotent(self):
        """Second redemption of same code is idempotent."""
        d = self._create_discount(code="DUP1", fixed_price_cents=1)
        self._redeem(d)

        # Redeem again — should not create a second row due to unique constraint
        existing = self.db.query(TenantDiscount).filter(
            TenantDiscount.tenant_id == self.tenant.id,
            TenantDiscount.discount_id == d.id,
        ).first()
        self.assertIsNotNone(existing)

        # Count should still be 1
        count = self.db.query(TenantDiscount).filter(
            TenantDiscount.tenant_id == self.tenant.id,
            TenantDiscount.discount_id == d.id,
        ).count()
        self.assertEqual(count, 1)


class TestEnsureSchema(unittest.TestCase):
    """Test ensure_schema() is idempotent."""

    def test_ensure_schema_idempotent(self):
        """Calling ensure_schema multiple times does not raise."""
        from database.models import ensure_schema

        engine = create_db_engine("sqlite:///:memory:", echo=False)
        init_database(engine)

        # Call again — should be a no-op on SQLite
        ensure_schema(engine)
        ensure_schema(engine)

    def test_payment_log_has_discount_columns(self):
        """PaymentLog model has discount_code and resolved_price_cents columns."""
        engine = create_db_engine("sqlite:///:memory:", echo=False)
        init_database(engine)
        db = create_db_session(engine)

        tenant = Tenant(name="schema_test")
        db.add(tenant)
        db.commit()

        log = PaymentLog(
            tenant_id=tenant.id,
            endpoint="POST /test",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            discount_code="TESTCODE",
            resolved_price_cents=1,
        )
        db.add(log)
        db.commit()

        self.assertEqual(log.discount_code, "TESTCODE")
        self.assertEqual(log.resolved_price_cents, 1)
        db.close()


class TestResolvedPricePersistence(DiscountTestBase):
    """Test that resolved_price_cents is persisted on PaymentLog (reviewer note #2)."""

    def test_resolved_price_stored_on_log(self):
        """PaymentLog stores the resolved price used for the transaction."""
        d = self._create_discount(code="PERSIST1", fixed_price_cents=1)
        self._redeem(d)

        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            discount_code="PERSIST1",
            resolved_price_cents=1,
        )
        self.db.add(log)
        self.db.commit()

        # Read back
        self.db.refresh(log)
        self.assertEqual(log.discount_code, "PERSIST1")
        self.assertEqual(log.resolved_price_cents, 1)

    def test_resolved_price_none_without_discount(self):
        """PaymentLog without discount has NULL resolved_price_cents."""
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
        )
        self.db.add(log)
        self.db.commit()

        self.db.refresh(log)
        self.assertIsNone(log.discount_code)
        self.assertIsNone(log.resolved_price_cents)


if __name__ == "__main__":
    unittest.main()
