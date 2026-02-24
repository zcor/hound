"""
Integration tests for x402 payment dependency and state machine.

Tests auth-before-payment ordering, idempotency, state machine transitions,
and payment replay protection. Uses SQLite in-memory DB for unit-level tests.
Concurrency tests require Postgres for IntegrityError behavior.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import (
    Base,
    PaymentLog,
    Tenant,
    create_db_engine,
    create_db_session,
    init_database,
)
from server.x402_deps import (
    LEGAL_TRANSITIONS,
    PaymentGate,
    PaymentStatus,
    canonical_request_hash,
    create_paid_job,
    mark_job_failed,
    transition,
)


class TestPaymentStatus(unittest.TestCase):
    """Test payment status constants and transitions."""

    def test_status_values(self):
        self.assertEqual(PaymentStatus.RESERVED, "reserved")
        self.assertEqual(PaymentStatus.PAID, "paid")
        self.assertEqual(PaymentStatus.JOB_CREATED, "job_created")
        self.assertEqual(PaymentStatus.JOB_FAILED, "job_failed")
        self.assertEqual(PaymentStatus.EXPIRED, "expired")

    def test_legal_transitions_from_reserved(self):
        allowed = LEGAL_TRANSITIONS[PaymentStatus.RESERVED]
        self.assertIn(PaymentStatus.PAID, allowed)
        self.assertIn(PaymentStatus.EXPIRED, allowed)
        self.assertNotIn(PaymentStatus.JOB_CREATED, allowed)

    def test_legal_transitions_from_expired(self):
        allowed = LEGAL_TRANSITIONS[PaymentStatus.EXPIRED]
        self.assertIn(PaymentStatus.RESERVED, allowed)
        self.assertEqual(len(allowed), 1)

    def test_legal_transitions_from_paid(self):
        allowed = LEGAL_TRANSITIONS[PaymentStatus.PAID]
        self.assertIn(PaymentStatus.JOB_CREATED, allowed)
        self.assertIn(PaymentStatus.JOB_FAILED, allowed)

    def test_legal_transitions_from_job_failed(self):
        allowed = LEGAL_TRANSITIONS[PaymentStatus.JOB_FAILED]
        self.assertIn(PaymentStatus.PAID, allowed)

    def test_job_created_is_terminal(self):
        self.assertNotIn(PaymentStatus.JOB_CREATED, LEGAL_TRANSITIONS)


class TestCanonicalRequestHash(unittest.TestCase):
    """Test request body canonicalization."""

    def test_json_sorted_keys(self):
        body1 = b'{"b": 2, "a": 1}'
        body2 = b'{"a": 1, "b": 2}'
        self.assertEqual(canonical_request_hash(body1), canonical_request_hash(body2))

    def test_whitespace_irrelevant(self):
        body1 = b'{"a": 1, "b": 2}'
        body2 = b'{ "a" : 1 , "b" : 2 }'
        self.assertEqual(canonical_request_hash(body1), canonical_request_hash(body2))

    def test_different_values_different_hash(self):
        body1 = b'{"a": 1}'
        body2 = b'{"a": 2}'
        self.assertNotEqual(canonical_request_hash(body1), canonical_request_hash(body2))

    def test_non_json_body(self):
        body = b"not json"
        h = canonical_request_hash(body)
        self.assertEqual(len(h), 64)  # SHA-256 hex

    def test_empty_body(self):
        h = canonical_request_hash(b"")
        self.assertEqual(len(h), 64)


class TestStateMachine(unittest.TestCase):
    """Test state machine transitions with real DB."""

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

    def _create_log(self, status="reserved", **kwargs):
        defaults = dict(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            status=status,
        )
        defaults.update(kwargs)
        log = PaymentLog(**defaults)
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        return log

    def test_reserved_to_paid(self):
        log = self._create_log(status="reserved")
        transition(log, PaymentStatus.PAID, self.db)
        self.assertEqual(log.status, "paid")

    def test_reserved_to_expired(self):
        log = self._create_log(status="reserved")
        transition(log, PaymentStatus.EXPIRED, self.db)
        self.assertEqual(log.status, "expired")

    def test_expired_to_reserved(self):
        log = self._create_log(status="expired")
        transition(log, PaymentStatus.RESERVED, self.db)
        self.assertEqual(log.status, "reserved")

    def test_paid_to_job_created(self):
        log = self._create_log(status="paid")
        transition(log, PaymentStatus.JOB_CREATED, self.db)
        self.assertEqual(log.status, "job_created")

    def test_paid_to_job_failed(self):
        log = self._create_log(status="paid")
        transition(log, PaymentStatus.JOB_FAILED, self.db)
        self.assertEqual(log.status, "job_failed")

    def test_job_failed_to_paid(self):
        log = self._create_log(status="job_failed")
        transition(log, PaymentStatus.PAID, self.db)
        self.assertEqual(log.status, "paid")

    def test_illegal_reserved_to_job_created(self):
        log = self._create_log(status="reserved")
        with self.assertRaises(ValueError) as ctx:
            transition(log, PaymentStatus.JOB_CREATED, self.db)
        self.assertIn("Illegal transition", str(ctx.exception))

    def test_illegal_paid_to_reserved(self):
        log = self._create_log(status="paid")
        with self.assertRaises(ValueError):
            transition(log, PaymentStatus.RESERVED, self.db)

    def test_illegal_expired_to_paid(self):
        log = self._create_log(status="expired")
        with self.assertRaises(ValueError):
            transition(log, PaymentStatus.PAID, self.db)

    def test_job_created_is_terminal(self):
        log = self._create_log(status="job_created")
        with self.assertRaises(ValueError):
            transition(log, PaymentStatus.PAID, self.db)


class TestCreatePaidJob(unittest.TestCase):
    """Test create_paid_job helper."""

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

    def test_links_job_and_transitions(self):
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=500000,
            amount_usd=Decimal("0.50"),
            status="paid",
        )
        self.db.add(log)
        self.db.commit()

        create_paid_job(self.db, log.id, "scan_abc123")
        self.db.refresh(log)
        self.assertEqual(log.status, "job_created")
        self.assertEqual(log.job_id, "scan_abc123")

    def test_cannot_create_job_from_reserved(self):
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            status="reserved",
        )
        self.db.add(log)
        self.db.commit()

        with self.assertRaises(ValueError):
            create_paid_job(self.db, log.id, "scan_abc123")

    def test_nonexistent_log_raises(self):
        with self.assertRaises(ValueError):
            create_paid_job(self.db, 99999, "scan_abc123")


class TestMarkJobFailed(unittest.TestCase):
    """Test mark_job_failed helper."""

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

    def test_marks_paid_as_failed(self):
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=500000,
            amount_usd=Decimal("0.50"),
            status="paid",
        )
        self.db.add(log)
        self.db.commit()

        mark_job_failed(self.db, log.id)
        self.db.refresh(log)
        self.assertEqual(log.status, "job_failed")

    def test_cannot_mark_reserved_as_failed(self):
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            status="reserved",
        )
        self.db.add(log)
        self.db.commit()

        with self.assertRaises(ValueError):
            mark_job_failed(self.db, log.id)


class TestPaymentGate(unittest.TestCase):
    """Test PaymentGate dataclass."""

    def test_disabled_gate(self):
        gate = PaymentGate(enabled=False, status="disabled")
        self.assertFalse(gate.enabled)
        self.assertEqual(gate.status, "disabled")
        self.assertIsNone(gate.payment_log_id)
        self.assertIsNone(gate.job_id)

    def test_paid_gate(self):
        gate = PaymentGate(enabled=True, status="paid", payment_log_id=42)
        self.assertTrue(gate.enabled)
        self.assertEqual(gate.status, "paid")
        self.assertEqual(gate.payment_log_id, 42)

    def test_entitled_gate(self):
        gate = PaymentGate(enabled=True, status="entitled", resource_id="audit_123")
        self.assertEqual(gate.status, "entitled")
        self.assertEqual(gate.resource_id, "audit_123")

    def test_already_processed_gate(self):
        gate = PaymentGate(
            enabled=True, status="already_processed",
            payment_log_id=1, job_id="scan_xyz",
        )
        self.assertEqual(gate.status, "already_processed")
        self.assertEqual(gate.job_id, "scan_xyz")


class TestPaymentLogModel(unittest.TestCase):
    """Test PaymentLog SQLAlchemy model."""

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

    def test_create_payment_log(self):
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=500000,
            amount_usd=Decimal("0.50"),
            token="USDC",
            status="reserved",
        )
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        self.assertIsNotNone(log.id)
        self.assertEqual(log.status, "reserved")
        self.assertIsNone(log.payment_id)
        self.assertIsNone(log.payer_address)

    def test_payment_id_unique_constraint(self):
        """payment_id unique constraint prevents replay."""
        log1 = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=500000,
            amount_usd=Decimal("0.50"),
            payment_id="tx_unique_123",
            status="paid",
        )
        self.db.add(log1)
        self.db.commit()

        log2 = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /audits/start",
            network="eip155:84532",
            amount_atomic=5000000,
            amount_usd=Decimal("5.00"),
            payment_id="tx_unique_123",  # Same payment_id = replay
            status="paid",
        )
        self.db.add(log2)
        with self.assertRaises(Exception):  # IntegrityError
            self.db.commit()
        self.db.rollback()

    def test_null_payment_ids_dont_conflict(self):
        """Multiple reserved rows with NULL payment_id should not conflict."""
        log1 = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            payment_id=None,
            idempotency_key="key1",
            status="reserved",
        )
        log2 = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            payment_id=None,
            idempotency_key="key2",
            status="reserved",
        )
        self.db.add(log1)
        self.db.add(log2)
        self.db.commit()  # Should not raise

    def test_amount_precision(self):
        """Verify Numeric(10,6) stores USDC amounts correctly."""
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=500000,
            amount_usd=Decimal("0.500000"),
            status="paid",
        )
        self.db.add(log)
        self.db.commit()
        self.db.refresh(log)
        self.assertEqual(log.amount_atomic, 500000)
        # SQLite stores Numeric as float, so compare with tolerance
        self.assertAlmostEqual(float(log.amount_usd), 0.5, places=6)


class TestFullLifecycle(unittest.TestCase):
    """Test the full payment lifecycle through state transitions."""

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

    def test_happy_path(self):
        """reserved -> paid -> job_created"""
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            status="reserved",
            idempotency_key="test-key-1",
        )
        self.db.add(log)
        self.db.commit()

        # Verify payment
        log.amount_atomic = 500000
        log.amount_usd = Decimal("0.50")
        log.payment_id = "tx_happy_path"
        log.payer_address = "0xpayer"
        log.tx_hash = "0xtxhash"
        transition(log, PaymentStatus.PAID, self.db)
        self.assertEqual(log.status, "paid")

        # Create job
        create_paid_job(self.db, log.id, "scan_happy")
        self.db.refresh(log)
        self.assertEqual(log.status, "job_created")
        self.assertEqual(log.job_id, "scan_happy")

    def test_job_failed_retry(self):
        """reserved -> paid -> job_failed -> paid -> job_created (no recharge)"""
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=500000,
            amount_usd=Decimal("0.50"),
            status="reserved",
            idempotency_key="test-key-2",
            payment_id="tx_retry",
        )
        self.db.add(log)
        self.db.commit()

        transition(log, PaymentStatus.PAID, self.db)
        mark_job_failed(self.db, log.id)
        self.assertEqual(log.status, "job_failed")

        # Retry: back to paid, then job_created
        transition(log, PaymentStatus.PAID, self.db)
        create_paid_job(self.db, log.id, "scan_retry_success")
        self.db.refresh(log)
        self.assertEqual(log.status, "job_created")
        self.assertEqual(log.job_id, "scan_retry_success")

    def test_expired_retry(self):
        """reserved -> expired -> reserved -> paid -> job_created"""
        log = PaymentLog(
            tenant_id=self.tenant.id,
            endpoint="POST /surface/scan/full",
            network="eip155:84532",
            amount_atomic=0,
            amount_usd=Decimal("0"),
            status="reserved",
            idempotency_key="test-key-3",
        )
        self.db.add(log)
        self.db.commit()
        original_id = log.id

        # Expire
        transition(log, PaymentStatus.EXPIRED, self.db)
        self.assertEqual(log.status, "expired")

        # Reclaim
        transition(log, PaymentStatus.RESERVED, self.db)
        self.assertEqual(log.status, "reserved")
        self.assertEqual(log.id, original_id)  # Same row reused

        # Complete
        log.amount_atomic = 500000
        log.amount_usd = Decimal("0.50")
        log.payment_id = "tx_expired_retry"
        transition(log, PaymentStatus.PAID, self.db)
        create_paid_job(self.db, log.id, "scan_expired_retry")
        self.assertEqual(log.status, "job_created")


if __name__ == "__main__":
    unittest.main()
