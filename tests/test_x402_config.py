"""
Unit tests for x402 configuration loading and validation.
"""

import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.x402_config import get_x402_config, x402_enabled, usd_to_atomic_usdc, reset_config


class TestX402Enabled(unittest.TestCase):
    """Test x402_enabled() flag."""

    def tearDown(self):
        reset_config()

    @patch.dict(os.environ, {}, clear=True)
    def test_disabled_by_default(self):
        self.assertFalse(x402_enabled())

    @patch.dict(os.environ, {"X402_ENABLED": "false"})
    def test_disabled_explicit(self):
        self.assertFalse(x402_enabled())

    @patch.dict(os.environ, {"X402_ENABLED": "true"})
    def test_enabled(self):
        self.assertTrue(x402_enabled())

    @patch.dict(os.environ, {"X402_ENABLED": "TRUE"})
    def test_enabled_case_insensitive(self):
        self.assertTrue(x402_enabled())


class TestUsdToAtomicUsdc(unittest.TestCase):
    """Test USD string to atomic USDC conversion."""

    def test_half_dollar(self):
        self.assertEqual(usd_to_atomic_usdc("$0.50"), 500000)

    def test_five_dollars(self):
        self.assertEqual(usd_to_atomic_usdc("$5.00"), 5000000)

    def test_ten_cents(self):
        self.assertEqual(usd_to_atomic_usdc("$0.10"), 100000)

    def test_one_dollar(self):
        self.assertEqual(usd_to_atomic_usdc("$1.00"), 1000000)

    def test_without_dollar_sign(self):
        self.assertEqual(usd_to_atomic_usdc("0.50"), 500000)


class TestGetX402Config(unittest.TestCase):
    """Test configuration loading and fail-fast validation."""

    def setUp(self):
        reset_config()
        self.pricing_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        json.dump({
            "routes": {
                "POST /surface/scan/full": {"price": "$0.50", "description": "Full scan"},
                "POST /audits/start": {"price": "$5.00", "description": "Deep audit"},
            }
        }, self.pricing_file)
        self.pricing_file.close()

    def tearDown(self):
        reset_config()
        os.unlink(self.pricing_file.name)

    @patch.dict(os.environ, {"X402_ENABLED": "false"}, clear=True)
    def test_disabled_returns_none(self):
        result = get_x402_config()
        self.assertIsNone(result)

    @patch.dict(os.environ, {"X402_ENABLED": "true"}, clear=True)
    def test_missing_wallet_crashes(self):
        with self.assertRaises(RuntimeError) as ctx:
            get_x402_config()
        self.assertIn("X402_WALLET_ADDRESS", str(ctx.exception))

    @patch.dict(os.environ, {
        "X402_ENABLED": "true",
        "X402_WALLET_ADDRESS": "0x1234567890abcdef1234567890abcdef12345678",
    }, clear=True)
    def test_missing_facilitator_crashes(self):
        with self.assertRaises(RuntimeError) as ctx:
            get_x402_config()
        self.assertIn("X402_FACILITATOR_URL", str(ctx.exception))

    @patch.dict(os.environ, {
        "X402_ENABLED": "true",
        "X402_WALLET_ADDRESS": "0x1234567890abcdef1234567890abcdef12345678",
        "X402_FACILITATOR_URL": "https://x402.org/facilitator",
    }, clear=True)
    def test_missing_network_crashes(self):
        with self.assertRaises(RuntimeError) as ctx:
            get_x402_config()
        self.assertIn("X402_NETWORK", str(ctx.exception))

    @patch.dict(os.environ, {
        "X402_ENABLED": "true",
        "X402_WALLET_ADDRESS": "0x1234567890abcdef1234567890abcdef12345678",
        "X402_FACILITATOR_URL": "https://api.cdp.coinbase.com/platform/v2/x402",
        "X402_NETWORK": "eip155:8453",
    }, clear=True)
    def test_mainnet_without_cdp_keys_crashes(self):
        with self.assertRaises(RuntimeError) as ctx:
            get_x402_config(config_path=Path(self.pricing_file.name))
        self.assertIn("CDP_API_KEY_ID", str(ctx.exception))

    @patch.dict(os.environ, {
        "X402_ENABLED": "true",
        "X402_WALLET_ADDRESS": "0x1234567890abcdef1234567890abcdef12345678",
        "X402_FACILITATOR_URL": "https://x402.org/facilitator",
        "X402_NETWORK": "eip155:84532",
    }, clear=True)
    def test_valid_config_loads(self):
        config = get_x402_config(config_path=Path(self.pricing_file.name))
        self.assertIsNotNone(config)
        self.assertEqual(config.wallet_address, "0x1234567890abcdef1234567890abcdef12345678")
        self.assertEqual(config.network, "eip155:84532")
        self.assertEqual(len(config.route_pricing), 2)
        self.assertIn("POST /surface/scan/full", config.route_pricing)
        self.assertIn("POST /audits/start", config.route_pricing)

    @patch.dict(os.environ, {
        "X402_ENABLED": "true",
        "X402_WALLET_ADDRESS": "0x1234567890abcdef1234567890abcdef12345678",
        "X402_FACILITATOR_URL": "https://x402.org/facilitator",
        "X402_NETWORK": "eip155:84532",
        "X402_FREE_SCAN_DAILY_BUDGET_USD": "50",
    }, clear=True)
    def test_custom_budget(self):
        config = get_x402_config(config_path=Path(self.pricing_file.name))
        self.assertEqual(config.free_scan_daily_budget_usd, 50)

    def test_missing_pricing_file_crashes(self):
        with patch.dict(os.environ, {
            "X402_ENABLED": "true",
            "X402_WALLET_ADDRESS": "0x1234567890abcdef1234567890abcdef12345678",
            "X402_FACILITATOR_URL": "https://x402.org/facilitator",
            "X402_NETWORK": "eip155:84532",
        }, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                get_x402_config(config_path=Path("/nonexistent/pricing.json"))
            self.assertIn("not found", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
