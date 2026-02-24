"""
x402 Agent Payments configuration.

Reads env vars and pricing config, initializes the x402 SDK as a library
(NOT middleware — auth must run before payment, see x402_deps.py).

Usage:
    from server.x402_config import get_x402_config

    config = get_x402_config()
    if config is None:
        # x402 is disabled
    else:
        config.server  # x402ResourceServer instance
        config.route_pricing  # dict of route_key -> RouteConfig
"""

import json
import logging
import os
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from x402.http import HTTPFacilitatorClient, FacilitatorConfig, PaymentOption
from x402.http.types import RouteConfig
from x402.http.x402_http_server import x402HTTPResourceServer
from x402.mechanisms.evm.exact import ExactEvmServerScheme
from x402.server import x402ResourceServer

logger = logging.getLogger(__name__)

# Base Sepolia (testnet) USDC contract address
USDC_ADDRESSES = {
    "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  # Base Sepolia
    "eip155:8453": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base Mainnet
}


def usd_to_atomic_usdc(usd_str: str) -> int:
    """Convert USD string like '$0.50' to USDC atomic units (500000)."""
    usd = Decimal(usd_str.replace("$", ""))
    return int(usd * 10**6)


@dataclass
class X402Config:
    """Validated x402 configuration."""
    wallet_address: str
    facilitator_url: str
    network: str
    free_scan_daily_budget_usd: int
    server: x402ResourceServer
    http_server: x402HTTPResourceServer
    route_pricing: dict[str, RouteConfig]
    pricing_raw: dict[str, dict]


def x402_enabled() -> bool:
    """Check if x402 is enabled via env var."""
    return os.environ.get("X402_ENABLED", "").lower() == "true"


def _load_pricing(config_path: Path | None = None) -> dict:
    """Load pricing config from JSON file."""
    if config_path is None:
        # Default: config/x402_pricing.json relative to tools/hound/
        config_path = Path(__file__).parent.parent / "config" / "x402_pricing.json"

    if not config_path.exists():
        raise RuntimeError(f"x402 pricing config not found: {config_path}")

    with open(config_path) as f:
        data = json.load(f)

    if "routes" not in data:
        raise RuntimeError(f"x402 pricing config missing 'routes' key: {config_path}")

    return data["routes"]


def get_x402_config(config_path: Path | None = None) -> X402Config | None:
    """
    Load and validate x402 configuration.

    Returns None if X402_ENABLED is not 'true'.
    Raises RuntimeError if enabled but misconfigured (fail-fast).
    """
    if not x402_enabled():
        return None

    # Fail-fast on missing required env vars
    wallet = os.environ.get("X402_WALLET_ADDRESS")
    if not wallet:
        raise RuntimeError("X402_ENABLED=true but X402_WALLET_ADDRESS is not set")

    facilitator_url = os.environ.get("X402_FACILITATOR_URL")
    if not facilitator_url:
        raise RuntimeError("X402_ENABLED=true but X402_FACILITATOR_URL is not set")

    network = os.environ.get("X402_NETWORK")
    if not network:
        raise RuntimeError("X402_ENABLED=true but X402_NETWORK is not set")

    # Mainnet facilitator requires CDP API keys
    if "cdp.coinbase.com" in facilitator_url:
        if not os.environ.get("CDP_API_KEY_ID") or not os.environ.get("CDP_API_KEY_SECRET"):
            raise RuntimeError(
                "Mainnet facilitator requires CDP_API_KEY_ID and CDP_API_KEY_SECRET"
            )

    free_budget = int(os.environ.get("X402_FREE_SCAN_DAILY_BUDGET_USD", "25"))

    # Load pricing
    pricing_raw = _load_pricing(config_path)

    # Initialize x402 SDK
    facilitator_config = FacilitatorConfig(url=facilitator_url)
    facilitator_client = HTTPFacilitatorClient(config=facilitator_config)
    server = x402ResourceServer(facilitator_clients=facilitator_client)

    # Register EVM scheme for the configured network
    evm_scheme = ExactEvmServerScheme()
    server.register(network, evm_scheme)

    # Initialize the server (required before verify/settle/build_payment_requirements)
    server.initialize()

    # Build route configs for the HTTP server
    routes: dict[str, RouteConfig] = {}
    for route_key, route_info in pricing_raw.items():
        price = route_info["price"]
        description = route_info.get("description", "")

        payment_option = PaymentOption(
            scheme="exact",
            pay_to=wallet,
            price=price,
            network=network,
        )

        routes[route_key] = RouteConfig(
            accepts=payment_option,
            description=description,
        )

    # Create HTTP server wrapper (used for verify/settle, not as middleware)
    http_server = x402HTTPResourceServer(server, routes)

    config = X402Config(
        wallet_address=wallet,
        facilitator_url=facilitator_url,
        network=network,
        free_scan_daily_budget_usd=free_budget,
        server=server,
        http_server=http_server,
        route_pricing=routes,
        pricing_raw=pricing_raw,
    )

    logger.info(
        "x402 payments enabled: wallet=%s network=%s facilitator=%s routes=%s",
        wallet[:10] + "..." + wallet[-4:],
        network,
        facilitator_url,
        list(routes.keys()),
    )

    return config


# Module-level singleton (initialized on first access)
_x402_config: X402Config | None = None
_x402_config_loaded = False


def get_config() -> X402Config | None:
    """Get cached x402 config singleton. Returns None if disabled."""
    global _x402_config, _x402_config_loaded
    if not _x402_config_loaded:
        _x402_config = get_x402_config()
        _x402_config_loaded = True
    return _x402_config


def reset_config():
    """Reset config singleton (for testing)."""
    global _x402_config, _x402_config_loaded
    _x402_config = None
    _x402_config_loaded = False
