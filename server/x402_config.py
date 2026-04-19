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
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from x402.http import AuthHeaders, FacilitatorConfig, HTTPFacilitatorClient, PaymentOption
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


class CdpAuthProvider:
    """AuthProvider for Coinbase Developer Platform (CDP) mainnet facilitator.

    Generates ES256 JWTs signed with the CDP API key. Each JWT has a 120-second
    lifetime and includes the request URI for the facilitator endpoint.
    """

    def __init__(self, api_key_id: str, api_key_secret: str, facilitator_url: str):
        self.api_key_id = api_key_id
        self.facilitator_url = facilitator_url
        self._private_key, self._algorithm = self._load_key(api_key_secret)

    @staticmethod
    def _load_key(key_data: str):
        """Load CDP private key. Returns (key, algorithm).

        Supports:
        - PEM-encoded EC (ES256) or Ed25519 (EdDSA) keys
        - Raw base64: 64-byte Ed25519 seed+pubkey, DER-encoded keys
        """
        import base64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_der_private_key

        key_data = key_data.strip().replace("\\n", "\n")

        # Format 1: Full PEM with headers
        if key_data.startswith("-----"):
            key = load_pem_private_key(key_data.encode(), password=None)
            if isinstance(key, Ed25519PrivateKey):
                return key, "EdDSA"
            return key, "ES256"

        # Format 2: Raw base64
        try:
            raw_bytes = base64.b64decode(key_data)
        except Exception:
            raise ValueError("CDP_API_KEY_SECRET is not valid PEM or base64")

        # 64 bytes = Ed25519 seed (32) + public key (32) — CDP portal default
        if len(raw_bytes) == 64:
            try:
                key = Ed25519PrivateKey.from_private_bytes(raw_bytes[:32])
                return key, "EdDSA"
            except Exception:
                pass

        # Try DER (PKCS8 or traditional EC)
        try:
            key = load_der_private_key(raw_bytes, password=None)
            if isinstance(key, Ed25519PrivateKey):
                return key, "EdDSA"
            return key, "ES256"
        except Exception:
            pass

        raise ValueError(
            "CDP_API_KEY_SECRET could not be parsed. Expected PEM format or "
            "base64-encoded key from portal.cdp.coinbase.com."
        )

    def _build_jwt(self, method: str, path: str) -> str:
        """Build a CDP ES256 JWT for a specific facilitator endpoint."""
        # Extract host from facilitator URL
        from urllib.parse import urlparse
        parsed = urlparse(self.facilitator_url)
        host = parsed.netloc  # e.g. "api.cdp.coinbase.com"
        base_path = parsed.path.rstrip("/")  # e.g. "/platform/v2/x402"

        now = int(time.time())
        uri = f"{method} {host}{base_path}/{path}"

        payload = {
            "sub": self.api_key_id,
            "iss": "cdp",
            "aud": ["cdp_service"],
            "nbf": now,
            "iat": now,
            "exp": now + 120,
            "uris": [uri],
        }

        return jwt.encode(
            payload,
            self._private_key,
            algorithm=self._algorithm,
            headers={
                "kid": self.api_key_id,
                "nonce": secrets.token_hex(16),
                "typ": "JWT",
            },
        )

    def get_auth_headers(self) -> AuthHeaders:
        """Generate fresh JWT auth headers for verify, settle, and supported endpoints."""
        return AuthHeaders(
            verify={"Authorization": f"Bearer {self._build_jwt('POST', 'verify')}"},
            settle={"Authorization": f"Bearer {self._build_jwt('POST', 'settle')}"},
            supported={"Authorization": f"Bearer {self._build_jwt('GET', 'supported')}"},
        )


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

    # Initialize x402 SDK (with CDP auth for mainnet facilitator)
    auth_provider = None
    if "cdp.coinbase.com" in facilitator_url:
        cdp_key_id = os.environ["CDP_API_KEY_ID"]
        cdp_key_secret = os.environ["CDP_API_KEY_SECRET"]
        auth_provider = CdpAuthProvider(cdp_key_id, cdp_key_secret, facilitator_url)
        logger.info("CDP auth provider configured for mainnet facilitator")

    facilitator_config = FacilitatorConfig(url=facilitator_url, auth_provider=auth_provider)
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
