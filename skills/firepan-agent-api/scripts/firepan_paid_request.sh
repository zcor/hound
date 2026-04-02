#!/usr/bin/env bash
set -euo pipefail

method="${1:-}"
url="${2:-}"
body_json="${3:-${BODY_JSON:-}}"
api_container="${API_CONTAINER:-hound-api}"
idempotency_key="${IDEMPOTENCY_KEY:-firepan-$(date +%s)}"
timeout_seconds="${TIMEOUT_SECONDS:-180}"

if [[ -z "$method" || -z "$url" ]]; then
  echo "Usage: $0 <METHOD> <URL> [BODY_JSON]" >&2
  exit 1
fi

if [[ -z "${JWT_TOKEN:-}" ]]; then
  echo "JWT_TOKEN is required." >&2
  exit 1
fi

if [[ -z "${WALLET_PRIVATE_KEY:-}" ]]; then
  echo "WALLET_PRIVATE_KEY is required." >&2
  exit 1
fi

docker exec -i \
  -e REQUEST_METHOD="$method" \
  -e REQUEST_URL="$url" \
  -e REQUEST_BODY_JSON="$body_json" \
  -e IDEMPOTENCY_KEY="$idempotency_key" \
  -e TIMEOUT_SECONDS="$timeout_seconds" \
  -e JWT_TOKEN="$JWT_TOKEN" \
  -e WALLET_PRIVATE_KEY="$WALLET_PRIVATE_KEY" \
  "$api_container" python3 - <<'PY'
import json
import os
import sys

import requests
from eth_account import Account
from x402.client import x402ClientSync
from x402.mechanisms.evm.exact import ExactEvmScheme
from x402.schemas import PaymentRequired

method = os.environ["REQUEST_METHOD"].upper()
url = os.environ["REQUEST_URL"]
body_json = os.environ.get("REQUEST_BODY_JSON", "")
idempotency_key = os.environ["IDEMPOTENCY_KEY"]
timeout_seconds = int(os.environ["TIMEOUT_SECONDS"])
jwt_token = os.environ["JWT_TOKEN"]
private_key = os.environ["WALLET_PRIVATE_KEY"]

headers = {
    "Authorization": f"Bearer {jwt_token}",
    "Content-Type": "application/json",
}
if method in {"POST", "PUT", "PATCH"}:
    headers["Idempotency-Key"] = idempotency_key

body = None
if body_json:
    body = json.loads(body_json)

print(f"Preflight {method} {url}")
resp = requests.request(method, url, headers=headers, json=body, timeout=timeout_seconds)
print(f"Preflight status: {resp.status_code}")

if resp.status_code != 402:
    try:
        print(json.dumps(resp.json(), indent=2))
    except Exception:
        print(resp.text)
    sys.exit(0 if resp.ok else 1)

payment_header = resp.headers.get("x-payment-requirements") or resp.headers.get("X-Payment-Requirements")
if not payment_header:
    print("Missing X-Payment-Requirements header on 402 response", file=sys.stderr)
    sys.exit(1)

payment_required = PaymentRequired.model_validate_json(payment_header)
client = x402ClientSync()
client.register("eip155:8453", ExactEvmScheme(Account.from_key(private_key)))
payment_payload = client.create_payment_payload(payment_required)

paid_headers = dict(headers)
paid_headers["X-PAYMENT"] = payment_payload.model_dump_json(by_alias=True, exclude_none=True)

print(f"Paid retry {method} {url}")
paid_resp = requests.request(method, url, headers=paid_headers, json=body, timeout=timeout_seconds)
print(f"Paid status: {paid_resp.status_code}")

try:
    print(json.dumps(paid_resp.json(), indent=2))
except Exception:
    print(paid_resp.text)

if not paid_resp.ok:
    sys.exit(1)
PY
