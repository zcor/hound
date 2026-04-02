#!/usr/bin/env bash
set -euo pipefail

wallet_path="${1:-$PWD/.firepan-agent-wallet.json}"
repo_url="${2:-https://github.com/assune-hue/bad-solidity-contracts.git}"
api_url="${API_URL:-https://api.firepan.com}"
llm_budget="${LLM_BUDGET:-1}"

if [[ ! -f "$wallet_path" ]]; then
  echo "Wallet file not found: $wallet_path" >&2
  exit 1
fi

if [[ -z "${JWT_TOKEN:-}" ]]; then
  if [[ -n "${TENANT_ID:-}" && -n "${USER_ID:-}" ]]; then
    JWT_TOKEN="$(bash "$(dirname "$0")/generate_local_jwt.sh" "$TENANT_ID" "$USER_ID")"
    export JWT_TOKEN
  else
    echo "JWT_TOKEN is required, or set TENANT_ID and USER_ID for local generation." >&2
    exit 1
  fi
fi

export WALLET_PRIVATE_KEY
WALLET_PRIVATE_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["private_key"])' "$wallet_path")"

body_json="$(python3 -c 'import json,sys; print(json.dumps({"repo_url": sys.argv[1], "llm_budget": int(sys.argv[2])}))' "$repo_url" "$llm_budget")"

bash "$(dirname "$0")/firepan_paid_request.sh" \
  POST \
  "$api_url/agent/surface-scan" \
  "$body_json"
