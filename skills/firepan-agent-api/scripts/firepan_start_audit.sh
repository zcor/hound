#!/usr/bin/env bash
set -euo pipefail

wallet_path="${1:-$PWD/.firepan-agent-wallet.json}"
repo_url="${2:-}"
api_url="${API_URL:-https://api.firepan.com}"

if [[ -z "$repo_url" ]]; then
  echo "Usage: $0 <wallet_path> <repo_url>" >&2
  exit 1
fi

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

body_json="$(
  python3 - <<'PY' "$repo_url" "${INSTALLATION_ID:-}" "${INVESTIGATION_PROMPT:-}" "${MAX_ITERATIONS:-30}" "${TIME_LIMIT_MINUTES:-120}" "${MODE:-sweep}" "${PLAN_N:-5}"
import json
import sys

repo_url, installation_id, investigation_prompt, max_iterations, time_limit_minutes, mode, plan_n = sys.argv[1:]

payload = {
    "repo_url": repo_url,
    "installation_id": int(installation_id) if installation_id else None,
    "investigation_prompt": investigation_prompt or None,
    "max_iterations": int(max_iterations),
    "time_limit_minutes": int(time_limit_minutes),
    "mode": mode,
    "plan_n": int(plan_n),
}

print(json.dumps(payload))
PY
)"

bash "$(dirname "$0")/firepan_paid_request.sh" \
  POST \
  "$api_url/agent/audits" \
  "$body_json"
