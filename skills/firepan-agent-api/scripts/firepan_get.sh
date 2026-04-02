#!/usr/bin/env bash
set -euo pipefail

url="${1:-}"

if [[ -z "$url" ]]; then
  echo "Usage: $0 <URL>" >&2
  exit 1
fi

if [[ -z "${JWT_TOKEN:-}" ]]; then
  if [[ -n "${TENANT_ID:-}" && -n "${USER_ID:-}" ]]; then
    JWT_TOKEN="$(bash "$(dirname "$0")/generate_local_jwt.sh" "$TENANT_ID" "$USER_ID")"
  else
    echo "JWT_TOKEN is required, or set TENANT_ID and USER_ID for local generation." >&2
    exit 1
  fi
fi

curl -fsS \
  -H "Authorization: Bearer $JWT_TOKEN" \
  "$url"
