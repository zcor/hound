#!/usr/bin/env bash
set -euo pipefail

tenant_id="${1:-${TENANT_ID:-}}"
user_id="${2:-${USER_ID:-}}"
api_container="${API_CONTAINER:-hound-api}"

if [[ -z "$tenant_id" || -z "$user_id" ]]; then
  echo "Usage: $0 <tenant_id> <user_id>" >&2
  echo "Or set TENANT_ID and USER_ID." >&2
  exit 1
fi

docker exec "$api_container" python3 -c "from server.auth_utils import create_access_token; print(create_access_token({'tenant_id': $tenant_id, 'user_id': $user_id}))" \
  | tail -n 1
