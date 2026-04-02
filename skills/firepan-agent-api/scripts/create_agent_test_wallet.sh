#!/usr/bin/env bash
set -euo pipefail

wallet_path="${1:-$PWD/.firepan-agent-wallet.json}"
api_container="${API_CONTAINER:-hound-api}"

if [[ -e "$wallet_path" ]]; then
  echo "Refusing to overwrite existing wallet file: $wallet_path" >&2
  echo "Move it aside or pass a different path." >&2
  exit 1
fi

mkdir -p "$(dirname "$wallet_path")"
umask 077

wallet_json="$(docker exec "$api_container" python3 -c '
import json
from eth_account import Account

acct = Account.create()
print(json.dumps({
    "network": "base",
    "chain_id": 8453,
    "address": acct.address,
    "private_key": acct.key.hex(),
}))
')"

printf '%s\n' "$wallet_json" > "$wallet_path"
chmod 600 "$wallet_path"

address="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["address"])' "$wallet_path")"

cat <<EOF
Created wallet file:
  $wallet_path

Address:
  $address

Next:
  1. Fund this address with USDC on Base.
  2. Keep a small amount of Base ETH available if your client path needs gas.
  3. Use this wallet with scripts/firepan_surface_scan.sh or scripts/firepan_start_audit.sh.
EOF
