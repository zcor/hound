#!/bin/bash
# firepan-pr79 — Claude CLI cost monitor for the hound worker.
#
# Tails worker logs, sums "total_cost_usd" entries per session id, and writes
# a daily summary to /opt/hound/var/cost-rollup.jsonl. Run via cron every
# hour or on demand. Zero Claude API calls — pure log scraping.
#
# Usage:
#   ./cost-monitor.sh                # roll up since 24h ago
#   ./cost-monitor.sh --since 7d     # last week
#   ./cost-monitor.sh --tail         # streaming mode (tail -f)
#
set -euo pipefail

SINCE="${SINCE:-24h}"
TAIL_MODE=false
for arg in "$@"; do
  case "$arg" in
    --since) shift; SINCE="$1"; shift;;
    --tail) TAIL_MODE=true; shift;;
  esac
done

OUT_DIR=/opt/hound/var
mkdir -p "$OUT_DIR"
OUT_FILE="$OUT_DIR/cost-rollup.jsonl"

if [ "$TAIL_MODE" = "true" ]; then
  docker logs hound-worker -f 2>&1 | grep --line-buffered -oE '"total_cost_usd":[0-9.]+|"session_id":"[^"]+"' | while read -r line; do
    echo "$(date -Iseconds) $line"
  done
  exit 0
fi

# Pull all cost reports from the last $SINCE worth of worker logs
docker logs hound-worker --since "$SINCE" 2>&1 > /tmp/worker-since.log

# Extract (session_id, cost) pairs — they appear in adjacent JSON fields
# in the same Claude CLI result blob.
python3 << EOF
import re, json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

with open("/tmp/worker-since.log") as f:
    text = f.read()

# Each Claude CLI call emits a JSON blob with both fields. Match them
# together via a single pattern.
pattern = re.compile(
    r'"session_id":"([^"]+)".*?"total_cost_usd":([0-9.]+)',
    re.DOTALL,
)
costs_by_session = defaultdict(float)
total = 0.0
n = 0
for m in pattern.finditer(text):
    sid, cost_str = m.group(1), m.group(2)
    try:
        c = float(cost_str)
        costs_by_session[sid] += c
        total += c
        n += 1
    except ValueError:
        pass

now = datetime.now(timezone.utc).isoformat()
rollup = {
    "rolled_up_at": now,
    "since": "$SINCE",
    "total_usd": round(total, 2),
    "call_count": n,
    "per_session_top10": sorted(
        [{"session_id": s, "cost_usd": round(c, 2)} for s, c in costs_by_session.items()],
        key=lambda x: -x["cost_usd"],
    )[:10],
}
out_path = Path("$OUT_FILE")
out_path.parent.mkdir(parents=True, exist_ok=True)
with out_path.open("a") as f:
    f.write(json.dumps(rollup) + "\n")

print(f"Cost rollup since $SINCE: \$\\\${rollup['total_usd']:.2f} across {n} Claude CLI calls, {len(costs_by_session)} sessions")
print(f"Top sessions by cost:")
for s in rollup["per_session_top10"][:5]:
    print(f"  \${s['cost_usd']:6.2f}  {s['session_id']}")
print(f"Appended to: $OUT_FILE")
EOF
