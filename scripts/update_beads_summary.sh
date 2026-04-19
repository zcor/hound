#!/usr/bin/env bash
# Generate beads_summary.json for the daily Telegram digest.
# Run via cron on the host (not inside Docker).
# Cron example: 55 9 * * * /opt/hound/scripts/update_beads_summary.sh
#   (5 min before the daily digest task at 10:00 UTC)
#
# Output shape: {"total": <int>, "top": [{id, title, priority, assignee, status}, ...]}
# - total = count of open + in_progress + blocked, excluding P4 (backlog)
# - top   = first 5 entries, sorted by priority asc, then updated_at desc

set -euo pipefail

BEADS_DIR="${BEADS_DIR:-/opt/hound/.beads}"
OUTPUT="${1:-/opt/hound/beads_summary.json}"

export BEADS_DIR

python3 <<PY
import json
import os
import subprocess
import sys
import time

TOP_N = 5
STATUSES = ("open", "in_progress", "blocked")
OUTPUT = "$OUTPUT"

def fetch(status):
    try:
        out = subprocess.check_output(
            ["bd", "list", "--status", status, "--json"],
            stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError:
        return []
    # bd list --json emits a JSON array
    try:
        data = json.loads(out.decode() or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return data

def normalize(obj, status):
    # priority may be int or None; treat missing as 99 so it sorts last
    raw_priority = obj.get("priority")
    try:
        priority = int(raw_priority) if raw_priority is not None and raw_priority != "" else 99
    except (TypeError, ValueError):
        priority = 99
    return {
        "id": obj.get("id", ""),
        "title": obj.get("title", ""),
        "priority": priority,
        "assignee": obj.get("assignee", "") or "",
        "status": obj.get("status", status) or status,
        "updated_at": obj.get("updated_at", "") or "",
    }

rows = []
for status in STATUSES:
    for obj in fetch(status):
        rows.append(normalize(obj, status))

# Drop P4 backlog
rows = [r for r in rows if r["priority"] < 4]

# Sort: priority asc, then updated_at desc within priority (ISO-8601 sorts lexically)
rows.sort(key=lambda r: r["updated_at"], reverse=True)
rows.sort(key=lambda r: r["priority"])

total = len(rows)
top = [
    {
        "id": r["id"],
        "title": r["title"],
        "priority": r["priority"],
        "assignee": r["assignee"],
        "status": r["status"],
    }
    for r in rows[:TOP_N]
]

# Guard against an empty local bd db clobbering a scp'd good file.
# If we found no active tasks AND the existing summary is <7d old, keep it.
if total == 0 and os.path.exists(OUTPUT):
    age_hours = (time.time() - os.path.getmtime(OUTPUT)) / 3600.0
    if age_hours < 7 * 24:
        print(f"SKIP: local bd empty; keeping existing {OUTPUT} ({age_hours:.0f}h old)", file=sys.stderr)
        sys.exit(0)

payload = {"total": total, "top": top}
with open(OUTPUT, "w") as f:
    json.dump(payload, f, indent=2)
    f.write("\n")
print(f"WROTE: total={total}, top={len(top)}")
PY
