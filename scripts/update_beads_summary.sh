#!/usr/bin/env bash
# Generate beads_summary.json for the daily Telegram digest.
# Run via cron on the host (not inside Docker).
# Cron example: 55 9 * * * /opt/hound/scripts/update_beads_summary.sh
#   (5 min before the daily-stripe-health task at 10:00 UTC)

set -euo pipefail

BEADS_DIR="${BEADS_DIR:-/opt/hound/.beads}"
OUTPUT="${1:-/opt/hound/beads_summary.json}"

export BEADS_DIR

# bd ready --json outputs one JSON object per line
# We want an array of {id, title, priority, assignee, status}
bd ready --json -n 50 2>/dev/null | python3 -c "
import sys, json

tasks = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
        tasks.append({
            'id': obj.get('id', ''),
            'title': obj.get('title', ''),
            'priority': obj.get('priority', ''),
            'assignee': obj.get('assignee', ''),
            'status': obj.get('status', ''),
        })
    except json.JSONDecodeError:
        continue

json.dump(tasks, sys.stdout, indent=2)
" > "$OUTPUT"

echo "Updated $OUTPUT with $(python3 -c "import json; print(len(json.load(open('$OUTPUT'))))" 2>/dev/null || echo '?') tasks"
