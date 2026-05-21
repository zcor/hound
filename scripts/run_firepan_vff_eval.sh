#!/usr/bin/env bash
# firepan-vff live-audit gate runner.
#
# Usage:
#   1. Ensure docker compose stack is up: `docker compose up -d`
#   2. Project IDs exist for yieldnest + curve-twocrypto-ng (see scripts/setup_firepan_vff_projects.sh)
#   3. Export YIELDNEST_PROJECT_ID + CURVE_PROJECT_ID + ADMIN_KEY (or pass as args)
#   4. Run: ./scripts/run_firepan_vff_eval.sh
#
# Outputs go to /tmp/firepan-vff-eval/ for the archive doc.
#
# Pass criteria (per firepan-vff plan):
#   1. Yieldnest auditor: 0 confirmed access-control template FPs.
#   2. Curve auditor: re-finds F-7 (donation_protection / chunked) + >=5/6 prior art.
#   3. Wall-clock auditor <= 2x sweep on same project.
#   4. Yieldnest auditor overview.symbol_exists_gate.rejected_count > 0.
#
# This script does NOT decide pass/fail — it captures the artifacts for the
# archive doc. Reviewer reads /tmp/firepan-vff-eval/SUMMARY.md and decides.

set -euo pipefail

ADMIN_KEY="${ADMIN_KEY:-${HOUND_ADMIN_KEY:-}}"
API_BASE="${API_BASE:-http://localhost:8000}"
YIELDNEST_PROJECT_ID="${YIELDNEST_PROJECT_ID:-}"
CURVE_PROJECT_ID="${CURVE_PROJECT_ID:-}"
OUT_DIR="${OUT_DIR:-/tmp/firepan-vff-eval}"
TIME_LIMIT="${TIME_LIMIT:-60}"        # minutes per audit
POLL_INTERVAL="${POLL_INTERVAL:-30}"  # seconds

if [[ -z "$ADMIN_KEY" ]]; then
    echo "ERROR: ADMIN_KEY or HOUND_ADMIN_KEY must be set." >&2
    exit 1
fi
if [[ -z "$YIELDNEST_PROJECT_ID" || -z "$CURVE_PROJECT_ID" ]]; then
    echo "ERROR: YIELDNEST_PROJECT_ID and CURVE_PROJECT_ID must be set." >&2
    echo "Hint: docker compose exec db psql -U hound -d hound -c \\" >&2
    echo "  \"SELECT id, name, git_url FROM projects WHERE git_url ILIKE '%yieldnest%' OR git_url ILIKE '%curve%';\"" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

run_audit() {
    local pid="$1" label="$2" mode="$3"
    local session_id status started elapsed http_code body

    echo ""
    echo "============================================================"
    echo "Running: project_id=$pid label=$label mode=$mode"
    echo "============================================================"

    body=$(curl -s -w "\n%{http_code}" -X POST "$API_BASE/admin/audits/force-run" \
        -H "X-Admin-Key: $ADMIN_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"project_id\": $pid, \"max_iterations\": 30, \"time_limit_minutes\": $TIME_LIMIT, \"mode\": \"$mode\"}")
    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')
    if [[ "$http_code" != "200" ]]; then
        echo "ERROR: force-run returned $http_code: $body" >&2
        return 1
    fi
    session_id=$(echo "$body" | jq -r '.session_id')
    started=$(date +%s)
    echo "[$label/$mode] session_id=$session_id"

    while true; do
        status=$(docker compose exec -T db psql -U hound -d hound -A -t -c \
            "SELECT status FROM audit_sessions WHERE session_id = '$session_id';" 2>/dev/null | tr -d '[:space:]')
        echo "[$label/$mode] status=$status (elapsed=$(($(date +%s) - started))s)"
        case "$status" in
            completed|failed|crashed) break ;;
            "") echo "[$label/$mode] WARN: no row yet — waiting" ;;
        esac
        sleep "$POLL_INTERVAL"
    done
    elapsed=$(($(date +%s) - started))
    echo "[$label/$mode] FINAL status=$status wall_clock=${elapsed}s"

    # 1. DB rows joined via Hypothesis.scan_execution_id (firepan-dar)
    docker compose exec -T db psql -U hound -d hound -c "\
        SELECT COALESCE(json_agg(row_to_json(h)), '[]'::json) FROM ( \
            SELECT h.id, h.hypothesis_id, h.title, h.description, h.status, h.confidence, \
                   h.severity, h.vulnerability_type, h.node_refs, h.evidence, \
                   h.reported_by_model, h.junior_model, h.senior_model \
            FROM hypotheses h \
            JOIN scan_executions s ON h.scan_execution_id = s.id \
            WHERE s.execution_id = '$session_id' \
            ORDER BY h.confidence DESC \
        ) h;" > "$OUT_DIR/${label}-${mode}-db-findings.json"

    # 2. Overview JSONB from scan_executions.deep_audit_overview
    docker compose exec -T db psql -U hound -d hound -A -t -c \
        "SELECT COALESCE(deep_audit_overview, '{}'::jsonb) FROM scan_executions WHERE execution_id = '$session_id';" \
        > "$OUT_DIR/${label}-${mode}-overview.json"

    # 3. Auditor-only properties from on-disk HypothesisStore JSON (mode=auditor only).
    # Session-scoped filename: hypotheses_<session_id>.json (PR-39 _session_filename_stem).
    if [[ "$mode" == "auditor" ]]; then
        if docker compose cp "worker:/app/hypotheses/${session_id}/hypotheses_${session_id}.json" \
            "$OUT_DIR/${label}-${mode}-store.json" 2>/dev/null; then
            echo "[$label/$mode] captured JSON store"
        else
            echo "[$label/$mode] WARN: HypothesisStore JSON not found (auditor may have crashed)"
            echo "{}" > "$OUT_DIR/${label}-${mode}-store.json"
        fi
    fi

    # Save wall-clock + final status into a per-run metadata file
    cat > "$OUT_DIR/${label}-${mode}-meta.json" <<META
{"session_id": "$session_id", "final_status": "$status", "wall_clock_seconds": $elapsed, "mode": "$mode", "project_id": $pid}
META
}

# ---------------------------------------------------------------------------
# Run all four audits: yieldnest sweep + auditor, curve sweep + auditor
# ---------------------------------------------------------------------------

run_audit "$YIELDNEST_PROJECT_ID" yieldnest sweep
run_audit "$YIELDNEST_PROJECT_ID" yieldnest auditor
run_audit "$CURVE_PROJECT_ID"     curve     sweep
run_audit "$CURVE_PROJECT_ID"     curve     auditor

# ---------------------------------------------------------------------------
# Generate SUMMARY.md for the archive doc
# ---------------------------------------------------------------------------

cat > "$OUT_DIR/SUMMARY.md" <<'SUMMARY_HEADER'
# firepan-vff live-audit eval

## Pass criteria
1. Yieldnest auditor: 0 confirmed access-control template FPs.
2. Curve auditor: re-finds F-7 + >=5/6 prior art.
3. Wall-clock auditor <= 2x sweep.
4. Yieldnest auditor overview.symbol_exists_gate.rejected_count > 0.

## Wall-clock comparison

SUMMARY_HEADER

for label in yieldnest curve; do
    for mode in sweep auditor; do
        m="$OUT_DIR/${label}-${mode}-meta.json"
        if [[ -f "$m" ]]; then
            wc=$(jq -r '.wall_clock_seconds' "$m")
            st=$(jq -r '.final_status' "$m")
            sid=$(jq -r '.session_id' "$m")
            printf "| %s | %s | %ds | %s | %s |\n" "$label" "$mode" "$wc" "$st" "$sid" >> "$OUT_DIR/SUMMARY.md"
        fi
    done
done

cat >> "$OUT_DIR/SUMMARY.md" <<'SUMMARY_END'

## Yieldnest auditor — pass-criterion 1 (zero confirmed access-control template FPs)

Confirmed access-control hits in DB:
SUMMARY_END

# Yieldnest pass-criterion 1: count confirmed access-control template matches
ACCESS_CONTROL_RE='(?i)missing access control'
jq -r --arg re "$ACCESS_CONTROL_RE" '
    if type == "array" then . else [] end
    | map(select(.status == "confirmed" and (.title // "" | test($re))))
    | length' "$OUT_DIR/yieldnest-auditor-db-findings.json" >> "$OUT_DIR/SUMMARY.md" 2>/dev/null || echo "0" >> "$OUT_DIR/SUMMARY.md"

cat >> "$OUT_DIR/SUMMARY.md" <<'SUMMARY_END2'

(Expected: 0. Any value > 0 = fail merge.)

## Yieldnest auditor — pass-criterion 4 (symbol_exists_gate fired)

rejected_count from overview:
SUMMARY_END2

jq '.symbol_exists_gate.rejected_count // 0' "$OUT_DIR/yieldnest-auditor-overview.json" >> "$OUT_DIR/SUMMARY.md" 2>/dev/null || echo "0" >> "$OUT_DIR/SUMMARY.md"

cat >> "$OUT_DIR/SUMMARY.md" <<'SUMMARY_END3'

(Expected: > 0. Zero = symbol gate not firing on real hallucinations; investigate.)

## Curve auditor — pass-criterion 2 (F-7 re-found + prior art)

Candidate F-7 matches in JSON store by numeric_gap_measurement content:
SUMMARY_END3

jq '.hypotheses | to_entries[]? | .value
    | select((.properties.numeric_gap_measurement // "") | test("F-7|donation_protection|chunked"))
    | {id, title, gap: .properties.numeric_gap_measurement}' \
   "$OUT_DIR/curve-auditor-store.json" >> "$OUT_DIR/SUMMARY.md" 2>/dev/null || echo "(no matches)" >> "$OUT_DIR/SUMMARY.md"

cat >> "$OUT_DIR/SUMMARY.md" <<'SUMMARY_END4'

Curve confirmed findings (all):
SUMMARY_END4

jq -r 'if type == "array" then map({hypothesis_id, title, severity, status, confidence}) else [] end' \
   "$OUT_DIR/curve-auditor-db-findings.json" >> "$OUT_DIR/SUMMARY.md" 2>/dev/null || echo "(none)" >> "$OUT_DIR/SUMMARY.md"

echo ""
echo "============================================================"
echo "DONE. Artifacts in $OUT_DIR/"
echo "Open $OUT_DIR/SUMMARY.md for the headline numbers."
echo "Full DB + store dumps for each audit are in *-db-findings.json + *-store.json."
echo "============================================================"
