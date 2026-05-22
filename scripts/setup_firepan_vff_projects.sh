#!/usr/bin/env bash
# Bootstrap a local docker-compose stack for the firepan-vff live-audit gate.
#
# Creates:
#   - 1 Tenant (id=1, name="firepan-vff-eval")
#   - 2 Projects (yieldnest + curve-twocrypto-ng) pointing at cloned sources
#   - Knowledge graphs built for each (so /audits/run-sync + /admin/audits/force-run can find them)
#
# Prereqs (you set these, NOT this script):
#   - /Users/gerrithall/dev/firepan/.env has a real ANTHROPIC_API_KEY (not placeholder)
#   - /Users/gerrithall/dev/firepan/.env has HOUND_ADMIN_KEY + HOUND_SECRET_KEY set
#   - docker compose stack image is built (see scripts/run_firepan_vff_eval.sh)
#
# Usage:
#   docker compose up -d db redis
#   docker compose up -d api worker
#   ./scripts/setup_firepan_vff_projects.sh
#
# After completion, the script prints YIELDNEST_PROJECT_ID + CURVE_PROJECT_ID
# which you export before running scripts/run_firepan_vff_eval.sh.

set -euo pipefail

# ---------------------------------------------------------------------------
# Step 1: ensure Tenant id=1 exists, return project IDs via SQL
# ---------------------------------------------------------------------------
# Note: worker/tasks.py clones from project.git_url on-demand (see line 344-367
# of worker/tasks.py), so we don't need to pre-clone or bind-mount sources.
# Each audit run will fresh-clone into a tempdir inside the worker container.

ensure_tenant_and_projects() {
    docker compose exec -T db psql -U hound -d hound <<'SQL'
-- Tenant: idempotent insert with default fields.
INSERT INTO tenants (id, name, status, plan, created_at)
VALUES (1, 'firepan-vff-eval', 'active', 'enterprise', NOW())
ON CONFLICT (id) DO NOTHING;
-- Sequence catch-up so the next CREATE doesn't collide
SELECT setval(pg_get_serial_sequence('tenants', 'id'), GREATEST(1, (SELECT MAX(id) FROM tenants)));

-- Project rows for yieldnest + curve. source_path left NULL — worker clones
-- fresh from git_url on each audit run (worker/tasks.py:344-367).
INSERT INTO projects (tenant_id, name, git_url, default_branch, status, created_at, last_accessed)
VALUES
    (1, 'yieldnest-protocol', 'https://github.com/yieldnest/yieldnest-protocol.git', 'main', 'active', NOW(), NOW()),
    (1, 'curve-twocrypto-ng', 'https://github.com/curvefi/twocrypto-ng.git',         'main', 'active', NOW(), NOW())
ON CONFLICT (tenant_id, name) DO UPDATE SET last_accessed = NOW()
RETURNING id, name;
SQL
}

echo "[setup] ensuring tenant + projects..."
ensure_tenant_and_projects

# ---------------------------------------------------------------------------
# Step 3: print project IDs for the eval runner
# ---------------------------------------------------------------------------

YN_ID=$(docker compose exec -T db psql -U hound -d hound -A -t -c \
    "SELECT id FROM projects WHERE name = 'yieldnest-protocol' AND tenant_id = 1;" | tr -d '[:space:]')
CURVE_ID=$(docker compose exec -T db psql -U hound -d hound -A -t -c \
    "SELECT id FROM projects WHERE name = 'curve-twocrypto-ng' AND tenant_id = 1;" | tr -d '[:space:]')

echo ""
echo "============================================================"
echo "Projects ready:"
echo "  YIELDNEST_PROJECT_ID=$YN_ID"
echo "  CURVE_PROJECT_ID=$CURVE_ID"
echo ""
echo "Next steps:"
echo "  1. Build graphs for each project (worker will clone the repo + build graphs):"
echo "     curl -s -X POST http://localhost:8000/graphs/build-sync \\"
echo "       -H \"X-Admin-Key: \$HOUND_ADMIN_KEY\" -H 'Content-Type: application/json' \\"
echo "       -d '{\"project_id\": $YN_ID, \"num_graphs\": 2, \"max_iterations\": 1}'"
echo "     curl -s -X POST http://localhost:8000/graphs/build-sync \\"
echo "       -H \"X-Admin-Key: \$HOUND_ADMIN_KEY\" -H 'Content-Type: application/json' \\"
echo "       -d '{\"project_id\": $CURVE_ID, \"num_graphs\": 2, \"max_iterations\": 1}'"
echo "     (~5-10 min per project; uses Anthropic API budget.)"
echo "  2. Export envs and run the eval:"
echo "     export YIELDNEST_PROJECT_ID=$YN_ID CURVE_PROJECT_ID=$CURVE_ID"
echo "     export ADMIN_KEY=\$(grep ^HOUND_ADMIN_KEY= /Users/gerrithall/dev/firepan/.env | cut -d= -f2)"
echo "     ./scripts/run_firepan_vff_eval.sh"
echo "============================================================"
