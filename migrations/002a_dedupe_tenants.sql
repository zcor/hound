-- Migration 002a: Detect and resolve duplicate tenants (case-insensitive github_account_login)
-- Run BEFORE 002_add_stripe_columns.sql
-- This is a PRE-CHECK — Step 1 is a safe SELECT. Step 2 is a template requiring manual review.

-- Step 1: DETECT duplicates. If this returns 0 rows, skip to migration 002.
SELECT LOWER(github_account_login) AS login,
       array_agg(id ORDER BY created_at) AS tenant_ids,
       count(*)
FROM tenants
WHERE github_account_login IS NOT NULL
GROUP BY LOWER(github_account_login)
HAVING count(*) > 1;

-- Step 2: For each duplicate group, keep the OLDEST tenant (first in array).
-- Reassign ALL child records from duplicate tenants to the keeper.
--
-- FK tables that reference tenants.id (from database/models.py):
--   users.tenant_id          (NOT NULL, cascade delete-orphan)
--   projects.tenant_id       (NOT NULL, cascade delete-orphan, unique on tenant_id+name)
--   scan_executions.tenant_id (NOT NULL, cascade delete-orphan)
--   token_usage_logs.tenant_id (NULLABLE, ON DELETE SET NULL)
--   payment_logs.tenant_id   (NOT NULL, unique on tenant_id+endpoint+idempotency_key)
--
-- IMPORTANT: projects has UNIQUE(tenant_id, name) — if both tenants have a project
-- with the same name, the UPDATE will fail. Handle manually (rename one first).
-- Same for payment_logs UNIQUE(tenant_id, endpoint, idempotency_key).
--
-- Template (replace <keep_id> and <dupe_ids> from Step 1 output):
--
-- BEGIN;
-- UPDATE users SET tenant_id = <keep_id> WHERE tenant_id IN (<dupe_ids>);
-- UPDATE projects SET tenant_id = <keep_id> WHERE tenant_id IN (<dupe_ids>);
-- UPDATE scan_executions SET tenant_id = <keep_id> WHERE tenant_id IN (<dupe_ids>);
-- UPDATE token_usage_logs SET tenant_id = <keep_id> WHERE tenant_id IN (<dupe_ids>);
-- UPDATE payment_logs SET tenant_id = <keep_id> WHERE tenant_id IN (<dupe_ids>);
-- DELETE FROM tenants WHERE id IN (<dupe_ids>);
-- COMMIT;

-- Step 3: POST-CHECK — hard deploy gate. Must return 0 rows before running 002.
SELECT LOWER(github_account_login) AS login, count(*)
FROM tenants
WHERE github_account_login IS NOT NULL
GROUP BY LOWER(github_account_login)
HAVING count(*) > 1;
