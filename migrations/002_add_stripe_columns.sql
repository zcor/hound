-- Migration 002: Add Stripe billing columns and supporting tables
-- Run: docker compose exec hound-db psql -U hound -d hound -f /dev/stdin < migrations/002_add_stripe_columns.sql
-- Prerequisites: Run 002a_dedupe_tenants.sql first and resolve any duplicates.

-- Stripe billing columns on tenants
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id VARCHAR UNIQUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR UNIQUE;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan VARCHAR(50) DEFAULT 'free';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_period VARCHAR(20);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan_updated_at TIMESTAMP;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS scan_credits INTEGER DEFAULT 0;

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tenants_stripe_customer ON tenants(stripe_customer_id);

-- Unique index on normalized github_account_login (prevents case-mismatch duplicates)
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_github_login_lower
    ON tenants (LOWER(github_account_login)) WHERE github_account_login IS NOT NULL;

-- Stripe webhook idempotency (crash-safe two-phase pattern)
CREATE TABLE IF NOT EXISTS stripe_processed_events (
    event_id VARCHAR PRIMARY KEY,
    status VARCHAR NOT NULL DEFAULT 'processing',
    processed_at TIMESTAMP
);

-- Credit refund tracking (prevents double-refund on retries)
CREATE TABLE IF NOT EXISTS credit_refunds (
    scan_execution_id VARCHAR PRIMARY KEY,
    tenant_id INTEGER NOT NULL,
    refunded_at TIMESTAMP DEFAULT NOW()
);
