-- Migration 001: Create payment_logs table for x402 agent payments
-- Run: psql $DATABASE_URL -f migrations/001_create_payment_logs.sql

CREATE TABLE IF NOT EXISTS payment_logs (
    id SERIAL PRIMARY KEY,
    payment_id VARCHAR UNIQUE,              -- From facilitator, NULL while reserved
    idempotency_key VARCHAR,
    request_hash VARCHAR,                   -- SHA-256 of canonicalized request body
    resource_id VARCHAR,                    -- Concrete resource ID (e.g., audit ID for report entitlement)
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    job_id VARCHAR,
    tx_hash VARCHAR UNIQUE,                 -- On-chain transaction hash
    network VARCHAR NOT NULL,
    amount_atomic BIGINT NOT NULL DEFAULT 0, -- USDC atomic units (1 USDC = 1_000_000)
    amount_usd NUMERIC(10,6) NOT NULL DEFAULT 0,
    token VARCHAR DEFAULT 'USDC',
    payer_address VARCHAR,                  -- NULL while reserved, filled after verify
    endpoint VARCHAR NOT NULL,
    status VARCHAR DEFAULT 'reserved',      -- reserved, paid, job_created, job_failed, expired
    settled_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT uq_payment_idempotency UNIQUE (tenant_id, endpoint, idempotency_key)
);

CREATE INDEX IF NOT EXISTS ix_payment_logs_payment_id ON payment_logs(payment_id);
CREATE INDEX IF NOT EXISTS ix_payment_logs_payer_address ON payment_logs(payer_address);
CREATE INDEX IF NOT EXISTS ix_payment_logs_tenant_id ON payment_logs(tenant_id);
CREATE INDEX IF NOT EXISTS ix_payment_logs_resource_id ON payment_logs(resource_id);
