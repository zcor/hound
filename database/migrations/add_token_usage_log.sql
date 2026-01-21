-- Migration: Add TokenUsageLog table for cost tracking
-- Run this with: psql $DATABASE_URL < database/migrations/add_token_usage_log.sql

CREATE TABLE IF NOT EXISTS token_usage_logs (
    id SERIAL PRIMARY KEY,
    project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    session_id VARCHAR(255),
    tenant_id INTEGER REFERENCES tenants(id) ON DELETE SET NULL,
    
    -- Provider and model info
    provider VARCHAR(100) NOT NULL,
    model VARCHAR(255) NOT NULL,
    profile VARCHAR(100),
    
    -- Token counts
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    
    -- Cost calculation (in USD)
    cost_usd DOUBLE PRECISION,
    
    -- Request context
    request_type VARCHAR(100),
    endpoint VARCHAR(255),
    
    -- Timing
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_token_usage_logs_project_id ON token_usage_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_logs_session_id ON token_usage_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_logs_provider ON token_usage_logs(provider);
CREATE INDEX IF NOT EXISTS idx_token_usage_logs_model ON token_usage_logs(model);
CREATE INDEX IF NOT EXISTS idx_token_usage_logs_profile ON token_usage_logs(profile);
CREATE INDEX IF NOT EXISTS idx_token_usage_logs_created_at ON token_usage_logs(created_at);

-- Success message
SELECT 'Migration complete: token_usage_logs table created' AS status;
