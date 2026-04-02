-- Add tenant_id to audit_sessions for agent-native audits (no project required)
ALTER TABLE audit_sessions ADD COLUMN IF NOT EXISTS tenant_id INTEGER REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS ix_audit_sessions_tenant_id ON audit_sessions(tenant_id);
