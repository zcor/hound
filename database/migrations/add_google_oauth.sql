-- Google OAuth: add Google provider fields, make GitHub nullable, add audit log
-- Safe to run multiple times (idempotent).

-- Google OAuth fields on users
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_email VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_name VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_avatar_url VARCHAR(500);
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_connected_at TIMESTAMP WITH TIME ZONE;

-- Track original signup provider (immutable after creation)
ALTER TABLE users ADD COLUMN IF NOT EXISTS signup_provider VARCHAR(50) NOT NULL DEFAULT 'github';

-- Make GitHub fields nullable (Google-only users won't have them)
ALTER TABLE users ALTER COLUMN github_id DROP NOT NULL;
ALTER TABLE users ALTER COLUMN github_login DROP NOT NULL;

-- Enforce at least one provider linked (idempotent via DO block)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_at_least_one_provider'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT chk_at_least_one_provider
            CHECK (github_id IS NOT NULL OR google_id IS NOT NULL) NOT VALID;
    END IF;
END $$;
ALTER TABLE users VALIDATE CONSTRAINT chk_at_least_one_provider;

-- Enforce signup_provider values
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_signup_provider_values'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT chk_signup_provider_values
            CHECK (signup_provider IN ('github', 'google')) NOT VALID;
    END IF;
END $$;
ALTER TABLE users VALIDATE CONSTRAINT chk_signup_provider_values;

-- Index for Google ID lookups
CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);

-- Audit log for OAuth events
CREATE TABLE IF NOT EXISTS oauth_audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    action VARCHAR(50) NOT NULL,       -- 'link', 'unlink', 'login', 'login_new'
    provider VARCHAR(50) NOT NULL,     -- 'github', 'google'
    provider_user_id VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oauth_audit_user ON oauth_audit_log(user_id);
