-- Fix OAuthAuditLog FK to cascade on user deletion
-- Without this, deleting a user with audit log entries fails with FK violation.

ALTER TABLE oauth_audit_log DROP CONSTRAINT IF EXISTS oauth_audit_log_user_id_fkey;
ALTER TABLE oauth_audit_log ADD CONSTRAINT oauth_audit_log_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
