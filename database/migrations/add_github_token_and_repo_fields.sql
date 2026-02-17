-- Migration: Add GitHub token storage to users and repository metadata to projects
-- Date: 2026-02-17
-- Description: Adds encrypted GitHub token column to users table,
--              and full_name, default_branch, is_private columns to projects table.

-- Users table: GitHub token storage
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_token_encrypted TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS github_connected_at TIMESTAMP;

-- Projects table: Additional repository metadata
ALTER TABLE projects ADD COLUMN IF NOT EXISTS full_name VARCHAR(512);
ALTER TABLE projects ADD COLUMN IF NOT EXISTS default_branch VARCHAR(255) DEFAULT 'main';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT FALSE;

-- Partial unique index: prevent duplicate github_repo_id per tenant (only when not null)
CREATE UNIQUE INDEX IF NOT EXISTS uq_project_tenant_github_repo
    ON projects (tenant_id, github_repo_id)
    WHERE github_repo_id IS NOT NULL;
