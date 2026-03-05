-- Add pr_comments_enabled column to projects table
-- Allows users to disable PR comments without uninstalling the GitHub App
-- NOT NULL DEFAULT TRUE backfills existing rows automatically
-- Idempotent: safe to rerun
ALTER TABLE projects ADD COLUMN IF NOT EXISTS pr_comments_enabled BOOLEAN NOT NULL DEFAULT TRUE;
