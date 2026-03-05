-- Add scan_log column to scan_executions table
-- Stores timestamped execution log (max 64KB, truncated at storage time)
-- Idempotent: safe to rerun
ALTER TABLE scan_executions ADD COLUMN IF NOT EXISTS scan_log TEXT;
