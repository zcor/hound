-- Add session_id column to graphs table for agent audits (no project required)
-- Also make project_id nullable since agent audits don't create projects

ALTER TABLE graphs ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_graphs_session_id ON graphs(session_id);

-- Make project_id nullable (existing rows keep their values)
-- Note: SQLite doesn't support ALTER COLUMN, but Postgres does
-- For SQLite, the column is already effectively nullable after model change
ALTER TABLE graphs ALTER COLUMN project_id DROP NOT NULL;
