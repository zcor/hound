-- Migration: Add missing fields to tenants and projects tables
-- Date: 2026-02-06
-- Description: Adds status, contact_email, github_account_login, github_account_type, 
--              created_at, updated_at to tenants table and ensures projects has all required fields

-- Add missing columns to tenants table if they don't exist
DO $$ 
BEGIN
    -- Add status column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='status') THEN
        ALTER TABLE tenants ADD COLUMN status VARCHAR(50) NOT NULL DEFAULT 'pending';
    END IF;
    
    -- Add contact_email column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='contact_email') THEN
        ALTER TABLE tenants ADD COLUMN contact_email VARCHAR(255);
    END IF;
    
    -- Add github_account_login column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='github_account_login') THEN
        ALTER TABLE tenants ADD COLUMN github_account_login VARCHAR(255);
    END IF;
    
    -- Add github_account_type column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='github_account_type') THEN
        ALTER TABLE tenants ADD COLUMN github_account_type VARCHAR(50);
    END IF;
    
    -- Add created_at column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='created_at') THEN
        ALTER TABLE tenants ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT NOW();
    END IF;
    
    -- Add updated_at column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='tenants' AND column_name='updated_at') THEN
        ALTER TABLE tenants ADD COLUMN updated_at TIMESTAMP NOT NULL DEFAULT NOW();
    END IF;
END $$;

-- Add missing columns to projects table if they don't exist
DO $$ 
BEGIN
    -- Add status column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='status') THEN
        ALTER TABLE projects ADD COLUMN status VARCHAR(50) NOT NULL DEFAULT 'active';
    END IF;
    
    -- Add description column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='description') THEN
        ALTER TABLE projects ADD COLUMN description TEXT;
    END IF;
    
    -- Add created_at column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='created_at') THEN
        ALTER TABLE projects ADD COLUMN created_at TIMESTAMP NOT NULL DEFAULT NOW();
    END IF;
    
    -- Add last_accessed column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='last_accessed') THEN
        ALTER TABLE projects ADD COLUMN last_accessed TIMESTAMP NOT NULL DEFAULT NOW();
    END IF;
    
    -- Add github_repo_id column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='github_repo_id') THEN
        ALTER TABLE projects ADD COLUMN github_repo_id BIGINT;
        CREATE INDEX IF NOT EXISTS idx_projects_github_repo_id ON projects(github_repo_id);
    END IF;
    
    -- Add installation_id column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='installation_id') THEN
        ALTER TABLE projects ADD COLUMN installation_id BIGINT;
        CREATE INDEX IF NOT EXISTS idx_projects_installation_id ON projects(installation_id);
    END IF;
END $$;

-- Set existing tenants to active status if they were created before this migration
UPDATE tenants SET status = 'active' WHERE status = 'pending' AND created_at < NOW();

-- Set existing projects to active status if they were created before this migration  
UPDATE projects SET status = 'active' WHERE status != 'active';

PRINT 'Migration completed successfully!';
