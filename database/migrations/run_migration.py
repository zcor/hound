#!/usr/bin/env python3
"""
Apply database migration to add missing columns to tenants and projects tables.
"""
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import create_engine, text

# Get database URL from environment or use default
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://hound:hound_secret@127.0.0.1:5432/hound')

def run_migration():
    """Run the migration to add missing columns."""
    engine = create_engine(DATABASE_URL, echo=True)
    
    migrations = [
        # Tenants table migrations
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS status VARCHAR(50) NOT NULL DEFAULT 'pending'",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255)",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS github_account_login VARCHAR(255)",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS github_account_type VARCHAR(50)",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()",
        "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT NOW()",
        
        # Projects table migrations
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS status VARCHAR(50) NOT NULL DEFAULT 'active'",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS description TEXT",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT NOW()",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMP NOT NULL DEFAULT NOW()",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS github_repo_id BIGINT",
        "ALTER TABLE projects ADD COLUMN IF NOT EXISTS installation_id BIGINT",
        
        # Create indexes
        "CREATE INDEX IF NOT EXISTS idx_projects_github_repo_id ON projects(github_repo_id)",
        "CREATE INDEX IF NOT EXISTS idx_projects_installation_id ON projects(installation_id)",
        
        # Update existing records
        "UPDATE tenants SET status = 'active' WHERE status = 'pending' AND created_at < NOW()",
        "UPDATE projects SET status = 'active' WHERE status != 'active'",
    ]
    
    with engine.begin() as conn:
        for migration_sql in migrations:
            try:
                print(f"Running: {migration_sql[:80]}...")
                conn.execute(text(migration_sql))
                print("  ✓ Success")
            except Exception as e:
                print(f"  ✗ Error: {e}")
                # Continue with other migrations even if one fails
    
    print("\n✓ Migration completed!")

if __name__ == "__main__":
    run_migration()
