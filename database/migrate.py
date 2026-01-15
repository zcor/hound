#!/usr/bin/env python3
"""
Database migration script for Hound.

This script creates the PostgreSQL database schema for Hound,
migrating from local JSON files to a relational database.

Usage:
    python -m database.migrate --database-url postgresql://user:pass@localhost/hound [--drop]
    
Options:
    --database-url: PostgreSQL connection URL
    --drop: Drop all existing tables before creating (WARNING: deletes all data)
    --create-default-tenant: Create a default tenant for single-tenant installations
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from database.models import (
    Base,
    Tenant,
    create_db_engine,
    create_db_session,
    drop_all_tables,
    init_database,
)


def migrate_database(database_url: str, drop_existing: bool = False, create_default_tenant: bool = True):
    """
    Run database migration.
    
    Args:
        database_url: PostgreSQL connection URL
        drop_existing: Whether to drop existing tables
        create_default_tenant: Whether to create a default tenant
    """
    print(f"Connecting to database: {database_url.split('@')[-1]}")  # Hide credentials
    engine = create_db_engine(database_url, echo=False)
    
    if drop_existing:
        print("WARNING: Dropping all existing tables...")
        response = input("Are you sure you want to delete all data? (yes/no): ")
        if response.lower() != "yes":
            print("Aborted.")
            return
        drop_all_tables(engine)
        print("All tables dropped.")
    
    print("Creating database schema...")
    init_database(engine)
    print("Database schema created successfully!")
    
    # Create default tenant if requested
    if create_default_tenant:
        session = create_db_session(engine)
        try:
            # Check if default tenant already exists
            existing = session.query(Tenant).filter_by(name="default").first()
            if not existing:
                default_tenant = Tenant(name="default")
                session.add(default_tenant)
                session.commit()
                print("Created default tenant.")
            else:
                print("Default tenant already exists.")
        except Exception as e:
            session.rollback()
            print(f"Error creating default tenant: {e}")
        finally:
            session.close()
    
    print("\nDatabase migration completed!")
    print("\nCreated tables:")
    for table in Base.metadata.sorted_tables:
        print(f"  - {table.name}")


def main():
    """Main entry point for migration script."""
    parser = argparse.ArgumentParser(description="Hound database migration script")
    parser.add_argument(
        "--database-url",
        required=True,
        help="PostgreSQL connection URL (e.g., postgresql://user:pass@localhost/hound)"
    )
    parser.add_argument(
        "--drop",
        action="store_true",
        help="Drop all existing tables before creating (WARNING: deletes all data)"
    )
    parser.add_argument(
        "--create-default-tenant",
        action="store_true",
        default=True,
        help="Create a default tenant for single-tenant installations (default: True)"
    )
    parser.add_argument(
        "--no-create-default-tenant",
        dest="create_default_tenant",
        action="store_false",
        help="Do not create a default tenant"
    )
    
    args = parser.parse_args()
    
    try:
        migrate_database(
            database_url=args.database_url,
            drop_existing=args.drop,
            create_default_tenant=args.create_default_tenant
        )
    except Exception as e:
        print(f"\nError during migration: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
