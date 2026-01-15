# Database Module

This module provides SQLAlchemy models and migration tools for Hound's PostgreSQL database schema.

## Overview

The database schema replaces local JSON files and directories with a relational PostgreSQL database, providing:

- **Multi-tenancy support** through the Tenant model
- **Structured project management** replacing `registry.json` and `project.json`
- **Session tracking** for audit runs, replacing local session directories
- **Graph storage** with JSONB for efficient querying of knowledge graphs
- **Hypothesis management** with full evidence tracking

## Schema

### Tables

1. **tenants** - Multi-tenancy support
   - id, name, created_at, updated_at

2. **projects** - Project metadata (replaces project.json)
   - id, tenant_id, name, source_path, git_url, description, status, created_at, last_accessed

3. **audit_sessions** - Session tracking (replaces SessionInfo)
   - id, project_id, session_id, status, start_time, end_time
   - models, token_usage, coverage, investigations (JSONB fields)

4. **graphs** - Knowledge graph storage (replaces graphs/*.json)
   - id, project_id, name, internal_name, data (JSONB), created_at, updated_at

5. **hypotheses** - Vulnerability hypotheses (replaces hypotheses.json)
   - id, project_id, hypothesis_id, title, description, vulnerability_type
   - status, confidence, severity, node_refs (ARRAY), evidence (JSONB)
   - reported_by_model, junior_model, senior_model, created_at, updated_at

## Usage

### Running Migrations

Create the database schema:

```bash
python -m database.migrate --database-url postgresql://user:pass@localhost/hound
```

Options:
- `--drop`: Drop all existing tables before creating (WARNING: deletes all data)
- `--create-default-tenant`: Create a default tenant (default: True)
- `--no-create-default-tenant`: Skip creating default tenant

### Using the Models

```python
from database.models import (
    Base, Tenant, Project, AuditSession, Graph, Hypothesis,
    create_db_engine, create_db_session, init_database
)

# Create engine
engine = create_db_engine("postgresql://user:pass@localhost/hound")

# Initialize database
init_database(engine)

# Create session
session = create_db_session(engine)

# Create a tenant
tenant = Tenant(name="my_org")
session.add(tenant)
session.commit()

# Create a project
project = Project(
    tenant_id=tenant.id,
    name="my_project",
    source_path="/path/to/source",
    description="My project description"
)
session.add(project)
session.commit()

# Query projects
projects = session.query(Project).filter_by(tenant_id=tenant.id).all()

# Close session
session.close()
```

### Testing

The models are tested with both PostgreSQL (production) and SQLite (testing). The `JSONType` and `ArrayType` custom types automatically adapt to the database backend:

- PostgreSQL: Uses `JSONB` and `ARRAY` types for optimal performance
- SQLite: Falls back to `JSON` type for compatibility

Run tests:

```bash
pytest tests/test_database_models.py -v
```

## Type Adapters

### JSONType

Platform-independent JSON storage that uses JSONB on PostgreSQL for better indexing and performance, and JSON on other databases.

### ArrayType

Platform-independent array storage that uses ARRAY on PostgreSQL and JSON on other databases.

## Migration from JSON Files

This schema is designed to replace the following local storage:

- `~/.hound/projects/registry.json` → `tenants` and `projects` tables
- `~/.hound/projects/<project>/project.json` → `projects` table
- `~/.hound/projects/<project>/graphs/*.json` → `graphs` table
- `~/.hound/projects/<project>/hypotheses.json` → `hypotheses` table
- `~/.hound/projects/<project>/sessions/<session_id>/` → `audit_sessions` table

Future work will include migration scripts to import existing data from JSON files into the database.
