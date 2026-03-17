"""
Audit trigger for GitHub push webhooks.

Triggers surface scans when push events include smart contract file changes.
Handles deduplication via Redis and dispatches to Celery worker.
"""

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# File extensions that indicate smart contract changes
CONTRACT_EXTENSIONS = {".sol", ".vy"}


def _has_contract_changes(payload: dict) -> bool:
    """Check if push includes .sol or .vy file changes.

    Checks added, modified, and removed lists. A rename shows up as
    removed (old name) + added (new name) across two commits or within
    one commit. By checking all three lists, we catch:
    - .sol added/modified/removed -> True
    - .sol renamed to .md -> True (appears in removed as .sol)
    - .md renamed to .sol -> True (appears in added as .sol)
    """
    for commit in payload.get("commits", []):
        for file_list in [commit.get("added", []), commit.get("modified", []), commit.get("removed", [])]:
            if any(Path(f).suffix in CONTRACT_EXTENSIONS for f in file_list):
                return True
    return False


def _get_redis_client():
    """Get Redis client for dedup. Returns None if unavailable."""
    import os
    try:
        import redis
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        return redis.from_url(redis_url)
    except Exception:
        return None


def run_audit_task(
    project_id: int,
    project_name: str,
    commit_sha: str,
    repo_url: str,
    tenant_id: int,
    installation_id: int | None = None,
    payload: dict | None = None,
) -> str | None:
    """
    Trigger a surface scan for a push event.

    Returns the scan execution_id if a scan was dispatched, or None if skipped.

    Args:
        project_id: Database ID of the project
        project_name: Name of the project
        commit_sha: Git commit SHA that triggered the push
        repo_url: Repository clone URL
        tenant_id: Tenant ID for multi-tenancy
        installation_id: GitHub App installation ID
        payload: Full push webhook payload (for file change detection)
    """
    # Check for contract file changes
    if payload and not _has_contract_changes(payload):
        logger.info(f"Push to {project_name} has no contract changes, skipping scan")
        return None

    # Dedup: prevent same commit from triggering multiple scans
    redis_client = _get_redis_client()
    dedup_key = f"push:scan:{project_id}:{commit_sha}"

    if redis_client:
        try:
            acquired = redis_client.set(dedup_key, "1", ex=300, nx=True)
        except Exception:
            # Redis down: fail open — scan without dedup
            logger.warning(f"Redis unavailable for dedup, scanning anyway: {dedup_key}")
            acquired = True
    else:
        # No Redis: scan without dedup
        acquired = True

    if not acquired:
        logger.info(f"Duplicate push for {project_name}@{commit_sha[:8]}, skipping")
        return None

    # Create scan execution record
    from database.models import ScanExecution, create_db_engine, create_db_session
    import os

    timestamp = int(datetime.now(timezone.utc).timestamp())
    execution_id = f"scan_{uuid.uuid4().hex[:12]}_{timestamp}"

    db_url = os.environ.get("DATABASE_URL", "sqlite:///hound.db")
    engine = create_db_engine(db_url)
    db = create_db_session(engine)

    try:
        scan = ScanExecution(
            execution_id=execution_id,
            project_id=project_id,
            tenant_id=tenant_id,
            repo_url=repo_url,
            repo_name=project_name,
            status="pending",
            scan_config={
                "trigger_source": "push",
                "commit_sha": commit_sha,
                "scan_type": "surface",
            },
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create ScanExecution for {project_name}: {e}")
        return None
    finally:
        db.close()

    # Dispatch Celery task
    try:
        from worker.tasks import execute_scan_task
        execute_scan_task.delay(
            repo_url=repo_url,
            scan_id=execution_id,
            tenant_id=tenant_id,
            llm_budget=5,
        )
        logger.info(f"Dispatched push scan {execution_id} for {project_name}@{commit_sha[:8]}")
        return execution_id

    except Exception as e:
        # Dispatch failed — mark scan as failed so it's not orphaned
        logger.error(f"Task dispatch failed for {project_name}: {e}")
        db = create_db_session(engine)
        try:
            scan = db.query(ScanExecution).filter_by(execution_id=execution_id).first()
            if scan:
                scan.status = "failed"
                scan.error_message = f"Task dispatch failed: {e}"
                db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()
        return None
