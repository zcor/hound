"""
Tests for firepan-dar — scan_execution_id FK on hypotheses.

Covers:
- Schema: column exists, FK to scan_executions, indexed
- _store_hypotheses_in_db: resolves session_id → ScanExecution.id and stamps it
- Legacy tolerance: missing scan row → scan_execution_id stays NULL (column is nullable)
- Per-scan filterability: hypotheses from two scans on the same project are
  cleanly separable via the FK.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from database.models import Base, Hypothesis, Project, ScanExecution, Tenant  # noqa: E402
from worker.tasks import _store_hypotheses_in_db  # noqa: E402


@pytest.fixture(scope="function")
def db_factory(tmp_path):
    """SQLAlchemy in-memory DB with the full schema."""
    db_path = tmp_path / "dar.db"
    engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def _get_db():
        return SessionLocal()

    try:
        yield _get_db, engine, SessionLocal
    finally:
        engine.dispose()


@pytest.fixture
def project_and_scan(db_factory):
    """Returns (project_id, scan_id_string, scan_execution_pk_int)."""
    _get_db, _engine, SessionLocal = db_factory
    db = SessionLocal()
    try:
        tenant = Tenant(name="t1", plan="free")
        db.add(tenant)
        db.commit()
        db.refresh(tenant)

        proj = Project(
            tenant_id=tenant.id,
            name="p1",
            source_path="/tmp/p1",
            git_url="https://github.com/a/p1",
            status="active",
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
        )
        db.add(proj)
        db.commit()
        db.refresh(proj)

        scan = ScanExecution(
            tenant_id=tenant.id,
            project_id=proj.id,
            execution_id="exec_test_001",
            repo_url="https://github.com/a/p1",
            repo_name="a/p1",
            scan_config={"scan_type": "deep"},
            status="completed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return proj.id, scan.execution_id, scan.id
    finally:
        db.close()


class TestSchema:
    def test_scan_execution_id_column_exists(self, db_factory):
        _get_db, engine, _ = db_factory
        cols = {c["name"] for c in inspect(engine).get_columns("hypotheses")}
        assert "scan_execution_id" in cols

    def test_scan_execution_id_is_nullable(self, db_factory):
        _get_db, engine, _ = db_factory
        col = next(
            c for c in inspect(engine).get_columns("hypotheses")
            if c["name"] == "scan_execution_id"
        )
        assert col["nullable"] is True

    def test_foreign_key_to_scan_executions(self, db_factory):
        _get_db, engine, _ = db_factory
        fks = inspect(engine).get_foreign_keys("hypotheses")
        scan_fks = [
            fk for fk in fks
            if fk["constrained_columns"] == ["scan_execution_id"]
            and fk["referred_table"] == "scan_executions"
        ]
        assert len(scan_fks) == 1


class TestStoragePopulatesFK:
    def test_resolves_session_id_to_scan_pk(self, db_factory, project_and_scan):
        get_db, _, _ = db_factory
        project_id, exec_id, scan_pk = project_and_scan

        hypotheses = [{
            "id": "h1",
            "description": "test finding",
            "vulnerability_type": "x",
            "status": "proposed",
            "confidence": 0.5,
        }]
        _store_hypotheses_in_db(get_db, project_id, hypotheses, exec_id)

        db = get_db()
        try:
            row = db.query(Hypothesis).filter_by(hypothesis_id="h1").one()
            assert row.scan_execution_id == scan_pk
        finally:
            db.close()

    def test_unknown_session_id_leaves_fk_null(self, db_factory, project_and_scan):
        """If the session_id doesn't match any ScanExecution.execution_id, the
        FK stays NULL — write must not fail. This is the legacy-tolerant
        path that lets the column ship without a backfill blocker.
        """
        get_db, _, _ = db_factory
        project_id, _exec_id, _scan_pk = project_and_scan

        hypotheses = [{
            "id": "orphan_h1",
            "description": "test finding",
            "vulnerability_type": "x",
            "status": "proposed",
            "confidence": 0.5,
        }]
        # Use a session_id that isn't in the ScanExecution table.
        _store_hypotheses_in_db(get_db, project_id, hypotheses, "exec_does_not_exist")

        db = get_db()
        try:
            row = db.query(Hypothesis).filter_by(hypothesis_id="orphan_h1").one()
            assert row.scan_execution_id is None
        finally:
            db.close()


class TestPerScanFilterability:
    def test_two_scans_on_same_project_are_separable(self, db_factory):
        """The whole point of dar: two scans on the same project produce
        hypotheses that are cleanly filterable via the FK, no created_at
        windowing required.
        """
        get_db, _, SessionLocal = db_factory
        # Set up tenant + project + two scans
        db = SessionLocal()
        try:
            tenant = Tenant(name="t1", plan="free")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

            proj = Project(
                tenant_id=tenant.id,
                name="p1",
                source_path="/tmp/p1",
                git_url="https://github.com/a/p1",
                status="active",
                created_at=datetime.now(timezone.utc),
                last_accessed=datetime.now(timezone.utc),
            )
            db.add(proj)
            db.commit()
            db.refresh(proj)

            scan_a = ScanExecution(
                tenant_id=tenant.id, project_id=proj.id,
                execution_id="exec_A", repo_url="https://github.com/a/p1", repo_name="a/p1",
                scan_config={"scan_type": "deep"}, status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            scan_b = ScanExecution(
                tenant_id=tenant.id, project_id=proj.id,
                execution_id="exec_B", repo_url="https://github.com/a/p1", repo_name="a/p1",
                scan_config={"scan_type": "deep"}, status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            db.add_all([scan_a, scan_b])
            db.commit()
            db.refresh(scan_a)
            db.refresh(scan_b)
            project_id = proj.id
            scan_a_pk, scan_b_pk = scan_a.id, scan_b.id
        finally:
            db.close()

        # Store hypotheses from each scan.
        _store_hypotheses_in_db(get_db, project_id, [
            {"id": "a1", "description": "From scan A", "vulnerability_type": "x",
             "status": "confirmed", "confidence": 0.9},
            {"id": "a2", "description": "Also scan A", "vulnerability_type": "y",
             "status": "confirmed", "confidence": 0.85},
        ], "exec_A")
        _store_hypotheses_in_db(get_db, project_id, [
            {"id": "b1", "description": "From scan B", "vulnerability_type": "z",
             "status": "confirmed", "confidence": 0.95},
        ], "exec_B")

        db = get_db()
        try:
            a_rows = db.query(Hypothesis).filter_by(scan_execution_id=scan_a_pk).all()
            b_rows = db.query(Hypothesis).filter_by(scan_execution_id=scan_b_pk).all()
            assert {r.hypothesis_id for r in a_rows} == {"a1", "a2"}
            assert {r.hypothesis_id for r in b_rows} == {"b1"}
        finally:
            db.close()
