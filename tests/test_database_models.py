"""
Unit tests for database models.

Tests the SQLAlchemy models and migration functionality.
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.models import (
    AuditSession,
    Base,
    Graph,
    Hypothesis,
    Project,
    ScanExecution,
    Tenant,
    create_db_engine,
    create_db_session,
    init_database,
)


class TestDatabaseModels(unittest.TestCase):
    """Test database models."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database."""
        # Use in-memory SQLite for testing
        cls.engine = create_db_engine("sqlite:///:memory:", echo=False)
        init_database(cls.engine)
    
    def setUp(self):
        """Set up test session."""
        self.session = create_db_session(self.engine)
    
    def tearDown(self):
        """Clean up test session."""
        # Rollback any uncommitted changes
        self.session.rollback()
        # Clear all data
        for table in reversed(Base.metadata.sorted_tables):
            self.session.execute(table.delete())
        self.session.commit()
        self.session.close()
    
    def test_create_tenant(self):
        """Test creating a tenant."""
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        # Verify tenant was created
        retrieved = self.session.query(Tenant).filter_by(name="test_org").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "test_org")
        self.assertIsNotNone(retrieved.created_at)
    
    def test_create_project(self):
        """Test creating a project."""
        # Create tenant first
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        # Create project
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source",
            description="Test project description",
            status="active"
        )
        self.session.add(project)
        self.session.commit()
        
        # Verify project was created
        retrieved = self.session.query(Project).filter_by(name="test_project").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "test_project")
        self.assertEqual(retrieved.source_path, "/path/to/source")
        self.assertEqual(retrieved.tenant_id, tenant.id)
    
    def test_create_audit_session(self):
        """Test creating an audit session."""
        # Create tenant and project
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create audit session
        session_data = AuditSession(
            project_id=project.id,
            session_id="sess_20250115_123456",
            status="active",
            models={"scout": "gpt-4", "strategist": "claude-3"},
            token_usage={"total_tokens": 1000}
        )
        self.session.add(session_data)
        self.session.commit()
        
        # Verify session was created
        retrieved = self.session.query(AuditSession).filter_by(session_id="sess_20250115_123456").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.status, "active")
        self.assertEqual(retrieved.models["scout"], "gpt-4")
    
    def test_create_graph(self):
        """Test creating a graph."""
        # Create tenant and project
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create graph
        graph_data = {
            "nodes": [
                {"id": "node1", "label": "Node 1"},
                {"id": "node2", "label": "Node 2"}
            ],
            "edges": [
                {"source": "node1", "target": "node2"}
            ]
        }
        
        graph = Graph(
            project_id=project.id,
            name="Test Graph",
            internal_name="test_graph",
            data=graph_data
        )
        self.session.add(graph)
        self.session.commit()
        
        # Verify graph was created
        retrieved = self.session.query(Graph).filter_by(name="Test Graph").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.internal_name, "test_graph")
        self.assertEqual(len(retrieved.data["nodes"]), 2)
    
    def test_create_hypothesis(self):
        """Test creating a hypothesis."""
        # Create tenant and project
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create hypothesis
        hypothesis = Hypothesis(
            project_id=project.id,
            hypothesis_id="hyp_20250115_123456",
            title="Test Vulnerability",
            description="This is a test vulnerability",
            vulnerability_type="access_control",
            status="proposed",
            confidence=0.7,
            severity="high",
            node_refs=["node1", "node2"],
            evidence={"supporting": ["evidence1"], "refuting": []},
            reported_by_model="gpt-4"
        )
        self.session.add(hypothesis)
        self.session.commit()
        
        # Verify hypothesis was created
        retrieved = self.session.query(Hypothesis).filter_by(hypothesis_id="hyp_20250115_123456").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, "Test Vulnerability")
        self.assertEqual(retrieved.confidence, 0.7)
        self.assertEqual(retrieved.node_refs, ["node1", "node2"])
    
    def test_relationships(self):
        """Test relationships between models."""
        # Create tenant
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        # Create project
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create multiple related entities
        session1 = AuditSession(
            project_id=project.id,
            session_id="sess_1",
            status="completed"
        )
        session2 = AuditSession(
            project_id=project.id,
            session_id="sess_2",
            status="active"
        )
        
        graph1 = Graph(
            project_id=project.id,
            name="Graph 1",
            data={"nodes": [], "edges": []}
        )
        
        hypothesis1 = Hypothesis(
            project_id=project.id,
            hypothesis_id="hyp_1",
            title="Hypothesis 1",
            description="Test",
            vulnerability_type="test"
        )
        
        self.session.add_all([session1, session2, graph1, hypothesis1])
        self.session.commit()
        
        # Verify relationships
        retrieved_project = self.session.query(Project).filter_by(name="test_project").first()
        self.assertEqual(len(retrieved_project.audit_sessions), 2)
        self.assertEqual(len(retrieved_project.graphs), 1)
        self.assertEqual(len(retrieved_project.hypotheses), 1)
        self.assertEqual(retrieved_project.tenant.name, "test_org")
    
    def test_cascade_delete(self):
        """Test cascade deletion of related entities."""
        # Create tenant and project with related entities
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Add related entities
        session1 = AuditSession(
            project_id=project.id,
            session_id="sess_1",
            status="active"
        )
        graph1 = Graph(
            project_id=project.id,
            name="Graph 1",
            data={}
        )
        hypothesis1 = Hypothesis(
            project_id=project.id,
            hypothesis_id="hyp_1",
            title="Test",
            description="Test",
            vulnerability_type="test"
        )
        
        self.session.add_all([session1, graph1, hypothesis1])
        self.session.commit()
        
        # Verify entities exist
        self.assertEqual(self.session.query(AuditSession).count(), 1)
        self.assertEqual(self.session.query(Graph).count(), 1)
        self.assertEqual(self.session.query(Hypothesis).count(), 1)
        
        # Delete project
        self.session.delete(project)
        self.session.commit()
        
        # Verify cascade deletion
        self.assertEqual(self.session.query(AuditSession).count(), 0)
        self.assertEqual(self.session.query(Graph).count(), 0)
        self.assertEqual(self.session.query(Hypothesis).count(), 0)
    
    def test_unique_constraints(self):
        """Test unique constraints on models."""
        # Create tenant
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        # Try to create duplicate tenant
        duplicate_tenant = Tenant(name="test_org")
        self.session.add(duplicate_tenant)
        
        with self.assertRaises(Exception):  # Should raise IntegrityError
            self.session.commit()
        
        self.session.rollback()
        
        # Create project
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Try to create duplicate project
        duplicate_project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/another/path"
        )
        self.session.add(duplicate_project)
        
        with self.assertRaises(Exception):  # Should raise IntegrityError
            self.session.commit()

    def test_create_scan_execution(self):
        """Test creating a scan execution."""
        # Create tenant first
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()

        # Create scan execution (without project - allowed for surface scans)
        findings = [
            {
                "pattern_id": "REENTRANCY-001",
                "title": "Reentrancy vulnerability",
                "severity": "critical",
                "confidence": 0.85,
                "location": "src/Vault.sol:42"
            }
        ]
        quality_metrics = {
            "solidity_version": "0.8.20",
            "has_tests": True,
            "test_count": 15,
            "total_loc": 1200
        }
        
        scan = ScanExecution(
            tenant_id=tenant.id,
            execution_id="scan_20250119_123456",
            repo_url="https://github.com/org/repo",
            repo_name="test-repo",
            status="completed",
            risk_score=74,
            risk_level="critical",
            findings=findings,
            quality_metrics=quality_metrics,
            summary="Critical security issues detected",
            scan_config={"llm_budget": 5, "model": "gpt-4o-mini"},
            llm_calls_made=3,
            contracts_scanned=5,
            contracts_total=5,
            artifacts_path="s3://bucket/scans/scan_20250119_123456/"
        )
        self.session.add(scan)
        self.session.commit()
        
        # Verify scan execution was created
        retrieved = self.session.query(ScanExecution).filter_by(execution_id="scan_20250119_123456").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.repo_name, "test-repo")
        self.assertEqual(retrieved.risk_score, 74)
        self.assertEqual(retrieved.risk_level, "critical")
        self.assertEqual(len(retrieved.findings), 1)
        self.assertEqual(retrieved.findings[0]["pattern_id"], "REENTRANCY-001")
        self.assertEqual(retrieved.quality_metrics["solidity_version"], "0.8.20")
        self.assertEqual(retrieved.tenant_id, tenant.id)

    def test_scan_execution_with_project(self):
        """Test scan execution linked to a project."""
        # Create tenant and project
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            source_path="/path/to/source"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create scan execution linked to project
        scan = ScanExecution(
            tenant_id=tenant.id,
            project_id=project.id,
            execution_id="scan_with_project",
            repo_name="test-repo",
            status="completed",
            risk_score=30,
            risk_level="low"
        )
        self.session.add(scan)
        self.session.commit()
        
        # Verify relationship
        retrieved = self.session.query(ScanExecution).filter_by(execution_id="scan_with_project").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.project.name, "test_project")
        self.assertEqual(retrieved.tenant.name, "test_org")
        
        # Verify project can access its scans
        retrieved_project = self.session.query(Project).filter_by(name="test_project").first()
        self.assertEqual(len(retrieved_project.scan_executions), 1)

    def test_scan_execution_statuses(self):
        """Test scan execution status transitions."""
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        # Create pending scan
        scan = ScanExecution(
            tenant_id=tenant.id,
            execution_id="scan_status_test",
            repo_name="test-repo",
            status="pending"
        )
        self.session.add(scan)
        self.session.commit()
        
        # Update to running
        scan.status = "running"
        self.session.commit()
        
        retrieved = self.session.query(ScanExecution).filter_by(execution_id="scan_status_test").first()
        self.assertEqual(retrieved.status, "running")
        
        # Update to completed with results
        scan.status = "completed"
        scan.risk_score = 45
        scan.risk_level = "medium"
        self.session.commit()
        
        retrieved = self.session.query(ScanExecution).filter_by(execution_id="scan_status_test").first()
        self.assertEqual(retrieved.status, "completed")
        self.assertEqual(retrieved.risk_score, 45)

    def test_scan_execution_error_handling(self):
        """Test scan execution error state."""
        tenant = Tenant(name="test_org")
        self.session.add(tenant)
        self.session.commit()
        
        # Create failed scan
        scan = ScanExecution(
            tenant_id=tenant.id,
            execution_id="scan_error_test",
            repo_name="broken-repo",
            status="failed",
            error_message="Failed to clone repository: access denied"
        )
        self.session.add(scan)
        self.session.commit()
        
        retrieved = self.session.query(ScanExecution).filter_by(execution_id="scan_error_test").first()
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.status, "failed")
        self.assertIn("access denied", retrieved.error_message)


if __name__ == "__main__":
    unittest.main()
