"""
Unit tests for GitHub App integration.

Tests the GitHub App authentication, webhook handling, and audit triggering.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from database.models import (
    Base,
    Project,
    Tenant,
    create_db_engine,
    create_db_session,
    init_database,
)


class TestGitHubAppIntegration(unittest.TestCase):
    """Test GitHub App integration functionality."""
    
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
    
    @patch('integrations.github_app.get_github_app_integration')
    def test_get_repo_token(self, mock_integration):
        """Test getting a repository token."""
        from integrations.github_app import get_repo_token
        
        # Mock the integration
        mock_auth = Mock()
        mock_auth.token = "test_token_123"
        mock_integration.return_value.get_access_token.return_value = mock_auth
        
        # Get token
        token = get_repo_token(12345)
        
        # Verify
        self.assertEqual(token, "test_token_123")
        mock_integration.return_value.get_access_token.assert_called_once_with(12345)
    
    def test_handle_installation_created(self):
        """Test handling installation.created event."""
        from integrations.github_app import handle_installation_created
        
        # Create test payload
        payload = {
            "action": "created",
            "installation": {
                "id": 12345,
                "account": {
                    "login": "test-org"
                }
            },
            "repositories": [
                {
                    "id": 1001,
                    "full_name": "test-org/repo1"
                },
                {
                    "id": 1002,
                    "full_name": "test-org/repo2"
                }
            ]
        }
        
        # Handle the event
        handle_installation_created(payload, self.session)
        
        # Verify tenant was created
        tenant = self.session.query(Tenant).filter_by(installation_id=12345).first()
        self.assertIsNotNone(tenant)
        self.assertEqual(tenant.name, "github_test-org")
        self.assertEqual(tenant.installation_id, 12345)
        
        # Verify projects were created
        projects = self.session.query(Project).filter_by(tenant_id=tenant.id).all()
        self.assertEqual(len(projects), 2)
        
        project_names = {p.name for p in projects}
        self.assertIn("test-org_repo1", project_names)
        self.assertIn("test-org_repo2", project_names)
        
        # Verify project details
        project1 = self.session.query(Project).filter_by(github_repo_id=1001).first()
        self.assertEqual(project1.git_url, "https://github.com/test-org/repo1")
        self.assertEqual(project1.installation_id, 12345)
        self.assertEqual(project1.status, "active")
    
    def test_handle_push_event(self):
        """Test handling push event."""
        from integrations.github_app import handle_push_event
        
        # Create test data
        tenant = Tenant(name="test-tenant", installation_id=12345)
        self.session.add(tenant)
        self.session.flush()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            github_repo_id=1001,
            installation_id=12345,
            git_url="https://github.com/test-org/repo1",
            status="active"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create push payload
        payload = {
            "repository": {
                "id": 1001,
                "full_name": "test-org/repo1",
                "clone_url": "https://github.com/test-org/repo1.git"
            },
            "head_commit": {
                "id": "abc123def456"
            },
            "after": "abc123def456"
        }
        
        # Mock the audit trigger
        with patch('integrations.audit_trigger.run_audit_task') as mock_audit:
            handle_push_event(payload, self.session)
            
            # Verify audit was triggered
            mock_audit.assert_called_once()
            call_kwargs = mock_audit.call_args[1]
            self.assertEqual(call_kwargs['project_id'], project.id)
            self.assertEqual(call_kwargs['project_name'], "test_project")
            self.assertEqual(call_kwargs['commit_sha'], "abc123def456")
            self.assertEqual(call_kwargs['installation_id'], 12345)
    
    def test_handle_push_event_inactive_project(self):
        """Test that push events are ignored for inactive projects."""
        from integrations.github_app import handle_push_event
        
        # Create inactive project
        tenant = Tenant(name="test-tenant", installation_id=12345)
        self.session.add(tenant)
        self.session.flush()
        
        project = Project(
            tenant_id=tenant.id,
            name="test_project",
            github_repo_id=1001,
            installation_id=12345,
            git_url="https://github.com/test-org/repo1",
            status="inactive"
        )
        self.session.add(project)
        self.session.commit()
        
        # Create push payload
        payload = {
            "repository": {
                "id": 1001,
                "full_name": "test-org/repo1"
            },
            "head_commit": {
                "id": "abc123def456"
            }
        }
        
        # Mock the audit trigger
        with patch('integrations.audit_trigger.run_audit_task') as mock_audit:
            handle_push_event(payload, self.session)
            
            # Verify audit was NOT triggered for inactive project
            mock_audit.assert_not_called()


class TestGitHubWebhookEndpoint(unittest.TestCase):
    """Test the FastAPI webhook endpoint."""
    
    @patch.dict(os.environ, {
        'GITHUB_APP_ID': '123456',
        'GITHUB_APP_PRIVATE_KEY_PATH': '/tmp/test.pem',
        'GITHUB_WEBHOOK_SECRET': 'test_secret',
        'DATABASE_URL': 'sqlite:///:memory:'
    })
    @patch('integrations.github_app.verify_webhook_signature')
    @patch('integrations.github_app.handle_installation_created')
    def test_webhook_installation_created(self, mock_handle, mock_verify):
        """Test webhook endpoint for installation.created event."""
        from integrations.github_app import app
        
        # Mock signature verification
        mock_verify.return_value = True
        
        client = TestClient(app)
        
        payload = {
            "action": "created",
            "installation": {"id": 12345, "account": {"login": "test-org"}},
            "repositories": []
        }
        
        response = client.post(
            "/webhooks/github",
            json=payload,
            headers={
                "X-Hub-Signature-256": "sha256=test",
                "X-GitHub-Event": "installation"
            }
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        mock_handle.assert_called_once()
    
    @patch.dict(os.environ, {
        'GITHUB_APP_ID': '123456',
        'GITHUB_APP_PRIVATE_KEY_PATH': '/tmp/test.pem',
        'GITHUB_WEBHOOK_SECRET': 'test_secret',
        'DATABASE_URL': 'sqlite:///:memory:'
    })
    @patch('integrations.github_app.verify_webhook_signature')
    @patch('integrations.github_app.handle_push_event')
    def test_webhook_push_event(self, mock_handle, mock_verify):
        """Test webhook endpoint for push event."""
        from integrations.github_app import app
        
        # Mock signature verification
        mock_verify.return_value = True
        
        client = TestClient(app)
        
        payload = {
            "repository": {"id": 1001, "full_name": "test-org/repo1"},
            "head_commit": {"id": "abc123"}
        }
        
        response = client.post(
            "/webhooks/github",
            json=payload,
            headers={
                "X-Hub-Signature-256": "sha256=test",
                "X-GitHub-Event": "push"
            }
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")
        mock_handle.assert_called_once()
    
    @patch.dict(os.environ, {
        'GITHUB_APP_ID': '123456',
        'GITHUB_APP_PRIVATE_KEY_PATH': '/tmp/test.pem',
        'GITHUB_WEBHOOK_SECRET': 'test_secret'
    })
    @patch('integrations.github_app.verify_webhook_signature')
    def test_webhook_invalid_signature(self, mock_verify):
        """Test webhook endpoint rejects invalid signatures."""
        from integrations.github_app import app
        
        # Mock signature verification to fail
        mock_verify.return_value = False
        
        client = TestClient(app)
        
        response = client.post(
            "/webhooks/github",
            json={"test": "data"},
            headers={
                "X-Hub-Signature-256": "sha256=invalid",
                "X-GitHub-Event": "push"
            }
        )
        
        self.assertEqual(response.status_code, 401)
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        from integrations.github_app import app
        
        client = TestClient(app)
        response = client.get("/health")
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
