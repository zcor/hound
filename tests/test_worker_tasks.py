"""
Tests for Celery worker tasks and Redis publisher.
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestRedisPublisher(unittest.TestCase):
    """Test RedisPublisher class."""

    def setUp(self):
        """Set up test fixtures."""
        self.scan_id = "test_scan_123"

    def test_channel_names(self):
        """Test that channel names are correctly formatted."""
        from worker.redis_publisher import RedisPublisher

        publisher = RedisPublisher(self.scan_id)
        
        self.assertEqual(publisher.channel_updates, f"audit:updates:{self.scan_id}")
        self.assertEqual(publisher.channel_status, f"audit:status:{self.scan_id}")

    def test_publish_graceful_degradation_no_redis(self):
        """Test that publishing works gracefully when redis is not available."""
        from worker.redis_publisher import RedisPublisher

        publisher = RedisPublisher(self.scan_id)
        # Force no redis client
        publisher._redis_client = None
        publisher._connected = False

        # Should not raise any exceptions
        publisher.publish_thought("test thought", iteration=1)
        publisher.publish_decision("load_graph", "testing", {}, iteration=1)
        publisher.publish_status("running", "Test message")
        publisher.publish_error("Test error", "test_type")

    @patch('redis.from_url')
    def test_publish_thought(self, mock_from_url):
        """Test publishing a thought message."""
        from worker.redis_publisher import RedisPublisher

        # Set up mock
        mock_client = MagicMock()
        mock_from_url.return_value = mock_client

        publisher = RedisPublisher(self.scan_id)
        publisher.publish_thought("Analyzing code...", iteration=5)

        # Verify publish was called
        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        channel = call_args[0][0]
        message = json.loads(call_args[0][1])

        self.assertEqual(channel, f"audit:updates:{self.scan_id}")
        self.assertEqual(message["type"], "thought")
        self.assertEqual(message["iteration"], 5)
        self.assertEqual(message["data"]["thought"], "Analyzing code...")
        self.assertEqual(message["scan_id"], self.scan_id)
        self.assertIn("timestamp", message)

    @patch('redis.from_url')
    def test_publish_decision(self, mock_from_url):
        """Test publishing a decision message."""
        from worker.redis_publisher import RedisPublisher

        mock_client = MagicMock()
        mock_from_url.return_value = mock_client

        publisher = RedisPublisher(self.scan_id)
        publisher.publish_decision(
            action="load_graph",
            reasoning="Need to understand system architecture",
            parameters={"graph_name": "SystemArchitecture"},
            iteration=3
        )

        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        message = json.loads(call_args[0][1])

        self.assertEqual(message["type"], "decision")
        self.assertEqual(message["data"]["action"], "load_graph")
        self.assertEqual(message["data"]["reasoning"], "Need to understand system architecture")
        self.assertEqual(message["data"]["parameters"]["graph_name"], "SystemArchitecture")

    @patch('redis.from_url')
    def test_publish_status(self, mock_from_url):
        """Test publishing a status message."""
        from worker.redis_publisher import RedisPublisher

        mock_client = MagicMock()
        mock_from_url.return_value = mock_client

        publisher = RedisPublisher(self.scan_id)
        publisher.publish_status("completed", "Audit finished successfully")

        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        channel = call_args[0][0]
        message = json.loads(call_args[0][1])

        # Status goes to status channel, not updates
        self.assertEqual(channel, f"audit:status:{self.scan_id}")
        self.assertEqual(message["type"], "status")
        self.assertEqual(message["data"]["status"], "completed")

    @patch('redis.from_url')
    def test_publish_progress(self, mock_from_url):
        """Test publishing a progress message."""
        from worker.redis_publisher import RedisPublisher

        mock_client = MagicMock()
        mock_from_url.return_value = mock_client

        publisher = RedisPublisher(self.scan_id)
        publisher.publish_progress(
            iteration=10,
            max_iterations=50,
            nodes_visited=25,
            hypotheses_count=3,
            graphs_loaded=2
        )

        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        message = json.loads(call_args[0][1])

        self.assertEqual(message["type"], "progress")
        self.assertEqual(message["data"]["iteration"], 10)
        self.assertEqual(message["data"]["max_iterations"], 50)
        self.assertEqual(message["data"]["progress_percent"], 20.0)
        self.assertEqual(message["data"]["nodes_visited"], 25)

    @patch('redis.from_url')
    def test_publish_hypothesis(self, mock_from_url):
        """Test publishing a hypothesis message."""
        from worker.redis_publisher import RedisPublisher

        mock_client = MagicMock()
        mock_from_url.return_value = mock_client

        publisher = RedisPublisher(self.scan_id)
        publisher.publish_hypothesis(
            hypothesis_id="hyp_001",
            title="Potential reentrancy vulnerability",
            confidence=0.85,
            severity="critical",
            iteration=15
        )

        mock_client.publish.assert_called_once()
        call_args = mock_client.publish.call_args
        message = json.loads(call_args[0][1])

        self.assertEqual(message["type"], "hypothesis")
        self.assertEqual(message["data"]["hypothesis_id"], "hyp_001")
        self.assertEqual(message["data"]["confidence"], 0.85)
        self.assertEqual(message["data"]["severity"], "critical")


class TestCeleryApp(unittest.TestCase):
    """Test Celery app configuration."""

    def test_celery_app_imports(self):
        """Test that celery app can be imported."""
        from worker.celery_app import celery_app
        
        self.assertEqual(celery_app.main, "hound_worker")

    def test_celery_config(self):
        """Test celery configuration settings."""
        from worker.celery_app import celery_app
        
        # Check key configuration values
        self.assertEqual(celery_app.conf.task_serializer, "json")
        self.assertEqual(celery_app.conf.result_serializer, "json")
        self.assertTrue(celery_app.conf.task_acks_late)
        self.assertEqual(celery_app.conf.worker_prefetch_multiplier, 1)


class TestWorkerTasks(unittest.TestCase):
    """Test Celery worker tasks."""

    def test_task_registration(self):
        """Test that tasks are properly registered."""
        from worker.celery_app import celery_app
        
        # Tasks should be registered
        self.assertIn("worker.tasks.execute_audit_task", celery_app.tasks)
        self.assertIn("worker.tasks.execute_scan_task", celery_app.tasks)

    @patch('worker.tasks.RedisPublisher')
    def test_execute_scan_task_structure(self, mock_publisher_class):
        """Test execute_scan_task basic structure."""
        from worker.tasks import execute_scan_task
        
        # Verify task has correct name
        self.assertEqual(execute_scan_task.name, "worker.tasks.execute_scan_task")

    @patch('worker.tasks.RedisPublisher')
    def test_execute_audit_task_structure(self, mock_publisher_class):
        """Test execute_audit_task basic structure."""
        from worker.tasks import execute_audit_task
        
        # Verify task has correct name
        self.assertEqual(execute_audit_task.name, "worker.tasks.execute_audit_task")

    @patch("server.token_crypto.decrypt_token", return_value="ghp_decrypted")
    def test_resolve_scan_github_token_uses_user_token_fallback(self, mock_decrypt):
        """OAuth-triggered scans should fall back to the user's stored GitHub token."""
        from worker.tasks import resolve_scan_github_token

        user = MagicMock(tenant_id=7, github_token_encrypted="encrypted-token")
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user

        token = resolve_scan_github_token(lambda: db, tenant_id=7, github_user_id=42)

        self.assertEqual(token, "ghp_decrypted")
        mock_decrypt.assert_called_once_with("encrypted-token")
        db.close.assert_called_once()

    @patch("integrations.github_auth.get_installation_token", return_value="ghs_installation")
    def test_resolve_scan_github_token_prefers_installation_token(self, mock_installation_token):
        """Installation auth should win over OAuth fallback when both are present."""
        from worker.tasks import resolve_scan_github_token

        db_factory = MagicMock()

        token = resolve_scan_github_token(
            db_factory,
            tenant_id=7,
            installation_id=99,
            github_user_id=42,
        )

        self.assertEqual(token, "ghs_installation")
        mock_installation_token.assert_called_once_with(99)
        db_factory.assert_not_called()


class TestAgentCoreRedisIntegration(unittest.TestCase):
    """Test Redis integration in AutonomousAgent."""

    def test_agent_accepts_redis_publisher(self):
        """Test that AutonomousAgent accepts redis_publisher parameter."""
        import inspect

        from analysis.agent_core import AutonomousAgent
        
        # Check that redis_publisher is in the __init__ signature
        sig = inspect.signature(AutonomousAgent.__init__)
        param_names = list(sig.parameters.keys())
        
        self.assertIn('redis_publisher', param_names)

    def test_publish_to_redis_method_exists(self):
        """Test that _publish_to_redis method exists."""
        from analysis.agent_core import AutonomousAgent
        
        self.assertTrue(hasattr(AutonomousAgent, '_publish_to_redis'))

    def test_publish_to_redis_no_op_without_publisher(self):
        """Test that _publish_to_redis is a no-op when no publisher is set."""
        from analysis.agent_core import AutonomousAgent
        
        # Create a mock agent-like object with minimal setup
        class MockAgent:
            redis_publisher = None
            debug = False
        
        agent = MockAgent()
        
        # Bind the method to our mock object
        bound_method = AutonomousAgent._publish_to_redis.__get__(agent, MockAgent)
        
        # Should not raise any exceptions
        bound_method('thought', iteration=1, data={'thought': 'test'})
        bound_method('decision', iteration=1, data={})


class TestCreatePublisher(unittest.TestCase):
    """Test the create_publisher factory function."""

    def test_create_publisher(self):
        """Test creating a publisher via factory function."""
        from worker.redis_publisher import create_publisher
        
        publisher = create_publisher("test_scan_456")
        
        self.assertEqual(publisher.scan_id, "test_scan_456")
        self.assertEqual(publisher.channel_updates, "audit:updates:test_scan_456")


if __name__ == "__main__":
    unittest.main()
