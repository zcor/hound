"""
Unit tests for SessionManager with blob storage support.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.session_manager import SessionManager
from storage.blob_storage import LocalStorageBackend


class TestSessionManagerLocal(unittest.TestCase):
    """Test SessionManager with local filesystem storage."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir) / "project"
        self.project_dir.mkdir()

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_creates_sessions_dir(self):
        """Test that SessionManager creates sessions directory."""
        SessionManager(self.project_dir)
        
        # Verify sessions directory was created
        sessions_dir = self.project_dir / "sessions"
        self.assertTrue(sessions_dir.exists())
        self.assertTrue(sessions_dir.is_dir())

    def test_init_with_custom_backend(self):
        """Test initialization with custom storage backend."""
        backend = LocalStorageBackend(base_path=self.project_dir)
        manager = SessionManager(self.project_dir, storage_backend=backend)
        
        self.assertIsNotNone(manager.storage)
        self.assertEqual(manager.storage, backend)

    def test_create_session_default_id(self):
        """Test creating a session with auto-generated ID."""
        manager = SessionManager(self.project_dir)
        
        session = manager.create()
        
        self.assertIsNotNone(session)
        self.assertTrue(session.session_id.startswith("sess_"))
        self.assertTrue(manager.storage.exists(session.path))

    def test_create_session_custom_id(self):
        """Test creating a session with custom ID."""
        manager = SessionManager(self.project_dir)
        
        custom_id = "custom_session_123"
        session = manager.create(session_id=custom_id)
        
        self.assertEqual(session.session_id, custom_id)
        self.assertEqual(session.path, f"sessions/{custom_id}")
        self.assertTrue(manager.storage.exists(session.path))

    def test_get_existing_session(self):
        """Test getting an existing session."""
        manager = SessionManager(self.project_dir)
        
        # Create a session
        created = manager.create(session_id="test_session")
        
        # Get the session
        retrieved = manager.get("test_session")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.session_id, created.session_id)
        self.assertEqual(retrieved.path, created.path)

    def test_get_nonexistent_session(self):
        """Test getting a non-existent session returns None."""
        manager = SessionManager(self.project_dir)
        
        result = manager.get("nonexistent_session")
        
        self.assertIsNone(result)

    def test_get_or_create_existing(self):
        """Test get_or_create returns existing session."""
        manager = SessionManager(self.project_dir)
        
        # Create a session
        original = manager.create(session_id="test_session")
        
        # Get or create should return the existing one
        retrieved = manager.get_or_create(session_id="test_session")
        
        self.assertEqual(retrieved.session_id, original.session_id)
        self.assertEqual(retrieved.path, original.path)

    def test_get_or_create_new(self):
        """Test get_or_create creates new session if not exists."""
        manager = SessionManager(self.project_dir)
        
        # Get or create should create new
        session = manager.get_or_create(session_id="new_session")
        
        self.assertEqual(session.session_id, "new_session")
        self.assertTrue(manager.storage.exists(session.path))

    def test_get_or_create_force_new(self):
        """Test get_or_create with new_session=True creates new session."""
        manager = SessionManager(self.project_dir)
        
        # Create a session
        manager.create(session_id="test_session")
        
        # Force create new session with same ID
        new_session = manager.get_or_create(session_id="test_session", new_session=True)
        
        # Should create a new one (though ID might be different due to timestamp)
        self.assertIsNotNone(new_session)

    def test_initialize_session_storage_specific(self):
        """Test initializing storage for a specific session."""
        manager = SessionManager(self.project_dir)
        
        session_id = "specific_session"
        manager.initialize_session_storage(session_id)
        
        # Verify session directory exists
        session_path = f"sessions/{session_id}"
        self.assertTrue(manager.storage.exists(session_path))

    def test_multiple_sessions(self):
        """Test creating and managing multiple sessions."""
        manager = SessionManager(self.project_dir)
        
        # Create multiple sessions
        session1 = manager.create(session_id="session1")
        session2 = manager.create(session_id="session2")
        session3 = manager.create(session_id="session3")
        
        # Verify all exist
        self.assertIsNotNone(manager.get("session1"))
        self.assertIsNotNone(manager.get("session2"))
        self.assertIsNotNone(manager.get("session3"))
        
        # Verify they're different
        self.assertNotEqual(session1.session_id, session2.session_id)
        self.assertNotEqual(session2.session_id, session3.session_id)


class TestSessionManagerS3(unittest.TestCase):
    """Test SessionManager with S3 storage backend."""

    def setUp(self):
        """Set up test fixtures with mocked S3."""
        self.temp_dir = tempfile.mkdtemp()
        self.project_dir = Path(self.temp_dir) / "project"
        
        # Mock S3 storage
        self.mock_storage = {}
        
        # Create mock storage backend
        self.mock_backend = MagicMock()
        
        def mock_exists(path):
            return path in self.mock_storage
        
        def mock_mkdir(path, parents=True, exist_ok=True):
            self.mock_storage[path] = "dir"
        
        def mock_write_text(path, content, encoding='utf-8'):
            self.mock_storage[path] = content
        
        def mock_read_text(path, encoding='utf-8'):
            if path in self.mock_storage:
                return self.mock_storage[path]
            raise FileNotFoundError(f"Path not found: {path}")
        
        self.mock_backend.exists.side_effect = mock_exists
        self.mock_backend.mkdir.side_effect = mock_mkdir
        self.mock_backend.write_text.side_effect = mock_write_text
        self.mock_backend.read_text.side_effect = mock_read_text

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_with_s3_backend(self):
        """Test SessionManager initialization with S3 backend."""
        manager = SessionManager(self.project_dir, storage_backend=self.mock_backend)
        
        self.assertIsNotNone(manager.storage)
        self.assertEqual(manager.storage, self.mock_backend)
        
        # Verify sessions directory was initialized
        self.mock_backend.mkdir.assert_called()

    def test_create_session_with_s3(self):
        """Test creating a session with S3 backend."""
        manager = SessionManager(self.project_dir, storage_backend=self.mock_backend)
        
        session = manager.create(session_id="s3_session")
        
        self.assertEqual(session.session_id, "s3_session")
        self.assertEqual(session.path, "sessions/s3_session")
        
        # Verify mkdir was called for the session
        self.mock_backend.mkdir.assert_any_call("sessions/s3_session", parents=True, exist_ok=True)

    def test_get_session_with_s3(self):
        """Test getting a session with S3 backend."""
        manager = SessionManager(self.project_dir, storage_backend=self.mock_backend)
        
        # Create a session (which adds to mock_storage)
        manager.create(session_id="s3_session")
        
        # Get the session
        retrieved = manager.get("s3_session")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.session_id, "s3_session")

    def test_session_info_path_is_string(self):
        """Test that SessionInfo.path is a string (not Path) for cloud compatibility."""
        manager = SessionManager(self.project_dir, storage_backend=self.mock_backend)
        
        session = manager.create(session_id="test")
        
        # Verify path is string, not Path object
        self.assertIsInstance(session.path, str)
        self.assertNotIsInstance(session.path, Path)


if __name__ == "__main__":
    unittest.main()
