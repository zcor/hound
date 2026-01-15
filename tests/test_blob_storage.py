"""
Unit tests for blob storage backends.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.blob_storage import BlobStorageBackend, LocalStorageBackend, S3StorageBackend


class TestLocalStorageBackend(unittest.TestCase):
    """Test the LocalStorageBackend class."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = LocalStorageBackend(base_path=self.temp_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_exists(self):
        """Test checking if paths exist."""
        # File doesn't exist yet
        self.assertFalse(self.storage.exists("test.txt"))

        # Create file
        test_file = Path(self.temp_dir) / "test.txt"
        test_file.write_text("test content")

        # File exists now
        self.assertTrue(self.storage.exists("test.txt"))

    def test_mkdir(self):
        """Test creating directories."""
        # Create nested directory
        self.storage.mkdir("subdir1/subdir2")

        # Verify directory exists
        self.assertTrue((Path(self.temp_dir) / "subdir1" / "subdir2").exists())
        self.assertTrue((Path(self.temp_dir) / "subdir1" / "subdir2").is_dir())

    def test_read_write_text(self):
        """Test reading and writing text files."""
        content = "Hello, World!"
        path = "test.txt"

        # Write text
        self.storage.write_text(path, content)

        # Read text
        read_content = self.storage.read_text(path)
        self.assertEqual(read_content, content)

    def test_read_write_bytes(self):
        """Test reading and writing binary files."""
        content = b"Binary content"
        path = "test.bin"

        # Write bytes
        self.storage.write_bytes(path, content)

        # Read bytes
        read_content = self.storage.read_bytes(path)
        self.assertEqual(read_content, content)

    def test_read_write_json(self):
        """Test reading and writing JSON files."""
        data = {"key": "value", "number": 42, "nested": {"a": 1}}
        path = "test.json"

        # Write JSON
        self.storage.write_json(path, data)

        # Read JSON
        read_data = self.storage.read_json(path)
        self.assertEqual(read_data, data)

    def test_list_dir(self):
        """Test listing directory contents."""
        # Create some files and directories
        self.storage.write_text("file1.txt", "content1")
        self.storage.write_text("file2.txt", "content2")
        self.storage.mkdir("subdir")

        # List directory
        contents = self.storage.list_dir(".")
        self.assertIn("file1.txt", contents)
        self.assertIn("file2.txt", contents)
        self.assertIn("subdir", contents)

    def test_delete_file(self):
        """Test deleting files."""
        path = "test.txt"
        self.storage.write_text(path, "content")
        self.assertTrue(self.storage.exists(path))

        # Delete file
        self.storage.delete(path)
        self.assertFalse(self.storage.exists(path))

    def test_delete_directory(self):
        """Test deleting directories."""
        self.storage.mkdir("testdir")
        self.storage.write_text("testdir/file.txt", "content")
        self.assertTrue(self.storage.exists("testdir"))

        # Delete directory
        self.storage.delete("testdir")
        self.assertFalse(self.storage.exists("testdir"))

    def test_write_creates_parent_dirs(self):
        """Test that writing files creates parent directories."""
        path = "nested/deep/file.txt"
        self.storage.write_text(path, "content")

        # Verify file and parent directories exist
        self.assertTrue(self.storage.exists(path))
        self.assertTrue(self.storage.exists("nested/deep"))


class TestS3StorageBackend(unittest.TestCase):
    """Test the S3StorageBackend class with mocked boto3."""

    def setUp(self):
        """Set up test fixtures with mocked S3."""
        # Mock boto3.client - must patch before importing
        self.boto3_patcher = patch('boto3.client')
        self.mock_boto3_client_factory = self.boto3_patcher.start()
        
        # Mock S3 client
        self.mock_s3_client = MagicMock()
        self.mock_boto3_client_factory.return_value = self.mock_s3_client
        
        # Create storage backend
        self.storage = S3StorageBackend(
            bucket="test-bucket",
            prefix="test-prefix",
            endpoint_url="http://localhost:9000",
            aws_access_key_id="test-key",
            aws_secret_access_key="test-secret",
        )
        
        # In-memory storage for mock
        self.mock_storage = {}

    def tearDown(self):
        """Clean up test fixtures."""
        self.boto3_patcher.stop()

    def _setup_mock_storage(self):
        """Helper to set up mock S3 operations."""
        def get_object(Bucket, Key):
            if Key in self.mock_storage:
                body = MagicMock()
                body.read.return_value = self.mock_storage[Key]
                return {'Body': body}
            raise Exception("NoSuchKey")

        def put_object(Bucket, Key, Body):
            if isinstance(Body, bytes):
                self.mock_storage[Key] = Body
            else:
                self.mock_storage[Key] = Body.encode() if isinstance(Body, str) else Body

        def head_object(Bucket, Key):
            if Key in self.mock_storage:
                return {'ContentLength': len(self.mock_storage[Key])}
            raise Exception("NotFound")

        def list_objects_v2(Bucket, Prefix, **kwargs):
            keys = [k for k in self.mock_storage.keys() if k.startswith(Prefix)]
            
            if 'Delimiter' in kwargs:
                # Return both files and "directories"
                contents = []
                prefixes = set()
                
                for key in keys:
                    relative = key[len(Prefix):]
                    if kwargs['Delimiter'] in relative:
                        # This is in a subdirectory
                        subdir = relative.split(kwargs['Delimiter'])[0]
                        prefixes.add(Prefix + subdir + kwargs['Delimiter'])
                    else:
                        # This is a direct file
                        contents.append({'Key': key})
                
                return {
                    'Contents': contents,
                    'CommonPrefixes': [{'Prefix': p} for p in prefixes],
                    'KeyCount': len(contents) + len(prefixes)
                }
            else:
                return {
                    'Contents': [{'Key': k} for k in keys],
                    'KeyCount': len(keys)
                }

        def delete_object(Bucket, Key):
            if Key in self.mock_storage:
                del self.mock_storage[Key]

        def delete_objects(Bucket, Delete):
            for obj in Delete['Objects']:
                if obj['Key'] in self.mock_storage:
                    del self.mock_storage[obj['Key']]

        self.mock_s3_client.get_object.side_effect = get_object
        self.mock_s3_client.put_object.side_effect = put_object
        self.mock_s3_client.head_object.side_effect = head_object
        self.mock_s3_client.list_objects_v2.side_effect = list_objects_v2
        self.mock_s3_client.delete_object.side_effect = delete_object
        self.mock_s3_client.delete_objects.side_effect = delete_objects

    def test_initialization(self):
        """Test S3 storage backend initialization."""
        self.assertEqual(self.storage.bucket, "test-bucket")
        self.assertEqual(self.storage.prefix, "test-prefix")
        self.assertIsNotNone(self.storage.s3_client)

    def test_get_key_with_prefix(self):
        """Test key generation with prefix."""
        key = self.storage._get_key("path/to/file.txt")
        self.assertEqual(key, "test-prefix/path/to/file.txt")

    def test_exists(self):
        """Test checking if objects exist in S3."""
        self._setup_mock_storage()
        
        # Object doesn't exist
        self.assertFalse(self.storage.exists("nonexistent.txt"))
        
        # Create object
        self.mock_storage["test-prefix/test.txt"] = b"content"
        
        # Object exists now
        self.assertTrue(self.storage.exists("test.txt"))

    def test_mkdir_is_noop(self):
        """Test that mkdir is a no-op for S3."""
        # Should not raise any errors
        self.storage.mkdir("some/path")
        self.storage.mkdir("another/path", parents=True, exist_ok=True)

    def test_read_write_text(self):
        """Test reading and writing text to S3."""
        self._setup_mock_storage()
        
        content = "Hello, S3!"
        path = "test.txt"
        
        # Write text
        self.storage.write_text(path, content)
        
        # Read text
        read_content = self.storage.read_text(path)
        self.assertEqual(read_content, content)

    def test_read_write_bytes(self):
        """Test reading and writing bytes to S3."""
        self._setup_mock_storage()
        
        content = b"Binary content for S3"
        path = "test.bin"
        
        # Write bytes
        self.storage.write_bytes(path, content)
        
        # Read bytes
        read_content = self.storage.read_bytes(path)
        self.assertEqual(read_content, content)

    def test_read_write_json(self):
        """Test reading and writing JSON to S3."""
        self._setup_mock_storage()
        
        data = {"key": "value", "number": 42}
        path = "test.json"
        
        # Write JSON
        self.storage.write_json(path, data)
        
        # Read JSON
        read_data = self.storage.read_json(path)
        self.assertEqual(read_data, data)

    def test_list_dir(self):
        """Test listing objects in S3."""
        self._setup_mock_storage()
        
        # Create some objects
        self.mock_storage["test-prefix/dir/file1.txt"] = b"content1"
        self.mock_storage["test-prefix/dir/file2.txt"] = b"content2"
        self.mock_storage["test-prefix/dir/subdir/file3.txt"] = b"content3"
        
        # List directory
        contents = self.storage.list_dir("dir")
        self.assertIn("file1.txt", contents)
        self.assertIn("file2.txt", contents)
        self.assertIn("subdir", contents)

    def test_delete(self):
        """Test deleting objects from S3."""
        self._setup_mock_storage()
        
        # Create object
        path = "test.txt"
        self.mock_storage["test-prefix/test.txt"] = b"content"
        
        # Delete object
        self.storage.delete(path)
        
        # Verify deletion
        self.assertNotIn("test-prefix/test.txt", self.mock_storage)

    def test_read_nonexistent_raises_error(self):
        """Test that reading non-existent object raises error."""
        self._setup_mock_storage()
        
        with self.assertRaises(FileNotFoundError):
            self.storage.read_text("nonexistent.txt")


class TestStorageBackendInterface(unittest.TestCase):
    """Test that storage backends implement the required interface."""

    def test_local_backend_implements_interface(self):
        """Test LocalStorageBackend implements BlobStorageBackend."""
        backend = LocalStorageBackend()
        self.assertIsInstance(backend, BlobStorageBackend)
        
        # Check all required methods exist
        self.assertTrue(hasattr(backend, 'exists'))
        self.assertTrue(hasattr(backend, 'mkdir'))
        self.assertTrue(hasattr(backend, 'read_text'))
        self.assertTrue(hasattr(backend, 'write_text'))
        self.assertTrue(hasattr(backend, 'read_bytes'))
        self.assertTrue(hasattr(backend, 'write_bytes'))
        self.assertTrue(hasattr(backend, 'list_dir'))
        self.assertTrue(hasattr(backend, 'delete'))
        self.assertTrue(hasattr(backend, 'read_json'))
        self.assertTrue(hasattr(backend, 'write_json'))

    def test_s3_backend_implements_interface(self):
        """Test S3StorageBackend implements BlobStorageBackend."""
        with patch('boto3.client'):
            backend = S3StorageBackend(bucket="test")
            self.assertIsInstance(backend, BlobStorageBackend)
            
            # Check all required methods exist
            self.assertTrue(hasattr(backend, 'exists'))
            self.assertTrue(hasattr(backend, 'mkdir'))
            self.assertTrue(hasattr(backend, 'read_text'))
            self.assertTrue(hasattr(backend, 'write_text'))
            self.assertTrue(hasattr(backend, 'read_bytes'))
            self.assertTrue(hasattr(backend, 'write_bytes'))
            self.assertTrue(hasattr(backend, 'list_dir'))
            self.assertTrue(hasattr(backend, 'delete'))
            self.assertTrue(hasattr(backend, 'read_json'))
            self.assertTrue(hasattr(backend, 'write_json'))


if __name__ == "__main__":
    unittest.main()
