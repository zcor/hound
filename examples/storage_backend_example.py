"""
Example: Using SessionManager with different storage backends.

This example demonstrates how to use SessionManager with both local
and S3/MinIO storage backends.
"""

from pathlib import Path
from analysis.session_manager import SessionManager
from storage.blob_storage import LocalStorageBackend, S3StorageBackend


def example_local_storage():
    """Example using local filesystem storage."""
    print("=" * 60)
    print("Example 1: Local Filesystem Storage")
    print("=" * 60)
    
    # Create SessionManager with default local storage
    project_dir = Path("/tmp/hound_example")
    manager = SessionManager(project_dir)
    
    # Create a new session
    session = manager.create(session_id="example_session_1")
    print(f"Created session: {session.session_id}")
    print(f"Session path: {session.path}")
    
    # Retrieve the session
    retrieved = manager.get("example_session_1")
    if retrieved:
        print(f"Retrieved session: {retrieved.session_id}")
    
    # Create multiple sessions
    for i in range(3):
        session = manager.create()
        print(f"Auto-generated session: {session.session_id}")
    
    print()


def example_s3_storage():
    """Example using S3/MinIO storage."""
    print("=" * 60)
    print("Example 2: S3/MinIO Storage")
    print("=" * 60)
    print("Note: This requires a running MinIO instance or AWS credentials")
    print()
    
    # Note: Uncomment the following code if you have MinIO running locally
    # or AWS credentials configured
    
    """
    # Create S3 storage backend
    storage = S3StorageBackend(
        bucket="hound-sessions",
        prefix="example",
        endpoint_url="http://localhost:9000",  # For MinIO
        aws_access_key_id="minioadmin",
        aws_secret_access_key="minioadmin"
    )
    
    # Create SessionManager with S3 backend
    manager = SessionManager(
        project_dir=Path("/tmp/hound_s3_example"),
        storage_backend=storage
    )
    
    # Create sessions - all data goes to S3/MinIO
    session = manager.create(session_id="s3_session_1")
    print(f"Created S3 session: {session.session_id}")
    print(f"Session path: {session.path}")
    
    # Retrieve the session
    retrieved = manager.get("s3_session_1")
    if retrieved:
        print(f"Retrieved S3 session: {retrieved.session_id}")
    """
    
    print("To use S3 storage:")
    print("1. Install boto3: pip install boto3")
    print("2. Start MinIO or configure AWS credentials")
    print("3. Uncomment the code in this example")
    print()


def example_custom_local_with_basepath():
    """Example using LocalStorageBackend with custom base path."""
    print("=" * 60)
    print("Example 3: Custom Local Storage with Base Path")
    print("=" * 60)
    
    # Create LocalStorageBackend with custom base path
    base_path = Path("/tmp/hound_custom_base")
    storage = LocalStorageBackend(base_path=base_path)
    
    # Create SessionManager with custom storage
    manager = SessionManager(
        project_dir=Path("project"),  # Relative to base_path
        storage_backend=storage
    )
    
    # Create sessions
    session = manager.create(session_id="custom_session_1")
    print(f"Created session: {session.session_id}")
    print(f"Session path: {session.path}")
    print(f"Actual location: {base_path / session.path}")
    
    print()


def example_session_operations():
    """Example of various session operations."""
    print("=" * 60)
    print("Example 4: Session Operations")
    print("=" * 60)
    
    project_dir = Path("/tmp/hound_operations")
    manager = SessionManager(project_dir)
    
    # Create a session
    session1 = manager.create(session_id="operation_session")
    print(f"Created session: {session1.session_id}")
    
    # Get existing session
    existing = manager.get("operation_session")
    if existing:
        print(f"Found existing session: {existing.session_id}")
    
    # Try to get non-existent session
    not_found = manager.get("nonexistent_session")
    if not_found is None:
        print("Non-existent session returned None (as expected)")
    
    # Get or create - returns existing
    session2 = manager.get_or_create(session_id="operation_session")
    print(f"Get or create returned: {session2.session_id}")
    
    # Get or create - creates new
    session3 = manager.get_or_create(session_id="new_session")
    print(f"Get or create created: {session3.session_id}")
    
    # Force new session even if it exists
    session4 = manager.get_or_create(session_id="operation_session", new_session=True)
    print(f"Forced new session: {session4.session_id}")
    
    print()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("SessionManager Storage Examples")
    print("=" * 60 + "\n")
    
    # Run examples
    example_local_storage()
    example_s3_storage()
    example_custom_local_with_basepath()
    example_session_operations()
    
    print("=" * 60)
    print("Examples completed!")
    print("=" * 60)
