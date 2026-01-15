# Cloud Storage Adapter for SessionManager & GraphStore

This document explains how to use the cloud storage adapter to store session data and graphs on S3/MinIO or other cloud storage services.

## Overview

The Hound project now supports multiple storage backends for session management and graph storage:

- **Local Filesystem** (default): Traditional file-based storage
- **S3/MinIO**: Cloud-based storage for distributed deployments
- **Custom**: Implement your own `BlobStorageBackend` for other services

## Basic Usage

### Local Storage (Default)

By default, SessionManager and GraphStore use the local filesystem:

```python
from pathlib import Path
from analysis.session_manager import SessionManager

# Default local storage
manager = SessionManager(Path("/path/to/project"))
session = manager.create(session_id="my_session")
```

### S3/MinIO Storage

To use S3 or MinIO for cloud storage:

```python
from pathlib import Path
from analysis.session_manager import SessionManager
from storage.blob_storage import S3StorageBackend

# Configure S3 storage backend
storage = S3StorageBackend(
    bucket="my-bucket",
    prefix="hound-sessions",  # Optional prefix for all keys
    endpoint_url="http://localhost:9000",  # For MinIO
    aws_access_key_id="YOUR_ACCESS_KEY",
    aws_secret_access_key="YOUR_SECRET_KEY",
    region_name="us-east-1"  # Optional
)

# Create SessionManager with S3 backend
manager = SessionManager(
    project_dir=Path("/path/to/project"),
    storage_backend=storage
)

# Use normally - all operations go to S3
session = manager.create(session_id="my_session")
```

### Using with AutonomousAgent

The `AutonomousAgent` also supports custom storage backends:

```python
from pathlib import Path
from analysis.agent_core import AutonomousAgent
from storage.blob_storage import S3StorageBackend

# Configure S3 storage
storage = S3StorageBackend(
    bucket="my-graphs-bucket",
    prefix="analysis/graphs"
)

# Create agent with S3 backend
agent = AutonomousAgent(
    graphs_metadata_path=Path("/path/to/graphs/metadata.json"),
    manifest_path=Path("/path/to/manifest"),
    agent_id="agent_1",
    storage_backend=storage
)

# All graph operations will use S3
result = agent.investigate("Check for access control issues")
```

## Configuration Options

### S3StorageBackend Parameters

- **bucket** (required): S3 bucket name
- **prefix** (optional): Prefix for all keys (acts like a base directory)
- **endpoint_url** (optional): Custom endpoint for MinIO or S3-compatible services
- **aws_access_key_id** (optional): AWS access key (defaults to environment variable)
- **aws_secret_access_key** (optional): AWS secret key (defaults to environment variable)
- **region_name** (optional): AWS region (defaults to environment variable or us-east-1)

### LocalStorageBackend Parameters

- **base_path** (optional): Base path for all operations. If not provided, paths are treated as absolute.

## Environment Variables

For S3 storage, you can use environment variables instead of passing credentials:

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

Then create the backend without credentials:

```python
storage = S3StorageBackend(
    bucket="my-bucket",
    prefix="hound-data"
)
```

## Using with MinIO

MinIO is an S3-compatible object storage server. To use it:

```python
from storage.blob_storage import S3StorageBackend

storage = S3StorageBackend(
    bucket="hound-data",
    prefix="sessions",
    endpoint_url="http://localhost:9000",  # MinIO endpoint
    aws_access_key_id="minioadmin",  # Default MinIO credentials
    aws_secret_access_key="minioadmin"
)
```

## Custom Storage Backend

You can implement your own storage backend for other cloud services:

```python
from storage.blob_storage import BlobStorageBackend

class AzureBlobStorage(BlobStorageBackend):
    def __init__(self, connection_string, container_name):
        # Initialize Azure Blob Storage client
        pass
    
    def exists(self, path: str) -> bool:
        # Check if blob exists
        pass
    
    def mkdir(self, path: str, parents: bool = True, exist_ok: bool = True) -> None:
        # No-op for blob storage
        pass
    
    def read_text(self, path: str, encoding: str = 'utf-8') -> str:
        # Read blob as text
        pass
    
    def write_text(self, path: str, content: str, encoding: str = 'utf-8') -> None:
        # Write text to blob
        pass
    
    # Implement other abstract methods...
```

## Best Practices

1. **Use environment variables for credentials**: Don't hardcode AWS credentials in your code
2. **Set appropriate prefixes**: Use prefixes to organize data in shared buckets
3. **Test with MinIO locally**: Use MinIO for local development before deploying to AWS S3
4. **Handle connection errors**: Wrap operations in try-except blocks for network issues
5. **Use appropriate bucket policies**: Ensure your S3 bucket has the right permissions

## Examples

### Example 1: Multi-Agent System with Shared S3 Storage

```python
from pathlib import Path
from analysis.agent_core import AutonomousAgent
from storage.blob_storage import S3StorageBackend

# Shared S3 storage for all agents
shared_storage = S3StorageBackend(
    bucket="multi-agent-graphs",
    prefix="production"
)

# Create multiple agents sharing the same storage
agents = []
for i in range(5):
    agent = AutonomousAgent(
        graphs_metadata_path=Path("/graphs/metadata.json"),
        manifest_path=Path("/manifest"),
        agent_id=f"agent_{i}",
        storage_backend=shared_storage
    )
    agents.append(agent)

# All agents can read/write to the same graphs
for agent in agents:
    agent.investigate("Check for vulnerabilities")
```

### Example 2: Local Development with MinIO

```bash
# Start MinIO server
docker run -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=minioadmin \
  minio/minio server /data --console-address ":9001"
```

```python
from pathlib import Path
from analysis.session_manager import SessionManager
from storage.blob_storage import S3StorageBackend

# Connect to local MinIO
storage = S3StorageBackend(
    bucket="local-dev",
    endpoint_url="http://localhost:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin"
)

manager = SessionManager(Path("."), storage_backend=storage)
session = manager.create()
print(f"Created session: {session.session_id}")
```

### Example 3: Fallback to Local Storage

```python
from pathlib import Path
from analysis.session_manager import SessionManager
from storage.blob_storage import S3StorageBackend, LocalStorageBackend

def create_session_manager(project_dir, use_s3=False):
    """Create session manager with optional S3 backend."""
    if use_s3:
        try:
            storage = S3StorageBackend(
                bucket="my-bucket",
                prefix="sessions"
            )
            print("Using S3 storage")
        except Exception as e:
            print(f"S3 connection failed: {e}, falling back to local storage")
            storage = LocalStorageBackend(base_path=project_dir)
    else:
        storage = LocalStorageBackend(base_path=project_dir)
        print("Using local storage")
    
    return SessionManager(project_dir, storage_backend=storage)

# Try S3, fall back to local if it fails
manager = create_session_manager(Path("/project"), use_s3=True)
```

## Troubleshooting

### boto3 not found

If you get an error about boto3 not being installed:

```bash
pip install boto3
```

### Connection timeout

If you're experiencing connection timeouts with S3:

1. Check your network connection
2. Verify the endpoint URL is correct
3. Check AWS credentials and permissions
4. Consider increasing timeout settings in boto3

### Permission denied

If you get permission errors:

1. Verify your AWS credentials have the necessary permissions
2. Check the S3 bucket policy
3. Ensure the IAM user/role has `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` permissions

## Migration Guide

To migrate from local storage to S3:

1. **Backup your data**: Always backup before migration
2. **Test with MinIO**: Test the migration process locally first
3. **Use a script**: Create a migration script to copy data to S3:

```python
import json
from pathlib import Path
from storage.blob_storage import LocalStorageBackend, S3StorageBackend

def migrate_to_s3(local_path, bucket, prefix):
    """Migrate local data to S3."""
    local = LocalStorageBackend(base_path=local_path)
    s3 = S3StorageBackend(bucket=bucket, prefix=prefix)
    
    # Recursively copy files
    def copy_dir(path):
        for item in local.list_dir(path):
            full_path = f"{path}/{item}" if path else item
            if local.exists(f"{full_path}/"):
                # It's a directory
                copy_dir(full_path)
            else:
                # It's a file
                content = local.read_bytes(full_path)
                s3.write_bytes(full_path, content)
                print(f"Copied: {full_path}")
    
    copy_dir("")
    print("Migration complete!")

# Usage
migrate_to_s3(
    local_path=Path("/project/sessions"),
    bucket="my-bucket",
    prefix="sessions"
)
```

## Performance Considerations

- **Latency**: Cloud storage has higher latency than local filesystem
- **Bandwidth**: Large graphs may take longer to upload/download
- **Caching**: Consider implementing caching for frequently accessed graphs
- **Concurrent access**: S3 handles concurrent access better than local filesystem

## Security Considerations

- **Encryption**: Enable S3 server-side encryption (SSE-S3 or SSE-KMS)
- **Access control**: Use IAM policies to restrict access
- **VPC endpoints**: Use VPC endpoints to keep traffic within AWS
- **Audit logging**: Enable S3 access logging for compliance
