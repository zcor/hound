"""
Blob storage abstraction for local and cloud storage backends.

This module provides a unified interface for storing session data and graphs
on local filesystem, S3, MinIO, or other cloud storage services.
"""

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BlobStorageBackend(ABC):
    """Abstract base class for blob storage backends."""

    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if a path exists in storage."""
        pass

    @abstractmethod
    def mkdir(self, path: str, parents: bool = True, exist_ok: bool = True) -> None:
        """Create a directory in storage."""
        pass

    @abstractmethod
    def read_text(self, path: str, encoding: str = 'utf-8') -> str:
        """Read text content from storage."""
        pass

    @abstractmethod
    def write_text(self, path: str, content: str, encoding: str = 'utf-8') -> None:
        """Write text content to storage."""
        pass

    @abstractmethod
    def read_bytes(self, path: str) -> bytes:
        """Read binary content from storage."""
        pass

    @abstractmethod
    def write_bytes(self, path: str, content: bytes) -> None:
        """Write binary content to storage."""
        pass

    @abstractmethod
    def list_dir(self, path: str) -> list[str]:
        """List contents of a directory."""
        pass

    @abstractmethod
    def delete(self, path: str) -> None:
        """Delete a file or directory."""
        pass

    def read_json(self, path: str) -> dict[str, Any]:
        """Read and parse JSON from storage."""
        content = self.read_text(path)
        return json.loads(content)

    def write_json(self, path: str, data: dict[str, Any], indent: int = 2) -> None:
        """Write JSON data to storage."""
        content = json.dumps(data, indent=indent, default=str)
        self.write_text(path, content)


class LocalStorageBackend(BlobStorageBackend):
    """Local filesystem storage backend."""

    def __init__(self, base_path: Path | str | None = None):
        """
        Initialize local storage backend.

        Args:
            base_path: Optional base path for all operations. If not provided,
                      paths are treated as absolute.
        """
        self.base_path = Path(base_path) if base_path else None

    def _resolve_path(self, path: str) -> Path:
        """Resolve a path relative to base_path if set."""
        p = Path(path)
        if self.base_path:
            # If path is absolute, make it relative to base_path
            if p.is_absolute():
                # Strip leading slash and make relative
                p = Path(str(p).lstrip('/'))
            return self.base_path / p
        return p

    def exists(self, path: str) -> bool:
        """Check if a path exists in local filesystem."""
        return self._resolve_path(path).exists()

    def mkdir(self, path: str, parents: bool = True, exist_ok: bool = True) -> None:
        """Create a directory in local filesystem."""
        self._resolve_path(path).mkdir(parents=parents, exist_ok=exist_ok)

    def read_text(self, path: str, encoding: str = 'utf-8') -> str:
        """Read text content from local filesystem."""
        return self._resolve_path(path).read_text(encoding=encoding)

    def write_text(self, path: str, content: str, encoding: str = 'utf-8') -> None:
        """Write text content to local filesystem."""
        resolved = self._resolve_path(path)
        # Ensure parent directory exists
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding=encoding)

    def read_bytes(self, path: str) -> bytes:
        """Read binary content from local filesystem."""
        return self._resolve_path(path).read_bytes()

    def write_bytes(self, path: str, content: bytes) -> None:
        """Write binary content to local filesystem."""
        resolved = self._resolve_path(path)
        # Ensure parent directory exists
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_bytes(content)

    def list_dir(self, path: str) -> list[str]:
        """List contents of a directory in local filesystem."""
        resolved = self._resolve_path(path)
        if not resolved.exists():
            return []
        return [str(p.name) for p in resolved.iterdir()]

    def delete(self, path: str) -> None:
        """Delete a file or directory from local filesystem."""
        resolved = self._resolve_path(path)
        if resolved.is_file():
            resolved.unlink()
        elif resolved.is_dir():
            import shutil
            shutil.rmtree(resolved)


class S3StorageBackend(BlobStorageBackend):
    """S3/MinIO storage backend using boto3."""

    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        endpoint_url: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        region_name: str | None = None,
    ):
        """
        Initialize S3 storage backend.

        Args:
            bucket: S3 bucket name
            prefix: Optional prefix for all keys (acts like a base path)
            endpoint_url: Optional custom endpoint (for MinIO or S3-compatible services)
            aws_access_key_id: AWS access key (defaults to environment variable)
            aws_secret_access_key: AWS secret key (defaults to environment variable)
            region_name: AWS region (defaults to environment variable or us-east-1)
        """
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "boto3 is required for S3 storage backend. "
                "Install it with: pip install boto3"
            ) from e

        self.bucket = bucket
        self.prefix = prefix.rstrip('/') if prefix else ""

        # Initialize S3 client with provided or environment credentials
        session_kwargs = {}
        if aws_access_key_id:
            session_kwargs['aws_access_key_id'] = aws_access_key_id
        if aws_secret_access_key:
            session_kwargs['aws_secret_access_key'] = aws_secret_access_key
        if region_name:
            session_kwargs['region_name'] = region_name

        client_kwargs = {}
        if endpoint_url:
            client_kwargs['endpoint_url'] = endpoint_url

        self.s3_client = boto3.client('s3', **session_kwargs, **client_kwargs)

    def _get_key(self, path: str) -> str:
        """Get S3 key from path, applying prefix."""
        # Remove leading slash if present
        path = path.lstrip('/')
        if self.prefix:
            return f"{self.prefix}/{path}"
        return path

    def exists(self, path: str) -> bool:
        """Check if a path exists in S3."""
        key = self._get_key(path)
        try:
            self.s3_client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            # Check if it's a "directory" (prefix with objects)
            try:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.bucket, Prefix=key + '/', MaxKeys=1
                )
                return response.get('KeyCount', 0) > 0
            except Exception:
                return False

    def mkdir(self, path: str, parents: bool = True, exist_ok: bool = True) -> None:
        """
        Create a "directory" in S3 (no-op, as S3 doesn't have real directories).

        S3 uses a flat namespace with keys that can contain slashes.
        Directories are virtual and don't need to be explicitly created.
        """
        # No-op for S3 - directories don't need to be created
        pass

    def read_text(self, path: str, encoding: str = 'utf-8') -> str:
        """Read text content from S3."""
        content = self.read_bytes(path)
        return content.decode(encoding)

    def write_text(self, path: str, content: str, encoding: str = 'utf-8') -> None:
        """Write text content to S3."""
        self.write_bytes(path, content.encode(encoding))

    def read_bytes(self, path: str) -> bytes:
        """Read binary content from S3."""
        key = self._get_key(path)
        try:
            response = self.s3_client.get_object(Bucket=self.bucket, Key=key)
            return response['Body'].read()
        except Exception as e:
            raise FileNotFoundError(f"Object not found: s3://{self.bucket}/{key}") from e

    def write_bytes(self, path: str, content: bytes) -> None:
        """Write binary content to S3."""
        key = self._get_key(path)
        self.s3_client.put_object(Bucket=self.bucket, Key=key, Body=content)

    def list_dir(self, path: str) -> list[str]:
        """List contents of a "directory" in S3."""
        prefix = self._get_key(path)
        if prefix and not prefix.endswith('/'):
            prefix += '/'

        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket, Prefix=prefix, Delimiter='/'
            )

            results = []
            # Add "subdirectories" (common prefixes)
            for common_prefix in response.get('CommonPrefixes', []):
                prefix_str = common_prefix['Prefix']
                # Extract just the directory name
                name = prefix_str.rstrip('/').split('/')[-1]
                results.append(name)

            # Add files
            for obj in response.get('Contents', []):
                key = obj['Key']
                # Skip the prefix itself if it's listed
                if key == prefix:
                    continue
                # Extract just the file name
                name = key[len(prefix):].split('/')[0]
                if name and name not in results:
                    results.append(name)

            return results
        except Exception:
            return []

    def delete(self, path: str) -> None:
        """Delete a file or "directory" from S3."""
        key = self._get_key(path)

        # Try to delete as a single object
        try:
            self.s3_client.delete_object(Bucket=self.bucket, Key=key)
        except Exception:
            pass

        # If it's a "directory", delete all objects with that prefix
        prefix = key if key.endswith('/') else key + '/'
        try:
            # List and delete all objects with this prefix
            paginator = self.s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                if 'Contents' in page:
                    objects = [{'Key': obj['Key']} for obj in page['Contents']]
                    if objects:
                        self.s3_client.delete_objects(
                            Bucket=self.bucket, Delete={'Objects': objects}
                        )
        except Exception:
            pass
