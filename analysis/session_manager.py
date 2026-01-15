"""Session manager for audit runs.

Provides simple session directory management under a project directory.
Supports both local filesystem and cloud storage (S3/MinIO) backends.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from storage.blob_storage import BlobStorageBackend


@dataclass
class SessionInfo:
    session_id: str
    path: str  # Changed from Path to str to support both local and remote paths


class SessionManager:
    def __init__(
        self,
        project_dir: Path | str,
        storage_backend: BlobStorageBackend | None = None,
    ):
        """
        Initialize session manager.

        Args:
            project_dir: Base project directory
            storage_backend: Optional storage backend. If None, uses local filesystem.
        """
        self.project_dir = Path(project_dir) if isinstance(project_dir, str) else project_dir
        self.sessions_dir_path = "sessions"  # Relative path for sessions
        
        # Initialize storage backend
        if storage_backend is None:
            from storage.blob_storage import LocalStorageBackend
            storage_backend = LocalStorageBackend(base_path=self.project_dir)
        
        self.storage = storage_backend
        
        # Initialize session storage
        self.initialize_session_storage()

    def initialize_session_storage(self, session_id: str | None = None) -> None:
        """
        Initialize storage for sessions.

        Args:
            session_id: Optional specific session ID to initialize.
                       If None, initializes the base sessions directory.
        """
        if session_id:
            session_path = f"{self.sessions_dir_path}/{session_id}"
            self.storage.mkdir(session_path, parents=True, exist_ok=True)
        else:
            self.storage.mkdir(self.sessions_dir_path, parents=True, exist_ok=True)

    def create(self, session_id: str | None = None) -> SessionInfo:
        """Create a new session."""
        sid = session_id or f"sess_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session_path = f"{self.sessions_dir_path}/{sid}"
        self.initialize_session_storage(sid)
        return SessionInfo(session_id=sid, path=session_path)

    def get(self, session_id: str) -> SessionInfo | None:
        """Get an existing session if it exists."""
        session_path = f"{self.sessions_dir_path}/{session_id}"
        if self.storage.exists(session_path):
            return SessionInfo(session_id=session_id, path=session_path)
        return None

    def get_or_create(self, session_id: str | None = None, new_session: bool = False) -> SessionInfo:
        """Get existing session or create a new one."""
        if session_id and not new_session:
            found = self.get(session_id)
            if found:
                return found
        return self.create(session_id)

