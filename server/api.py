"""
FastAPI server for Hound Dashboard API.

Provides REST and WebSocket endpoints to serve data to the React frontend,
replacing CLI commands with API endpoints.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from commands.project import ProjectManager
from database.models import (
    AuditSession,
    Base,
    Graph,
    Hypothesis,
    Project,
    Tenant,
    create_db_engine,
    create_db_session,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///hound.db")

# Create engine lazily to avoid connection errors during import
_engine = None


def get_engine():
    """Get or create database engine."""
    global _engine
    if _engine is None:
        _engine = create_db_engine(DATABASE_URL)
        # Initialize database tables
        Base.metadata.create_all(_engine)
    return _engine


# Create FastAPI app
app = FastAPI(
    title="Hound Dashboard API",
    description="API for Hound security analysis dashboard",
    version="1.0.0",
)

# Configure CORS
# In production, configure with specific allowed origins via environment variable
allowed_origins = os.environ.get("HOUND_ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency for database session
def get_db():
    """Get database session."""
    engine = get_engine()
    db = create_db_session(engine)
    try:
        yield db
    finally:
        db.close()


# Pydantic models for request/response
class ProjectCreate(BaseModel):
    """Request model for creating a project."""

    name: str = Field(..., description="Project name")
    git_url: Optional[str] = Field(None, description="Git repository URL")
    source_path: Optional[str] = Field(None, description="Local source path")
    description: Optional[str] = Field(None, description="Project description")


class ProjectResponse(BaseModel):
    """Response model for project data."""

    id: int
    name: str
    source_path: Optional[str]
    git_url: Optional[str]
    description: Optional[str]
    status: str
    created_at: datetime
    last_accessed: datetime
    graphs_count: int = 0
    sessions_count: int = 0
    hypotheses_count: int = 0
    confirmed_count: int = 0

    class Config:
        from_attributes = True


class SessionResponse(BaseModel):
    """Response model for session data."""

    id: int
    session_id: str
    status: str
    start_time: datetime
    end_time: Optional[datetime]
    models: Optional[Dict[str, Any]]
    token_usage: Optional[Dict[str, Any]]
    coverage: Optional[Dict[str, Any]]
    investigations_count: int = 0

    class Config:
        from_attributes = True


class GraphResponse(BaseModel):
    """Response model for graph data."""

    id: int
    name: str
    internal_name: Optional[str]
    data: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    """Response model for hypothesis/finding data."""

    id: int
    hypothesis_id: str
    title: str
    description: str
    vulnerability_type: str
    status: str
    confidence: float
    severity: str
    node_refs: Optional[List[str]]
    evidence: Optional[Dict[str, Any]]
    reported_by_model: Optional[str]
    junior_model: Optional[str]
    senior_model: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# API Endpoints


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Hound Dashboard API",
        "version": "1.0.0",
        "endpoints": {
            "projects": "/projects",
            "create_project": "POST /projects",
            "sessions": "/projects/{id}/sessions",
            "graph": "/sessions/{id}/graph",
            "findings": "/sessions/{id}/findings",
            "websocket": "/ws/sessions/{id}",
        },
    }


@app.get("/projects", response_model=List[ProjectResponse])
async def list_projects(db: Session = Depends(get_db)):
    """
    List all projects from the database.

    Returns project metadata with statistics including:
    - Number of graphs
    - Number of sessions
    - Number of hypotheses
    - Number of confirmed hypotheses
    """
    projects = db.query(Project).all()

    response = []
    for project in projects:
        # Count related items
        graphs_count = db.query(Graph).filter(Graph.project_id == project.id).count()
        sessions_count = db.query(AuditSession).filter(AuditSession.project_id == project.id).count()
        hypotheses_count = db.query(Hypothesis).filter(Hypothesis.project_id == project.id).count()
        confirmed_count = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == project.id, Hypothesis.status == "confirmed")
            .count()
        )

        response.append(
            ProjectResponse(
                id=project.id,
                name=project.name,
                source_path=project.source_path,
                git_url=project.git_url,
                description=project.description,
                status=project.status,
                created_at=project.created_at,
                last_accessed=project.last_accessed,
                graphs_count=graphs_count,
                sessions_count=sessions_count,
                hypotheses_count=hypotheses_count,
                confirmed_count=confirmed_count,
            )
        )

    return response


@app.post("/projects", response_model=ProjectResponse)
async def create_project(project_data: ProjectCreate, db: Session = Depends(get_db)):
    """
    Create a new project for manual git URLs or source paths.

    Accepts either git_url or source_path. Creates the project using
    the ProjectManager and stores it in the database.
    
    Note: If git_url is provided without source_path, the repository
    should be cloned first. This is currently a placeholder for future
    git clone functionality.
    """
    # Validate that at least one source is provided
    if not project_data.git_url and not project_data.source_path:
        raise HTTPException(
            status_code=400, detail="Either git_url or source_path must be provided"
        )

    # Use ProjectManager to create the project
    manager = ProjectManager()

    try:
        # For now, require source_path for actual project creation
        # TODO: Add git clone functionality for git_url
        source = project_data.source_path
        if not source:
            # Placeholder: git_url should trigger clone to temp directory
            raise HTTPException(
                status_code=400, 
                detail="source_path is required. Git URL cloning not yet implemented."
            )

        # Create project using ProjectManager
        project_config = manager.create_project(
            name=project_data.name,
            source_path=source,
            description=project_data.description,
        )

        # Also create database entry
        # First, get or create default tenant
        tenant = db.query(Tenant).first()
        if not tenant:
            tenant = Tenant(name="default")
            db.add(tenant)
            db.commit()
            db.refresh(tenant)

        # Create database project entry with error handling for datetime parsing
        try:
            created_at = datetime.fromisoformat(project_config["created_at"])
            last_accessed = datetime.fromisoformat(project_config["last_accessed"])
        except (ValueError, KeyError) as e:
            logger.warning(f"Failed to parse datetime from project config: {e}")
            # Fallback to current time
            created_at = datetime.now(timezone.utc)
            last_accessed = datetime.now(timezone.utc)
        
        db_project = Project(
            tenant_id=tenant.id,
            name=project_data.name,
            source_path=project_data.source_path,
            git_url=project_data.git_url,
            description=project_data.description or project_config.get("description"),
            status="active",
            created_at=created_at,
            last_accessed=last_accessed,
        )
        db.add(db_project)
        db.commit()
        db.refresh(db_project)

        return ProjectResponse(
            id=db_project.id,
            name=db_project.name,
            source_path=db_project.source_path,
            git_url=db_project.git_url,
            description=db_project.description,
            status=db_project.status,
            created_at=db_project.created_at,
            last_accessed=db_project.last_accessed,
            graphs_count=0,
            sessions_count=0,
            hypotheses_count=0,
            confirmed_count=0,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create project: {str(e)}")


@app.get("/projects/{project_id}/sessions", response_model=List[SessionResponse])
async def list_project_sessions(project_id: int, db: Session = Depends(get_db)):
    """
    List all audit sessions for a project.

    Returns session metadata including:
    - Session ID and status
    - Start and end times
    - Models used
    - Token usage statistics
    - Coverage information
    - Number of investigations
    """
    # Verify project exists
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Query sessions for the project
    sessions = (
        db.query(AuditSession)
        .filter(AuditSession.project_id == project_id)
        .order_by(AuditSession.start_time.desc())
        .all()
    )

    response = []
    for session in sessions:
        investigations_count = len(session.investigations or [])

        response.append(
            SessionResponse(
                id=session.id,
                session_id=session.session_id,
                status=session.status,
                start_time=session.start_time,
                end_time=session.end_time,
                models=session.models,
                token_usage=session.token_usage,
                coverage=session.coverage,
                investigations_count=investigations_count,
            )
        )

    return response


@app.get("/sessions/{session_id}/graph")
async def get_session_graph(session_id: str, db: Session = Depends(get_db)):
    """
    Return the system_graph JSON for visualization.

    This endpoint retrieves the graph data associated with a session.
    If the session has a project, it returns the SystemArchitecture graph
    for that project.
    """
    # First, try to get the session from the database
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get the project's graphs
    project = db.query(Project).filter(Project.id == session.project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found for session")

    # Try to get SystemArchitecture graph from database
    system_graph = (
        db.query(Graph)
        .filter(
            Graph.project_id == project.id,
            Graph.internal_name == "SystemArchitecture",
        )
        .first()
    )

    if system_graph:
        return system_graph.data

    # Fallback: Try to load from filesystem
    manager = ProjectManager()
    project_path = manager.get_project_path(project.name)

    if not project_path:
        raise HTTPException(status_code=404, detail="Project path not found")

    graphs_dir = project_path / "graphs"
    system_graph_file = graphs_dir / "graph_SystemArchitecture.json"

    if system_graph_file.exists():
        try:
            with open(system_graph_file, "r") as f:
                graph_data = json.load(f)
            return graph_data
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to load graph: {str(e)}")

    raise HTTPException(status_code=404, detail="System graph not found")


@app.get("/sessions/{session_id}/findings", response_model=List[FindingResponse])
async def get_session_findings(session_id: str, db: Session = Depends(get_db)):
    """
    Return the list of confirmed hypotheses (findings).

    This endpoint retrieves all confirmed hypotheses/findings for a project
    associated with the given session.
    """
    # Get the session
    session = db.query(AuditSession).filter(AuditSession.session_id == session_id).first()

    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get confirmed hypotheses for the project
    hypotheses = (
        db.query(Hypothesis)
        .filter(
            Hypothesis.project_id == session.project_id,
            Hypothesis.status == "confirmed",
        )
        .order_by(Hypothesis.confidence.desc())
        .all()
    )

    response = []
    for hypothesis in hypotheses:
        response.append(
            FindingResponse(
                id=hypothesis.id,
                hypothesis_id=hypothesis.hypothesis_id,
                title=hypothesis.title,
                description=hypothesis.description,
                vulnerability_type=hypothesis.vulnerability_type,
                status=hypothesis.status,
                confidence=hypothesis.confidence,
                severity=hypothesis.severity,
                node_refs=hypothesis.node_refs,
                evidence=hypothesis.evidence,
                reported_by_model=hypothesis.reported_by_model,
                junior_model=hypothesis.junior_model,
                senior_model=hypothesis.senior_model,
                created_at=hypothesis.created_at,
                updated_at=hypothesis.updated_at,
            )
        )

    return response


class FindingStatusUpdate(BaseModel):
    """Request model for updating finding status."""

    status: str = Field(..., description="New status (proposed, investigating, confirmed, rejected, resolved)")


@app.post("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: int, status_update: FindingStatusUpdate, db: Session = Depends(get_db)
):
    """
    Update the status of a finding (hypothesis).

    This endpoint allows users to confirm or reject findings from the UI.
    Valid statuses are: proposed, investigating, confirmed, rejected, resolved.
    """
    # Validate status
    valid_statuses = ["proposed", "investigating", "confirmed", "rejected", "resolved"]
    if status_update.status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )

    # Get the finding
    finding = db.query(Hypothesis).filter(Hypothesis.id == finding_id).first()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update status
    finding.status = status_update.status
    finding.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    return {
        "id": finding.id,
        "hypothesis_id": finding.hypothesis_id,
        "status": finding.status,
        "updated_at": finding.updated_at.isoformat(),
    }


# WebSocket endpoint for live audit logs
class ConnectionManager:
    """Manage WebSocket connections for live audit log streaming."""

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str):
        """Accept a new WebSocket connection for a session."""
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)

    def disconnect(self, websocket: WebSocket, session_id: str):
        """Remove a WebSocket connection."""
        if session_id in self.active_connections:
            self.active_connections[session_id].remove(websocket)
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]

    async def send_message(self, message: str, session_id: str):
        """Send a message to all connections for a session."""
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                await connection.send_text(message)

    async def broadcast(self, message: dict, session_id: str):
        """Broadcast a JSON message to all connections for a session."""
        if session_id in self.active_connections:
            message_text = json.dumps(message)
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_text(message_text)
                except Exception:
                    pass  # Connection closed, will be cleaned up


manager_ws = ConnectionManager()


@app.websocket("/ws/sessions/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """
    WebSocket endpoint for streaming live audit logs.

    This endpoint establishes a WebSocket connection for real-time updates
    during an audit session. In the future, this will subscribe to Redis
    pub/sub channels to receive live updates from the audit process.

    Current implementation provides a placeholder connection that can be
    used for testing. The Redis integration (Task 3 mentioned in the issue)
    should be implemented separately.
    """
    await manager_ws.connect(websocket, session_id)

    try:
        # Send initial connection confirmation
        await websocket.send_json(
            {
                "type": "connected",
                "session_id": session_id,
                "message": "WebSocket connection established",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        )

        # TODO: Subscribe to Redis channel for this session
        # This is a placeholder implementation until Redis integration (Task 3) is complete
        # Future implementation should:
        # 1. Connect to Redis
        # 2. Subscribe to channel: f"audit:session:{session_id}"
        # 3. Forward messages from Redis to the WebSocket client

        # Keep connection alive and handle incoming messages
        while True:
            data = await websocket.receive_text()
            # Echo back for now (placeholder)
            await websocket.send_json(
                {
                    "type": "echo",
                    "data": data,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

    except WebSocketDisconnect:
        manager_ws.disconnect(websocket, session_id)
    except Exception as e:
        logger.error(f"WebSocket error for session {session_id}: {e}")
        manager_ws.disconnect(websocket, session_id)


# Health check endpoint
@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    
    Returns the current server status and timestamp. Used by load balancers
    and monitoring systems to verify the server is running and responsive.
    
    Returns:
        dict: Status and UTC timestamp
    """
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
