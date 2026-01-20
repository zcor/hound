# Hound Dashboard API Server

This FastAPI server provides REST and WebSocket endpoints to serve data to the React frontend and handles the SaaS orchestration layer.

## Quick Start with Docker

```bash
# From repository root
docker compose up -d

# API available at http://localhost:8000
curl http://localhost:8000/health
curl http://localhost:8000/docs   # OpenAPI docs
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  GitHub App     │     │  Web Server     │     │  Celery Worker  │
│  (Webhooks)     │────▶│  (FastAPI)      │────▶│  (Background)   │
└─────────────────┘     └────────┬────────┘     └────────┬────────┘
                                 │                       │
                        ┌────────▼────────┐     ┌────────▼────────┐
                        │  PostgreSQL     │     │  Redis Pub/Sub  │
                        │  (Database)     │     │  (Live Updates) │
                        └─────────────────┘     └────────┬────────┘
                                                         │
                                                ┌────────▼────────┐
                                                │  WebSocket      │
                                                │  (Browser)      │
                                                └─────────────────┘
```

## Features

- **REST API Endpoints**: CRUD operations for projects, sessions, graphs, and findings
- **Audit Control**: Start audits via API, track progress, get results
- **GitHub Webhooks**: Auto-trigger audits on PR open/push events
- **WebSocket Support**: Real-time audit log streaming via Redis Pub/Sub
- **Database Integration**: Uses PostgreSQL/SQLite with SQLAlchemy ORM
- **CORS Support**: Configured for cross-origin requests from frontend
- **API Documentation**: Auto-generated Swagger/OpenAPI docs at `/docs`

## Endpoints

### 1. GET /projects
List all projects from the database with statistics:
- Number of graphs
- Number of sessions
- Number of hypotheses
- Number of confirmed findings

**Response:**
```json
[
  {
    "id": 1,
    "name": "my-project",
    "source_path": "/path/to/source",
    "git_url": "https://github.com/user/repo",
    "description": "Project description",
    "status": "active",
    "created_at": "2025-01-16T12:00:00",
    "last_accessed": "2025-01-16T14:30:00",
    "graphs_count": 5,
    "sessions_count": 3,
    "hypotheses_count": 12,
    "confirmed_count": 4
  }
]
```

### 2. POST /projects
Create a new project for manual git URLs or source paths.

**Request:**
```json
{
  "name": "new-project",
  "git_url": "https://github.com/user/repo",
  "source_path": "/path/to/source",
  "description": "Optional description"
}
```

**Response:** Same as GET /projects item

### 3. GET /projects/{id}/sessions
List all audit sessions for a project.

**Response:**
```json
[
  {
    "id": 1,
    "session_id": "sess_20250116_120000_abc123",
    "status": "completed",
    "start_time": "2025-01-16T12:00:00",
    "end_time": "2025-01-16T13:30:00",
    "models": {
      "scout": "gpt-4o",
      "strategist": "gpt-4o-mini"
    },
    "token_usage": {
      "total_tokens": 10000,
      "input_tokens": 5000,
      "output_tokens": 5000
    },
    "coverage": {
      "nodes": {"visited": 45, "total": 100},
      "cards": {"visited": 23, "total": 50}
    },
    "investigations_count": 5
  }
]
```

### 4. GET /sessions/{id}/graph
Return the system_graph JSON for visualization.

**Response:** Complete graph structure with nodes and edges

### 5. GET /sessions/{id}/findings
Return the list of confirmed hypotheses (findings).

**Response:**
```json
[
  {
    "id": 1,
    "hypothesis_id": "hyp_20250116_120000_xyz789",
    "title": "SQL Injection in login endpoint",
    "description": "The login endpoint is vulnerable...",
    "vulnerability_type": "SQL Injection",
    "status": "confirmed",
    "confidence": 0.9,
    "severity": "high",
    "node_refs": ["node1", "node2"],
    "evidence": {...},
    "reported_by_model": "gpt-4o",
    "created_at": "2025-01-16T12:00:00",
    "updated_at": "2025-01-16T12:30:00"
  }
]
```

### 6. POST /audits/start ⭐ NEW
Start a new security audit (async, returns immediately).

**Request:**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "tenant_id": 1,
  "max_iterations": 50,
  "installation_id": 12345,
  "pr_number": 42,
  "repo_full_name": "owner/repo"
}
```

**Response:**
```json
{
  "session_id": "audit_abc123def456_1737331200",
  "status": "queued",
  "message": "Audit queued successfully. Task ID: celery-task-id",
  "websocket_url": "/ws/sessions/audit_abc123def456_1737331200"
}
```

### 7. GET /audits/{session_id}/status ⭐ NEW
Get the current status of an audit.

**Response:**
```json
{
  "session_id": "audit_abc123def456_1737331200",
  "status": "running",
  "progress": {"iteration": 15, "hypotheses_formed": 3},
  "findings_count": 2,
  "started_at": "2025-01-19T12:00:00",
  "completed_at": null
}
```

### 8. POST /webhooks/github ⭐ NEW
Handle GitHub App webhook events.

Automatically triggers audits on:
- `pull_request` events (opened, synchronize, reopened)
- `installation` events (app installed/uninstalled)
- `push` events (to default branch - configurable)

**Headers Required:**
- `X-GitHub-Event`: Event type (e.g., "pull_request")
- `X-Hub-Signature-256`: HMAC signature for verification

**Response (PR event):**
```json
{
  "status": "ok",
  "event": "pull_request",
  "action": "opened",
  "session_id": "pr_owner_repo_42_abc123",
  "task_id": "celery-task-id"
}
```

### 9. WS /ws/sessions/{session_id}
WebSocket endpoint for streaming live audit logs.

Establishes a WebSocket connection and subscribes to Redis Pub/Sub channels for real-time updates during an audit session.

**Channels Subscribed:**
- `audit:updates:{session_id}` - Live progress updates
- `audit:status:{session_id}` - Status changes

**Connection Message:**
```json
{
  "type": "connected",
  "session_id": "audit_abc123def456_1737331200",
  "message": "WebSocket connection established. Subscribing to audit updates...",
  "timestamp": "2025-01-19T12:00:00"
}
```

**Progress Messages (from worker):**
```json
{
  "type": "thought",
  "scan_id": "audit_abc123def456_1737331200",
  "iteration": 5,
  "data": {"thought": "Analyzing authentication flow..."},
  "timestamp": "2025-01-19T12:05:00"
}
```

## Setup

### Prerequisites
- Python 3.10+
- PostgreSQL database (or SQLite for development)

### Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set database URL (optional, defaults to postgresql://localhost/hound):
```bash
export DATABASE_URL="postgresql://user:password@localhost/hound"
```

3. Initialize database:
```bash
python -m database.migrate --database-url "$DATABASE_URL"
```

### Running the Server

**Development mode:**
```bash
python server/api.py
```

**Production mode with Uvicorn:**
```bash
uvicorn server.api:app --host 0.0.0.0 --port 8000
```

**With workers:**
```bash
uvicorn server.api:app --host 0.0.0.0 --port 8000 --workers 4
```

### Access API Documentation

Once the server is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

## Development

### Running Tests

```bash
pytest tests/test_api_server.py -v
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL/SQLite connection string | `sqlite:///hound.db` |
| `REDIS_URL` | Redis connection for Celery & Pub/Sub | `redis://localhost:6379/0` |
| `GITHUB_WEBHOOK_SECRET` | Secret for verifying GitHub webhooks | (none - dev mode skips verification) |
| `HOUND_ALLOWED_ORIGINS` | Comma-separated CORS origins | `*` |

## Running with Celery Workers

For production SaaS deployment, run both the API server and Celery workers:

```bash
# Terminal 1: API Server
uvicorn server.api:app --host 0.0.0.0 --port 8000

# Terminal 2: Celery Worker
celery -A worker.celery_app worker --loglevel=info

# Terminal 3: Redis (if not using managed Redis)
redis-server
```

## Future Enhancements

1. ~~Redis Integration~~: ✅ Implemented - WebSocket now subscribes to Redis Pub/Sub
2. **Authentication**: Add JWT or OAuth2 authentication
3. **Rate Limiting**: Implement rate limiting for API endpoints
4. **Caching**: Add Redis caching for frequently accessed data
5. **Pagination**: Implement cursor-based pagination for large result sets
6. **Multi-tenancy**: Add tenant isolation and billing integration

## Architecture

The server follows a clean architecture pattern:

```
server/
├── __init__.py
└── api.py              # FastAPI app with all endpoints

database/
├── models.py           # SQLAlchemy models
└── migrate.py          # Database migration scripts

commands/
└── project.py          # ProjectManager for CLI compatibility
```

## Testing

The test suite includes:
- Unit tests for all endpoints (including new audit control endpoints)
- Integration tests with file-based SQLite database
- WebSocket connection tests
- GitHub webhook handling tests
- Request/response validation tests

All 24 tests pass successfully.
