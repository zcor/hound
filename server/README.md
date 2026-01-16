# Hound Dashboard API Server

This FastAPI server provides REST and WebSocket endpoints to serve data to the React frontend, replacing CLI commands with API endpoints.

## Features

- **REST API Endpoints**: CRUD operations for projects, sessions, graphs, and findings
- **WebSocket Support**: Real-time audit log streaming (ready for Redis integration)
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

### 6. WS /ws/sessions/{id}
WebSocket endpoint for streaming live audit logs.

Establishes a WebSocket connection for real-time updates during an audit session. Ready for Redis pub/sub integration.

**Connection Message:**
```json
{
  "type": "connected",
  "session_id": "sess_20250116_120000_abc123",
  "message": "WebSocket connection established",
  "timestamp": "2025-01-16T12:00:00"
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

- `DATABASE_URL`: PostgreSQL connection string (default: `postgresql://localhost/hound`)
- For testing, set to `sqlite:///:memory:` or `sqlite:///test.db`

## Future Enhancements

1. **Redis Integration**: The WebSocket endpoint is prepared for Redis pub/sub to stream live audit logs
2. **Authentication**: Add JWT or OAuth2 authentication
3. **Rate Limiting**: Implement rate limiting for API endpoints
4. **Caching**: Add Redis caching for frequently accessed data
5. **Pagination**: Implement cursor-based pagination for large result sets

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
- Unit tests for all endpoints
- Integration tests with in-memory SQLite database
- WebSocket connection tests
- Request/response validation tests

All 16 tests pass successfully.
