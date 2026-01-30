# API Reference

This document provides a comprehensive reference for Hound's REST API and WebSocket interfaces.

## Table of Contents

- [Authentication](#authentication)
- [Base URL](#base-url)
- [Projects API](#projects-api)
- [Audit Sessions API](#audit-sessions-api)
- [Graphs API](#graphs-api)
- [Hypotheses API](#hypotheses-api)
- [Scans API](#scans-api)
- [WebSocket API](#websocket-api)
- [Admin API](#admin-api)
- [Error Handling](#error-handling)

## Authentication

### Admin Key Authentication

Protected endpoints (prefixed with `/admin/`) require authentication via the `HOUND_ADMIN_KEY` environment variable.

**Methods:**

1. **HTTP Header**:
   ```
   X-Admin-Key: your_admin_key
   Authorization: Bearer your_admin_key
   ```

2. **Query Parameter** (for browser testing):
   ```
   ?admin_key=your_admin_key
   ```

3. **Session Cookie** (after login):
   - Login at `/admin/login` with POST request
   - Receives `admin_session` cookie for subsequent requests

**Example:**
```bash
curl -H "X-Admin-Key: mysecretkey" http://localhost:8000/admin/projects
```

## Base URL

**Development:** `http://localhost:8000`  
**Production:** Set via `HOUND_API_URL` environment variable

## Projects API

### List Projects

```http
GET /projects
```

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `per_page` (integer, optional): Items per page (default: 20, max: 100)

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "name": "myaudit",
      "git_url": "https://github.com/owner/repo",
      "source_path": "/path/to/local/repo",
      "created_at": "2024-01-15T10:30:00Z",
      "session_count": 5,
      "hypothesis_count": 12
    }
  ],
  "total": 50,
  "page": 1,
  "per_page": 20,
  "pages": 3
}
```

### Create Project

```http
POST /projects
```

**Request Body:**
```json
{
  "name": "myaudit",
  "source_path": "/path/to/repo",
  "git_url": "https://github.com/owner/repo"
}
```

**Response:** `201 Created`
```json
{
  "id": 1,
  "name": "myaudit",
  "git_url": "https://github.com/owner/repo",
  "source_path": "/path/to/repo",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Get Project

```http
GET /projects/{project_id}
```

**Response:**
```json
{
  "id": 1,
  "name": "myaudit",
  "git_url": "https://github.com/owner/repo",
  "source_path": "/path/to/repo",
  "created_at": "2024-01-15T10:30:00Z",
  "sessions": [...],
  "hypotheses": [...],
  "graphs": [...]
}
```

### Delete Project

```http
DELETE /projects/{project_id}
```

**Response:** `204 No Content`

## Audit Sessions API

### List Sessions

```http
GET /projects/{project_id}/sessions
```

**Response:**
```json
{
  "items": [
    {
      "id": "session_abc123",
      "project_id": 1,
      "mode": "intuition",
      "status": "completed",
      "started_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T11:45:00Z",
      "token_usage": {
        "total_tokens": 125000,
        "total_cost": 2.50
      },
      "coverage": {
        "nodes_visited": 45,
        "nodes_total": 120
      }
    }
  ]
}
```

### Get Session

```http
GET /sessions/{session_id}
```

**Response:**
```json
{
  "id": "session_abc123",
  "project_id": 1,
  "mode": "intuition",
  "status": "completed",
  "started_at": "2024-01-15T10:30:00Z",
  "completed_at": "2024-01-15T11:45:00Z",
  "token_usage": {...},
  "coverage": {...},
  "investigations": [...],
  "planning_history": [...]
}
```

### Create Session

```http
POST /projects/{project_id}/sessions
```

**Request Body:**
```json
{
  "mode": "intuition",
  "time_limit": 3600,
  "model": "gpt-4o",
  "strategist_model": "gpt-5"
}
```

**Response:** `201 Created`

## Graphs API

### List Graphs

```http
GET /projects/{project_id}/graphs
```

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "name": "SystemArchitecture",
      "display_name": "System Architecture",
      "description": "High-level system components and relationships",
      "node_count": 45,
      "edge_count": 78,
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T11:00:00Z"
    }
  ]
}
```

### Get Graph

```http
GET /graphs/{graph_id}
```

**Response:**
```json
{
  "id": 1,
  "name": "SystemArchitecture",
  "display_name": "System Architecture",
  "description": "High-level system components and relationships",
  "nodes": [
    {
      "id": "node_1",
      "type": "Contract",
      "label": "TokenVault",
      "properties": {...},
      "observations": [...],
      "assumptions": [...]
    }
  ],
  "edges": [
    {
      "source": "node_1",
      "target": "node_2",
      "type": "calls",
      "properties": {...}
    }
  ],
  "metadata": {...}
}
```

### Build Graph

```http
POST /projects/{project_id}/graphs/build
```

**Request Body:**
```json
{
  "auto": true,
  "max_graphs": 5,
  "iterations": 3,
  "files": ["src/Token.sol", "src/Vault.sol"]
}
```

**Response:** `202 Accepted`

## Hypotheses API

### List Hypotheses

```http
GET /projects/{project_id}/hypotheses
```

**Query Parameters:**
- `status` (string, optional): Filter by status (proposed, investigating, confirmed, rejected)
- `severity` (string, optional): Filter by severity (critical, high, medium, low)
- `min_confidence` (float, optional): Minimum confidence score (0.0-1.0)

**Response:**
```json
{
  "items": [
    {
      "id": "hyp_abc123",
      "title": "Reentrancy vulnerability in withdraw function",
      "description": "The withdraw function does not follow checks-effects-interactions...",
      "severity": "high",
      "confidence": 0.85,
      "status": "confirmed",
      "type": "reentrancy",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T11:00:00Z",
      "evidence": [...],
      "annotations": [...]
    }
  ]
}
```

### Get Hypothesis

```http
GET /hypotheses/{hypothesis_id}
```

**Response:**
```json
{
  "id": "hyp_abc123",
  "title": "Reentrancy vulnerability in withdraw function",
  "description": "Detailed description...",
  "severity": "high",
  "confidence": 0.85,
  "status": "confirmed",
  "type": "reentrancy",
  "evidence": [
    {
      "type": "code",
      "file": "src/Vault.sol",
      "line": 45,
      "snippet": "...",
      "reasoning": "..."
    }
  ],
  "annotations": [...],
  "poc_files": [...]
}
```

### Update Hypothesis Status

```http
PATCH /hypotheses/{hypothesis_id}/status
```

**Request Body:**
```json
{
  "status": "confirmed"
}
```

**Response:** `200 OK`

## Scans API

### Create Scan

```http
POST /scans
```

**Request Body:**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "tenant_id": 1,
  "scan_type": "surface",
  "llm_budget": 10,
  "pr_number": 42,
  "installation_id": 12345678
}
```

**Response:** `202 Accepted`
```json
{
  "scan_id": "scan_abc123",
  "status": "queued",
  "message": "Scan queued successfully"
}
```

### Get Scan Status

```http
GET /scans/{scan_id}
```

**Response:**
```json
{
  "scan_id": "scan_abc123",
  "status": "running",
  "progress": 45,
  "started_at": "2024-01-15T10:30:00Z",
  "findings": [...]
}
```

## WebSocket API

### Real-time Audit Updates

```
WS /ws/audits/{session_id}
```

**Connection:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/audits/session_abc123');

ws.onmessage = (event) => {
  const update = JSON.parse(event.data);
  console.log('Update type:', update.type);
};
```

**Message Types:**

#### Status Update
```json
{
  "type": "status",
  "timestamp": "2024-01-15T10:30:00Z",
  "status": "running",
  "message": "Investigating access control patterns"
}
```

#### Planning Update
```json
{
  "type": "plan",
  "timestamp": "2024-01-15T10:30:00Z",
  "plan_items": [
    {
      "id": "plan_1",
      "title": "Investigate reentrancy patterns",
      "priority": "high",
      "status": "pending"
    }
  ]
}
```

#### Hypothesis Update
```json
{
  "type": "hypothesis",
  "timestamp": "2024-01-15T10:30:00Z",
  "hypothesis": {
    "id": "hyp_abc123",
    "title": "Potential reentrancy",
    "severity": "high",
    "confidence": 0.75
  }
}
```

#### Progress Update
```json
{
  "type": "progress",
  "timestamp": "2024-01-15T10:30:00Z",
  "coverage": {
    "nodes_visited": 45,
    "nodes_total": 120,
    "percentage": 37.5
  }
}
```

### Redis Pub/Sub (Worker Updates)

For Celery workers, updates are published via Redis:

```python
import redis

r = redis.Redis()
pubsub = r.pubsub()
pubsub.subscribe("audit:updates:scan_abc123")

for message in pubsub.listen():
    if message["type"] == "message":
        update = json.loads(message["data"])
        # Process update
```

## Admin API

All admin endpoints require authentication (see [Authentication](#authentication)).

### List All Projects (Admin)

```http
GET /admin/projects
```

Includes additional metadata not visible in public API.

### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "redis": "connected",
  "version": "2.0.0"
}
```

### Database Stats (Admin)

```http
GET /admin/stats
```

**Response:**
```json
{
  "total_projects": 50,
  "total_sessions": 250,
  "total_hypotheses": 1200,
  "active_scans": 3,
  "storage_usage_gb": 5.2
}
```

## Error Handling

All errors follow a consistent format:

**Structure:**
```json
{
  "detail": "Error message",
  "error_code": "PROJECT_NOT_FOUND",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Common Error Codes:**

| Code | Status | Description |
|------|--------|-------------|
| `PROJECT_NOT_FOUND` | 404 | Project does not exist |
| `SESSION_NOT_FOUND` | 404 | Audit session does not exist |
| `HYPOTHESIS_NOT_FOUND` | 404 | Hypothesis does not exist |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `VALIDATION_ERROR` | 422 | Invalid request body |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

**Example Error Response:**
```json
{
  "detail": "Project with name 'myaudit' not found",
  "error_code": "PROJECT_NOT_FOUND",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Rate Limiting

The API implements rate limiting on public endpoints:

- **Projects API**: 100 requests/minute
- **Sessions API**: 50 requests/minute
- **WebSocket**: 10 connections per IP

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705320600
```

## Pagination

All list endpoints support pagination:

**Parameters:**
- `page` (integer): Page number (starts at 1)
- `per_page` (integer): Items per page (default: 20, max: 100)

**Response includes pagination metadata:**
```json
{
  "items": [...],
  "total": 250,
  "page": 1,
  "per_page": 20,
  "pages": 13
}
```

## CORS

CORS is configured via `HOUND_ALLOWED_ORIGINS` environment variable:

```bash
export HOUND_ALLOWED_ORIGINS="http://localhost:3000,https://dashboard.example.com"
```

Default: `*` (all origins allowed in development)

## Examples

### Complete Audit Workflow via API

```bash
# 1. Create a project
PROJECT_ID=$(curl -X POST http://localhost:8000/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "myaudit", "source_path": "/path/to/repo"}' \
  | jq -r '.id')

# 2. Build graphs
curl -X POST http://localhost:8000/projects/$PROJECT_ID/graphs/build \
  -H "Content-Type: application/json" \
  -d '{"auto": true, "iterations": 3}'

# 3. Create audit session
SESSION_ID=$(curl -X POST http://localhost:8000/projects/$PROJECT_ID/sessions \
  -H "Content-Type: application/json" \
  -d '{"mode": "intuition", "time_limit": 1800}' \
  | jq -r '.id')

# 4. Monitor via WebSocket
wscat -c ws://localhost:8000/ws/audits/$SESSION_ID

# 5. Get findings
curl http://localhost:8000/projects/$PROJECT_ID/hypotheses?status=confirmed
```

### Submitting a Surface Scan

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{
    "repo_url": "https://github.com/owner/repo",
    "tenant_id": 1,
    "scan_type": "surface",
    "llm_budget": 10
  }'
```

## See Also

- [Server README](../server/README.md) - Deployment and configuration
- [Worker README](../worker/README.md) - Background task processing
- [SaaS Architecture](architecture/saas_architecture.md) - System design
