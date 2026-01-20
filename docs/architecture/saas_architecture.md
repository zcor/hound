# Hound SaaS Architecture

This document describes how Hound transforms from a CLI tool into a production SaaS service.

## Overview

Hound's SaaS architecture follows a **Server/Worker** pattern where:

1. **Web Server** (FastAPI) - Handles HTTP requests, creates database records, dispatches tasks
2. **Worker Queue** (Celery) - Executes long-running audits in background processes
3. **Message Broker** (Redis) - Coordinates tasks and streams real-time progress

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Hound SaaS Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │
│   │   GitHub    │     │   Browser   │     │   API       │                  │
│   │   Webhook   │     │   Client    │     │   Client    │                  │
│   └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                  │
│          │                   │                   │                          │
│          └───────────────────┼───────────────────┘                          │
│                              ▼                                              │
│                    ┌─────────────────────┐                                  │
│                    │   FastAPI Server    │                                  │
│                    │   (server/api.py)   │                                  │
│                    └─────────┬───────────┘                                  │
│                              │                                              │
│          ┌───────────────────┼───────────────────┐                          │
│          ▼                   ▼                   ▼                          │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │
│   │ PostgreSQL  │     │    Redis    │     │  WebSocket  │                  │
│   │  Database   │     │   Broker    │◄────│  Pub/Sub    │                  │
│   └─────────────┘     └──────┬──────┘     └─────────────┘                  │
│                              │                   ▲                          │
│                              ▼                   │                          │
│                    ┌─────────────────────┐       │                          │
│                    │   Celery Workers    │───────┘                          │
│                    │  (worker/tasks.py)  │                                  │
│                    └─────────┬───────────┘                                  │
│                              │                                              │
│          ┌───────────────────┼───────────────────┐                          │
│          ▼                   ▼                   ▼                          │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                  │
│   │Agent Core  │     │ Graph Build │     │  PR Bot     │                  │
│   │ (Analysis)  │     │  (Ingest)   │     │ (GitHub)    │                  │
│   └─────────────┘     └─────────────┘     └─────────────┘                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Request Flow

### 1. GitHub Webhook → Automatic Audit

```
GitHub PR Opened
       │
       ▼
POST /webhooks/github
       │
       ├─► Verify X-Hub-Signature-256
       │
       ├─► Parse webhook payload
       │
       ├─► Create AuditSession (status="queued")
       │
       ├─► execute_audit_task.delay()  ◄── Returns immediately!
       │
       └─► Return {"status": "ok", "session_id": "..."}

       [Worker picks up task asynchronously]
              │
              ├─► Clone repo (with GitHub App token)
              │
              ├─► Build knowledge graphs
              │
              ├─► Run AutonomousAgent
              │   └─► Publish progress to Redis ─────► WebSocket ─► Browser
              │
              ├─► Store findings in database
              │
              └─► Post findings to PR via PR Bot
```

### 2. Manual Audit via API

```
POST /audits/start
{
  "repo_url": "https://github.com/owner/repo",
  "installation_id": 12345  // Optional for private repos
}
       │
       ├─► Create AuditSession (status="queued")
       │
       ├─► execute_audit_task.delay()
       │
       └─► Return {"session_id": "...", "websocket_url": "..."}

Client connects to WebSocket for live updates:
  ws://server/ws/sessions/{session_id}
```

## Key Components

### Web Server (`server/api.py`)

The FastAPI server handles:

| Endpoint | Purpose |
|----------|---------|
| `POST /audits/start` | Start a new audit (async) |
| `GET /audits/{id}/status` | Check audit progress |
| `POST /webhooks/github` | Receive GitHub events |
| `WS /ws/sessions/{id}` | Stream live progress |
| `GET /projects` | List projects |
| `GET /sessions/{id}/findings` | Get audit results |

### Worker Tasks (`worker/tasks.py`)

Celery tasks that run in background workers:

| Task | Purpose |
|------|---------|
| `execute_audit_task` | Full autonomous security audit |
| `execute_scan_task` | Quick surface scan |

Tasks use `RedisPublisher` to stream progress to WebSocket clients.

### Redis Publisher (`worker/redis_publisher.py`)

Publishes real-time updates to Redis Pub/Sub channels:

- `audit:updates:{scan_id}` - Progress updates
- `audit:status:{scan_id}` - Status changes

Message types:
- `thought` - Agent's current thinking
- `decision` - Action decision made
- `action_start` - Starting an action
- `action_result` - Action completed
- `hypothesis` - New hypothesis formed
- `status` - Status change (running, completed, failed)

### GitHub Integration

| Component | File | Purpose |
|-----------|------|---------|
| GitHub Auth | `integrations/github_auth.py` | Get installation tokens |
| PR Bot | `integrations/pr_bot.py` | Post findings as PR comments |
| Webhook Handler | `server/api.py` | Handle incoming webhooks |

## Database Schema

Key models in `database/models.py`:

```
Tenant (1) ──────────────── (*) Project
                                  │
                                  ├── (*) AuditSession
                                  │        └── status: queued→running→completed
                                  │
                                  ├── (*) Graph
                                  │
                                  └── (*) Hypothesis
                                           └── status: proposed→confirmed→rejected

ScanExecution (standalone scans not linked to projects)
```

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@host:5432/hound

# Redis
REDIS_URL=redis://localhost:6379/0

# GitHub App
GITHUB_APP_ID=123456
GITHUB_PRIVATE_KEY_PATH=/path/to/private-key.pem
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# CORS
HOUND_ALLOWED_ORIGINS=https://app.hound.dev,http://localhost:3000
```

## Deployment

### Docker Compose (Development)

Hound includes a complete `docker-compose.yml` in the repository root:

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your settings

# 2. Start the full stack
docker compose up -d

# 3. Verify all services are running
docker compose ps
# NAME           STATUS         PORTS
# hound-api      Up             0.0.0.0:8000->8000/tcp
# hound-db       Up (healthy)   0.0.0.0:5432->5432/tcp
# hound-redis    Up (healthy)   0.0.0.0:6379->6379/tcp
# hound-worker   Up             8000/tcp

# 4. Test the API
curl http://localhost:8000/health
# {"status":"healthy","timestamp":"..."}

# 5. View logs
docker compose logs -f worker
```

**Services defined in `docker-compose.yml`:**

| Service | Image | Purpose |
|---------|-------|--------|
| `db` | postgres:15 | Database with healthcheck |
| `redis` | redis:7 | Message broker + Pub/Sub |
| `api` | Dockerfile | FastAPI server (`uvicorn server.api:app`) |
| `worker` | Dockerfile | Celery worker (`-Q default,audits,scans`) |

**Environment variables** (see `.env.example` for complete list):

```bash
# Database
POSTGRES_USER=hound
POSTGRES_PASSWORD=change_me
DATABASE_URL=postgresql://hound:change_me@db:5432/hound

# Redis
REDIS_URL=redis://redis:6379/0

# LLM API Keys (at least one required)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
DEEPSEEK_API_KEY=...

# GitHub App (for PR bot)
GITHUB_APP_ID=123456
GITHUB_WEBHOOK_SECRET=...
GITHUB_APP_PRIVATE_KEY_PATH=/path/to/key.pem
```

### Production Considerations

1. **Scaling Workers**: Run multiple Celery workers for parallel audits
2. **Database**: Use managed PostgreSQL (RDS, Cloud SQL)
3. **Redis**: Use managed Redis (ElastiCache, Memorystore)
4. **Secrets**: Store GitHub private key in secrets manager
5. **Monitoring**: Add Prometheus metrics, Sentry error tracking
6. **Rate Limiting**: Implement per-tenant rate limits

## Security

1. **Webhook Verification**: All GitHub webhooks are verified using HMAC-SHA256
2. **Token Caching**: Installation tokens are cached and refreshed before expiry
3. **Database Isolation**: Multi-tenant data isolated by tenant_id
4. **API Authentication**: (TODO) Add JWT authentication for API endpoints
