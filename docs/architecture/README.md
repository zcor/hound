# Firepan Architecture Documentation

This folder contains detailed technical documentation for Hound's architecture and implementation.

## Contents

### Core Architecture
- [Technical Overview](technical_overview.md) - Core concepts: knowledge graphs, hypothesis system, model switching

### SaaS Infrastructure
- [SaaS Architecture](saas_architecture.md) - **⭐ NEW** Server/Worker pattern, request flow, Docker deployment
- [Cloud Storage](cloud_storage.md) - S3/MinIO blob storage integration
- [Headless Agent](headless_agent.md) - Rate limiting, budget management, abort signals
- [Coverage Tracking](coverage_tracking.md) - Card-based coverage analysis (planned)

### Integrations
- [PR Reporter](pr_reporter.md) - GitHub PR comment integration (legacy)
- See also: `integrations/` module for current GitHub App integration

## Docker Quick Start

```bash
# From repository root
cp .env.example .env    # Configure environment
docker compose up -d    # Start all services
curl localhost:8000/health  # Verify API
```

See [SaaS Architecture](saas_architecture.md) for complete deployment guide.

## Quick Links

| Component | Location | Description |
|-----------|----------|-------------|
| **Dockerfile** | `Dockerfile` | Python 3.10-slim image |
| **Docker Compose** | `docker-compose.yml` | 4-service stack (db, redis, api, worker) |
| **Environment** | `.env.example` | Complete env var reference |
| **API Server** | `server/api.py` | FastAPI endpoints + webhook handler |
| **Worker Tasks** | `worker/tasks.py` | Celery background tasks |
| **Redis Pub/Sub** | `worker/redis_publisher.py` | Real-time progress streaming |
| Agent Core | `analysis/agent_core.py` | Autonomous investigation agent |
| Graph Builder | `analysis/graph_builder.py` | Knowledge graph construction |
| GitHub Auth | `integrations/github_auth.py` | GitHub App authentication |
| PR Bot | `integrations/pr_bot.py` | PR comment posting |
| Storage | `storage/blob_storage.py` | S3/Local storage backends |
| Database | `database/models.py` | SQLAlchemy models |
