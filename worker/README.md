# Worker Module

Background task processing for Hound SaaS using Celery and Redis.

## Components

| File | Purpose |
|------|---------|
| `celery_app.py` | Celery application configuration |
| `tasks.py` | Task definitions (audit, scan) |
| `redis_publisher.py` | Real-time progress streaming |

## Quick Start

```bash
# 1. Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# 2. Set environment variables
export CELERY_BROKER_URL="redis://localhost:6379/0"
export DATABASE_URL="postgresql://user:password@localhost/hound"

# 3. Start worker
celery -A worker.celery_app worker --loglevel=info
```

## Tasks

### `execute_audit_task`

Full autonomous security audit with graph building and agent investigation.

```python
from worker.tasks import execute_audit_task

result = execute_audit_task.delay(
    repo_url="https://github.com/owner/repo",
    scan_id="scan_abc123",
    tenant_id=1,
    project_id=42,  # Optional
    max_iterations=50,
    investigation_prompt="Focus on access control",
    # GitHub integration (optional)
    installation_id=12345678,
    pr_number=42,
    repo_full_name="owner/repo",
)
```

### `execute_scan_task`

Lightweight surface scan for quick risk assessment.

```python
from worker.tasks import execute_scan_task

result = execute_scan_task.delay(
    repo_url="https://github.com/owner/repo",
    scan_id="scan_xyz789",
    tenant_id=1,
    llm_budget=5,  # Max LLM calls
    model="gpt-4o-mini",
)
```

## Real-Time Progress

Workers publish updates via Redis Pub/Sub for live "Agent Thinking" feeds.

### Channel Naming
- `audit:updates:{scan_id}` - Progress updates
- `audit:status:{scan_id}` - Status changes

### Message Types
- `thought` - Agent reasoning
- `decision` - Action decisions
- `action_start` - Action beginning
- `action_result` - Action completion
- `status` - Overall status
- `progress` - Progress percentage
- `error` - Error details

### Example Consumer

```python
import redis
import json

r = redis.Redis()
pubsub = r.pubsub()
pubsub.subscribe("audit:updates:scan_abc123")

for message in pubsub.listen():
    if message["type"] == "message":
        update = json.loads(message["data"])
        print(f"[{update['type']}] {update.get('message', '')}")
```

## Configuration

### Environment Variables

```bash
# Required
CELERY_BROKER_URL="redis://localhost:6379/0"
DATABASE_URL="postgresql://user:password@localhost/hound"

# Optional - GitHub App for private repos
GITHUB_APP_ID="123456"
GITHUB_APP_PRIVATE_KEY_PATH="/path/to/key.pem"

# Optional - Task limits
CELERY_TASK_TIME_LIMIT=3600  # 1 hour max per task
CELERY_TASK_SOFT_TIME_LIMIT=3300  # Soft limit for graceful shutdown
```

### Celery Settings

```python
# worker/celery_app.py
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_track_started=True,
    task_time_limit=3600,
    task_soft_time_limit=3300,
    worker_prefetch_multiplier=1,
)
```

## Production Deployment

### Docker Compose

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  worker:
    build: .
    command: celery -A worker.celery_app worker --loglevel=info --concurrency=4
    environment:
      - CELERY_BROKER_URL=redis://redis:6379/0
      - DATABASE_URL=postgresql://postgres:password@db/hound
    depends_on:
      - redis
      - db
```

### Scaling

```bash
# Multiple workers with different queues
celery -A worker.celery_app worker -Q audits --concurrency=2
celery -A worker.celery_app worker -Q scans --concurrency=4
```

## Error Handling

Tasks handle errors gracefully:
- Rate limits: Saves state for resumption
- Timeouts: Graceful shutdown with partial results
- Failures: Publishes error to Redis, updates DB status
