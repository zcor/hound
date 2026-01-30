# Developer Guide

This guide covers development setup, architecture, and contribution guidelines for Hound.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Core Concepts](#core-concepts)
- [Adding New Features](#adding-new-features)
- [Testing](#testing)
- [Code Style](#code-style)
- [Contributing](#contributing)

## Development Setup

### Prerequisites

- Python 3.10 or higher
- PostgreSQL 15+ (for SaaS mode)
- Redis 7+ (for workers)
- Node.js 18+ (for frontend)

### Local Development

1. **Clone the repository:**
   ```bash
   git clone https://github.com/firepan-labs/hound.git
   cd hound
   ```

2. **Set up Python environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Install development dependencies:**
   ```bash
   pip install pytest pytest-asyncio pytest-cov black mypy ruff
   ```

4. **Configure environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and settings
   ```

5. **Set up the database (for SaaS mode):**
   ```bash
   # Start PostgreSQL
   docker run -d -p 5432:5432 \
     -e POSTGRES_USER=hound \
     -e POSTGRES_PASSWORD=hound_secret \
     -e POSTGRES_DB=hound \
     postgres:15

   # Run migrations
   python database/migrate.py
   ```

6. **Start Redis (for workers):**
   ```bash
   docker run -d -p 6379:6379 redis:7-alpine
   ```

### Running in Development

#### CLI Mode

```bash
# Create a test project
./hound.py project create testaudit /path/to/test/code

# Build graphs
./hound.py graph build testaudit --auto --iterations 2

# Run audit
./hound.py agent audit testaudit --mode sweep --time-limit 10
```

#### SaaS Mode

```bash
# Terminal 1: Start API server
python server/start.py

# Terminal 2: Start Celery worker
celery -A worker.celery_app worker --loglevel=info

# Terminal 3: Start frontend
cd frontend
npm install
npm run dev
```

### Docker Development

```bash
# Start full stack
docker compose up -d

# View logs
docker compose logs -f

# Restart a service
docker compose restart hound-api

# Run commands in container
docker compose exec hound-api ./hound.py project ls
```

## Project Structure

```
hound/
├── analysis/              # Core analysis engine
│   ├── agent_core.py     # Main agent orchestrator
│   ├── strategist.py     # Strategic planning agent
│   ├── scout.py          # Exploration agent
│   ├── graph_builder.py  # Knowledge graph builder
│   ├── report_generator.py  # Report generation
│   └── surface/          # Surface scan modules
│
├── commands/             # CLI command implementations
│   ├── agent.py         # Agent commands
│   ├── graph.py         # Graph commands
│   ├── project.py       # Project management
│   ├── finalize.py      # QA finalization
│   └── report.py        # Report generation
│
├── database/            # Database models and migrations
│   ├── models.py       # SQLAlchemy models
│   └── migrations/     # Database migrations
│
├── llm/                # LLM provider integrations
│   ├── unified_client.py  # Unified LLM interface
│   ├── openai_provider.py
│   ├── anthropic_provider.py
│   ├── gemini_provider.py
│   ├── deepseek_provider.py
│   └── xai_provider.py
│
├── server/             # FastAPI server
│   ├── api.py         # API endpoints
│   └── start.py       # Server startup
│
├── worker/            # Celery background workers
│   ├── celery_app.py # Celery configuration
│   ├── tasks.py      # Task definitions
│   └── redis_publisher.py  # Progress streaming
│
├── integrations/      # External integrations
│   ├── github_app.py # GitHub App
│   ├── github_auth.py  # GitHub authentication
│   └── pr_bot.py     # PR comment bot
│
├── storage/           # Storage backends
│   └── blob_storage.py  # S3/MinIO storage
│
├── frontend/          # React/Next.js dashboard
│   ├── app/          # Next.js pages
│   ├── components/   # React components
│   └── lib/          # Utilities
│
├── chatbot/          # Interactive chatbot UI
│   └── run.py       # Chatbot server
│
├── visualization/    # Graph visualization
│   └── dynamic_graph_viz.py
│
└── docs/             # Documentation
    ├── architecture/ # Technical deep-dives
    └── examples/     # Usage examples
```

## Core Concepts

### 1. Projects

Projects are the top-level organizational unit. Each project represents a codebase to audit.

**Storage:**
- CLI: `~/.hound/projects/{project_name}/`
- SaaS: PostgreSQL `projects` table

**Key files:**
- `project.json` - Project metadata
- `card_store.json` - Code snippets with context
- `hypothesis_store.json` - Security findings
- `graphs/*.json` - Knowledge graphs

### 2. Knowledge Graphs

Dynamic, agent-constructed graphs that model the codebase.

**Common graph types:**
- `SystemArchitecture` - High-level components
- `StateMutationGraph` - State changes
- `InterContractCallGraph` - Function calls
- `AuthorizationRolesMap` - Access control

**Structure:**
```python
{
  "nodes": [
    {
      "id": "node_1",
      "type": "Contract",
      "label": "TokenVault",
      "observations": [...],
      "assumptions": [...]
    }
  ],
  "edges": [
    {
      "source": "node_1",
      "target": "node_2",
      "type": "calls"
    }
  ]
}
```

### 3. Agents

Hound uses a multi-agent architecture with role specialization:

**Scout (Exploration):**
- Lightweight model (e.g., GPT-4o-mini)
- Explores code and graphs
- Collects observations
- Fast and cost-effective

**Strategist (Planning):**
- Advanced model (e.g., GPT-5, Claude Opus)
- Strategic planning
- Hypothesis formation
- Deep reasoning

**Graph Builder:**
- Constructs knowledge graphs
- Iteratively refines structure
- Links code to graph nodes

### 4. Hypotheses

Security findings tracked through their lifecycle:

**Status flow:**
```
proposed → investigating → confirmed/rejected
```

**Properties:**
- `confidence` (0.0-1.0) - Likelihood of being real
- `severity` - critical, high, medium, low
- `type` - reentrancy, access_control, logic_error, etc.
- `evidence` - Code snippets and reasoning
- `annotations` - Specific locations

### 5. Sessions

Audit runs with comprehensive tracking:

**Data tracked:**
- Coverage (nodes/cards visited)
- Token usage by model
- Investigation history
- Planning decisions
- Hypotheses formed

**Session modes:**
- `sweep` - Broad component analysis
- `intuition` - Targeted deep investigation

## Adding New Features

### Adding a New LLM Provider

1. **Create provider class:**
   ```python
   # llm/newprovider_provider.py
   from llm.base_provider import BaseProvider
   
   class NewProviderProvider(BaseProvider):
       def __init__(self, api_key: str, base_url: str = None):
           self.api_key = api_key
           self.base_url = base_url or "https://api.newprovider.com"
       
       async def complete(self, messages, model, **kwargs):
           # Implement completion logic
           pass
   ```

2. **Register in unified client:**
   ```python
   # llm/unified_client.py
   from llm.newprovider_provider import NewProviderProvider
   
   # Add to PROVIDER_MAP
   PROVIDER_MAP = {
       ...
       "newprovider": NewProviderProvider,
   }
   ```

3. **Add configuration:**
   ```yaml
   # config.yaml.example
   newprovider:
     api_key_env: NEWPROVIDER_API_KEY
     base_url_env: NEWPROVIDER_BASE_URL
     models:
       default: newprovider-chat-v1
   ```

4. **Add tests:**
   ```python
   # tests/test_newprovider_provider.py
   def test_newprovider_completion():
       provider = NewProviderProvider(api_key="test")
       # Test implementation
   ```

### Adding a New CLI Command

1. **Create command function:**
   ```python
   # commands/mycommand.py
   import typer
   
   def my_command(
       project_name: str,
       option: str = typer.Option("default", help="An option")
   ):
       """Description of what this command does."""
       # Implementation
   ```

2. **Register in main CLI:**
   ```python
   # hound.py
   from commands.mycommand import my_command
   
   @app.command(name="mycommand")
   def mycommand_cli(...):
       my_command(...)
   ```

### Adding a New API Endpoint

1. **Define endpoint:**
   ```python
   # server/api.py
   @app.get("/my-endpoint/{param}")
   async def my_endpoint(param: str, db: Session = Depends(get_db)):
       """Endpoint description."""
       # Implementation
       return {"result": "data"}
   ```

2. **Add to admin endpoints (if protected):**
   ```python
   @app.get("/admin/my-endpoint")
   async def my_admin_endpoint(
       db: Session = Depends(get_db),
       admin_valid: bool = Depends(verify_admin)
   ):
       if not admin_valid:
           raise HTTPException(status_code=401)
       # Implementation
   ```

3. **Add tests:**
   ```python
   # tests/test_api.py
   def test_my_endpoint(client):
       response = client.get("/my-endpoint/test")
       assert response.status_code == 200
   ```

### Adding a New Celery Task

1. **Define task:**
   ```python
   # worker/tasks.py
   from worker.celery_app import celery
   
   @celery.task(name="my_task")
   def my_task(param: str):
       """Task description."""
       # Implementation
       return {"result": "success"}
   ```

2. **Use Redis for progress:**
   ```python
   from worker.redis_publisher import RedisPublisher
   
   @celery.task(name="my_task")
   def my_task(task_id: str):
       publisher = RedisPublisher(task_id)
       publisher.publish_status("Starting task...")
       # Do work
       publisher.publish_status("Task complete")
   ```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_agent_core.py

# Run specific test
pytest tests/test_agent_core.py::test_hypothesis_formation

# Run with markers
pytest -m "not slow"
pytest -m integration
```

### Writing Tests

**Unit test example:**
```python
# tests/test_hypothesis_dedup.py
import pytest
from analysis.hypothesis_dedup import deduplicate_hypotheses

def test_dedup_identical():
    h1 = {"title": "Bug A", "confidence": 0.8}
    h2 = {"title": "Bug A", "confidence": 0.9}
    result = deduplicate_hypotheses([h1, h2])
    assert len(result) == 1
    assert result[0]["confidence"] == 0.9
```

**Integration test example:**
```python
# tests/test_api.py
import pytest
from fastapi.testclient import TestClient
from server.api import app

@pytest.fixture
def client():
    return TestClient(app)

def test_create_project(client):
    response = client.post("/projects", json={
        "name": "test",
        "source_path": "/tmp/test"
    })
    assert response.status_code == 201
    assert response.json()["name"] == "test"
```

**Mock provider for tests:**
```python
from llm.mock_provider import MockProvider

async def test_with_mock_llm():
    provider = MockProvider(responses=["Mocked response"])
    result = await provider.complete(messages=[...])
    assert result == "Mocked response"
```

### Test Structure

```
tests/
├── fixtures/           # Test data
│   ├── sample_code/   # Example codebases
│   └── configs/       # Test configurations
├── test_agent_core.py
├── test_graph_builder.py
├── test_api.py
└── test_integration.py
```

## Code Style

### Python Style Guide

**Formatter:** Black (line length: 100)
```bash
black . --line-length 100
```

**Linter:** Ruff
```bash
ruff check .
ruff check --fix .
```

**Type checking:** MyPy
```bash
mypy llm/ analysis/ commands/
```

### Conventions

**Naming:**
- Functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

**Imports:**
```python
# Standard library
import os
from pathlib import Path

# Third-party
import typer
from rich.console import Console

# Local
from llm.unified_client import LLMClient
from analysis.agent_core import AgentCore
```

**Docstrings:**
```python
def build_graph(project_name: str, iterations: int = 3) -> dict:
    """Build knowledge graph for a project.
    
    Args:
        project_name: Name of the project
        iterations: Number of refinement iterations
        
    Returns:
        Graph data with nodes and edges
        
    Raises:
        ProjectNotFoundError: If project doesn't exist
    """
    pass
```

### Frontend Style (TypeScript/React)

**Formatter:** Prettier
```bash
cd frontend
npm run format
```

**Linter:** ESLint
```bash
npm run lint
```

## Contributing

### Workflow

1. **Fork and clone:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/hound.git
   cd hound
   git remote add upstream https://github.com/firepan-labs/hound.git
   ```

2. **Create a feature branch:**
   ```bash
   git checkout -b feature/my-feature
   ```

3. **Make changes:**
   - Write code
   - Add tests
   - Update documentation

4. **Run quality checks:**
   ```bash
   # Format code
   black . --line-length 100
   
   # Lint
   ruff check .
   
   # Type check
   mypy llm/ analysis/
   
   # Run tests
   pytest
   ```

5. **Commit:**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   ```

   **Commit message format:**
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation
   - `test:` - Tests
   - `refactor:` - Code refactoring
   - `perf:` - Performance improvement
   - `chore:` - Maintenance

6. **Push and create PR:**
   ```bash
   git push origin feature/my-feature
   ```

### Pull Request Guidelines

**PR should include:**
- Clear description of changes
- Tests for new functionality
- Updated documentation
- Screenshots for UI changes

**PR checklist:**
- [ ] Tests pass (`pytest`)
- [ ] Code is formatted (`black`)
- [ ] No linting errors (`ruff`)
- [ ] Type hints are correct (`mypy`)
- [ ] Documentation is updated
- [ ] Commit messages follow convention

### Code Review Process

1. Automated checks run (tests, linting)
2. Maintainer reviews code
3. Address feedback
4. Approval and merge

## Debugging

### Debug Mode

Enable debug logging for LLM interactions:
```bash
./hound.py agent audit myaudit --debug
```

Debug files saved to `.hound_debug/`:
- HTML reports with prompts/responses
- Token usage statistics
- Error traces

### Logging

Configure logging level:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

View logs in Docker:
```bash
docker compose logs -f hound-api
docker compose logs -f hound-worker
```

### Common Issues

**Issue: Module not found**
```bash
# Ensure you're in the project root
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**Issue: Database connection failed**
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Verify DATABASE_URL
echo $DATABASE_URL
```

**Issue: Redis connection failed**
```bash
# Check Redis is running
docker ps | grep redis

# Test connection
redis-cli ping
```

## Performance Optimization

### Token Usage

Monitor token consumption:
```python
from llm.token_tracker import TokenTracker

tracker = TokenTracker()
tracker.track_usage("gpt-4o", prompt_tokens=1000, completion_tokens=500)
print(tracker.get_summary())
```

### Caching

Use caching for repeated queries:
```python
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_operation(param):
    # Expensive computation
    pass
```

### Database Optimization

Add indexes for common queries:
```python
# database/models.py
class Project(Base):
    __tablename__ = "projects"
    
    name = Column(String, index=True)  # Add index
    created_at = Column(DateTime, index=True)
```

## Resources

- [Architecture Overview](architecture/README.md)
- [API Reference](API_REFERENCE.md)
- [SaaS Architecture](architecture/saas_architecture.md)
- [GitHub Repository](https://github.com/firepan-labs/hound)

## Getting Help

- **GitHub Issues:** Report bugs or request features
- **Discussions:** Ask questions in GitHub Discussions
- **Discord:** Join the community (link in README)

## License

Apache 2.0 - See [LICENSE.txt](../LICENSE.txt) for details.
