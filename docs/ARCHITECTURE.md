# Architecture Deep Dive

This document provides a comprehensive technical overview of Firepan's architecture, design decisions, and implementation details.

## Table of Contents

- [System Overview](#system-overview)
- [Deployment Modes](#deployment-modes)
- [Data Flow](#data-flow)
- [Agent Architecture](#agent-architecture)
- [Knowledge Graph System](#knowledge-graph-system)
- [LLM Integration](#llm-integration)
- [Storage Architecture](#storage-architecture)
- [Security Considerations](#security-considerations)
- [Scalability](#scalability)
- [Design Decisions](#design-decisions)

## System Overview

Firepan is a security analysis platform that combines LLM-powered agents with knowledge graph reasoning to find vulnerabilities in code.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FIREPAN PLATFORM                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────┐         ┌──────────────────────┐         │
│  │   CLI Interface     │         │   Web Dashboard      │         │
│  │   (hound.py)        │         │   (Next.js/React)    │         │
│  └──────────┬──────────┘         └──────────┬───────────┘         │
│             │                               │                      │
│             ▼                               ▼                      │
│  ┌─────────────────────────────────────────────────────┐          │
│  │              Core Analysis Engine                   │          │
│  │  ┌──────────┐  ┌────────────┐  ┌────────────────┐ │          │
│  │  │ Scout    │  │ Strategist │  │ Graph Builder  │ │          │
│  │  │ Agent    │  │ Agent      │  │                │ │          │
│  │  └──────────┘  └────────────┘  └────────────────┘ │          │
│  └─────────────────────────────────────────────────────┘          │
│             │                                                      │
│             ▼                                                      │
│  ┌─────────────────────────────────────────────────────┐          │
│  │           Knowledge Management Layer                │          │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐ │          │
│  │  │   Graphs     │  │  Hypotheses  │  │ Coverage │ │          │
│  │  │   Storage    │  │   Storage    │  │  Tracker │ │          │
│  │  └──────────────┘  └──────────────┘  └──────────┘ │          │
│  └─────────────────────────────────────────────────────┘          │
│             │                                                      │
│             ▼                                                      │
│  ┌─────────────────────────────────────────────────────┐          │
│  │              External Services                      │          │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────────────┐  │          │
│  │  │   LLM    │  │ Database │  │  Cloud Storage  │  │          │
│  │  │ Providers│  │(Postgres)│  │   (S3/MinIO)    │  │          │
│  │  └──────────┘  └──────────┘  └─────────────────┘  │          │
│  └─────────────────────────────────────────────────────┘          │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Analysis Engine** (`analysis/`)
   - Agent orchestration
   - Graph construction
   - Hypothesis management
   - Coverage tracking

2. **LLM Integration** (`llm/`)
   - Unified provider interface
   - Token tracking
   - Cost optimization
   - Rate limiting

3. **Storage Layer**
   - Local filesystem (CLI mode)
   - PostgreSQL (SaaS mode)
   - S3/MinIO (artifacts)

4. **API Server** (`server/`)
   - REST endpoints
   - WebSocket streaming
   - Authentication
   - CORS handling

5. **Worker System** (`worker/`)
   - Celery task queue
   - Background processing
   - Progress streaming
   - GitHub integration

## Deployment Modes

### 1. CLI Mode (Local Development)

**Use case:** Individual developers, local audits

**Architecture:**
```
┌──────────────────┐
│   User Terminal  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────┐
│    hound.py (CLI)        │
│  ┌────────────────────┐  │
│  │  Analysis Engine   │  │
│  └────────────────────┘  │
└────────┬─────────────────┘
         │
         ├─────────────────────┐
         │                     │
         ▼                     ▼
┌──────────────┐      ┌──────────────┐
│  Filesystem  │      │  LLM APIs    │
│  ~/.hound/   │      │  (OpenAI,    │
│              │      │   etc.)      │
└──────────────┘      └──────────────┘
```

**Characteristics:**
- No database required
- Local JSON file storage
- Direct LLM API calls
- Single-user operation
- No authentication needed

**Data location:** `~/.hound/projects/{project_name}/`

### 2. SaaS Mode (Production)

**Use case:** Multi-tenant web service, CI/CD integration

**Architecture:**
```
┌──────────────────┐     ┌──────────────────┐
│   Web Dashboard  │     │   API Clients    │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         └────────┬───────────────┘
                  │
                  ▼
         ┌────────────────┐
         │  Load Balancer │
         └────────┬────────┘
                  │
         ┌────────┴────────┐
         │                 │
         ▼                 ▼
┌──────────────┐  ┌──────────────┐
│ API Server   │  │ API Server   │
│ (FastAPI)    │  │ (FastAPI)    │
└──────┬───────┘  └──────┬───────┘
       │                 │
       └────────┬────────┘
                │
       ┌────────┴─────────┬─────────────┐
       │                  │             │
       ▼                  ▼             ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Celery Worker│  │  PostgreSQL  │  │    Redis     │
│              │  │   Database   │  │ (Queue/Cache)│
└──────┬───────┘  └──────────────┘  └──────────────┘
       │
       └─────────┐
                 │
                 ▼
         ┌──────────────┐
         │   S3/MinIO   │
         │   Storage    │
         └──────────────┘
```

**Characteristics:**
- Multi-tenant with tenant isolation
- PostgreSQL for persistent storage
- Redis for task queue and pub/sub
- Celery workers for background tasks
- S3 for artifact storage
- API authentication
- Horizontal scaling

### 3. Docker Compose (Local SaaS)

**Use case:** Local SaaS development, testing

Runs full SaaS stack locally:
- API server
- Celery worker
- PostgreSQL
- Redis

See `docker-compose.yml` for configuration.

## Data Flow

### Audit Flow

```
1. User initiates audit
         │
         ▼
2. Project created/loaded
         │
         ▼
3. Code ingested → Cards created
         │
         ▼
4. Graph Builder constructs knowledge graphs
         │    ┌─────────────────────┐
         │    │ Iterative refinement│
         │    │ - Add nodes/edges   │
         │    │ - Add observations  │
         │    │ - Link to code      │
         │    └─────────────────────┘
         ▼
5. Audit Session started
         │
         ├──────────────────────────┐
         │                          │
         ▼                          │
6. Strategist creates plan          │
    - Review graphs                 │
    - Check coverage                │
    - Prioritize investigations     │
         │                          │
         ▼                          │
7. Scout executes investigations    │
    - Load relevant code            │
    - Explore paths                 │
    - Form hypotheses               │
         │                          │
         ▼                          │
8. Update knowledge base            │
    - Add/update hypotheses         │
    - Track coverage                │
    - Update graphs                 │
         │                          │
         └──────────────────────────┘
         │
         ▼
9. Finalization (QA review)
         │
         ▼
10. Report generation
```

### Graph Building Flow

```
1. Discover graph types
   (Agent proposes useful graphs)
         │
         ▼
2. Initialize graph
   (Create SystemArchitecture first)
         │
         ▼
3. Iterative refinement (N iterations)
   │
   ├─► 3.1 Load current graph + code cards
   │      │
   │      ▼
   │   3.2 Agent analyzes
   │      │
   │      ▼
   │   3.3 Propose updates
   │      - New nodes
   │      - New edges
   │      - Updated observations
   │      - Confidence adjustments
   │      │
   │      ▼
   │   3.4 Apply updates & save
   │      │
   └──────┘
         │
         ▼
4. Final graph with annotations
```

### WebSocket Update Flow

```
┌──────────────┐
│ Agent Core   │
└──────┬───────┘
       │
       │ emit_status()
       │ emit_hypothesis()
       │ emit_progress()
       │
       ▼
┌──────────────┐
│  Telemetry   │
│  Registry    │
└──────┬───────┘
       │
       │ SSE/HTTP
       │
       ▼
┌──────────────┐       WebSocket       ┌──────────────┐
│   Chatbot    │◄──────────────────────│  Dashboard   │
│   Server     │                       │   Client     │
└──────────────┘                       └──────────────┘

OR (for SaaS)

┌──────────────┐
│ Worker Task  │
└──────┬───────┘
       │
       │ publish()
       │
       ▼
┌──────────────┐
│ Redis Pub/Sub│
└──────┬───────┘
       │
       │ subscribe
       │
       ▼
┌──────────────┐       WebSocket       ┌──────────────┐
│ API Server   │◄──────────────────────│  Dashboard   │
│              │                       │   Client     │
└──────────────┘                       └──────────────┘
```

## Agent Architecture

### Agent Roles

Firepan uses a **multi-agent architecture** with specialized roles:

```
┌─────────────────────────────────────────────────────┐
│                 Agent Orchestrator                  │
│              (agent_core.py)                        │
└───────────────────┬─────────────────────────────────┘
                    │
        ┌───────────┴─────────────┬──────────────┐
        │                         │              │
        ▼                         ▼              ▼
┌───────────────┐      ┌──────────────────┐  ┌──────────────┐
│  Scout Agent  │      │ Strategist Agent │  │ Graph Builder│
│               │      │                  │  │              │
│ - Lightweight │      │ - Heavy model    │  │ - Constructs │
│ - Exploration │      │ - Planning       │  │   graphs     │
│ - Fast        │      │ - Deep reasoning │  │ - Iterative  │
│ - Low cost    │      │ - Hypothesis     │  │              │
│               │      │   formation      │  │              │
└───────────────┘      └──────────────────┘  └──────────────┘
  GPT-4o-mini           GPT-5/Claude Opus     GPT-4o
```

### Scout Agent

**Purpose:** Fast, cost-effective exploration

**Model:** Lightweight (GPT-4o-mini, Claude Haiku, DeepSeek)

**Responsibilities:**
- Load and analyze code cards
- Navigate knowledge graphs
- Collect observations
- Execute investigations
- Note potential issues

**Design rationale:**
- Handles bulk of token consumption
- Can run many iterations cheaply
- Good enough for most exploration tasks
- Calls Strategist when deep reasoning needed

### Strategist Agent

**Purpose:** Strategic planning and deep reasoning

**Model:** Advanced (GPT-5, Claude Opus, Gemini Pro)

**Responsibilities:**
- Analyze overall audit state
- Create investigation plans
- Form security hypotheses
- Evaluate evidence
- Make strategic decisions

**Design rationale:**
- Used sparingly to control costs
- Provides expert-level reasoning
- Makes high-level decisions
- Quality over quantity

### Collaboration Pattern

```python
# Pseudo-code for agent collaboration

async def audit_loop():
    while not done:
        # 1. Strategist plans (expensive, infrequent)
        plan = await strategist.create_plan(
            graphs=load_graphs(),
            coverage=get_coverage(),
            hypotheses=get_hypotheses()
        )
        
        # 2. Scout executes (cheap, frequent)
        for investigation in plan:
            findings = await scout.investigate(
                concern=investigation.concern,
                context=build_context()
            )
            
            # 3. Update shared knowledge
            hypothesis_store.add(findings)
            coverage.mark_visited(investigation.nodes)
        
        # 4. Periodically, Strategist reviews
        if iteration % 5 == 0:
            await strategist.review_hypotheses()
```

### Parallelization

Agents can run in parallel for faster audits:

```python
# Multiple Scout agents exploring different areas
async def parallel_audit():
    tasks = []
    for investigation in plan:
        task = asyncio.create_task(
            scout.investigate(investigation)
        )
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
```

**Synchronization:**
- Concurrent graph store with file locking
- Hypothesis deduplication on merge
- Coverage tracking uses sets

## Knowledge Graph System

### Graph Structure

```python
{
  "name": "SystemArchitecture",
  "nodes": [
    {
      "id": "node_1",
      "type": "Contract",
      "label": "TokenVault",
      "properties": {
        "file": "src/TokenVault.sol",
        "line": 10
      },
      "observations": [
        {
          "text": "Manages user token deposits",
          "confidence": 0.9,
          "iteration": 1
        }
      ],
      "assumptions": [
        {
          "text": "Withdrawal requires authentication",
          "confidence": 0.8,
          "iteration": 1
        }
      ]
    }
  ],
  "edges": [
    {
      "source": "node_1",
      "target": "node_2",
      "type": "calls",
      "properties": {
        "function": "transfer",
        "frequency": "high"
      }
    }
  ],
  "metadata": {
    "created_at": "2024-01-15T10:30:00Z",
    "iterations": 3,
    "focus": "Core architecture"
  }
}
```

### Graph Types

**SystemArchitecture:**
- High-level components
- System boundaries
- Major relationships
- Entry points

**StateMutationGraph:**
- State variables
- Mutation operations
- State transitions
- Invariants

**InterContractCallGraph:**
- Function calls
- Control flow
- Call chains
- Reentrancy paths

**AuthorizationRolesMap:**
- Access control
- Permission checks
- Role hierarchies
- Privilege escalation paths

**ValueFlowGraph:**
- Asset movements
- Balance changes
- Value transfers
- Monetary flows

### Graph Building Algorithm

```python
async def build_graph(name, iterations):
    # 1. Initialize empty graph
    graph = {"nodes": [], "edges": []}
    
    # 2. Iterative refinement
    for i in range(iterations):
        # Load context
        cards = load_relevant_cards()
        
        # Agent analyzes
        updates = await graph_builder.analyze(
            graph=graph,
            cards=cards,
            focus=name
        )
        
        # Apply updates
        for update in updates.nodes:
            if update.id not in graph.node_ids:
                graph.nodes.append(update)
            else:
                merge_node(graph, update)
        
        for update in updates.edges:
            if not edge_exists(graph, update):
                graph.edges.append(update)
        
        # Save checkpoint
        save_graph(graph, iteration=i)
    
    return graph
```

### Graph Querying

```python
def get_reachable_nodes(graph, start_id, max_depth=3):
    """BFS traversal to find reachable nodes."""
    visited = set()
    queue = [(start_id, 0)]
    
    while queue:
        node_id, depth = queue.pop(0)
        if depth > max_depth or node_id in visited:
            continue
        
        visited.add(node_id)
        
        # Get neighbors
        for edge in graph.edges:
            if edge.source == node_id:
                queue.append((edge.target, depth + 1))
    
    return [n for n in graph.nodes if n.id in visited]

def find_paths(graph, start, end, max_length=5):
    """Find all paths between two nodes."""
    # DFS with path tracking
    paths = []
    
    def dfs(current, path):
        if current == end:
            paths.append(path[:])
            return
        if len(path) > max_length:
            return
        
        for edge in graph.edges:
            if edge.source == current and edge.target not in path:
                path.append(edge.target)
                dfs(edge.target, path)
                path.pop()
    
    dfs(start, [start])
    return paths
```

## LLM Integration

### Provider Architecture

```
┌─────────────────────────────────────────────────┐
│           LLMClient (unified_client.py)         │
│  - Model routing                                │
│  - Automatic retries                            │
│  - Token tracking                               │
│  - Cost calculation                             │
└────────────────────┬────────────────────────────┘
                     │
         ┌───────────┴──────────┬─────────────────┐
         │                      │                 │
         ▼                      ▼                 ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐
│ OpenAI Provider  │  │Anthropic Provider│  │Gemini Provider│
│                  │  │                  │  │              │
│ - GPT-4o        │  │ - Claude 3       │  │ - Gemini Pro │
│ - GPT-4o-mini   │  │ - Claude Haiku   │  │              │
│ - Function calls│  │ - Tool use       │  │ - Vertex AI  │
└──────────────────┘  └──────────────────┘  └──────────────┘
```

### Model Selection Strategy

**For exploration (Scout):**
- Cheap, fast models
- High volume of calls
- Examples: GPT-4o-mini, Claude Haiku, DeepSeek

**For reasoning (Strategist):**
- Advanced models
- Low volume of calls
- Examples: GPT-5, Claude Opus, Gemini Pro

**For graph building:**
- Medium-tier models
- Balanced cost/quality
- Examples: GPT-4o, Claude Sonnet

### Token Optimization

```python
class TokenTracker:
    def __init__(self):
        self.usage = defaultdict(lambda: {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cached_tokens": 0,
            "total_cost": 0.0
        })
    
    def track_usage(self, model, prompt_tokens, completion_tokens):
        """Track token usage and calculate cost."""
        pricing = self.get_pricing(model)
        
        cost = (
            (prompt_tokens * pricing["input"] / 1_000_000) +
            (completion_tokens * pricing["output"] / 1_000_000)
        )
        
        self.usage[model]["prompt_tokens"] += prompt_tokens
        self.usage[model]["completion_tokens"] += completion_tokens
        self.usage[model]["total_cost"] += cost
```

### Caching Strategy

**Prompt caching:**
- Gemini: Automatic context caching
- Anthropic: Claude supports prompt caching
- OpenAI: No native caching (use application-level)

**Application-level caching:**
```python
@lru_cache(maxsize=1000)
def get_code_card(file_path: str, line_range: tuple):
    """Cache frequently accessed code snippets."""
    return load_file(file_path)[line_range[0]:line_range[1]]
```

### Rate Limiting

```python
class RateLimiter:
    def __init__(self, requests_per_minute=50):
        self.rpm = requests_per_minute
        self.tokens = []
    
    async def acquire(self):
        """Wait if rate limit exceeded."""
        now = time.time()
        
        # Remove tokens older than 1 minute
        self.tokens = [t for t in self.tokens if now - t < 60]
        
        # Wait if at limit
        if len(self.tokens) >= self.rpm:
            wait_time = 60 - (now - self.tokens[0])
            await asyncio.sleep(wait_time)
        
        self.tokens.append(time.time())
```

## Storage Architecture

### CLI Mode Storage

**Location:** `~/.hound/projects/{project_name}/`

```
~/.hound/
└── projects/
    └── myaudit/
        ├── project.json            # Project metadata
        ├── card_store.json         # Code cards
        ├── hypothesis_store.json   # Findings
        ├── graphs/
        │   ├── SystemArchitecture.json
        │   ├── StateMutationGraph.json
        │   └── ...
        ├── sessions/
        │   └── session_abc123/
        │       ├── session.json
        │       ├── coverage.json
        │       └── plan_store.json
        └── poc/
            └── hyp_123/
                ├── exploit.sol
                └── test.js
```

**Concurrency:** File locking via `portalocker`

### SaaS Mode Storage

**PostgreSQL schema:**
- `projects` - Project metadata
- `audit_sessions` - Session tracking
- `hypotheses` - Security findings
- `graphs` - Knowledge graphs (JSON column)
- `tenants` - Multi-tenant isolation

**S3/MinIO for artifacts:**
- Reports (HTML)
- PoC files
- Debug logs
- Visualizations

**Redis:**
- Task queue (Celery)
- Pub/Sub (real-time updates)
- Session cache

### Data Isolation

**Multi-tenancy:**
```python
class Project(Base):
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, nullable=False, index=True)
    name = Column(String)
    
    # All queries filtered by tenant_id
```

**Row-level security (PostgreSQL):**
```sql
CREATE POLICY tenant_isolation ON projects
    USING (tenant_id = current_setting('app.current_tenant')::int);
```

## Security Considerations

### Authentication

**Admin endpoints:**
- `X-Admin-Key` header
- Session cookies (after login)
- Per-request validation

**GitHub App:**
- JWT tokens for app authentication
- Installation tokens for repo access
- Webhook signature verification

### Input Validation

```python
from pydantic import BaseModel, validator

class ProjectCreate(BaseModel):
    name: str
    source_path: str
    
    @validator('name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Invalid project name')
        return v
    
    @validator('source_path')
    def validate_path(cls, v):
        # Prevent path traversal
        if '..' in v or v.startswith('/'):
            raise ValueError('Invalid path')
        return v
```

### Secrets Management

**Environment variables:**
- API keys in `.env` file
- Never committed to repository
- Separate per environment

**GitHub App private key:**
- Stored as file or env var
- Encrypted at rest
- Limited permissions

### Rate Limiting

**API endpoints:**
```python
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.get("/projects")
@limiter.limit("100/minute")
async def list_projects():
    ...
```

## Scalability

### Horizontal Scaling

**API servers:**
- Stateless design
- Load balancer distribution
- Session in Redis/PostgreSQL

**Celery workers:**
- Multiple workers
- Task-based parallelism
- Auto-scaling based on queue depth

### Database Optimization

**Indexes:**
```python
class Project(Base):
    name = Column(String, index=True)
    tenant_id = Column(Integer, index=True)
    created_at = Column(DateTime, index=True)
```

**Query optimization:**
- Pagination for list endpoints
- Eager loading for relationships
- Query result caching

### Caching Strategy

**Application cache:**
- Frequently accessed projects
- Graph metadata
- User sessions

**Redis cache:**
```python
def get_project(project_id: int):
    # Check cache
    cached = redis.get(f"project:{project_id}")
    if cached:
        return json.loads(cached)
    
    # Query database
    project = db.query(Project).get(project_id)
    
    # Cache result
    redis.setex(
        f"project:{project_id}",
        3600,  # 1 hour
        json.dumps(project)
    )
    
    return project
```

## Design Decisions

### Why JSON for Graphs?

**Pros:**
- Flexible schema (agent-driven structure)
- Easy to serialize/deserialize
- Human-readable for debugging
- Version control friendly

**Cons:**
- No built-in indexing
- Query performance vs. graph database

**Alternative considered:** Neo4j
- Rejected due to complexity
- JSON sufficient for current scale

### Why Multi-Agent?

**Reasoning:**
- Cost optimization (cheap vs. expensive models)
- Mirrors human workflow (junior/senior auditors)
- Parallelization opportunities
- Role specialization

### Why Celery?

**Alternatives considered:**
- RQ (rejected - less features)
- Dramatiq (rejected - less mature)
- Custom queue (rejected - reinventing wheel)

**Celery chosen for:**
- Mature ecosystem
- Rich features (retries, scheduling, etc.)
- Good monitoring tools
- Redis/RabbitMQ support

### Why FastAPI?

**Alternatives:**
- Flask (rejected - less modern, no async)
- Django (rejected - too heavyweight)
- Express.js (rejected - prefer Python)

**FastAPI chosen for:**
- Async/await support
- Automatic OpenAPI docs
- Type hints
- WebSocket support
- High performance

## Performance Metrics

**Typical audit (medium codebase ~5K LOC):**
- Graph building: 5-10 minutes
- Sweep mode: 15-30 minutes
- Intuition mode: 30-60 minutes

**Token usage:**
- Scout: 50-100K tokens/hour
- Strategist: 10-20K tokens/hour
- Graph builder: 30-50K tokens/graph

**Cost (DeepSeek):**
- Full audit: $0.50-$2.00
- Surface scan: $0.05-$0.20

**Cost (GPT-4o):**
- Full audit: $5-$20
- Surface scan: $0.50-$2.00

## Monitoring

### Telemetry

```python
def emit_status(message: str):
    """Emit status update to connected clients."""
    telemetry_server.broadcast({
        "type": "status",
        "message": message,
        "timestamp": datetime.utcnow()
    })

def emit_hypothesis(hypothesis: Dict):
    """Emit new hypothesis."""
    telemetry_server.broadcast({
        "type": "hypothesis",
        "data": hypothesis
    })
```

### Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hound.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("Starting audit", extra={"project": project_name})
```

### Metrics

**Key metrics:**
- Audit duration
- Token usage by model
- Hypothesis count
- Coverage percentage
- Error rate
- API response time

## Future Considerations

### Planned Improvements

1. **Graph database integration**
   - Better query performance
   - Graph algorithms (PageRank, etc.)

2. **Distributed workers**
   - Kubernetes deployment
   - Multi-region support

3. **ML-based prioritization**
   - Learn from past audits
   - Predict vulnerability likelihood

4. **Enhanced visualization**
   - 3D graph rendering
   - Interactive exploration

5. **Plugin system**
   - Custom analyzers
   - Domain-specific rules

## Conclusion

Firepan's architecture balances:
- **Cost** - Multi-agent with cheap/expensive models
- **Quality** - Advanced reasoning when needed
- **Scalability** - Horizontal scaling, async processing
- **Flexibility** - Agent-driven graphs, multiple LLM providers
- **Usability** - CLI and web interfaces

The design prioritizes **modularity** and **extensibility** while maintaining **simplicity** where possible.

## See Also

- [Technical Overview](technical_overview.md)
- [SaaS Architecture](saas_architecture.md)
- [API Reference](../API_REFERENCE.md)
- [Developer Guide](../DEVELOPER_GUIDE.md)
