# Module Documentation

This document provides detailed technical documentation for each major module in Hound.

## Table of Contents

- [LLM Module](#llm-module)
- [Analysis Module](#analysis-module)
- [Commands Module](#commands-module)
- [Database Module](#database-module)
- [Server Module](#server-module)
- [Worker Module](#worker-module)
- [Storage Module](#storage-module)
- [Integrations Module](#integrations-module)

---

## LLM Module

Location: `llm/`

Provides unified interface to multiple LLM providers with automatic fallback, rate limiting, and token tracking.

### Architecture

```
┌─────────────────────────────────────────────┐
│           unified_client.py                 │
│  (LLMClient - main entry point)            │
└────────────────┬────────────────────────────┘
                 │
     ┌───────────┴────────────┐
     │                        │
     ▼                        ▼
┌─────────────────┐  ┌─────────────────┐
│ Base Providers  │  │  Token Tracker  │
│                 │  │                 │
│ - OpenAI        │  │  - Usage stats  │
│ - Anthropic     │  │  - Cost calc    │
│ - Gemini        │  │  - Rate limits  │
│ - DeepSeek      │  └─────────────────┘
│ - xAI           │
└─────────────────┘
```

### Key Files

#### `unified_client.py`

Main LLM client with provider abstraction.

**Key Classes:**

```python
class LLMClient:
    """Unified LLM client supporting multiple providers."""
    
    def __init__(
        self,
        platform: str = "openai",
        model: str = None,
        api_key: str = None,
        base_url: str = None
    ):
        """Initialize client with provider and model."""
        
    async def complete(
        self,
        messages: List[Dict],
        model: str = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs
    ) -> str:
        """Generate completion from messages."""
        
    async def complete_with_schema(
        self,
        messages: List[Dict],
        schema: Dict,
        **kwargs
    ) -> Dict:
        """Generate structured output matching schema."""
```

**Usage:**

```python
from llm.unified_client import LLMClient

# Initialize client
client = LLMClient(platform="openai", model="gpt-4o")

# Generate completion
response = await client.complete(
    messages=[
        {"role": "system", "content": "You are a security auditor"},
        {"role": "user", "content": "Review this code..."}
    ],
    temperature=0.7
)

# Structured output
result = await client.complete_with_schema(
    messages=[...],
    schema={
        "type": "object",
        "properties": {
            "findings": {"type": "array"},
            "severity": {"type": "string"}
        }
    }
)
```

#### `base_provider.py`

Abstract base class for all LLM providers.

```python
class BaseProvider(ABC):
    """Base class for LLM providers."""
    
    @abstractmethod
    async def complete(self, messages, model, **kwargs) -> str:
        """Generate text completion."""
        pass
        
    @abstractmethod
    async def complete_with_schema(self, messages, model, schema, **kwargs) -> Dict:
        """Generate structured output."""
        pass
```

#### Provider Implementations

Each provider implements the base interface:

**`openai_provider.py`**
- Supports OpenAI API and compatible endpoints
- Structured output via function calling
- Streaming support

**`anthropic_provider.py`**
- Claude models (Haiku, Sonnet, Opus)
- Tool use for structured output
- Vision support

**`gemini_provider.py`**
- Google Gemini models
- Vertex AI integration
- Configurable safety settings

**`deepseek_provider.py`**
- DeepSeek models (cost-effective)
- OpenAI-compatible API
- Code-focused capabilities

**`xai_provider.py`**
- xAI Grok models
- Latest reasoning capabilities

**`mock_provider.py`**
- Testing and development
- Predefined responses
- No API calls

#### `token_tracker.py`

Tracks token usage and costs across providers.

```python
class TokenTracker:
    """Track LLM token usage and costs."""
    
    def track_usage(
        self,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cached_tokens: int = 0
    ):
        """Record token usage for a model."""
        
    def get_summary(self) -> Dict:
        """Get usage summary with costs."""
        
    def reset(self):
        """Reset all tracked data."""
```

**Pricing data** (as of 2024):

| Provider | Model | Input/1M | Output/1M |
|----------|-------|----------|-----------|
| OpenAI | gpt-4o | $2.50 | $10.00 |
| OpenAI | gpt-4o-mini | $0.15 | $0.60 |
| Anthropic | claude-3-opus | $15.00 | $75.00 |
| Anthropic | claude-3-sonnet | $3.00 | $15.00 |
| DeepSeek | deepseek-chat | $0.14 | $0.28 |
| Gemini | gemini-1.5-pro | $1.25 | $5.00 |

#### Configuration

**Via environment variables:**
```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GOOGLE_API_KEY="..."
export DEEPSEEK_API_KEY="..."
```

**Via config file:**
```yaml
# config.yaml
openai:
  api_key_env: OPENAI_API_KEY
  base_url_env: OPENAI_BASE_URL
  models:
    scout: gpt-4o-mini
    strategist: gpt-4o
    
anthropic:
  api_key_env: ANTHROPIC_API_KEY
  models:
    scout: claude-3-haiku
    strategist: claude-3-opus
```

---

## Analysis Module

Location: `analysis/`

Core security analysis engine with agents, graph building, and hypothesis management.

### Architecture

```
┌──────────────────────────────────────────────────┐
│              agent_core.py                       │
│  (Main orchestrator - coordinates all agents)    │
└───────────┬──────────────────────────────────────┘
            │
    ┌───────┴──────────┬─────────────┬─────────────┐
    │                  │             │             │
    ▼                  ▼             ▼             ▼
┌─────────┐    ┌─────────────┐  ┌─────────┐  ┌──────────┐
│ Scout   │    │ Strategist  │  │ Graph   │  │ Report   │
│ (scout  │    │ (strategist │  │ Builder │  │ Generator│
│ .py)    │    │ .py)        │  │         │  │          │
└─────────┘    └─────────────┘  └─────────┘  └──────────┘
     │              │                 │             │
     └──────────────┴─────────────────┴─────────────┘
                    │
        ┌───────────┴──────────────┐
        │                          │
        ▼                          ▼
┌─────────────────┐    ┌────────────────────┐
│ Knowledge Graphs│    │ Hypothesis Store  │
│ (JSON files)    │    │ (JSON file)       │
└─────────────────┘    └────────────────────┘
```

### Key Files

#### `agent_core.py`

Main agent orchestrator coordinating the audit process.

**Key Classes:**

```python
class AgentCore:
    """Main security analysis agent."""
    
    def __init__(
        self,
        project_name: str,
        mode: str = "intuition",
        scout_client: LLMClient = None,
        strategist_client: LLMClient = None
    ):
        """Initialize agent with project and LLM clients."""
        
    async def run_audit(
        self,
        time_limit: int = None,
        plan_n: int = 10,
        session_id: str = None,
        headless: bool = False
    ):
        """Execute security audit."""
        
    async def investigate(
        self,
        concern: str,
        iterations: int = 10
    ) -> List[Dict]:
        """Investigate specific security concern."""
```

**Audit modes:**

1. **Sweep mode** (`mode="sweep"`):
   - Systematic component-by-component analysis
   - Examines all contracts/modules
   - Builds comprehensive coverage
   - Terminates when all components analyzed

2. **Intuition mode** (`mode="intuition"`):
   - Hypothesis-driven investigation
   - Focuses on high-risk areas
   - Deep reasoning on promising findings
   - Time-limited exploration

**Main loop:**

```python
async def run_audit(self):
    while not self._should_stop():
        # 1. Strategist plans next investigations
        plan = await self.strategist.create_plan(
            graphs=self.graphs,
            coverage=self.coverage,
            hypotheses=self.hypotheses
        )
        
        # 2. Scout executes investigations
        for investigation in plan:
            findings = await self.scout.investigate(
                concern=investigation.concern,
                context=self._build_context()
            )
            
            # 3. Update hypotheses
            self.hypothesis_store.add_findings(findings)
        
        # 4. Update coverage tracking
        self.coverage.mark_visited(nodes)
```

#### `strategist.py`

High-level planning and hypothesis formation agent.

```python
class Strategist:
    """Strategic planning agent for security audits."""
    
    async def create_plan(
        self,
        graphs: List[Dict],
        coverage: CoverageIndex,
        hypotheses: List[Dict],
        plan_n: int = 10
    ) -> List[Investigation]:
        """Generate prioritized investigation plan."""
        
    async def form_hypothesis(
        self,
        observations: List[str],
        context: Dict
    ) -> Dict:
        """Form security hypothesis from observations."""
        
    async def evaluate_hypothesis(
        self,
        hypothesis: Dict,
        evidence: List[Dict]
    ) -> float:
        """Evaluate hypothesis confidence based on evidence."""
```

**Planning algorithm:**

1. Analyze existing coverage and hypotheses
2. Identify high-priority areas (e.g., money flows, access control)
3. Generate diverse investigation concerns
4. Prioritize by potential impact and unexplored code
5. Return top-N investigations

#### `scout.py`

Lightweight exploration and investigation agent.

```python
class Scout:
    """Exploration agent for code investigation."""
    
    async def investigate(
        self,
        concern: str,
        graphs: List[Dict],
        cards: Dict,
        iterations: int = 10
    ) -> List[Dict]:
        """Investigate specific security concern."""
```

**Investigation process:**

1. Load relevant graphs and code cards
2. Explore code paths related to concern
3. Note observations and assumptions
4. Identify potential vulnerabilities
5. Return findings with evidence

#### `graph_builder.py`

Constructs and refines knowledge graphs.

```python
class GraphBuilder:
    """Build knowledge graphs from code."""
    
    async def build_graphs(
        self,
        auto: bool = False,
        max_graphs: int = 5,
        iterations: int = 3,
        files: List[str] = None
    ):
        """Build graphs for project."""
        
    async def refine_graph(
        self,
        graph_name: str,
        iterations: int = 3
    ):
        """Refine existing graph."""
        
    async def _discover_graphs(
        self,
        cards: List[Dict]
    ) -> List[str]:
        """Agent discovers useful graph types."""
```

**Graph types discovered:**

- `SystemArchitecture` - Components and relationships
- `StateMutationGraph` - State changes and flows
- `InterContractCallGraph` - Function call relationships
- `AuthorizationRolesMap` - Access control structure
- `ValueFlowGraph` - Asset and value transfers
- `EventEmissionGraph` - Event relationships

**Graph refinement:**

Each iteration:
1. Agent reviews current graph
2. Proposes new nodes/edges or updates
3. Adds observations and assumptions
4. Links to code evidence (cards)
5. Adjusts confidence scores

#### `report_generator.py`

Generates professional audit reports.

```python
class ReportGenerator:
    """Generate security audit reports."""
    
    def generate_html_report(
        self,
        project_name: str,
        output_path: str = None,
        include_all: bool = False
    ):
        """Generate HTML report with findings."""
        
    def generate_json_report(
        self,
        project_name: str,
        output_path: str = None
    ) -> Dict:
        """Generate machine-readable JSON report."""
```

**Report sections:**

1. Executive Summary
   - Risk assessment
   - Finding statistics
   - Critical issues highlighted

2. System Architecture
   - High-level components
   - Key relationships
   - Attack surface analysis

3. Findings
   - Detailed vulnerability descriptions
   - Severity and confidence scores
   - Code snippets with line numbers
   - Proof-of-concepts (if available)
   - Remediation recommendations

4. Methodology
   - Audit approach
   - Coverage statistics
   - Tools and models used

#### `concurrent_knowledge.py`

Thread-safe stores for shared knowledge.

```python
class ConcurrentGraphStore:
    """Thread-safe graph storage."""
    
    def load_graph(self, name: str) -> Dict:
        """Load graph by name."""
        
    def save_graph(self, name: str, graph: Dict):
        """Save graph with locking."""

class ConcurrentHypothesisStore:
    """Thread-safe hypothesis storage."""
    
    def add_hypothesis(self, hypothesis: Dict) -> str:
        """Add new hypothesis, returns ID."""
        
    def update_hypothesis(
        self,
        hyp_id: str,
        updates: Dict
    ):
        """Update existing hypothesis."""
        
    def get_hypotheses(
        self,
        status: str = None,
        min_confidence: float = 0.0
    ) -> List[Dict]:
        """Query hypotheses."""
```

#### `coverage_index.py`

Tracks what code and graph nodes have been analyzed.

```python
class CoverageIndex:
    """Track audit coverage."""
    
    def mark_visited(
        self,
        node_ids: List[str] = None,
        card_ids: List[str] = None
    ):
        """Mark nodes/cards as visited."""
        
    def get_coverage(self) -> Dict:
        """Get coverage statistics."""
        
    def get_unvisited_nodes(
        self,
        graph_name: str = None
    ) -> List[str]:
        """Get nodes not yet analyzed."""
```

#### `session_tracker.py`

Manages audit session state and metadata.

```python
class SessionTracker:
    """Track audit session progress."""
    
    def __init__(self, project_name: str, session_id: str):
        self.session_id = session_id
        self.project_name = project_name
        
    def log_investigation(
        self,
        concern: str,
        findings: List[Dict]
    ):
        """Log investigation results."""
        
    def update_token_usage(
        self,
        model: str,
        tokens: int
    ):
        """Track LLM token usage."""
        
    def finalize(self, status: str):
        """Finalize session with status."""
```

---

## Commands Module

Location: `commands/`

CLI command implementations for all Hound operations.

### Key Files

#### `project.py`

Project management commands.

```python
class ProjectManager:
    """Manage Hound projects."""
    
    def create_project(
        self,
        name: str,
        source_path: str,
        git_url: str = None
    ):
        """Create new project."""
        
    def list_projects(self) -> List[Dict]:
        """List all projects."""
        
    def get_project_info(self, name: str) -> Dict:
        """Get project details."""
        
    def delete_project(self, name: str):
        """Delete project and all data."""
```

#### `graph.py`

Knowledge graph building commands.

```python
def build_graph(
    project_name: str,
    auto: bool = False,
    init: bool = False,
    max_graphs: int = 5,
    iterations: int = 3,
    files: List[str] = None,
    visualize: bool = False
):
    """Build knowledge graphs for project."""
    
def refine_graph(
    project_name: str,
    graph_name: str = None,
    all_graphs: bool = False,
    iterations: int = 3
):
    """Refine existing graphs."""
    
def list_graphs(project_name: str):
    """List project graphs."""
    
def visualize_graph(
    project_name: str,
    graph_name: str = None
):
    """Generate interactive visualization."""
```

#### `agent.py`

Agent execution commands.

```python
def run_audit(
    project_name: str,
    mode: str = "intuition",
    time_limit: int = None,
    plan_n: int = 10,
    session_id: str = None,
    headless: bool = False,
    telemetry: bool = False,
    debug: bool = False,
    model: str = None,
    strategist_model: str = None
):
    """Run security audit agent."""
    
def investigate(
    concern: str,
    project_name: str,
    iterations: int = 10,
    model: str = None
):
    """Run targeted investigation."""
```

#### `finalize.py`

Quality assurance and hypothesis review.

```python
def finalize_audit(
    project_name: str,
    threshold: float = 0.7,
    include_below_threshold: bool = False,
    model: str = None
):
    """Run QA review of hypotheses."""
```

#### `report.py`

Report generation commands.

```python
def generate_report(
    project_name: str,
    output: str = None,
    include_all: bool = False,
    format: str = "html"
):
    """Generate audit report."""
```

#### `poc.py`

Proof-of-concept management.

```python
def make_poc_prompt(
    project_name: str,
    hypothesis_id: str = None
):
    """Generate PoC exploit prompts."""
    
def import_poc(
    project_name: str,
    hypothesis_id: str,
    files: List[str],
    description: str
):
    """Import PoC files."""
    
def list_pocs(project_name: str):
    """List all PoCs."""
```

---

## Database Module

Location: `database/`

SQLAlchemy models and migrations for SaaS mode.

### Schema

```python
# database/models.py

class Project(Base):
    """Project model."""
    __tablename__ = "projects"
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    git_url = Column(String)
    source_path = Column(String)
    tenant_id = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    sessions = relationship("AuditSession", back_populates="project")
    hypotheses = relationship("Hypothesis", back_populates="project")
    graphs = relationship("Graph", back_populates="project")

class AuditSession(Base):
    """Audit session model."""
    __tablename__ = "audit_sessions"
    
    id = Column(String, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    mode = Column(String)
    status = Column(String)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    token_usage = Column(JSON)
    coverage = Column(JSON)
    
    project = relationship("Project", back_populates="sessions")

class Hypothesis(Base):
    """Security finding model."""
    __tablename__ = "hypotheses"
    
    id = Column(String, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    confidence = Column(Float)
    status = Column(String)
    type = Column(String)
    evidence = Column(JSON)
    annotations = Column(JSON)
    created_at = Column(DateTime)
    
    project = relationship("Project", back_populates="hypotheses")

class Graph(Base):
    """Knowledge graph model."""
    __tablename__ = "graphs"
    
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    name = Column(String)
    display_name = Column(String)
    description = Column(Text)
    data = Column(JSON)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)
    
    project = relationship("Project", back_populates="graphs")
```

### Migrations

```bash
# Run migrations
python database/migrate.py

# Migrations are in database/migrations/
```

### Usage

```python
from database.models import Project, AuditSession
from sqlalchemy.orm import Session

# Create project
project = Project(
    name="myaudit",
    source_path="/path/to/code"
)
db.add(project)
db.commit()

# Query projects
projects = db.query(Project).filter(
    Project.tenant_id == 1
).all()

# Update JSON field (important!)
from sqlalchemy.orm.attributes import flag_modified

hypothesis.evidence.append(new_evidence)
flag_modified(hypothesis, "evidence")
db.commit()
```

---

## Server Module

Location: `server/`

FastAPI server providing REST and WebSocket APIs.

### Files

#### `api.py`

Main API application with all endpoints.

**Key routes:**

```python
# Projects
GET    /projects
POST   /projects
GET    /projects/{project_id}
DELETE /projects/{project_id}

# Sessions
GET  /projects/{project_id}/sessions
POST /projects/{project_id}/sessions
GET  /sessions/{session_id}

# Graphs
GET  /projects/{project_id}/graphs
GET  /graphs/{graph_id}
POST /projects/{project_id}/graphs/build

# Hypotheses
GET   /projects/{project_id}/hypotheses
GET   /hypotheses/{hypothesis_id}
PATCH /hypotheses/{hypothesis_id}/status

# Scans
POST /scans
GET  /scans/{scan_id}

# WebSocket
WS /ws/audits/{session_id}

# Admin (protected)
GET    /admin/projects
GET    /admin/stats
POST   /admin/login
POST   /admin/logout

# Health
GET /health
```

#### `start.py`

Server startup script.

```python
# server/start.py
import uvicorn
from server.api import app

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
```

### WebSocket Protocol

**Client connection:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/audits/session_123');

ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  handleUpdate(msg.type, msg.data);
};
```

**Message types:**
- `status` - Agent status updates
- `plan` - Planning updates
- `hypothesis` - New/updated findings
- `progress` - Coverage progress
- `error` - Error messages

---

## Worker Module

Location: `worker/`

Celery background workers for async task processing.

### Files

#### `celery_app.py`

Celery configuration.

```python
from celery import Celery

celery = Celery(
    "hound",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)
```

#### `tasks.py`

Task definitions.

```python
@celery.task(name="execute_audit_task")
def execute_audit_task(
    repo_url: str,
    scan_id: str,
    tenant_id: int,
    installation_id: int = None,
    pr_number: int = None,
    repo_full_name: str = None
):
    """Execute full security audit."""
    # Implementation

@celery.task(name="execute_scan_task")
def execute_scan_task(
    repo_url: str,
    scan_id: str,
    tenant_id: int,
    llm_budget: int = 5
):
    """Execute surface scan."""
    # Implementation
```

#### `redis_publisher.py`

Real-time progress streaming via Redis Pub/Sub.

```python
class RedisPublisher:
    """Publish task updates to Redis."""
    
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.channel = f"audit:updates:{scan_id}"
        
    def publish_status(self, message: str):
        """Publish status update."""
        
    def publish_finding(self, hypothesis: Dict):
        """Publish new finding."""
        
    def publish_progress(self, coverage: Dict):
        """Publish progress update."""
```

### Usage

```bash
# Start worker
celery -A worker.celery_app worker --loglevel=info

# Monitor tasks
celery -A worker.celery_app inspect active

# Purge queue
celery -A worker.celery_app purge
```

---

## Storage Module

Location: `storage/`

Blob storage backends for artifacts and reports.

### Files

#### `blob_storage.py`

S3/MinIO storage interface.

```python
class BlobStorage:
    """Blob storage for artifacts."""
    
    def __init__(
        self,
        bucket: str,
        endpoint_url: str = None,
        access_key: str = None,
        secret_key: str = None
    ):
        """Initialize storage client."""
        
    def upload_file(
        self,
        local_path: str,
        remote_key: str
    ) -> str:
        """Upload file, returns URL."""
        
    def download_file(
        self,
        remote_key: str,
        local_path: str
    ):
        """Download file."""
        
    def get_url(
        self,
        remote_key: str,
        expires_in: int = 3600
    ) -> str:
        """Get signed URL."""
```

**Usage:**

```python
from storage.blob_storage import BlobStorage

# Initialize
storage = BlobStorage(
    bucket="hound-artifacts",
    endpoint_url="https://s3.amazonaws.com"
)

# Upload report
url = storage.upload_file(
    local_path="/tmp/report.html",
    remote_key="reports/project_123/report.html"
)

# Get signed URL
download_url = storage.get_url(
    remote_key="reports/project_123/report.html",
    expires_in=7200  # 2 hours
)
```

---

## Integrations Module

Location: `integrations/`

External service integrations (GitHub, Telegram, etc.).

### Files

#### `github_app.py`

GitHub App installation and webhook handling.

```python
class GitHubApp:
    """GitHub App integration."""
    
    def __init__(
        self,
        app_id: str,
        private_key: str
    ):
        """Initialize GitHub App."""
        
    def get_installation_client(
        self,
        installation_id: int
    ):
        """Get authenticated client for installation."""
```

#### `github_auth.py`

GitHub App authentication.

```python
def get_github_client(
    installation_id: int
) -> Github:
    """Get authenticated GitHub client."""
    
def clone_repo(
    repo_url: str,
    target_dir: str,
    installation_id: int = None
):
    """Clone repository with authentication."""
```

#### `pr_bot.py`

GitHub PR comment bot.

```python
class PRBot:
    """Post findings to GitHub PRs."""
    
    def post_findings(
        self,
        repo_full_name: str,
        pr_number: int,
        findings: List[Dict],
        installation_id: int
    ):
        """Post findings as PR comment."""
        
    def format_finding(self, finding: Dict) -> str:
        """Format finding as markdown."""
```

**Example PR comment:**

```markdown
## 🔍 Hound Security Audit Results

Found **3 high-severity** and **2 medium-severity** issues:

### High Severity Issues

#### 🚨 Reentrancy Vulnerability in withdraw()
**File:** `src/Vault.sol:45`  
**Confidence:** 85%

The withdraw function does not follow the checks-effects-interactions pattern...

```solidity
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");
    balances[msg.sender] -= amount;  // ⚠️ State update after external call
}
```

**Recommendation:** Move state update before external call.

---

[View full report](https://hound.example.com/reports/scan_123)
```

---

## Testing

Each module has corresponding tests in `tests/`:

```
tests/
├── test_llm/
│   ├── test_unified_client.py
│   ├── test_openai_provider.py
│   └── test_token_tracker.py
├── test_analysis/
│   ├── test_agent_core.py
│   ├── test_strategist.py
│   └── test_graph_builder.py
├── test_commands/
│   ├── test_project.py
│   └── test_graph.py
└── test_api.py
```

**Run tests:**
```bash
# All tests
pytest

# Specific module
pytest tests/test_llm/

# With coverage
pytest --cov=llm --cov-report=html
```

---

## Performance Considerations

### LLM Module
- Use token tracking to monitor costs
- Implement caching for repeated queries
- Batch similar requests when possible
- Use cheaper models (DeepSeek, GPT-4o-mini) for exploration

### Analysis Module
- Graph operations are I/O bound (JSON file reads)
- Coverage index uses in-memory sets for fast lookup
- Hypothesis deduplication runs on save

### Database Module
- Add indexes for common query patterns
- Use `flag_modified()` for JSON field updates
- Connection pooling in production

### Worker Module
- Celery workers are stateless
- Redis Pub/Sub for real-time updates
- Task timeouts prevent hanging jobs

---

## See Also

- [API Reference](API_REFERENCE.md)
- [Developer Guide](DEVELOPER_GUIDE.md)
- [Architecture Overview](architecture/README.md)
