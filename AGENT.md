# AGENT.md - AI Agent Knowledge Base for Hound

> **Purpose**: This file contains critical context for AI agents working on this project. Read this first before making changes.

---

## 🎯 Project Overview

**Hound** is a security analysis platform that uses LLM agents to find vulnerabilities in smart contracts and codebases. It operates in two modes:

1. **CLI Mode**: Local analysis via `python hound.py <command>`
2. **SaaS Mode**: API-driven via FastAPI server at `server/api.py`

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         HOUND SYSTEM                            │
├─────────────────────────────────────────────────────────────────┤
│  CLI (hound.py)              │  SaaS API (server/api.py)       │
│  - Local filesystem storage  │  - PostgreSQL database          │
│  - ~/.hound/projects/        │  - Redis for task queue         │
│  - Direct LLM calls          │  - Celery workers               │
├─────────────────────────────────────────────────────────────────┤
│                     SHARED COMPONENTS                           │
│  - llm/unified_client.py (LLM abstraction)                     │
│  - analysis/ (agent core, strategist, graph builder)           │
│  - commands/ (CLI commands - can be called from API too)       │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🗄️ Database Configuration

**PostgreSQL Connection** (SaaS mode):
```
DATABASE_URL=postgresql://hound:hound_secret@localhost:5432/hound
```

**Key Tables**:
- `projects` - Project metadata (name, git_url, source_path)
- `audit_sessions` - Audit run records
- `hypotheses` - Security findings/vulnerabilities
- `graphs` - Knowledge graphs for codebase understanding

**Important**: When updating JSON fields in SQLAlchemy, use `flag_modified()`:
```python
from sqlalchemy.orm.attributes import flag_modified
hypothesis.evidence = {...}  # Update the dict
flag_modified(hypothesis, "evidence")  # Tell SQLAlchemy it changed
db.commit()
```

---

## 🔑 Key Commands & Endpoints

### CLI Commands (commands/*.py)

| Command | File | Purpose |
|---------|------|---------|
| `agent run` | commands/agent.py | Run security analysis agent |
| `graph build` | commands/graph.py | Build knowledge graphs |
| `scan surface` | commands/scan.py | Surface-level security scan |
| `finalize` | commands/finalize.py | QA review of hypotheses |
| `poc make-prompt` | commands/poc.py | Generate PoC exploit prompts |
| `report generate` | commands/report.py | Generate audit reports |

### SaaS API Endpoints (server/api.py)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/audits/start` | POST | Start new audit (async) |
| `/sessions/{id}/finalize` | POST | QA finalize hypotheses |
| `/sessions/{id}/poc` | POST | Generate PoC prompts |
| `/sessions/{id}/findings` | GET | Get hypotheses/findings |
| `/projects` | GET/POST | List/create projects |
| `/ws/sessions/{id}` | WebSocket | Live progress streaming |

---

## 🧠 LLM Configuration

**Profiles** (defined in config.yaml):
- `strategist` - High-level reasoning (Claude/GPT-4)
- `junior` - Code analysis tasks
- `senior` - Hypothesis validation
- `finalize` - QA review

**Using the LLM Client**:
```python
from llm.unified_client import UnifiedLLMClient

llm = UnifiedLLMClient(cfg=config, profile="strategist")
response = llm.raw(system="...", user="...")
```

**Environment Variables**:
- `OPENAI_API_KEY` - OpenAI API key
- `ANTHROPIC_API_KEY` - Anthropic API key
- `GEMINI_API_KEY` - Google Gemini API key

---

## 📁 Project Structure Patterns

### CLI Mode (filesystem)
```
~/.hound/projects/{project_name}/
├── hypotheses.json      # All hypotheses
├── manifest/
│   └── manifest.json    # File index
├── graphs/              # Knowledge graphs
└── poc_prompts/         # Generated PoC prompts
```

### SaaS Mode (database)
- Projects stored in `projects` table
- Hypotheses in `hypotheses` table with `project_id` FK

---

## 🔌 API Endpoints Reference

### PoC Generation
**`POST /sessions/{session_id}/poc`**

Generate proof-of-concept prompts for vulnerabilities.

```json
// Request
{
  "hypothesis_id": "audit_xxx_hyp_1",  // optional, specific hypothesis
  "max_hypotheses": 10,                 // max to process
  "min_confidence": 0.7                 // confidence threshold
}

// Response
{
  "session_id": "audit_xxx",
  "project_name": "ProjectName",
  "total_generated": 3,
  "results": [
    {
      "hypothesis_id": "audit_xxx_hyp_1",
      "title": "Vulnerability Title",
      "vulnerability_type": "reentrancy",
      "severity": "critical",
      "affected_files": ["contracts/File.sol"],
      "prompt": "Generated PoC prompt...",
      "output_path": "/home/user/.hound/poc_prompts/ProjectName/audit_xxx_hyp_1_poc_prompt.md"
    }
  ]
}
```

### QA Finalization
**`POST /sessions/{session_id}/finalize`**

Finalize audit hypotheses with QA review.

```json
// Request
{
  "hypothesis_ids": ["hyp_1", "hyp_2"],  // optional, all if omitted
  "finalize_all": false,
  "min_confidence": 0.7
}

// Response  
{
  "session_id": "audit_xxx",
  "total_reviewed": 10,
  "confirmed": 7,
  "rejected": 2,
  "uncertain": 1,
  "results": [...]
}
```

### Analysis Session
**`POST /sessions/{session_id}/analyze`**

Run security analysis on a project.
- Source code accessed via `git_url` (cloned on demand)

### Report Generation
**`POST /sessions/{session_id}/report`**

Generate professional security audit reports.

```json
// Request
{
  "format": "html",              // html, markdown, or pdf
  "title": "Custom Report Title", // optional
  "auditors": "Security Team",    // comma-separated names
  "include_all": false            // include unconfirmed hypotheses
}

// Response
{
  "session_id": "audit_xxx",
  "project_name": "ProjectName",
  "format": "html",
  "total_findings": 25,
  "output_path": "/home/user/.hound/reports/ProjectName/audit_report_20260120_140000.html"
}
```

### Surface Scan (Lead Generation)
**`POST /surface/scan`**

Run lightweight security scan for marketing/lead generation.

```json
// Request
{
  "target": "https://github.com/org/repo",  // GitHub URL or local path
  "llm_budget": 5,                          // Max LLM calls (0 for fast scan)
  "model": null                             // Override model
}

// Response
{
  "execution_id": "scan_xxx_123",
  "repo_name": "repo",
  "risk_score": 74,
  "risk_level": "high",
  "findings": [...],
  "quality_metrics": {...},
  "summary": "Critical security issues detected..."
}
```

**`GET /surface/scans`** - List all scans (paginated, filterable)

**`GET /surface/scans/{execution_id}`** - Get scan details

**`GET /surface/stats`** - Dashboard statistics

---

## 🔧 Common Patterns

### Loading Data from Both Modes

Many commands support both CLI (filesystem) and SaaS (database) modes:

```python
# Try database first
db_data = _load_from_db(project_name)
if db_data:
    # Use database data
    pass
else:
    # Fall back to filesystem
    project_dir = Path.home() / f".hound/projects/{project_name}"
```

### Cloning Repos on Demand

When source_path is None but git_url exists:
```python
if not repo_root and git_url:
    import subprocess
    clone_path = Path('/tmp') / repo_name
    subprocess.run(["git", "clone", "--depth", "1", git_url, str(clone_path)])
    repo_root = clone_path
```

### Finding Source Files from Hypothesis Text

Use `guess_relpaths()` or keyword matching:
```python
from analysis.path_utils import guess_relpaths
files = guess_relpaths(hypothesis_text, repo_root)
```

---

## ⚠️ Critical Implementation Notes

### 1. SQLAlchemy JSON Field Updates
Always use `flag_modified()` when updating JSON/dict columns or changes won't persist.

### 2. API Key Handling
Check for missing API keys gracefully:
```python
try:
    llm = UnifiedLLMClient(cfg=config, profile="finalize")
except ValueError as e:
    if "API key not found" in str(e):
        raise HTTPException(status_code=503, detail="LLM not configured")
```

### 3. Source Code Loading Priority
1. Check `project.source_path` (local path)
2. Check `/tmp/{repo_name}` (previously cloned)
3. Check `/workspaces/{repo_name}` (dev container)
4. Clone from `project.git_url` if needed

### 4. Hypothesis Status Flow
```
proposed → investigating → confirmed/rejected/uncertain
```

### 5. Confidence Scores
- 0.0-0.5: Low confidence
- 0.5-0.7: Medium confidence  
- 0.7-1.0: High confidence (eligible for PoC generation)

---

## 🧪 Testing

Run tests with PostgreSQL:
```bash
export DATABASE_URL="postgresql://hound:hound_secret@localhost:5432/hound"
pytest tests/ -v
```

Start the API server:
```bash
export DATABASE_URL="postgresql://hound:hound_secret@localhost:5432/hound"
export OPENAI_API_KEY="..."
python -m uvicorn server.api:app --host 0.0.0.0 --port 8000
```

---

## 📋 Recent Changes (January 2026)

### QA Finalization Endpoint
- **File**: `server/api.py` (lines ~3050-3370)
- **Endpoint**: `POST /sessions/{session_id}/finalize`
- **Features**: LLM-based hypothesis review, source code loading, git clone fallback

### PoC Generation
- **File**: `commands/poc.py`
- **CLI**: `hound poc make-prompt <project> [--hypothesis <id>]`
- **Features**: Database support, keyword-based file discovery, git clone on demand

---

## 🚀 Adding New Features Checklist

When adding a new feature:

1. **CLI Command**: Add to `commands/` directory
2. **API Endpoint**: Add to `server/api.py`
3. **Both Modes**: Ensure it works with filesystem AND database
4. **Error Handling**: Graceful API key checks, 404s for missing data
5. **Update this file**: Document the new feature here

---

## 🐛 Known Issues / TODOs

- [ ] PoC API endpoint not yet implemented (need to add to server/api.py)
- [ ] Report generation endpoint not yet SaaS-ready
- [ ] Webhook integration needs testing with live GitHub App

---

*Last updated: January 20, 2026*
