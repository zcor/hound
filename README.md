<p align="center">
  <img src="static/hound.png" alt="Hound Banner" width="75%">
</p>
<h1 align="center">Hound</h1>

<p align="center"><strong>Autonomous agents for code security auditing</strong></p>

<p align="center">
  <a href="https://github.com/muellerberndt/hound/actions"><img src="https://github.com/muellerberndt/hound/workflows/Tests/badge.svg" alt="Tests"></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python 3.8+"/></a>
  <a href="https://openai.com"><img src="https://img.shields.io/badge/OpenAI-Compatible-74aa9c" alt="OpenAI"/></a>
  <a href="https://ai.google.dev/"><img src="https://img.shields.io/badge/Gemini-Compatible-4285F4" alt="Gemini"/></a>
  <a href="https://anthropic.com"><img src="https://img.shields.io/badge/Anthropic-Compatible-6B46C1" alt="Anthropic"/></a>
  <a href="https://www.deepseek.com"><img src="https://img.shields.io/badge/DeepSeek-Compatible-00ADD8" alt="DeepSeek"/></a>
</p>

<p align="center">
  <sub>
    <a href="#overview"><b>Overview</b></a>
    • <a href="#configuration"><b>Configuration</b></a>
    • <a href="#complete-audit-workflow"><b>Workflow</b></a>
    • <a href="#chatbot-telemetry-ui"><b>Chatbot</b></a>
    • <a href="#contributing"><b>Contributing</b></a>
  </sub>
</p>

---

## Overview

Hound is a Language-agnostic AI auditor that autonomously builds and refines adaptive knowledge graphs for deep, iterative code reasoning.

### Key Features

- Graph-driven analysis – Flexible, agent-designed graphs that can model any aspect of a system (e.g. architecture, access control, value flows, math, etc.)
- Relational graph views – High-level graphs support cross-aspect reasoning and precise retrieval of the code snippets that back each subsystem investigated.
- Belief & hypothesis system – Observations, assumptions, and hypotheses evolve with confidence scores, enabling long-horizon reasoning and cumulative audits.
- Dynamic model switching – Lightweight "scout" models handle exploration; heavyweight "strategist" models provide deep reasoning, mirroring expert workflows while keeping costs efficient.
- Strategic audit planning - Balances broad code coverage with focused investigation of the most promising aspects, ensuring both depth and efficiency.

**Codebase size considerations:** While Hound can analyze any codebase, it's optimized for small-to-medium sized projects like typical smart contract applications. Large enterprise codebases may exceed context limits and require selective analysis of specific subsystems.

### Links

- [Paper](https://arxiv.org/html/2510.09633v1)
- [Walkthrough](https://muellerberndt.medium.com/hunting-for-security-bugs-in-code-with-ai-agents-a-full-walkthrough-a0dc24e1adf0)

## Installation

```bash
pip install -r requirements.txt
```

## 🚀 Development with GitHub Codespaces

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/firepan-labs/hound)

Codespaces automatically configures the development environment. See [.devcontainer/README.md](.devcontainer/README.md) for details.

**Quick Start:**
1. Click "Open in Codespaces" above
2. Wait for setup to complete
3. Set environment variables (see terminal output)
4. Run `bash scripts/start-dev.sh`

## Docker Quickstart (SaaS Mode)

Run Hound as a full SaaS stack with PostgreSQL, Redis, API server, and background workers:

```bash
# 1. Copy and configure environment
cp .env.example .env
# Edit .env with your API keys and settings

# 2. Start the stack
docker compose up -d

# 3. Check status
docker compose ps

# 4. View logs
docker compose logs -f

# 5. Test the API
curl http://localhost:8000/health
```

**Services:**
| Service | Port | Description |
|---------|------|-------------|
| `hound-api` | 8000 | FastAPI server + WebSocket |
| `hound-worker` | - | Celery background worker |
| `hound-db` | 5432 | PostgreSQL 15 |
| `hound-redis` | 6379 | Redis 7 (broker + pub/sub) |

See [docs/architecture/saas_architecture.md](docs/architecture/saas_architecture.md) for detailed architecture documentation.

## Quick Start (Development)

For local development and testing with pre-seeded data:

### 1. Setup Database and Test Data

```bash
# Create database and seed test data
python scripts/seed_test_data.py
```

### 2. Start Development Server

```bash
# Start Hound API
bash scripts/start-dev.sh

# In another terminal, start frontend (if available)
cd frontend
npm install
npm run dev
```

### 3. Run Integration Tests

```bash
# Verify everything works
bash scripts/test_integration.sh
```

### 4. Access the Dashboard

- Frontend: http://localhost:3000 (if running)
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

### Test Data

The seed script creates:
- 1 test organization (tenant_id=1)
- 3 projects (DeFi Protocol, NFT Marketplace, Token Bridge)
- 9 scans across all projects (various statuses: completed, running, failed, queued)
- Multiple findings for completed scans

Use `tenant_id=1` for testing API endpoints.

## Configuration

Set up your API keys for the LLM provider you want to use:

**Using DeepSeek (recommended for cost efficiency):**

```bash
export DEEPSEEK_API_KEY=your_key_here
# Optional: override the base URL (defaults to https://api.deepseek.com)
export DEEPSEEK_BASE_URL=https://api.deepseek.com
```

**Using OpenAI:**

```bash
export OPENAI_API_KEY=your_key_here
# Optional: override the base URL (defaults to https://api.openai.com)
export OPENAI_BASE_URL=https://api.openai.com
```

**Using Anthropic:**

```bash
export ANTHROPIC_API_KEY=your_key_here
```

For detailed DeepSeek setup and cost comparison, see [examples/deepseek_example.md](examples/deepseek_example.md).

Using Gemini via Vertex AI (optional):

- Enable Vertex AI mode (instead of AI Studio) and set your GCP project and region.
- Credentials are taken from ADC (Application Default Credentials) or a service account; GOOGLE_API_KEY is not used in Vertex AI mode.

```bash
# Enable Vertex AI routing for Gemini
export GOOGLE_USE_VERTEX_AI=1

# Provide project and region (region examples: us-central1, europe-west1, asia-northeast1, etc.)
export VERTEX_PROJECT_ID=my-gcp-project
export VERTEX_LOCATION=us-central1
# Alternatively (fallbacks also supported):
# export GOOGLE_CLOUD_PROJECT=my-gcp-project
# export GOOGLE_CLOUD_REGION=us-central1

# Authenticate (one of the following)
# 1) Use gcloud ADC (recommended for local dev):
#    gcloud auth application-default login
# 2) Or point to a service account key file:
#    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

When configured, the effective Vertex AI endpoint will be constructed as:
https://{region}-aiplatform.googleapis.com/v1/projects/{project}/locations/{region}
For example:
https://us-central1-aiplatform.googleapis.com/v1/projects/my-gcp-project/locations/us-central1

Optional: configure via config.yaml instead of env vars:

```yaml
gemini:
  api_key_env: GOOGLE_API_KEY
  vertex_ai:
    enabled: true
    project_id: "my-gcp-project"
    region: "us-central1"
```

Copy the example configuration and edit as needed:

```bash
cp hound/config.yaml.example hound/config.yaml
# then edit hound/config.yaml to select providers/models and options
```

Notes:
- Defaults work out-of-the-box; you can override many options via CLI flags.
- Keep API keys out of the repo; `API_KEYS.txt` is gitignored and can be sourced.

<!-- Quick Start and Repository Layout removed to avoid duplication; see Complete Audit Workflow below. -->

**Note:** Audit quality scales with time and model capability. Use longer runs and advanced models for more complete results.

## Complete Audit Workflow

### Step 1: Create a Project

Projects organize your audits and store all analysis data:

```bash
# Create a project from local code
./hound.py project create myaudit /path/to/code

# List all projects
./hound.py project ls

# View project details and coverage
./hound.py project info myaudit
```

### Step 2: Build Knowledge Graphs

Hound analyzes your codebase and builds aspect‑oriented knowledge graphs that serve as the foundation for all subsequent analysis.

Recommended (one‑liner):

```bash
# Auto-generate a default set of graphs (up to 5) and refine
# Strongly recommended: pass a whitelist of files (comma-separated)
./hound.py graph build myaudit --auto \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# View generated graphs
./hound.py graph ls myaudit
```

Alternative (manual guidance):

```bash
# 1) Initialize the baseline SystemArchitecture graph
./hound.py graph build myaudit --init \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# 2) Add a specific graph with your own description (exactly one graph)
./hound.py graph custom myaudit \
  "Call graph focusing on function call relationships across modules" \
  --iterations 2 \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# (Repeat 'graph custom' for additional targeted graphs as needed)
```

Operational notes:
- `--auto` always includes the SystemArchitecture graph as the first graph. You do not need to run `--init` in addition to `--auto`.
- If `--init` is used and a `SystemArchitecture` graph already exists, initialization is skipped. Use `--auto` to add more graphs, or remove existing graphs first if you want a clean re‑init.
- When running `--auto` and graphs already exist, Hound asks for confirmation before updating/overwriting graphs (including SystemArchitecture). To clear graphs:

```bash
./hound.py graph rm myaudit --all                 # remove all graphs
./hound.py graph rm myaudit --name SystemArchitecture  # remove one graph
```

- For large repos, you can constrain scope with `--files` (comma‑separated whitelist) alongside either approach.

Whitelists (strongly recommended):

- Always pass a whitelist of input files via `--files`. For the best results, the selected files should fit in the model’s available context window; whitelisting keeps the graph builder focused and avoids token overflows.
- If you do not pass `--files`, Hound will consider all files in the repository. On large codebases this triggers sampling and may degrade coverage/quality.
- `--files` expects a comma‑separated list of paths relative to the repo root.

Examples:

```bash
# Manual (small projects)
./hound.py graph build myaudit --auto \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# Use the generated list (newline-separated) as a comma list for --files
./hound.py graph build myaudit --auto \
  --files "$(tr '\n' ',' < whitelists/myaudit | sed 's/,$//')"
```

- Refine existing graphs (resume building):

You can resume/refine an existing graph without creating new ones using `graph refine`. This skips discovery and saves updates incrementally.

```bash
# Refine a single graph by name (internal or display)
./hound.py graph refine myaudit SystemArchitecture \
  --iterations 2 \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"

# Refine all existing graphs
./hound.py graph refine myaudit --all --iterations 2 \
  --files "src/A.sol,src/B.sol,src/utils/Lib.sol"
```

### Step 3: Run the Audit

The audit phase uses the **senior/junior pattern** with planning and investigation:

```bash
# 1. Sweep all components for shallow bugs, build code understanding
./hound.py agent audit myaudit --mode sweep

# 2. Intuition-guided search to find complex bugs
./hound.py agent audit myaudit --mode intuition --time-limit 300

# Start with telemetry (connect the Chatbot UI to steer)
./hound.py agent audit myaudit --mode intuition --time-limit 30 --telemetry 

# Attach to an existing session and continue where you left off
./hound.py agent audit myaudit --mode intuition --session <session_id>
```

Tip: When started with `--telemetry`, you can connect the Chatbot UI and steer the audit interactively (see Chatbot section above).

**Audit Modes:**

Hound supports two distinct audit modes:

- **Sweep Mode (`--mode sweep`)**: Phase 1 - Systematic component analysis
  - Performs a broad, systematic analysis of every major component
  - Examines each contract, module, and class for vulnerabilities
  - Builds comprehensive graph annotations for later analysis
  - Terminates when all accessible components have been analyzed
  - Best for: Initial vulnerability discovery and building code understanding

- **Intuition Mode (`--mode intuition`)**: Phase 2 - Deep, targeted exploration
  - Uses intuition-guided search to find high-impact vulnerabilities
  - Prioritizes monetary flows, value transfers, and theft opportunities
  - Investigates contradictions between assumptions and observations
  - Focuses on authentication bypasses and state corruption
  - Best for: Finding complex, cross-component vulnerabilities

**Key parameters:**
- **--time-limit**: Stop after N minutes (useful for incremental audits)
- **--plan-n**: Number of investigations per planning batch
- **--session**: Resume a specific session (continues coverage/planning)
- **--debug**: Save all LLM interactions to `.hound_debug/`
- **--headless**: Run in headless mode for automated services (see below)

Normally, you want to run sweep mode first followed by intuition mode. The quality and duration depend heavily on the models used. Faster models provide quick results but may miss subtle issues, while advanced reasoning models find deeper vulnerabilities but require more time.

**Headless Mode for Automated Services:**

For CI/CD pipelines and automated monthly audits, use the `--headless` flag to run audits without human interaction:

```bash
# Run audit in headless mode (fire-and-forget)
./hound.py agent audit myaudit --headless --mode sweep --time-limit 60

# Headless audit with custom settings
./hound.py agent audit myaudit --headless --mode intuition --time-limit 120 --plan-n 10
```

Headless mode features:
- **No UI/Telemetry**: Disables the Chatbot UI and telemetry server
- **Auto-approval**: All investigation plans are automatically approved
- **Audit Logging**: Creates `audit_{project}_{timestamp}.log` in the current directory with:
  - Agent decisions and reasoning for each iteration
  - Investigation lifecycle events (start/completion)
  - Hypotheses formed during analysis
  - Final summary with coverage statistics
- **Exit Codes**: Returns non-zero exit codes for CI integration:
  - `0`: Successful completion
  - `1`: Critical failure occurred
  - `130`: Interrupted (SIGINT/Ctrl+C)

Example CI workflow:
```bash
#!/bin/bash
# Run headless audit and capture exit code
./hound.py agent audit myproject --headless --mode sweep --time-limit 30
AUDIT_EXIT=$?

if [ $AUDIT_EXIT -eq 0 ]; then
  echo "Audit completed successfully"
  # Generate report
  ./hound.py report myproject --output audit_report.html
else
  echo "Audit failed with exit code $AUDIT_EXIT"
  exit $AUDIT_EXIT
fi
```

### Step 4: Monitor Progress

Check audit progress and findings at any time during the audit. If you started the agent with `--telemetry`, you can also monitor and steer via the Chatbot UI:

- Open http://127.0.0.1:5280 and attach to the running instance
- Watch live Activity, Plan, and Findings
- Use the Steer form to guide the next investigations

```bash
# View current hypotheses (findings)
./hound.py project ls-hypotheses myaudit

# See detailed hypothesis information
./hound.py project hypotheses myaudit --details

# List hypotheses with confidence ratings
./hound.py project hypotheses myaudit

# Check coverage statistics
./hound.py project coverage myaudit

# View session details
./hound.py project sessions myaudit --list
```

**Understanding hypotheses:** Each hypothesis represents a potential vulnerability with:
- **Confidence score**: 0.0-1.0 indicating likelihood of being a real issue
- **Status**: `proposed` (initial), `investigating`, `confirmed`, `rejected`
- **Severity**: critical, high, medium, low
- **Type**: reentrancy, access control, logic error, etc.
- **Annotations**: Exact code locations and evidence

### Step 5: Run Targeted Investigations (Optional)

For specific concerns, run focused investigations without full planning:

```bash
# Investigate a specific concern
./hound.py agent investigate "Check for reentrancy in withdraw function" myaudit

# Quick investigation with fewer iterations
./hound.py agent investigate "Analyze access control in admin functions" myaudit \
  --iterations 5

# Use specific models for investigation
./hound.py agent investigate "Review emergency functions" myaudit \
  --model gpt-4o \
  --strategist-model gpt-5
```

**When to use targeted investigations:**
- Following up on specific concerns after initial audit
- Testing a hypothesis about a particular vulnerability
- Quick checks before full audit
- Investigating areas not covered by automatic planning

**Note:** These investigations still update the hypothesis store and coverage tracking.

### Step 6: Quality Assurance

A reasoning model reviews all hypotheses and updates their status based on evidence:

```bash
# Run finalization with quality review
./hound.py finalize myaudit
# Re-run all pending (including below threshold)
./hound.py finalize myaudit --include-below-threshold

# Customize confidence threshold
./hound.py finalize myaudit -t 0.7 --model gpt-4o

# Include all findings (not just confirmed)
# (Use on the report command, not finalize)
./hound.py report myaudit --all
```

**What happens during finalization:**
1. A reasoning model (default: GPT-5) reviews each hypothesis
2. Evaluates the evidence and code context
3. Updates status to `confirmed` or `rejected` based on analysis
4. Adjusts confidence scores based on evidence strength
5. Prepares findings for report generation

**Important:** By default, only `confirmed` findings appear in the final report. Use `--include-all` to include all hypotheses regardless of status.

### Step 7: Generate Proof-of-Concepts

Create and manage proof-of-concept exploits for confirmed vulnerabilities:

```bash
# Generate PoC prompts for confirmed vulnerabilities
./hound.py poc make-prompt myaudit

# Generate for a specific hypothesis
./hound.py poc make-prompt myaudit --hypothesis hyp_12345

# Import existing PoC files
./hound.py poc import myaudit hyp_12345 exploit.sol test.js \
  --description "Demonstrates reentrancy exploit"

# List all imported PoCs
./hound.py poc list myaudit
```

**The PoC workflow:**
1. **make-prompt**: Generates detailed prompts for coding agents (like Claude Code)
   - Includes vulnerable file paths (project-relative)
   - Specifies exact functions to target
   - Provides clear exploit requirements
   - Saves prompts to `poc_prompts/` directory

2. **import**: Links PoC files to specific vulnerabilities
   - Files stored in `poc/[hypothesis-id]/`
   - Metadata tracks descriptions and timestamps
   - Multiple files per vulnerability supported

3. **Automatic inclusion**: Imported PoCs appear in reports with syntax highlighting

### Step 8: Generate Professional Reports

Produce comprehensive audit reports with all findings and PoCs:

```bash
# Generate HTML report (includes imported PoCs)
./hound.py report myaudit

# Include all hypotheses, not just confirmed
./hound.py report myaudit --include-all

# Export report to specific location
./hound.py report myaudit --output /path/to/report.html
```

**Report contents:**
- **Executive summary**: High-level overview and risk assessment
- **System architecture**: Understanding of the codebase structure
- **Findings**: Detailed vulnerability descriptions (only `confirmed` by default)
- **Code snippets**: Relevant vulnerable code with line numbers
- **Proof-of-concepts**: Any imported PoCs with syntax highlighting
- **Severity distribution**: Visual breakdown of finding severities
- **Recommendations**: Suggested fixes and improvements

**Note:** The report uses a professional dark theme and includes all imported PoCs automatically.

<!-- Removed duplicate "Complete Example Workflow" in favor of the detailed Complete Audit Workflow. -->

## Session Management

Each audit run operates under a session with comprehensive tracking and per-session planning:

- Planning is stored in a per-session PlanStore with statuses: `planned`, `in_progress`, `done`, `dropped`, `superseded`.
- Existing `planned` items are executed first; Strategist only tops up new items to reach your `--plan-n`.
- On resume, any stale `in_progress` items are reset to `planned`; completed items remain `done` and are not duplicated.
- Completed investigations, coverage, and hypotheses are fed back into planning to avoid repeats and guide prioritization.

```bash
# View session details
./hound.py project sessions myaudit <session_id>

# List and inspect sessions
./hound.py project sessions myaudit --list
./hound.py project sessions myaudit <session_id>

# Show planned investigations for a session (Strategist PlanStore)
./hound.py project plan myaudit <session_id>

# Session data includes:
# - Coverage statistics (nodes/cards visited)
# - Investigation history
# - Token usage by model
# - Planning decisions
# - Hypothesis formation
```

Sessions are stored in `~/.hound/projects/myaudit/sessions/` and contain:
- `session_id`: Unique identifier
- `coverage`: Visited nodes and analyzed code
- `investigations`: All executed investigations
- `planning_history`: Strategic decisions made
- `token_usage`: Detailed API usage metrics

Resume/attach to an existing session during an audit run by passing the session ID:

```bash
# Attach to a specific session and continue auditing under it
./hound.py agent audit myaudit --session <session_id>
```

When you attach to a session, its status is set to `active` while the audit runs and finalized on completion (`completed` or `interrupted` if a time limit was hit). Any `in_progress` plan items are reset to `planned` so you can continue cleanly.

### Simple Planning Examples

```bash
# Start an audit (creates a session automatically)
./hound.py agent audit myaudit

# List sessions to get the session id
./hound.py project sessions myaudit --list

# Show planned investigations for that session
./hound.py project plan myaudit <session_id>

# Attach later and continue planning/execution under the same session
./hound.py agent audit myaudit --session <session_id>
```

## Chatbot (Telemetry UI)

Hound ships with a lightweight web UI for steering and monitoring a running audit session. It discovers local runs via a simple telemetry registry and streams status/decisions live.

Prerequisites:
- Set API keys (at least `OPENAI_API_KEY`, optional `OPENAI_BASE_URL` for custom endpoints): `source ../API_KEYS.txt` or export manually
- Install Python deps in this submodule: `pip install -r requirements.txt`

1) Start the agent with telemetry enabled

```bash
# From the hound/ directory
./hound.py agent audit myaudit --telemetry --debug

# Notes
# - The --telemetry flag exposes a local SSE/control endpoint and registers the run
# - Optional: ensure the registry dir matches the chatbot by setting:
#   export HOUND_REGISTRY_DIR="$HOME/.local/state/hound/instances"
```

2) Launch the chatbot server

```bash
# From the hound/ directory
python chatbot/run.py

# Optional: customize host/port
HOST=0.0.0.0 PORT=5280 python chatbot/run.py
```

Open the UI: http://127.0.0.1:5280

3) Select the running instance and stream activity

- The input next to “Start” lists detected instances as `project_path | instance_id`.
- Click “Start” to attach; the UI auto‑connects the realtime channel and begins streaming decisions/results.
- The lower panel has tabs:
  - Activity: live status/decisions
  - Plan: current strategist plan (✓ done, ▶ active, • pending)
  - Findings: hypotheses with confidence; you can Confirm/Reject manually

4) Steer the audit

- Use the “Steer” form (e.g., “Investigate reentrancy across the whole app next”).
- Steering is queued at `<project>/.hound/steering.jsonl` and consumed exactly once when applied.
- Broad, global instructions may preempt the current investigation and trigger immediate replanning.

Troubleshooting
- No instances in dropdown: ensure you started the agent with `--telemetry`.
- Wrong or stale project shown: clear the input; the UI defaults to the most recent alive instance.
- Registry mismatch: confirm both processes print the same `Using registry dir:` or set `HOUND_REGISTRY_DIR` for both.
- Raw API: open `/api/instances` in the browser to inspect entries (includes `alive` flag and registry path).

## Managing Hypotheses

Hypotheses are the core findings that accumulate across sessions:

```bash
# List hypotheses with confidence scores
./hound.py project hypotheses myaudit

# View with full details
./hound.py project hypotheses myaudit --details

# Update hypothesis status
./hound.py project set-hypothesis-status myaudit hyp_12345 confirmed

# Reset hypotheses (creates backup)
./hound.py project reset-hypotheses myaudit

# Force reset without confirmation
./hound.py project reset-hypotheses myaudit --force
```

Hypothesis statuses:
- **proposed**: Initial finding, needs review
- **investigating**: Under active investigation
- **confirmed**: Verified vulnerability
- **rejected**: False positive
- **resolved**: Fixed in code

## Dashboard API Server

Hound provides a FastAPI server that exposes REST and WebSocket endpoints for integration with React frontends or other clients.

### Starting the API Server

```bash
# Using the startup script (recommended)
python server/start.py

# Or with uvicorn directly
uvicorn server.api:app --host 0.0.0.0 --port 8000

# Production with workers
uvicorn server.api:app --host 0.0.0.0 --port 8000 --workers 4
```

### Configuration

Environment variables:
```bash
# Database connection (defaults to SQLite for local development)
export DATABASE_URL="sqlite:///hound.db"
# For PostgreSQL in production:
# export DATABASE_URL="postgresql://user:password@localhost/hound"

# CORS configuration (comma-separated origins, defaults to *)
export HOUND_ALLOWED_ORIGINS="http://localhost:3000,https://dashboard.example.com"

# Server settings
export HOUND_API_HOST="0.0.0.0"
export HOUND_API_PORT="8000"
```

For detailed API documentation, see [server/README.md](server/README.md).

## SaaS Worker Infrastructure

Hound includes a production-ready worker infrastructure for running audits as background tasks.

### Components

| Component | Location | Purpose |
|-----------|----------|---------|
| Celery App | `worker/celery_app.py` | Task queue configuration |
| Tasks | `worker/tasks.py` | Audit and scan task definitions |
| Redis Publisher | `worker/redis_publisher.py` | Live progress streaming |
| GitHub Auth | `integrations/github_auth.py` | GitHub App authentication |
| PR Bot | `integrations/pr_bot.py` | Post findings to PRs |
| Storage | `storage/blob_storage.py` | S3/Local file storage |

### Starting Workers

```bash
# Start Redis (required for task queue and pub/sub)
docker run -d -p 6379:6379 redis:7-alpine

# Start Celery worker
celery -A worker.celery_app worker --loglevel=info

# Optional: Start with concurrency
celery -A worker.celery_app worker --loglevel=info --concurrency=4
```

### Environment Variables

```bash
# Required
export CELERY_BROKER_URL="redis://localhost:6379/0"
export DATABASE_URL="postgresql://user:password@localhost/hound"

# GitHub App (for private repos and PR comments)
export GITHUB_APP_ID="123456"
export GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----..."
# Or use a file path:
export GITHUB_APP_PRIVATE_KEY_PATH="/path/to/private-key.pem"

# Cloud Storage (optional, for S3/MinIO)
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export S3_BUCKET="hound-artifacts"
export S3_ENDPOINT_URL="https://s3.amazonaws.com"  # Or MinIO URL
```

### Submitting Tasks

```python
from worker.tasks import execute_audit_task, execute_scan_task

# Full audit with GitHub App authentication
result = execute_audit_task.delay(
    repo_url="https://github.com/owner/repo",
    scan_id="scan_abc123",
    tenant_id=1,
    installation_id=12345678,  # GitHub App installation
    pr_number=42,              # Post findings to PR
    repo_full_name="owner/repo",
)

# Lightweight surface scan
result = execute_scan_task.delay(
    repo_url="https://github.com/owner/repo",
    scan_id="scan_xyz789",
    tenant_id=1,
    llm_budget=5,
)
```

### Live Progress Streaming

Workers publish real-time updates via Redis Pub/Sub:

```python
import redis

r = redis.Redis()
pubsub = r.pubsub()
pubsub.subscribe("audit:updates:scan_abc123")

for message in pubsub.listen():
    if message["type"] == "message":
        update = json.loads(message["data"])
        print(f"[{update['type']}] {update.get('message', '')}")
```

For detailed architecture documentation, see [docs/architecture/](docs/architecture/).

## React Dashboard

Hound includes a modern React/Next.js dashboard for managing projects and viewing audits through a professional web interface.

### Starting the Dashboard

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (first time only)
npm install

# Start development server
npm run dev

# Open browser to http://localhost:3000
```

### Dashboard Features

- **Project Management**: Browse all security audit projects with statistics
- **Session Navigation**: View and manage audit sessions for each project
- **Real-time Audit View**: Three-panel layout for comprehensive analysis
  - **Activity Panel**: Live activity log with WebSocket updates
  - **Graph Panel**: Interactive system architecture visualization using ReactFlow
  - **Findings Panel**: Security findings with confirm/reject actions

### Configuration

Create a `.env.local` file in the `frontend/` directory:

```bash
# API server URL (defaults to http://localhost:8000)
NEXT_PUBLIC_API_URL=http://localhost:8000
```

For detailed setup instructions and troubleshooting, see [frontend/README.md](frontend/README.md).

## Advanced Features

### Model Selection

Override default models per component:

```bash
# Use different models for each role
./hound.py agent audit myaudit \
  --platform openai --model gpt-4o-mini \           # Scout
  --strategist-platform anthropic --strategist-model claude-3-opus   # Strategist
```

### Debug Mode

Capture all LLM interactions for analysis:

```bash
# Enable debug logging
./hound.py agent audit myaudit --debug

# Debug logs saved to .hound_debug/
# Includes HTML reports with all prompts and responses
```

### Coverage Tracking

Monitor audit progress and completeness:

```bash
# View coverage statistics
./hound.py project coverage myaudit

# Coverage shows:
# - Graph nodes visited vs total
# - Code cards analyzed vs total
# - Percentage completion
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.
