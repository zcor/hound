# Quick Start Guide

This quick start guide helps you get up and running with Hound in minutes.

## Choose Your Mode

### Option 1: CLI Mode (Recommended for Beginners)

**Best for:** Individual developers, local security audits

1. **Install:**
   ```bash
   git clone https://github.com/firepan-labs/hound.git
   cd hound
   pip install -r requirements.txt
   ```

2. **Configure API keys:**
   ```bash
   # Use OpenAI (requires API key)
   export OPENAI_API_KEY="sk-..."
   
   # OR use DeepSeek (cost-effective alternative)
   export DEEPSEEK_API_KEY="..."
   ```

3. **Run your first audit:**
   ```bash
   # Create a project
   ./hound.py project create myaudit /path/to/your/code
   
   # Build knowledge graphs (5-10 min)
   ./hound.py graph build myaudit --auto --iterations 3
   
   # Run security audit (15-30 min)
   ./hound.py agent audit myaudit --mode sweep --time-limit 30
   
   # Generate report
   ./hound.py report myaudit
   ```

4. **View results:**
   - Report saved to `report_myaudit.html`
   - Open in browser to see findings

### Option 2: Docker Mode (Full Stack)

**Best for:** Teams, production deployments, CI/CD integration

1. **Setup:**
   ```bash
   git clone https://github.com/firepan-labs/hound.git
   cd hound
   cp .env.example .env
   # Edit .env with your API keys
   ```

2. **Start services:**
   ```bash
   docker compose up -d
   ```

3. **Access interfaces:**
   - API: http://localhost:8000
   - Dashboard: http://localhost:3000
   - API Docs: http://localhost:8000/docs

4. **Create project via API:**
   ```bash
   curl -X POST http://localhost:8000/projects \
     -H "Content-Type: application/json" \
     -d '{"name": "myaudit", "source_path": "/path/to/code"}'
   ```

## Basic Workflow

### 1. Create Project
```bash
./hound.py project create myaudit /path/to/code
```

Projects organize all audit data:
- Knowledge graphs
- Security findings
- Session history
- Coverage tracking

### 2. Build Graphs
```bash
./hound.py graph build myaudit --auto --iterations 3
```

Graphs provide structural understanding:
- System architecture
- Control flow
- Data flow
- Access control

**Tip:** Use `--files` to focus on specific files:
```bash
./hound.py graph build myaudit --auto \
  --files "src/Token.sol,src/Vault.sol"
```

### 3. Run Audit

**Phase 1: Sweep (broad coverage)**
```bash
./hound.py agent audit myaudit --mode sweep
```
- Analyzes all components systematically
- Builds comprehensive coverage
- Finds surface-level issues

**Phase 2: Intuition (deep investigation)**
```bash
./hound.py agent audit myaudit --mode intuition --time-limit 60
```
- Hypothesis-driven exploration
- Focuses on high-risk areas
- Finds complex vulnerabilities

### 4. Review Findings
```bash
# List findings
./hound.py project hypotheses myaudit

# Get details
./hound.py project hypotheses myaudit --details
```

Each finding includes:
- Severity (critical, high, medium, low)
- Confidence score (0.0-1.0)
- Evidence (code snippets, reasoning)
- Status (proposed, investigating, confirmed, rejected)

### 5. Quality Review
```bash
./hound.py finalize myaudit
```
A reasoning model reviews all findings to confirm or reject them.

### 6. Generate Report
```bash
./hound.py report myaudit --output audit_report.html
```

Report includes:
- Executive summary
- Confirmed findings
- Code snippets
- Recommendations

## Interactive Monitoring

Start audit with telemetry to monitor progress:

```bash
# Terminal 1: Start audit with telemetry
./hound.py agent audit myaudit --telemetry --time-limit 30

# Terminal 2: Start chatbot UI
python chatbot/run.py
```

Open http://127.0.0.1:5280 to:
- Watch live progress
- See findings in real-time
- Steer investigation direction

## Common Commands

### Project Management
```bash
# List projects
./hound.py project ls

# Get project info
./hound.py project info myaudit

# View coverage
./hound.py project coverage myaudit

# List sessions
./hound.py project sessions myaudit --list
```

### Graph Operations
```bash
# List graphs
./hound.py graph ls myaudit

# Visualize graph
./hound.py graph visualize myaudit SystemArchitecture

# Refine existing graph
./hound.py graph refine myaudit SystemArchitecture --iterations 2
```

### Targeted Investigation
```bash
# Investigate specific concern
./hound.py agent investigate \
  "Check for reentrancy in withdraw functions" \
  myaudit
```

### Proof of Concept
```bash
# Generate PoC prompts
./hound.py poc make-prompt myaudit

# Import PoC files
./hound.py poc import myaudit hyp_12345 exploit.sol \
  --description "Reentrancy exploit"
```

## Configuration

### Cost Optimization

**Use DeepSeek (cheapest):**
```bash
export DEEPSEEK_API_KEY="..."
./hound.py agent audit myaudit \
  --platform deepseek \
  --model deepseek-chat
```

**Hybrid approach (balance cost/quality):**
```yaml
# config.yaml
scout:
  platform: deepseek
  model: deepseek-chat
  
strategist:
  platform: openai
  model: gpt-4o
```

### Model Selection

**For fast, cheap audits:**
- Scout: GPT-4o-mini or DeepSeek
- Strategist: GPT-4o

**For thorough, high-quality audits:**
- Scout: GPT-4o
- Strategist: GPT-5 or Claude Opus

**Override per audit:**
```bash
./hound.py agent audit myaudit \
  --model gpt-4o-mini \
  --strategist-model gpt-5
```

## API Integration

### Using the REST API

```python
import requests

# Create project
response = requests.post(
    "http://localhost:8000/projects",
    json={
        "name": "myaudit",
        "source_path": "/path/to/code"
    }
)
project_id = response.json()["id"]

# Start audit
response = requests.post(
    f"http://localhost:8000/projects/{project_id}/sessions",
    json={
        "mode": "intuition",
        "time_limit": 1800
    }
)
session_id = response.json()["id"]

# Monitor via WebSocket
import websockets
import asyncio

async def monitor():
    uri = f"ws://localhost:8000/ws/audits/{session_id}"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            print(f"Update: {message}")

asyncio.run(monitor())
```

### Using Celery Workers

```python
from worker.tasks import execute_audit_task

# Submit audit task
result = execute_audit_task.delay(
    repo_url="https://github.com/owner/repo",
    scan_id="scan_123",
    tenant_id=1
)

# Check status
print(f"Task ID: {result.task_id}")
print(f"Status: {result.status}")
```

## Troubleshooting

### Issue: "Module not found"
```bash
# Ensure you're in project root
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Issue: "API key not found"
```bash
# Check environment variables
echo $OPENAI_API_KEY
echo $DEEPSEEK_API_KEY

# Or set them
export OPENAI_API_KEY="sk-..."
```

### Issue: "Database connection failed"
```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Verify DATABASE_URL
echo $DATABASE_URL
```

### Issue: "Graph building takes too long"
```bash
# Use file whitelist to reduce scope
./hound.py graph build myaudit --auto \
  --files "src/core.sol,src/vault.sol" \
  --iterations 2
```

### Issue: "Too expensive"
```bash
# Use DeepSeek (10x cheaper)
export DEEPSEEK_API_KEY="..."
./hound.py agent audit myaudit \
  --platform deepseek \
  --time-limit 15  # Shorter time = lower cost
```

## Next Steps

### Learn More
- [Developer Guide](DEVELOPER_GUIDE.md) - Development setup
- [API Reference](API_REFERENCE.md) - Complete API docs
- [Architecture](ARCHITECTURE.md) - System design
- [Module Docs](MODULES.md) - Code reference

### Advanced Features
- **Headless mode:** Automate audits in CI/CD
- **Surface scans:** Quick lightweight security checks
- **PR bot:** Automatic PR comments with findings
- **Custom graphs:** Build domain-specific graphs

### Examples

**Surface scan (fast, lightweight):**
```bash
./hound.py scan surface myaudit --llm-budget 5
```

**Headless audit (CI/CD):**
```bash
./hound.py agent audit myaudit \
  --headless \
  --mode sweep \
  --time-limit 30
```

**Custom graph:**
```bash
./hound.py graph custom myaudit \
  "Token economics and fee distribution analysis" \
  --iterations 3
```

## Best Practices

### 1. Start Small
- Begin with a focused file set
- Run short audits (15-30 min)
- Iterate and expand

### 2. Use Whitelists
```bash
# Focus on core contracts only
./hound.py graph build myaudit --auto \
  --files "src/Core.sol,src/Token.sol"
```

### 3. Monitor Costs
- Check token usage: `./hound.py project sessions myaudit <session_id>`
- Use cheaper models for exploration
- Set time limits to control spending

### 4. Iterate
- Run sweep first for coverage
- Then intuition for depth
- Review and rerun if needed

### 5. Review Findings
- Don't trust all findings blindly
- Check confidence scores
- Verify with manual review
- Use finalize for QA

## Tips

- **Save API keys:** Store in `API_KEYS.txt` (gitignored) and source it
- **Debug mode:** Use `--debug` to save all LLM interactions
- **Telemetry:** Use `--telemetry` to monitor live progress
- **Session resume:** Use `--session <id>` to continue an audit
- **Parallel scans:** Run multiple projects simultaneously

## Getting Help

- **Documentation:** Start with [docs/README.md](README.md)
- **GitHub Issues:** Report bugs or request features
- **Examples:** Check `examples/` directory
- **Community:** Join discussions on GitHub

## Cost Estimates

**Small project (~1K LOC):**
- DeepSeek: $0.10-$0.50
- GPT-4o: $1-$5
- Claude: $2-$10

**Medium project (~5K LOC):**
- DeepSeek: $0.50-$2
- GPT-4o: $5-$20
- Claude: $10-$50

**Large project (~20K LOC):**
- DeepSeek: $2-$10
- GPT-4o: $20-$100
- Claude: $50-$200

**Tips to reduce costs:**
1. Use file whitelists
2. Shorter time limits
3. DeepSeek for exploration
4. Advanced models only for strategist

## Quick Reference

**Essential commands:**
```bash
# Setup
./hound.py project create NAME PATH

# Analyze
./hound.py graph build NAME --auto
./hound.py agent audit NAME --mode sweep

# Review
./hound.py project hypotheses NAME
./hound.py finalize NAME
./hound.py report NAME

# Monitor
./hound.py project coverage NAME
./hound.py project sessions NAME --list
```

**Environment variables:**
```bash
OPENAI_API_KEY         # OpenAI API key
ANTHROPIC_API_KEY      # Anthropic API key
DEEPSEEK_API_KEY       # DeepSeek API key
DATABASE_URL           # PostgreSQL connection
CELERY_BROKER_URL      # Redis for Celery
HOUND_ADMIN_KEY        # API admin password
```

## Summary

Hound provides:
✅ Autonomous security analysis  
✅ Knowledge graph reasoning  
✅ Multi-agent architecture  
✅ Cost-efficient operation  
✅ CLI and API interfaces  
✅ Real-time monitoring  
✅ Professional reports  

Get started in 3 steps:
1. Install and configure API keys
2. Create project and build graphs
3. Run audit and review findings

**Happy hunting! 🔍**
