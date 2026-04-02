# Agent Audit API

Pay-per-audit API for external agents. No SaaS dashboard or project setup required.

## Authentication

All endpoints require a JWT bearer token in the `Authorization` header. The JWT contains `tenant_id` which scopes ownership of all resources.

```
Authorization: Bearer <jwt_token>
```

## Payment (x402)

Paid endpoints are protected by [x402](https://www.x402.org/) payment.
When x402 is enabled, the server returns `402 Payment Required` with an
`X-Payment-Requirements` header. Your x402 client library handles payment
automatically. Include an `Idempotency-Key` header on every POST to prevent
double-charges on retries.

| Route | Price | Description |
|-------|-------|-------------|
| `POST /agent/audits` | $5.00 | Deep autonomous security audit |
| `POST /agent/surface-scan` | $0.50 | Quick surface-level vulnerability scan |
| `GET /audits/{id}/report` | $0.10 | Formatted audit report |

---

## Endpoints

### Start an Audit

```
POST /agent/audits
```

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | `Bearer <jwt>` |
| `Idempotency-Key` | Yes (when x402 on) | UUID to prevent double-charge |
| `X-PAYMENT` | Yes (when x402 on) | x402 payment payload |

**Request body:**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "installation_id": 12345,
  "investigation_prompt": "Focus on authentication and authorization flaws",
  "max_iterations": 30,
  "time_limit_minutes": 120,
  "mode": "sweep",
  "plan_n": 5
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `repo_url` | string | **required** | Git HTTPS URL |
| `installation_id` | int \| null | null | GitHub App installation ID (for private repos) |
| `investigation_prompt` | string \| null | null | Custom focus area |
| `max_iterations` | int | 30 | Max agent iterations per investigation (1–200) |
| `time_limit_minutes` | int | 120 | Time budget in minutes (5–480) |
| `mode` | string | `"sweep"` | `"sweep"` (broad) or `"intuition"` (deep) |
| `plan_n` | int | 5 | Investigations per batch (1–20) |

**Response (200):**
```json
{
  "session_id": "agent_a1b2c3d4e5f6_1711929600",
  "status": "queued",
  "status_url": "/agent/audits/agent_a1b2c3d4e5f6_1711929600/status",
  "results_url": "/agent/audits/agent_a1b2c3d4e5f6_1711929600/findings",
  "message": "Audit queued. Celery task: abc-123"
}
```

**Idempotent replay (200):**
If the same `Idempotency-Key` is reused with the same request body, the
original `session_id` is returned with `"status": "already_processed"`.

---

### Poll Status

```
GET /agent/audits/{session_id}/status
```

**Response (200):**
```json
{
  "session_id": "agent_a1b2c3d4e5f6_1711929600",
  "status": "running",
  "progress": {"total_tokens": 15000, "input_tokens": 10000, "output_tokens": 5000},
  "findings_count": 3,
  "error_message": null,
  "started_at": "2026-04-01T12:00:00Z",
  "completed_at": null
}
```

**Status values:** `queued` → `running` → `completed` | `failed` | `in_review`

---

### Fetch Findings

```
GET /agent/audits/{session_id}/findings
```

**Response (200):**
```json
{
  "session_id": "agent_a1b2c3d4e5f6_1711929600",
  "findings": [
    {
      "id": 1,
      "hypothesis_id": "hyp_20260401_120000_abc123",
      "title": "SQL Injection in /api/users",
      "description": "User input is concatenated directly into SQL query...",
      "vulnerability_type": "SQL Injection",
      "status": "confirmed",
      "confidence": 0.95,
      "severity": "critical",
      "evidence": {"code_snippet": "..."},
      "created_at": "2026-04-01T12:05:00Z"
    }
  ],
  "total": 1
}
```

---

### Fetch Report

```
GET /agent/audits/{session_id}/report
```

**Response (200):**
```json
{
  "session_id": "agent_a1b2c3d4e5f6_1711929600",
  "status": "completed",
  "report_markdown": "# Security Audit Report\n\n## Summary\n...",
  "report_url": "/reports/agent_a1b2c3d4e5f6_1711929600"
}
```

If the audit is still running, `report_markdown` will be `null`.

---

### List Knowledge Graphs

```
GET /agent/audits/{session_id}/graphs
```

Returns metadata for all knowledge graphs built during the audit.
Graphs are built automatically as part of the deep audit (SystemArchitecture,
AssetFlow, PermissionChecks, etc.).

**Response (200):**
```json
{
  "session_id": "agent_a1b2c3d4e5f6_1711929600",
  "graphs": [
    {
      "id": 42,
      "name": "System Architecture",
      "internal_name": "system_architecture",
      "node_count": 156,
      "edge_count": 312,
      "node_types": ["function", "storage", "modifier", "class"],
      "edge_types": ["calls", "depends_on", "references"],
      "created_at": "2026-04-01T12:02:00Z",
      "updated_at": "2026-04-01T12:02:00Z"
    }
  ],
  "total": 3
}
```

---

### Get Full Graph Data

```
GET /agent/audits/{session_id}/graphs/{graph_id}
```

Returns the complete knowledge graph with all nodes, edges, and metadata.

**Response (200):**
```json
{
  "id": 42,
  "session_id": "agent_a1b2c3d4e5f6_1711929600",
  "name": "System Architecture",
  "internal_name": "system_architecture",
  "data": {
    "name": "System Architecture",
    "focus": "Map overall system structure",
    "nodes": [
      {
        "id": "FUNC_AUTH_PAUSE",
        "type": "function",
        "label": "Auth.pause()",
        "confidence": 1.0,
        "observations": ["only STRATEGIST_ROLE can call"],
        "source_refs": ["card_879d7f315640"]
      }
    ],
    "edges": [
      {
        "id": "edge_0cfbac88",
        "type": "grants_role",
        "source_id": "CONST_PAUSER_ROLE",
        "target_id": "FUNC_AUTH_PAUSE",
        "confidence": 1.0
      }
    ],
    "stats": {
      "num_nodes": 156,
      "num_edges": 312,
      "node_types": ["function", "storage", "modifier", "class"],
      "edge_types": ["grants_role", "requires_role", "depends_on"]
    }
  },
  "created_at": "2026-04-01T12:02:00Z",
  "updated_at": "2026-04-01T12:02:00Z"
}
```

---

### Quick Surface Scan

```
POST /agent/surface-scan
```

Fast, cheap ($0.50) surface-level scan. Runs synchronously — results are
returned in the response. Ideal as a first pass before committing to a
deep audit.

**Request body:**
```json
{
  "repo_url": "https://github.com/owner/repo",
  "llm_budget": 5,
  "model": null
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `repo_url` | string | **required** | Git HTTPS URL |
| `llm_budget` | int | 5 | Max LLM calls for verification (0 = pattern-only) |
| `model` | string \| null | null | Override LLM model |

**Response (200):**
```json
{
  "execution_id": "agent_surface_abc123_1711929600",
  "repo_url": "https://github.com/owner/repo",
  "repo_name": "repo",
  "risk_score": 65,
  "risk_level": "medium",
  "findings": [
    {
      "pattern_id": "SOL-001",
      "title": "Reentrancy in withdraw()",
      "severity": "high",
      "category": "reentrancy",
      "confidence": 0.92,
      "location": "contracts/Vault.sol:42",
      "code_snippet": "msg.sender.call{value: amount}(\"\")",
      "description": "External call before state update",
      "llm_verified": true,
      "llm_notes": "Confirmed: state is updated after external call"
    }
  ],
  "contracts_scanned": 12,
  "llm_calls_used": 3,
  "scan_duration_seconds": 8.5,
  "summary": "Found 3 issues (1 high, 2 medium)",
  "error": null
}
```

---

## Example: Full Lifecycle (curl)

```bash
# 0. Quick surface scan first ($0.50 — runs synchronously)
curl -X POST https://api.firepan.ai/agent/surface-scan \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{"repo_url": "https://github.com/owner/repo"}'

# Response: {"execution_id": "agent_surface_...", "risk_score": 65, "findings": [...]}

# 1. Start deep audit ($5.00)
curl -X POST https://api.firepan.ai/agent/audits \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{
    "repo_url": "https://github.com/owner/repo",
    "max_iterations": 20,
    "mode": "sweep"
  }'

# Response: {"session_id": "agent_abc123_1711929600", "status": "queued", ...}

# 2. Poll status (repeat until status is "completed" or "failed")
curl https://api.firepan.ai/agent/audits/agent_abc123_1711929600/status \
  -H "Authorization: Bearer $JWT"

# 3. Fetch knowledge graphs (built during the audit)
curl https://api.firepan.ai/agent/audits/agent_abc123_1711929600/graphs \
  -H "Authorization: Bearer $JWT"

# 4. Fetch a specific graph (full node/edge data)
curl https://api.firepan.ai/agent/audits/agent_abc123_1711929600/graphs/42 \
  -H "Authorization: Bearer $JWT"

# 5. Fetch findings
curl https://api.firepan.ai/agent/audits/agent_abc123_1711929600/findings \
  -H "Authorization: Bearer $JWT"

# 6. Fetch formatted report
curl https://api.firepan.ai/agent/audits/agent_abc123_1711929600/report \
  -H "Authorization: Bearer $JWT"
```

## Example: Python Client (Progressive Flow)

```python
import requests
import time
import uuid

BASE = "https://api.firepan.ai"
HEADERS = {"Authorization": f"Bearer {JWT_TOKEN}"}
REPO = "https://github.com/owner/repo"

# --- Step 1: Quick surface scan ($0.50) ---
surface = requests.post(f"{BASE}/agent/surface-scan", headers={
    **HEADERS,
    "Idempotency-Key": str(uuid.uuid4()),
}, json={"repo_url": REPO}).json()

print(f"Surface: {surface['risk_level']} ({surface['risk_score']}/100)")
print(f"  {len(surface['findings'])} findings in {surface['scan_duration_seconds']:.1f}s")

# Decide whether a deep audit is worthwhile
if surface["risk_score"] < 30:
    print("Low risk — skipping deep audit")
    exit(0)

# --- Step 2: Deep audit ($5.00) ---
resp = requests.post(f"{BASE}/agent/audits", headers={
    **HEADERS,
    "Idempotency-Key": str(uuid.uuid4()),
}, json={
    "repo_url": REPO,
    "max_iterations": 30,
})
session_id = resp.json()["session_id"]

# --- Step 3: Poll until done ---
while True:
    status = requests.get(
        f"{BASE}/agent/audits/{session_id}/status", headers=HEADERS
    ).json()
    if status["status"] in ("completed", "failed"):
        break
    time.sleep(30)

# --- Step 4: Fetch knowledge graphs ---
graphs = requests.get(
    f"{BASE}/agent/audits/{session_id}/graphs", headers=HEADERS
).json()
print(f"\n{graphs['total']} knowledge graphs built:")
for g in graphs["graphs"]:
    print(f"  {g['name']}: {g['node_count']} nodes, {g['edge_count']} edges")

# Fetch full graph data for each
for g in graphs["graphs"]:
    detail = requests.get(
        f"{BASE}/agent/audits/{session_id}/graphs/{g['id']}", headers=HEADERS
    ).json()
    nodes = detail["data"]["nodes"]
    edges = detail["data"]["edges"]
    print(f"  {g['name']}: {len(nodes)} nodes, {len(edges)} edges")

# --- Step 5: Fetch findings ---
findings = requests.get(
    f"{BASE}/agent/audits/{session_id}/findings", headers=HEADERS
).json()
print(f"\nFound {findings['total']} issues")
for f in findings["findings"]:
    print(f"  [{f['severity']}] {f['title']} (confidence: {f['confidence']})")
```

## Limitations

- Reports may not be available immediately after `completed` status; allow a few seconds.
- Knowledge graphs are available once the audit moves past the graph-building phase.
- `installation_id` is required for private repositories.
- Maximum `time_limit_minutes` is 480 (8 hours).
- Maximum `max_iterations` is 200.
- Results are scoped to the JWT tenant — other tenants cannot access your audits.
- Surface scan runs synchronously and may take 10–60 seconds depending on repo size.

## x402 Pricing

| Route | Price | Description |
|-------|-------|-------------|
| `POST /agent/surface-scan` | $0.50 | Quick surface scan (sync, immediate results) |
| `POST /agent/audits` | $5.00 | Deep audit (async, builds graphs + findings) |
| `GET /audits/{id}/report` | $0.10 | Formatted audit report |
