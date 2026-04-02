# FirePan Agent API Reference

Base URL:
- `https://api.firepan.com`

Authentication:
- `Authorization: Bearer <jwt>`

x402 behavior:
- Paid routes respond with `402 Payment Required` and `X-Payment-Requirements`
- Paid `POST` requests require `Idempotency-Key`

## Paid Routes

| Route | Price | Notes |
|-------|-------|-------|
| `POST /agent/surface-scan` | `$0.50` | synchronous, immediate results |
| `POST /agent/audits` | `$5.00` | async deep audit |
| `GET /agent/audits/{session_id}/report` | may be x402-protected | use paid helper if needed |

## Surface Scan

Route:
- `POST /agent/surface-scan`

Body:

```json
{
  "repo_url": "https://github.com/owner/repo.git",
  "llm_budget": 1,
  "model": null
}
```

Key response fields:
- `execution_id`
- `risk_score`
- `risk_level`
- `findings`
- `contracts_scanned`
- `llm_calls_used`
- `summary`

## Deep Audit

Route:
- `POST /agent/audits`

Body:

```json
{
  "repo_url": "https://github.com/owner/repo.git",
  "installation_id": null,
  "investigation_prompt": null,
  "max_iterations": 30,
  "time_limit_minutes": 120,
  "mode": "sweep",
  "plan_n": 5
}
```

Key response fields:
- `session_id`
- `status`
- `status_url`
- `results_url`

## Read Endpoints

Use JWT only:
- `GET /agent/audits/{session_id}/status`
- `GET /agent/audits/{session_id}/findings`
- `GET /agent/audits/{session_id}/graphs`
- `GET /agent/audits/{session_id}/graphs/{graph_id}`

The report route may require payment in some deployments:
- `GET /agent/audits/{session_id}/report`

## Status Lifecycle

Typical status progression:
- `queued`
- `running`
- `completed`
- `failed`
- `in_review`

## Minimal Usage Pattern

1. Run surface scan.
2. If risk is meaningful, start deep audit.
3. Poll status.
4. Retrieve findings and graphs.
5. Retrieve report if needed.
