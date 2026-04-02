---
name: firepan-agent-api
description: Use when an agent needs to use the FirePan production API end-to-end, including JWT auth, x402 payment, quick surface scans, deep audits, status polling, findings retrieval, report retrieval, and audit graph access. Supports both external agent usage and server-local testing from a FirePan host with the hound-api container.
---

# FirePan Agent API

Use this skill when an agent needs to call the FirePan API directly instead of going through the SaaS dashboard.

Default production base URL:
- `https://api.firepan.com`

Read [references/agent_api.md](references/agent_api.md) when you need exact request or response shapes.

## Core Rules

- Every endpoint requires `Authorization: Bearer <jwt>`.
- Every paid `POST` must include `Idempotency-Key`.
- x402-protected routes return `402 Payment Required` with `X-Payment-Requirements`.
- Private repos require `installation_id`.
- Preferred flow is:
  1. surface scan first
  2. deep audit only if warranted
  3. poll status
  4. fetch findings, report, and graphs

## Auth Modes

Use one of these modes:

- External agent mode:
  - the caller already has a valid JWT
  - the caller already has an x402 wallet or payment client
- FirePan host mode:
  - use `scripts/generate_local_jwt.sh` to mint a JWT from `tenant_id` and `user_id`
  - use `scripts/create_agent_test_wallet.sh` to create a Base wallet JSON file for testing
  - use the bundled paid-request helpers, which execute inside `hound-api`

## Bundled Scripts

These scripts are for server-local testing and operations on a FirePan host.

Generate a JWT from the running API container:

```bash
bash scripts/generate_local_jwt.sh 49 24
```

Create a test wallet file:

```bash
bash scripts/create_agent_test_wallet.sh
```

Run the cheapest real paid check:

```bash
JWT_TOKEN="$(bash scripts/generate_local_jwt.sh 49 24)" \
bash scripts/firepan_surface_scan.sh ./.firepan-agent-wallet.json https://github.com/assune-hue/bad-solidity-contracts.git
```

Start a deep audit:

```bash
JWT_TOKEN="$(bash scripts/generate_local_jwt.sh 49 24)" \
MAX_ITERATIONS=20 \
MODE=sweep \
bash scripts/firepan_start_audit.sh ./.firepan-agent-wallet.json https://github.com/owner/repo.git
```

Fetch read-only resources:

```bash
JWT_TOKEN="..." \
bash scripts/firepan_get.sh https://api.firepan.com/agent/audits/<session_id>/status
```

Use `firepan_get.sh` for:
- `/agent/audits/{session_id}/status`
- `/agent/audits/{session_id}/findings`
- `/agent/audits/{session_id}/graphs`
- `/agent/audits/{session_id}/graphs/{graph_id}`

Use `firepan_paid_request.sh` directly for routes that may return `402`, including report retrieval:

```bash
JWT_TOKEN="..." \
WALLET_PRIVATE_KEY="0x..." \
bash scripts/firepan_paid_request.sh GET https://api.firepan.com/agent/audits/<session_id>/report
```

## Recommended Workflow

1. Acquire JWT.
2. Acquire wallet or payment client.
3. Run `POST /agent/surface-scan`.
4. If the repo merits deeper work, run `POST /agent/audits`.
5. Poll `/agent/audits/{session_id}/status` until `completed` or `failed`.
6. Fetch:
   - `/findings`
   - `/report`
   - `/graphs`
   - `/graphs/{graph_id}`

## Practical Notes

- Use a fresh `Idempotency-Key` for each distinct paid request.
- Reuse the same `Idempotency-Key` only when retrying the exact same request.
- Surface scan is synchronous and cheapest.
- Deep audit is asynchronous and produces graphs plus findings.
- If a route unexpectedly returns `401`, verify the JWT tenant and expiration first.
- If a private repo fails to clone, verify `installation_id`.

## When To Read References

Read [references/agent_api.md](references/agent_api.md) when you need:
- exact endpoint inventory
- request body fields
- sample payloads
- status lifecycle
- pricing summary
