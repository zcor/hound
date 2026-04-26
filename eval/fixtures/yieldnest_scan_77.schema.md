# yieldnest_scan_77.jsonl — schema

64 hypothesis dicts archived from production scan 77 (project_id=28, tenant_id=17,
"yieldnest-audit77-archive"). One JSON object per line.

Source extractor: `tools/hound/scripts/export_yieldnest_corpus.py`.

## Fields

| Field | Type | Notes |
|-------|------|-------|
| `hypothesis_id` | string | Stable unique ID. Use as the dedup/lookup key in the harness. |
| `title` | string | Short title (≤ 512 chars per DB schema). |
| `description` | string | Full description as written by the model. |
| `vulnerability_type` | string | Free-text label (e.g. `"access_control"`, `"reentrancy"`). |
| `status` | string | `"confirmed"` or `"uncertain"`. **In yieldnest, every `confirmed` row is a labeled FP.** |
| `confidence` | float | 0.0–1.0. All 13 FPs are at 0.9. |
| `severity` | string | `"low"` / `"medium"` / `"high"` / `"critical"`. |
| `node_refs` | list[string] | Knowledge-graph node IDs the hypothesis references. |
| `evidence` | dict | Evidence JSONB blob. |
| `junior_model` | string | Model that generated the candidate. **All yieldnest rows: `deepseek:deepseek-chat`.** |
| `senior_model` | string | Model that verified. **All yieldnest rows: `deepseek:deepseek-chat`** — the self-verification problem the postmortem flagged. |
| `reported_by_model` | string | Legacy field; either junior or senior. |
| `expected_fp` | bool | **Ground-truth label.** `true` for the 13 confirmed-status rows (= postmortem table); `false` for the 51 uncertain rows. |
| `fp_reason` | string \| null | Free-text reason; `null` when `expected_fp=false`. |

## Counts

- Total rows: 64
- `expected_fp=True`: 13 (all status=`confirmed`)
- `expected_fp=False`: 51 (all status=`uncertain`)
- Confabulation-detector trigger condition met (10/13 ≥ 0.5): yes.

## Re-extraction

To refresh the fixture from production (e.g., after schema changes):

```bash
# On droplet, via the existing api container:
cat /opt/hound/scripts/export_yieldnest_corpus.py | \
  docker compose -f /opt/hound/docker-compose.yml exec -T api python - \
  > /tmp/yieldnest_scan_77.jsonl

# Then scp back and commit.
```

The extractor performs only `db.query(...)` — read-only, safe to run against
production.

## Provenance

Postmortem: `docs/archive/dev/2026-04-21-deepseek-deep-audit-false-positive-postmortem.md`.
