# Eval — offline replay harness for the deep-audit curation pipeline

Replays a labeled hypothesis corpus through the production curation gates
(`_filter_template_fps`, `_quality_aware_demote`, `_detect_confabulation_pattern`)
and reports per-stage drop/demote counts. Lets us answer:

- **Did this PR help?** Compare the headline FP-filter rate before vs after.
- **Are we hurting real findings?** The "TPs incorrectly filtered" counter
  is the regression alarm.
- **What does Confab gate stamp?** Visible in the per-replay markdown.

## Quick start

```bash
cd tools/hound

# Fast offline replay (skips source-grep gates):
python -m eval.harness --offline --corpus yieldnest_scan_77

# Full replay (clones yieldnest source on first run, ~30s, cached after):
python -m eval.harness --corpus yieldnest_scan_77 --write \
  /Users/gerrithall/dev/firepan/docs/archive/dev/$(date +%Y-%m-%d)-yieldnest-eval-replay.md
```

The full replay needs an Anthropic API key in env (the verifier model). Without
one, the LLM step short-circuits with `verifier_init_failed` and only the
`_MODIFIER_HINTS` lexical shortcut runs — that still catches the obvious cases.

## Adding a new corpus

1. Write an extractor under `scripts/export_<name>_corpus.py` that queries
   the relevant `Hypothesis` rows and labels each one with `expected_fp`.
   See `scripts/export_yieldnest_corpus.py` as the template.
2. Run it via `docker compose exec -T api python -` and scp the JSONL back.
3. Commit to `eval/fixtures/<name>.jsonl` + a `.schema.md`.
4. Replay: `python -m eval.harness --corpus <name>`.

The labeling rule is corpus-specific. Yieldnest uses
`expected_fp = (status == "confirmed")` because the postmortem confirmed 0/13
TPs on confirmed. Other postmortems may need title-substring matching, manual
hypothesis_id allowlists, or a separate `triage_status` column.

## Coverage

Stages currently exercised:

| Stage | Source-needed? | First in branch |
|-------|---------------|-----------------|
| `_filter_template_fps` (8kv lexical + verifier; 7nu adds view/pure/constructor/rounding) | Yes | `feature/surface-scan` (8kv); 7nu in PR #53 |
| `_quality_aware_demote` (e5x meta-pattern demote) | No | PR #55 — harness skips with `not_in_branch` until merged |
| `_detect_confabulation_pattern` (ygy gating signal) | No | `feature/surface-scan` |

Earlier pipeline stages (raw → exact-dedup → test-filter → semantic-dedup) are
**not replayable**: the 765 raw candidates were never persisted, only the 64
dedup-survivors.

## Directory layout

```
eval/
├── __init__.py
├── corpus.py          # load_corpus(), expected_fp_ids()
├── source_repo.py     # clone-on-demand for the contract source
├── harness.py         # run_curation_pipeline() + CLI
├── metrics.py         # CurationReport + summary()
├── fixtures/
│   ├── yieldnest_scan_77.jsonl       (64 rows, 13 labeled FPs)
│   └── yieldnest_scan_77.schema.md
└── README.md
```

## Future: firepan-lg8

This harness is the seed for the planned Claude-verification pipeline
(firepan-lg8). When that lands, it'll run the same corpus through both
DeepSeek-only and Claude-senior pipelines and emit a side-by-side report.
The per-stage shape is already prepared for that — `CurationReport` carries
arbitrary stages, just push a new one for the Claude verifier.
