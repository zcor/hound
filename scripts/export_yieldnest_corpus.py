#!/usr/bin/env python3
"""
firepan-tw7: one-shot extractor for the yieldnest scan 77 evaluation corpus.

Reads `Hypothesis` rows under tenant 17 / project 28 (yieldnest-audit77-archive)
and dumps them to JSONL with manually-curated `expected_fp` labels lifted from
the postmortem at:
  docs/archive/dev/2026-04-21-deepseek-deep-audit-false-positive-postmortem.md

Run via `docker compose exec -T api`:

    docker compose -f /opt/hound/docker-compose.yml exec -T api \\
      python scripts/export_yieldnest_corpus.py > /tmp/yieldnest_scan_77.jsonl

scp the JSONL back to local and commit to
`tools/hound/eval/fixtures/yieldnest_scan_77.jsonl`.

The extractor performs READ-ONLY queries (`db.query(...)`) — no writes, no
transactions, safe to run against production. It also fetches the related
`ScanExecution.scan_config` so we can pin the source SHA in the harness if
the column is populated.
"""
from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable
from typing import Any


# ---------------------------------------------------------------------------
# FP labeling rule.
#
# Per the postmortem (docs/archive/dev/2026-04-21-deepseek-deep-audit-false-
# positive-postmortem.md): the corpus contains exactly 13 hypotheses with
# status="confirmed", and the manual reviewer determined every one of them is
# a false positive. So `expected_fp = (status == "confirmed")` is exact.
#
# This rule is corpus-specific — the yieldnest scan happened to produce 0/13
# TPs on confirmed. Other corpora (e.g. Curve postmortem) will need different
# labeling. We keep the labeling code per-extractor rather than per-table so
# each corpus can encode its own ground truth.
# ---------------------------------------------------------------------------
def _label_row(status: str | None) -> tuple[bool, str | None]:
    """Returns (expected_fp, reason).

    For yieldnest: every status="confirmed" row is a false positive (postmortem
    determined 0/13 TP rate on confirmed). The reason field summarizes the
    typical pattern but is not row-specific — the postmortem table at the
    top of the postmortem doc has per-row reasons if needed.
    """
    if status == "confirmed":
        return (
            True,
            "All confirmed findings on yieldnest scan 77 were classified as "
            "false positives by manual review (0/13 TP rate). See postmortem "
            "table for per-row diagnosis.",
        )
    return (False, None)


# Tenant + project IDs from the postmortem and HANDOFF/MEMORY notes.
TENANT_ID = 17
PROJECT_ID = 28


def _row_to_dict(hyp: Any, expected_fp: bool, fp_reason: str | None) -> dict:
    """Materialize a Hypothesis SQLAlchemy row into the JSONL row shape."""
    return {
        "hypothesis_id": hyp.hypothesis_id,
        "title": hyp.title,
        "description": hyp.description,
        "vulnerability_type": hyp.vulnerability_type,
        "status": hyp.status,
        "confidence": float(hyp.confidence) if hyp.confidence is not None else None,
        "severity": hyp.severity,
        "node_refs": list(hyp.node_refs or []),
        "evidence": hyp.evidence or {},
        "junior_model": hyp.junior_model,
        "senior_model": hyp.senior_model,
        "reported_by_model": hyp.reported_by_model,
        "expected_fp": expected_fp,
        "fp_reason": fp_reason,
    }


EXPECTED_FP_COUNT = 13  # Per the yieldnest postmortem table.


def main() -> int:
    """Entry point. Reads DATABASE_URL from env, queries hypotheses, prints JSONL."""
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print(
            "[export_yieldnest_corpus] DATABASE_URL env var is required.",
            file=sys.stderr,
        )
        return 2

    # Imports are deferred so the module is importable for tests without a DB.
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from database.models import Hypothesis, ScanExecution

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Fetch the corpus.
        hypotheses: Iterable[Hypothesis] = (
            db.query(Hypothesis)
            .filter(Hypothesis.project_id == PROJECT_ID)
            .order_by(Hypothesis.id.asc())
            .all()
        )

        rows: list[dict] = []
        labeled_count = 0
        for hyp in hypotheses:
            expected_fp, fp_reason = _label_row(hyp.status)
            if expected_fp:
                labeled_count += 1
            rows.append(_row_to_dict(hyp, expected_fp, fp_reason))

        # Diagnostic — go to stderr so JSONL on stdout stays clean.
        print(
            f"[export_yieldnest_corpus] {len(rows)} rows extracted, "
            f"{labeled_count} labeled as expected_fp",
            file=sys.stderr,
        )
        if labeled_count != EXPECTED_FP_COUNT:
            print(
                f"[export_yieldnest_corpus] WARN: expected {EXPECTED_FP_COUNT} "
                f"FP labels (= confirmed-status rows per postmortem), matched "
                f"{labeled_count}. The corpus may have been updated.",
                file=sys.stderr,
            )

        # Also surface the source SHA from the most recent scan on this project.
        scan = (
            db.query(ScanExecution)
            .filter(ScanExecution.project_id == PROJECT_ID)
            .order_by(ScanExecution.id.desc())
            .first()
        )
        if scan and isinstance(scan.scan_config, dict):
            commit_sha = scan.scan_config.get("commit_sha") or scan.scan_config.get(
                "sha"
            )
            print(
                f"[export_yieldnest_corpus] scan_config commit_sha: {commit_sha or 'NOT SET'}",
                file=sys.stderr,
            )

        # Emit JSONL on stdout.
        for row in rows:
            print(json.dumps(row, default=str))

    finally:
        db.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
