"""firepan-tw7: orchestrate the deep-audit curation pipeline against a labeled corpus.

The harness takes a list of hypothesis dicts (each carrying an `expected_fp`
boolean label) and runs them through the same curation gates the production
worker uses. After each gate, it counts how many `expected_fp=True` rows
the gate dropped/demoted vs. how many non-FP rows it mistakenly affected.

The output is a `CurationReport` whose `summary()` produces a markdown table
suitable for archiving under `docs/archive/dev/`.

Pipeline stages exercised (in order):
  1. _filter_template_fps   (8kv per-row + 7nu view/pure/constructor/rounding)
  2. _quality_aware_demote  (e5x meta-pattern; only if the function is present)
  3. _detect_confabulation_pattern (ygy gating signal)

Stages 1 and 3 are present on `feature/surface-scan` HEAD. Stage 2 lands with
PR #55 (firepan-e5x); the harness imports it lazily and skips when absent so
this PR can land independently.
"""
from __future__ import annotations

from importlib import import_module
from pathlib import Path

from eval.corpus import expected_fp_ids
from eval.metrics import CurationReport, StageResult


def _split_kept_dropped(
    before: list[dict], after: list[dict]
) -> tuple[set[str], set[str]]:
    """Return (kept_ids, dropped_ids) by hypothesis_id.

    Stages may mutate the rows in-place (severity-fallback / e5x demote) but
    membership in the returned list determines kept vs dropped. ID-based set
    diff handles dict re-ordering and re-wrapping.
    """
    before_ids = {h.get("hypothesis_id") or h.get("id") for h in before}
    after_ids = {h.get("hypothesis_id") or h.get("id") for h in after}
    kept = before_ids & after_ids
    dropped = before_ids - after_ids
    return kept, dropped


def _stage_metrics(
    name: str,
    before: list[dict],
    after: list[dict],
    fp_ids: set[str],
    raw_stats: dict | None = None,
) -> StageResult:
    """Build a StageResult by diffing input vs output and counting FP overlap."""
    _, dropped_ids = _split_kept_dropped(before, after)
    fps_dropped = len(dropped_ids & fp_ids)
    tps_dropped = len(dropped_ids - fp_ids)
    return StageResult(
        name=name,
        input_count=len(before),
        output_count=len(after),
        fps_dropped_or_demoted=fps_dropped,
        tps_dropped_or_demoted=tps_dropped,
        raw_stats=raw_stats or {},
    )


def _stage_metrics_demote(
    name: str,
    before: list[dict],
    after: list[dict],
    fp_ids: set[str],
    demote_threshold: float,
    raw_stats: dict | None = None,
) -> StageResult:
    """Stage that *demotes confidence* without dropping rows.

    Effective drop = "row was at confidence >= demote_threshold before, now
    below". For the headline metric we treat that as "filtered" since the
    row can no longer reach `confirmed` status without a separate per-row
    promotion.
    """
    by_id_after = {(h.get("hypothesis_id") or h.get("id")): h for h in after}
    fps_demoted = 0
    tps_demoted = 0
    for h_before in before:
        hid = h_before.get("hypothesis_id") or h_before.get("id")
        if hid not in by_id_after:
            continue  # dropped, not our concern (drops accounted upstream)
        before_conf = float(h_before.get("confidence", 0.5))
        after_conf = float(by_id_after[hid].get("confidence", before_conf))
        if before_conf >= demote_threshold > after_conf:
            if hid in fp_ids:
                fps_demoted += 1
            else:
                tps_demoted += 1

    return StageResult(
        name=name,
        input_count=len(before),
        output_count=len(after),
        fps_dropped_or_demoted=fps_demoted,
        tps_dropped_or_demoted=tps_demoted,
        raw_stats=raw_stats or {},
    )


def run_curation_pipeline(
    corpus: list[dict],
    *,
    source_path: Path | None = None,
    audit_config: dict | None = None,
    corpus_name: str = "unnamed",
) -> CurationReport:
    """Run the curation pipeline against a labeled corpus.

    Args:
        corpus: list of hypothesis dicts. Each dict should carry a stable
            `hypothesis_id` (or `id`) and a boolean `expected_fp` label.
        source_path: directory holding the original source code. If `None`,
            source-grep gates (8kv modifier check, 7nu view/pure check)
            are skipped — the gate stamps `skipped_reason="no_repo_path"`.
        audit_config: optional config dict. Mirrors the production
            `audit_config` shape — controls which gates run. Defaults to a
            sensible all-on config that uses an Anthropic verifier (so the
            self-verification guard doesn't trip).
        corpus_name: label for the report header.

    Returns:
        `CurationReport` with per-stage drop/demote counts.
    """
    fp_ids = expected_fp_ids(corpus)

    if audit_config is None:
        audit_config = {
            "deep_audit_template_fp_filter": True,
            "models": {
                "scout": {"provider": "deepseek", "model": "deepseek-chat"},
                "strategist": {"provider": "deepseek", "model": "deepseek-chat"},
                "template_verifier": {
                    "provider": "anthropic",
                    "model": "claude-sonnet-4-6",
                },
            },
        }

    # Defensive copies — we don't want to mutate the caller's corpus list.
    working = [dict(row) for row in corpus]

    report = CurationReport(
        corpus_name=corpus_name,
        input_count=len(corpus),
        expected_fp_count=len(fp_ids),
    )

    # ---------------- Stage 1: _filter_template_fps (8kv + 7nu) -------------
    from worker.tasks import _filter_template_fps

    before_stage1 = list(working)
    if source_path is None:
        report.skipped_gates.append("filter_template_fps:no_source_path")
        report.stages.append(
            StageResult(
                name="filter_template_fps",
                input_count=len(before_stage1),
                output_count=len(before_stage1),
                fps_dropped_or_demoted=0,
                tps_dropped_or_demoted=0,
                raw_stats={"skipped_reason": "no_source_path"},
            )
        )
    else:
        working, stats = _filter_template_fps(working, source_path, audit_config)
        report.stages.append(
            _stage_metrics(
                "filter_template_fps",
                before_stage1,
                working,
                fp_ids,
                raw_stats=stats,
            )
        )

    # ---------------- Stage 2: _quality_aware_demote (e5x, lazy) ------------
    quality_demote = None
    try:
        worker_tasks = import_module("worker.tasks")
        quality_demote = getattr(worker_tasks, "_quality_aware_demote", None)
    except ImportError:
        pass

    if quality_demote is None:
        report.skipped_gates.append("quality_aware_demote:not_in_branch")
        report.stages.append(
            StageResult(
                name="quality_aware_demote",
                input_count=len(working),
                output_count=len(working),
                fps_dropped_or_demoted=0,
                tps_dropped_or_demoted=0,
                raw_stats={"skipped_reason": "not_in_branch"},
            )
        )
    else:
        before_stage2 = [dict(row) for row in working]
        working, demote_stats = quality_demote(working)
        # The demote threshold from e5x's _E5X_DEMOTED_CONFIDENCE_CEILING.
        # If the constant is exposed, use it; otherwise fall back to 0.5
        # (one-tick below the historical confirm threshold).
        threshold = getattr(worker_tasks, "_E5X_DEMOTED_CONFIDENCE_CEILING", 0.4) + 0.1
        report.stages.append(
            _stage_metrics_demote(
                "quality_aware_demote",
                before_stage2,
                working,
                fp_ids,
                demote_threshold=threshold,
                raw_stats=demote_stats,
            )
        )

    # ---------------- Stage 3: _detect_confabulation_pattern (ygy) ----------
    from worker.tasks import _detect_confabulation_pattern

    flagged, reason = _detect_confabulation_pattern(working)
    report.confabulation_flagged = flagged
    report.confabulation_reason = reason
    report.stages.append(
        StageResult(
            name="detect_confabulation_pattern",
            input_count=len(working),
            output_count=len(working),
            fps_dropped_or_demoted=0,
            tps_dropped_or_demoted=0,
            raw_stats={"flagged": flagged, "reason": reason},
        )
    )

    return report


def main() -> int:
    """CLI entry: `python -m eval.harness [--corpus NAME] [--offline]`.

    Default corpus: `yieldnest_scan_77`. Default behavior: clone yieldnest
    source-on-demand via `eval.source_repo.get_yieldnest_source_path()`.
    `--offline` skips the clone (and therefore source-grep gates).
    """
    import argparse

    parser = argparse.ArgumentParser(description="Replay deep-audit curation")
    parser.add_argument("--corpus", default="yieldnest_scan_77")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip source-grep gates (no clone, faster)",
    )
    parser.add_argument(
        "--write",
        metavar="PATH",
        help="write the markdown report to PATH (default: stdout only)",
    )
    args = parser.parse_args()

    from eval.corpus import load_corpus
    from eval.source_repo import get_yieldnest_source_path

    corpus = load_corpus(args.corpus)
    if not corpus:
        print(f"[eval.harness] corpus '{args.corpus}' is empty or missing")
        return 2

    source_path: Path | None = None
    if not args.offline:
        source_path = get_yieldnest_source_path()
        if source_path is None:
            print(
                "[eval.harness] source clone unavailable — running offline-mode"
                " (source-grep gates will be skipped)"
            )

    report = run_curation_pipeline(
        corpus, source_path=source_path, corpus_name=args.corpus
    )
    out = report.summary()
    print(out)

    if args.write:
        Path(args.write).write_text(out + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
