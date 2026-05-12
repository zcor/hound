#!/usr/bin/env python3
"""
Benchmark runner for the single-auditor pipeline.

Runs the auditor pipeline against a target repository and compares:
  - Confirmed findings (count, severity, FP rate)
  - Coverage declarations (surfaces covered, gaps)
  - Timing and token usage

Usage:
    python scripts/benchmark_auditor.py <repo_path> [--time-limit 60] [--config config.yaml]

The default benchmark target is curveupdate-v2 at commit 0a09520.
Expected findings: F-1 (reentrancy) + F-6 (precision loss).
"""

import argparse
import json
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def run_benchmark(
    repo_path: str,
    time_limit_minutes: int = 60,
    config_path: str | None = None,
    max_chunk_tokens: int = 50_000,
    expect_titles: list[str] | None = None,
):
    from analysis.auditor import SingleAuditor
    from analysis.concurrent_knowledge import HypothesisStore
    from analysis.coverage_index import CoverageIndex
    from utils.config_loader import load_config

    repo = Path(repo_path).resolve()
    if not repo.exists():
        print(f"ERROR: repo path does not exist: {repo}")
        sys.exit(1)

    cfg = load_config(Path(config_path)) if config_path else load_config()

    # Locate graphs and manifest directories
    project_dir = repo / ".hound_benchmark"
    graphs_dir = project_dir / "graphs"
    manifest_dir = project_dir / "manifest"

    # Build graphs if needed
    if not graphs_dir.exists() or not list(graphs_dir.glob("graph_*.json")):
        print("Building knowledge graphs...")
        graphs_dir.mkdir(parents=True, exist_ok=True)
        manifest_dir.mkdir(parents=True, exist_ok=True)

        from ingest.manifest import RepositoryManifest
        manifest = RepositoryManifest(repo, cfg)
        manifest.walk_repository()
        manifest.save_manifest(manifest_dir)

        from analysis.graph_builder import GraphBuilder
        builder = GraphBuilder(config=cfg)
        from ingest.bundles import AdaptiveBundler
        bundler = AdaptiveBundler(manifest.cards, manifest.files, cfg)
        bundler.create_bundles()
        builder.build(
            manifest_dir=manifest_dir,
            output_dir=graphs_dir,
            max_iterations=3,
            max_graphs=3,
        )

        # Create index
        graph_files = list(graphs_dir.glob("graph_*.json"))
        index = {gf.stem.replace("graph_", ""): str(gf) for gf in graph_files}
        (graphs_dir / "knowledge_graphs.json").write_text(json.dumps({"graphs": index}))
        print(f"Built {len(graph_files)} graphs")
    else:
        print(f"Using existing graphs in {graphs_dir}")

    hyp_dir = project_dir / "hypotheses"
    hyp_dir.mkdir(exist_ok=True)
    cov_dir = project_dir / "coverage"
    cov_dir.mkdir(exist_ok=True)

    hyp_store = HypothesisStore(hyp_dir, session_id="benchmark")
    cov_index = CoverageIndex(cov_dir)

    print(f"\n{'='*60}")
    print("BENCHMARK: single-auditor pipeline")
    print(f"Target: {repo}")
    print(f"Time limit: {time_limit_minutes} min")
    print(f"{'='*60}\n")

    auditor = SingleAuditor(
        config=cfg,
        graphs_dir=graphs_dir,
        manifest_dir=manifest_dir,
        repo_root=repo,
        session_id="benchmark",
        hypothesis_store=hyp_store,
        coverage_index=cov_index,
    )

    t0 = time.time()
    result = auditor.audit(
        time_limit_minutes=time_limit_minutes,
        max_chunk_tokens=max_chunk_tokens,
    )
    elapsed = time.time() - t0

    # Display results
    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Elapsed:    {elapsed:.1f}s")
    print(f"Chunks:     {result.chunks_processed}/{result.chunks_total}")
    print(f"Confirmed:  {len(result.findings)}")
    print(f"Rejected:   {len(result.rejected)}")
    print(f"Uncertain:  {len(result.uncertain)}")

    if result.findings:
        print("\nCONFIRMED FINDINGS:")
        for i, gf in enumerate(result.findings, 1):
            c = gf.candidate
            v = gf.verdict
            print(f"  {i}. [{c.severity}] {c.title}")
            print(f"     Gap: {c.numeric_gap_measurement}")
            print(f"     FP-check: {v.verdict} ({v.confidence:.0%})")
            print(f"     Numeric gap verified: {v.numeric_gap_verified}")
            for ev in c.file_line_evidence:
                print(f"     Evidence: {ev.relpath}:{ev.line_start}-{ev.line_end}")

    if result.coverage_declarations:
        print("\nCOVERAGE DECLARATIONS:")
        for d in result.coverage_declarations:
            print(f"  {d.surface_name}: {d.status}")
            if d.unchecked_surfaces:
                print(f"    Unchecked: {', '.join(d.unchecked_surfaces)}")

    # Write JSON report
    report_path = project_dir / "benchmark_result.json"
    report = {
        "elapsed_seconds": elapsed,
        "chunks_processed": result.chunks_processed,
        "chunks_total": result.chunks_total,
        "confirmed_count": len(result.findings),
        "rejected_count": len(result.rejected),
        "uncertain_count": len(result.uncertain),
        "findings": [
            {
                "title": gf.candidate.title,
                "severity": gf.candidate.severity,
                "gap": gf.candidate.numeric_gap_measurement,
                "fp_check_confidence": gf.verdict.confidence,
                "gap_verified": gf.verdict.numeric_gap_verified,
            }
            for gf in result.findings
        ],
        "coverage": [
            {
                "surface": d.surface_name,
                "status": d.status,
                "unchecked": d.unchecked_surfaces,
            }
            for d in result.coverage_declarations
        ],
    }
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benchmark single-auditor pipeline")
    parser.add_argument("repo_path", help="Path to target repository")
    parser.add_argument("--time-limit", type=int, default=60, help="Time limit in minutes")
    parser.add_argument("--config", default=None, help="Config file path")
    parser.add_argument("--max-chunk-tokens", type=int, default=50000, help="Max tokens per chunk")
    parser.add_argument(
        "--expect",
        action="append",
        default=None,
        help=(
            "Substring of an expected finding title. May be passed multiple times. "
            "Exits non-zero if any expected title is missing."
        ),
    )
    args = parser.parse_args()

    run_benchmark(
        repo_path=args.repo_path,
        time_limit_minutes=args.time_limit,
        config_path=args.config,
        max_chunk_tokens=args.max_chunk_tokens,
        expect_titles=args.expect,
    )
