"""firepan-tw7: offline evaluation harness for the deep-audit curation pipeline.

The corpus archived under `eval/fixtures/` contains real false-positive
examples from production scans (yieldnest scan 77, 2026-04-20). The harness
re-runs the curation steps (template-FP filter, quality-aware demote,
confabulation detector) against this corpus and reports how many of the
labeled FPs each gate caught.

Usage:
    from eval.harness import run_curation_pipeline
    from eval.corpus import load_corpus

    corpus = load_corpus("yieldnest_scan_77")
    report = run_curation_pipeline(corpus, source_path=None)
    print(report.summary())

See `eval/README.md` for the full guide.
"""
