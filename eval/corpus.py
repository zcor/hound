"""firepan-tw7: corpus loader for evaluation harness fixtures.

Fixtures live under `eval/fixtures/<name>.jsonl`, each line a JSON object
matching the shape documented in `<name>.schema.md`.
"""
from __future__ import annotations

import json
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_corpus(name: str) -> list[dict]:
    """Load `eval/fixtures/<name>.jsonl` as a list of hypothesis dicts.

    Returns an empty list if the fixture is missing — callers can decide
    whether to fail or skip. Raises `json.JSONDecodeError` if the file is
    present but malformed (corrupt fixture should fail loudly).
    """
    path = FIXTURES_DIR / f"{name}.jsonl"
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open() as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def expected_fp_ids(corpus: list[dict]) -> set[str]:
    """Set of hypothesis_ids labeled `expected_fp=True` in the corpus."""
    return {
        row["hypothesis_id"]
        for row in corpus
        if row.get("expected_fp") and row.get("hypothesis_id")
    }


def fixture_path(name: str) -> Path:
    """Return the absolute path to a fixture (whether or not it exists)."""
    return FIXTURES_DIR / f"{name}.jsonl"
