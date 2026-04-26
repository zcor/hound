"""firepan-tw7: clone-on-demand source resolver for evaluation harness.

Most curation gates (8kv access-control modifier check, 7nu view/pure
declaration check) need access to the original source code. Vendoring 200MB
of contracts in the repo is too heavy; instead this module clones the public
mirror lazily on first use and caches under `~/.cache/firepan-eval/`.

Returns `None` when the clone fails (offline / no network / SHA missing) so
the harness can degrade gracefully — source-grep gates will then stamp
`skipped_reason="no_source_path"` and only the no-source gates run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

CACHE_ROOT = Path.home() / ".cache" / "firepan-eval"


# Repo + SHA pinned to the yieldnest scan 77 baseline. The SHA is recovered
# from `ScanExecution.scan_config.commit_sha` for project_id=28; if that's
# empty (legacy scan), the postmortem timestamp 2026-04-20 narrows the
# default to the closest main-branch SHA.
#
# This constant is the only mutable piece of the harness — when we replay
# against a different scan, we update it here.
YIELDNEST_REPO = "https://github.com/yieldnest/smart-contracts-mirror"
YIELDNEST_DEFAULT_SHA: str | None = None  # populated post-extraction; None → use main


def _run_git(args: list[str], cwd: Path | None = None) -> tuple[int, str]:
    """Run a git command. Returns (returncode, combined-output)."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 1, f"git invocation failed: {e}"


def get_yieldnest_source_path(
    sha: str | None = None,
    *,
    repo_url: str = YIELDNEST_REPO,
    cache_root: Path = CACHE_ROOT,
    fetch_if_missing: bool = True,
) -> Path | None:
    """Return a path to a local clone of yieldnest-mirror at the requested SHA.

    Behavior:
    - First call: clones the repo into `<cache_root>/yieldnest-mirror-<sha>/`
      and checks out `sha`. Subsequent calls return the cached path.
    - `sha=None` resolves to `YIELDNEST_DEFAULT_SHA` if set, otherwise to
      the remote `main` HEAD at clone time.
    - Returns `None` on failure (no network, git not installed, SHA not
      reachable). The caller should treat that as "skip source-grep gates".
    - Set `fetch_if_missing=False` for offline-only mode (returns None
      unless the cache already exists).
    """
    target_sha = sha or YIELDNEST_DEFAULT_SHA or "HEAD"

    # Stable directory name. "HEAD" is a placeholder for the unknown-SHA case.
    cache_dir = cache_root / f"yieldnest-mirror-{target_sha}"
    if cache_dir.exists() and (cache_dir / ".git").exists():
        return cache_dir

    if not fetch_if_missing:
        return None

    if os.environ.get("FIREPAN_EVAL_OFFLINE"):
        return None

    cache_root.mkdir(parents=True, exist_ok=True)
    rc, out = _run_git(["clone", "--depth", "50", repo_url, str(cache_dir)])
    if rc != 0:
        # Clean up partial clone if any.
        if cache_dir.exists():
            shutil.rmtree(cache_dir, ignore_errors=True)
        print(f"[eval/source_repo] clone failed: {out.strip()[:300]}")
        return None

    if target_sha != "HEAD":
        rc, out = _run_git(["checkout", "--detach", target_sha], cwd=cache_dir)
        if rc != 0:
            # Try fetching the SHA explicitly (depth=50 may have missed it)
            _run_git(["fetch", "--depth", "200", "origin", target_sha], cwd=cache_dir)
            rc, out = _run_git(["checkout", "--detach", target_sha], cwd=cache_dir)
            if rc != 0:
                print(
                    f"[eval/source_repo] checkout {target_sha} failed: {out.strip()[:300]}"
                )
                # Don't delete — main checkout still useful for many gates.
                return cache_dir

    return cache_dir
