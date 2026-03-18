"""Regression tests for surface scanner type annotations."""
import typing


def test_surface_scanner_import():
    """Importing SurfaceScanner must not raise TypeError (regression for callable | None bug)."""
    from analysis.surface.scanner import SurfaceScanner
    assert SurfaceScanner is not None


def test_resolve_target_type_hints():
    """Type hints on _resolve_target must be evaluable (catches invalid annotations)."""
    from analysis.surface.scanner import SurfaceScanner
    hints = typing.get_type_hints(SurfaceScanner._resolve_target)
    assert "return" in hints


def test_fetch_github_repo_type_hints():
    """Type hints on _fetch_github_repo must be evaluable."""
    from analysis.surface.scanner import SurfaceScanner
    hints = typing.get_type_hints(SurfaceScanner._fetch_github_repo)
    assert "return" in hints


def test_surface_scanner_prefers_explicit_github_token(monkeypatch):
    """Explicit constructor token should override the process-wide fallback."""
    from analysis.surface.scanner import SurfaceScanner

    monkeypatch.setenv("GITHUB_TOKEN", "env-token")
    scanner = SurfaceScanner(github_token="explicit-token")

    assert scanner.github_token == "explicit-token"
