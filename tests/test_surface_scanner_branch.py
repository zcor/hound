"""Branch / ref support in the surface scanner.

The load-bearing concerns covered here:

1. When a ref is supplied, the GitHub tarball URL ends with the encoded ref —
   slashes in `feature/foo` must be `%2F`, not raw `/`, or GitHub treats the
   slash as a path separator and 404s.
2. A 404 from the archive endpoint is ambiguous: it can be a missing branch
   OR a private-repo auth problem. We disambiguate by probing the repo URL
   itself before raising the wrong sentinel — otherwise an authed scan of a
   private repo would mislabel a token problem as "branch not found" the
   moment a user picks a branch.
"""
from unittest.mock import MagicMock, patch

import httpx
import pytest

from analysis.surface.scanner import SurfaceScanner


def _scanner() -> SurfaceScanner:
    return SurfaceScanner(github_token="fake-token", quiet=True)


def _fake_response(status_code: int, content: bytes = b"") -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.content = content
    if status_code >= 400:
        err = httpx.HTTPStatusError(
            f"HTTP {status_code}", request=MagicMock(), response=resp
        )
        resp.raise_for_status.side_effect = err
    else:
        resp.raise_for_status.return_value = None
    return resp


def _patch_client(get_side_effect):
    """Patch httpx.Client so .get() returns the supplied side_effect (callable or list)."""
    client_instance = MagicMock()
    client_instance.__enter__ = MagicMock(return_value=client_instance)
    client_instance.__exit__ = MagicMock(return_value=False)
    if callable(get_side_effect):
        client_instance.get.side_effect = get_side_effect
    else:
        client_instance.get.side_effect = get_side_effect
    return patch("analysis.surface.scanner.httpx.Client", return_value=client_instance), client_instance


def test_fetch_github_repo_with_ref_url_encodes_slashes():
    """`feature/foo` must become `feature%2Ffoo` in the tarball URL."""
    scanner = _scanner()
    captured: list[str] = []

    def fake_get(url, headers=None, **kwargs):
        captured.append(url)
        return _fake_response(500)  # short-circuit before tarball extraction

    cm, _ = _patch_client(fake_get)
    with cm:
        with pytest.raises((ValueError, httpx.HTTPStatusError)):
            scanner._fetch_github_repo(
                "https://github.com/owner/repo", ref="feature/foo"
            )

    assert captured, "scanner did not call httpx.Client().get()"
    assert captured[0].endswith("/tarball/feature%2Ffoo"), (
        f"expected encoded ref in URL, got {captured[0]!r}"
    )


def test_fetch_github_repo_without_ref_uses_default_tarball_url():
    """No ref → URL has no /tarball/<ref> suffix."""
    scanner = _scanner()
    captured: list[str] = []

    def fake_get(url, headers=None, **kwargs):
        captured.append(url)
        return _fake_response(500)

    cm, _ = _patch_client(fake_get)
    with cm:
        with pytest.raises((ValueError, httpx.HTTPStatusError)):
            scanner._fetch_github_repo("https://github.com/owner/repo")

    assert captured[0].endswith("/owner/repo/tarball")


def test_404_with_ref_and_repo_reachable_raises_branch_not_found():
    """Tarball 404 + repo probe 200 → REPO_BRANCH_NOT_FOUND."""
    scanner = _scanner()
    responses = [
        _fake_response(404),  # archive call
        _fake_response(200, content=b'{"name": "repo"}'),  # repo probe
    ]
    cm, _ = _patch_client(responses)
    with cm:
        with pytest.raises(ValueError) as exc:
            scanner._fetch_github_repo(
                "https://github.com/owner/repo", ref="missing-branch"
            )
    assert "REPO_BRANCH_NOT_FOUND" in str(exc.value)
    assert "missing-branch" in str(exc.value)


def test_404_with_ref_and_repo_also_404_falls_through_to_auth_required():
    """Tarball 404 + repo probe 404 → REPO_AUTH_REQUIRED, not branch-not-found.

    This is the private-repo + ref case: GitHub returns 404 for both layers
    when the caller can't see the repo at all. The probe matches, so we
    correctly report it as an auth problem instead of misclassifying it.
    """
    scanner = _scanner()
    responses = [
        _fake_response(404),  # archive
        _fake_response(404),  # repo probe — also hidden
    ]
    cm, _ = _patch_client(responses)
    with cm:
        with pytest.raises(ValueError) as exc:
            scanner._fetch_github_repo(
                "https://github.com/owner/repo", ref="any-branch"
            )
    msg = str(exc.value)
    assert "REPO_AUTH_REQUIRED" in msg
    assert "REPO_BRANCH_NOT_FOUND" not in msg


def test_404_with_ref_and_repo_403_raises_token_invalid():
    """Tarball 404 + repo probe 401/403 with token → REPO_TOKEN_INVALID."""
    scanner = _scanner()
    responses = [
        _fake_response(404),  # archive
        _fake_response(403),  # repo probe says token rejected
    ]
    cm, _ = _patch_client(responses)
    with cm:
        with pytest.raises(ValueError) as exc:
            scanner._fetch_github_repo(
                "https://github.com/owner/repo", ref="any-branch"
            )
    msg = str(exc.value)
    assert "REPO_TOKEN_INVALID" in msg
    assert "REPO_BRANCH_NOT_FOUND" not in msg


def test_404_with_ref_and_probe_network_error_falls_through():
    """If the probe itself errors, we fall through to the original 404 mapping."""
    scanner = _scanner()

    call_count = {"n": 0}

    def fake_get(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _fake_response(404)
        raise httpx.RequestError("network down", request=MagicMock())

    cm, _ = _patch_client(fake_get)
    with cm:
        with pytest.raises(ValueError) as exc:
            scanner._fetch_github_repo(
                "https://github.com/owner/repo", ref="any-branch"
            )
    msg = str(exc.value)
    # With a token, original 404 maps to REPO_AUTH_REQUIRED ("not accessible
    # with current permissions"). The point is we DON'T claim branch-not-found
    # when we couldn't actually verify the repo was reachable.
    assert "REPO_BRANCH_NOT_FOUND" not in msg
    assert "REPO_AUTH_REQUIRED" in msg


def test_404_without_ref_skips_probe_and_uses_legacy_mapping():
    """No ref → no probe → existing REPO_AUTH_REQUIRED behavior is preserved."""
    scanner = _scanner()
    captured: list[str] = []

    def fake_get(url, headers=None, **kwargs):
        captured.append(url)
        return _fake_response(404)

    cm, _ = _patch_client(fake_get)
    with cm:
        with pytest.raises(ValueError) as exc:
            scanner._fetch_github_repo("https://github.com/owner/repo")
    assert "REPO_AUTH_REQUIRED" in str(exc.value)
    # Only the archive call — no repo-probe call.
    assert len(captured) == 1


def test_scan_signature_accepts_ref_kwarg():
    """`scan()` must accept ref as a keyword argument (worker calls it that way)."""
    import inspect

    sig = inspect.signature(SurfaceScanner.scan)
    assert "ref" in sig.parameters
    assert sig.parameters["ref"].default is None


def test_resolve_target_local_path_accepts_ref(tmp_path):
    """Local-path targets ignore ref but must not error."""
    scanner = _scanner()
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    path, url, cleanup = scanner._resolve_target(str(repo_dir), ref="ignored")
    assert path == repo_dir.resolve()
    assert url is None
    assert cleanup is None
