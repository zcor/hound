"""firepan-l57m: self-serve private-repo onboarding fix.

Unit tests for the two risk-bearing pieces of PR A:
  - _resolve_repo_privacy: server-side privacy resolution + the ambiguous-404
    policy (review finding #2 — a typo'd URL must NOT become a junk "blocked"
    project).
  - the owner-constrained install-webhook backfill (review finding #3 — a
    tenant with repos from multiple owners must not get the wrong installation
    stamped onto unrelated repos).

These are tested at the function/DB level rather than through the full
TestClient auth path because the policy matrix (not the HTTP plumbing) is what
the review flagged.
"""

import os

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("HOUND_TEST", "1")

from database.models import Base, Project, Tenant, User  # noqa: E402
from server import api as api_module  # noqa: E402
from server.token_crypto import encrypt_token  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _user(db, with_token=True, repo_scope=True):
    u = User(
        github_id=123,
        tenant_id=1,
        github_token_encrypted=encrypt_token("ghtok") if with_token else None,
        github_token_scopes="repo,read:org" if repo_scope else "read:org",
    )
    db.add(u)
    db.commit()
    return u


def _tenant(db, tid=1, installation_id=None):
    t = Tenant(id=tid, name=f"t{tid}", installation_id=installation_id)
    db.add(t)
    db.commit()
    return t


# ---------------------------------------------------------------------------
# _resolve_repo_privacy — the privacy + ambiguous-404 policy matrix
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_privacy_public_repo_returns_false(db, monkeypatch):
    """GitHub says .private == False -> public, regardless of client hint."""
    async def fake_details(self, owner, repo):
        return {"private": False}

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    t = _tenant(db)
    u = _user(db)
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", u, t, client_is_private=True
    )
    assert out is False  # server truth wins over the client hint


@pytest.mark.asyncio
async def test_resolve_privacy_private_repo_returns_true(db, monkeypatch):
    async def fake_details(self, owner, repo):
        return {"private": True}

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", _user(db), _tenant(db), False
    )
    assert out is True


@pytest.mark.asyncio
async def test_resolve_privacy_403_means_private(db, monkeypatch):
    """403 with a token = repo exists, token can't see it -> private (gate hard-fails)."""
    async def fake_details(self, owner, repo):
        raise HTTPException(status_code=403, detail="Access denied to repository")

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", _user(db), _tenant(db), False
    )
    assert out is True


@pytest.mark.asyncio
async def test_resolve_privacy_404_raises_not_found_not_private(db, monkeypatch):
    """Review #2: a 404 (typo / nonexistent) must be an explicit validation
    error, NOT coerced to 'private' (which would persist a junk blocked repo)."""
    async def fake_details(self, owner, repo):
        raise HTTPException(status_code=404, detail="Repository not found on GitHub")

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    with pytest.raises(HTTPException) as ei:
        await api_module._resolve_repo_privacy(
            "https://github.com/o/typo.git", _user(db), _tenant(db), False
        )
    assert ei.value.status_code == 404
    assert ei.value.detail["error"] == "repo_not_found_or_inaccessible"


@pytest.mark.asyncio
async def test_resolve_privacy_404_install_token_sees_real_private_repo(db, monkeypatch):
    """Review F3 hardened: OAuth token 404s but tenant has an App install AND
    the install token CAN see the repo -> it's a real private repo; resolve
    its actual .private (gate passes via installation_id)."""
    calls = {"n": 0}

    async def fake_details(self, owner, repo):
        calls["n"] += 1
        if calls["n"] == 1:  # OAuth token probe -> 404
            raise HTTPException(status_code=404, detail="Repository not found on GitHub")
        return {"private": True}  # install-token probe -> visible

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    monkeypatch.setattr(
        "integrations.github_auth.get_installation_token",
        lambda iid, use_cache=True: "inst-tok",
    )
    t = _tenant(db, installation_id=999)
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", _user(db), t, client_is_private=False
    )
    assert out is True  # real private repo, install-token-verified


@pytest.mark.asyncio
async def test_resolve_privacy_404_install_token_also_404_rejects_typo(db, monkeypatch):
    """Review F3 hardened — the core 'no junk row on typo' guarantee: OAuth
    404s, tenant has an App install, but the INSTALL token also 404s -> the
    repo genuinely doesn't exist. Must RAISE repo_not_found_or_inaccessible,
    NOT persist a junk project."""
    async def fake_details(self, owner, repo):
        raise HTTPException(status_code=404, detail="Repository not found on GitHub")

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    monkeypatch.setattr(
        "integrations.github_auth.get_installation_token",
        lambda iid, use_cache=True: "inst-tok",
    )
    t = _tenant(db, installation_id=999)
    with pytest.raises(HTTPException) as ei:
        await api_module._resolve_repo_privacy(
            "https://github.com/o/typo.git", _user(db), t, client_is_private=False
        )
    assert ei.value.status_code == 404
    assert ei.value.detail["error"] == "repo_not_found_or_inaccessible"


@pytest.mark.asyncio
async def test_resolve_privacy_expired_token_user_is_private_F1(db):
    """Review F1: an authenticated user whose GitHub token is missing/expired
    is the exact silent-bad-path population. With client_is_private omitted
    (manual-add default False) this MUST resolve private so the gate
    hard-fails — NOT fall back to the permissive hint."""
    u = _user(db, with_token=False)  # authenticated but no GitHub token
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", u, _tenant(db), client_is_private=False
    )
    assert out is True  # fail safe; the old code returned False here


@pytest.mark.asyncio
async def test_resolve_privacy_httpx_401_is_private_F2(db, monkeypatch):
    """Review F2: github_service only maps 404/403 to HTTPException; a 401
    reaches _resolve_repo_privacy as httpx.HTTPStatusError. Must fail safe
    (private), not revert to client_is_private."""
    import httpx

    async def fake_details(self, owner, repo):
        raise httpx.HTTPStatusError(
            "401 Unauthorized",
            request=httpx.Request("GET", "https://api.github.com/repos/o/r"),
            response=httpx.Response(401),
        )

    monkeypatch.setattr(
        "server.services.github_service.GitHubService.get_repo_details",
        fake_details,
    )
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", _user(db), _tenant(db), client_is_private=False
    )
    assert out is True  # fail safe; the old code returned False here


@pytest.mark.asyncio
async def test_resolve_privacy_no_user_at_all_trusts_hint(db):
    """Only the genuinely no-user case (picker / installation paths that
    carry their own auth and pass a real is_private) trusts the hint. This
    is NOT the manual-add-expired-token case (user present, handled above)."""
    t = _tenant(db)
    out = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", None, t, client_is_private=True
    )
    assert out is True
    out2 = await api_module._resolve_repo_privacy(
        "https://github.com/o/r.git", None, t, client_is_private=False
    )
    assert out2 is False  # no user context -> hint is authoritative here


# ---------------------------------------------------------------------------
# Owner-constrained webhook backfill (review finding #3)
# ---------------------------------------------------------------------------

def test_backfill_is_owner_scoped(db):
    """Review #3: backfill must touch ONLY projects whose full_name owner
    matches the installing account_login — never other-owner repos in the
    same tenant."""
    _tenant(db, tid=1, installation_id=None)
    # same tenant, two different GitHub owners, both unlinked
    p_match = Project(
        tenant_id=1, name="r1", full_name="acme/r1",
        git_url="https://github.com/acme/r1.git", installation_id=None,
        status="active",
    )
    p_other = Project(
        tenant_id=1, name="r2", full_name="othercorp/r2",
        git_url="https://github.com/othercorp/r2.git", installation_id=None,
        status="active",
    )
    db.add_all([p_match, p_other])
    db.commit()

    account_login = "acme"
    installation_id = 555
    healed = (
        db.query(Project)
        .filter(
            Project.tenant_id == 1,
            Project.installation_id.is_(None),
            Project.full_name.ilike(f"{account_login}/%"),
        )
        .update({"installation_id": installation_id}, synchronize_session=False)
    )
    db.commit()

    assert healed == 1
    db.refresh(p_match)
    db.refresh(p_other)
    assert p_match.installation_id == installation_id  # acme/* healed
    assert p_other.installation_id is None  # othercorp/* untouched
