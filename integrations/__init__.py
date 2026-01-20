"""Integrations package for external services."""

# Lazy imports to avoid import errors when optional dependencies are not installed


def __getattr__(name):
    """Lazy import for optional dependencies."""
    if name in (
        "get_installation_token",
        "get_clone_url_with_token",
        "get_authenticated_github_client",
        "InstallationTokenCache",
    ):
        from .github_auth import (
            get_installation_token,
            get_clone_url_with_token,
            get_authenticated_github_client,
            InstallationTokenCache,
        )
        return locals()[name]
    
    if name in ("PRCommentBot", "post_findings_to_pr", "FindingLocation"):
        from .pr_bot import (
            PRCommentBot,
            post_findings_to_pr,
            FindingLocation,
        )
        return locals()[name]
    
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # GitHub App Authentication
    "get_installation_token",
    "get_clone_url_with_token",
    "get_authenticated_github_client",
    "InstallationTokenCache",
    # PR Comment Bot
    "PRCommentBot",
    "post_findings_to_pr",
    "FindingLocation",
]
