"""
GitHub App Authentication for Hound SaaS.

Provides secure authentication as a GitHub App to:
- Clone private customer repositories
- Post PR comments with findings
- Access repository metadata

This module centralizes all GitHub App authentication logic.
"""

import os
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

import jwt
from github import Auth, Github, GithubIntegration


# Configuration from environment variables
GITHUB_APP_ID = os.environ.get("GITHUB_APP_ID")
GITHUB_APP_PRIVATE_KEY = os.environ.get("GITHUB_APP_PRIVATE_KEY")  # Key content directly
GITHUB_APP_PRIVATE_KEY_PATH = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")  # Or path to key file


class GitHubAppAuthError(Exception):
    """Raised when GitHub App authentication fails."""
    pass


class InstallationTokenCache:
    """
    Simple cache for installation access tokens.
    
    Tokens are cached until they expire (minus a 5-minute buffer).
    """
    
    def __init__(self):
        self._cache: dict[int, tuple[str, datetime]] = {}
    
    def get(self, installation_id: int) -> Optional[str]:
        """Get cached token if still valid."""
        if installation_id not in self._cache:
            return None
        
        token, expires_at = self._cache[installation_id]
        
        # Check if token is still valid (with 5-minute buffer)
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        
        buffer = 300  # 5 minutes
        if (expires_at.timestamp() - buffer) <= now.timestamp():
            # Token expired or about to expire
            del self._cache[installation_id]
            return None
        
        return token
    
    def set(self, installation_id: int, token: str, expires_at: datetime):
        """Cache a token with its expiration time."""
        self._cache[installation_id] = (token, expires_at)
    
    def clear(self, installation_id: Optional[int] = None):
        """Clear cached token(s)."""
        if installation_id:
            self._cache.pop(installation_id, None)
        else:
            self._cache.clear()


# Global token cache
_token_cache = InstallationTokenCache()


def get_private_key() -> str:
    """
    Get the GitHub App private key.
    
    Checks environment variables in order:
    1. GITHUB_APP_PRIVATE_KEY - Key content directly
    2. GITHUB_APP_PRIVATE_KEY_PATH - Path to key file
    
    Returns:
        Private key as a string
        
    Raises:
        GitHubAppAuthError: If no private key is configured
    """
    # Try direct key content first
    if GITHUB_APP_PRIVATE_KEY:
        key = GITHUB_APP_PRIVATE_KEY
        # Handle escaped newlines from environment variables
        if "\\n" in key:
            key = key.replace("\\n", "\n")
        return key
    
    # Try key file path
    if GITHUB_APP_PRIVATE_KEY_PATH:
        try:
            with open(GITHUB_APP_PRIVATE_KEY_PATH) as f:
                return f.read()
        except FileNotFoundError:
            raise GitHubAppAuthError(
                f"Private key file not found: {GITHUB_APP_PRIVATE_KEY_PATH}"
            )
        except IOError as e:
            raise GitHubAppAuthError(
                f"Failed to read private key file: {e}"
            )
    
    raise GitHubAppAuthError(
        "GitHub App private key not configured. "
        "Set GITHUB_APP_PRIVATE_KEY or GITHUB_APP_PRIVATE_KEY_PATH environment variable."
    )


def get_app_id() -> int:
    """
    Get the GitHub App ID.
    
    Returns:
        App ID as an integer
        
    Raises:
        GitHubAppAuthError: If App ID is not configured
    """
    if not GITHUB_APP_ID:
        raise GitHubAppAuthError(
            "GITHUB_APP_ID environment variable is not set"
        )
    
    try:
        return int(GITHUB_APP_ID)
    except ValueError:
        raise GitHubAppAuthError(
            f"Invalid GITHUB_APP_ID: {GITHUB_APP_ID} (must be an integer)"
        )


def generate_jwt_token(expiration_seconds: int = 600) -> str:
    """
    Generate a JWT token for GitHub App authentication.
    
    This JWT is used to authenticate as the GitHub App itself,
    before obtaining an installation access token.
    
    Args:
        expiration_seconds: Token lifetime in seconds (max 600 = 10 minutes)
        
    Returns:
        JWT token string
        
    Raises:
        GitHubAppAuthError: If authentication fails
    """
    app_id = get_app_id()
    private_key = get_private_key()
    
    now = int(time.time())
    
    payload = {
        "iat": now - 60,  # Issued 60 seconds ago (clock skew tolerance)
        "exp": now + expiration_seconds,
        "iss": app_id,
    }
    
    try:
        return jwt.encode(payload, private_key, algorithm="RS256")
    except Exception as e:
        raise GitHubAppAuthError(f"Failed to generate JWT: {e}")


def get_installation_token(installation_id: int, use_cache: bool = True) -> str:
    """
    Get an installation access token for a GitHub App installation.
    
    This is the main function for authenticating to access repositories.
    The token can be used for:
    - Cloning private repositories
    - Making API calls on behalf of the installation
    - Posting PR comments
    
    Args:
        installation_id: The GitHub App installation ID
        use_cache: Whether to use cached tokens (default: True)
        
    Returns:
        Installation access token as a string
        
    Raises:
        GitHubAppAuthError: If token generation fails
        
    Example:
        token = get_installation_token(12345678)
        # Clone URL: https://x-access-token:{token}@github.com/owner/repo.git
    """
    # Check cache first
    if use_cache:
        cached_token = _token_cache.get(installation_id)
        if cached_token:
            return cached_token
    
    try:
        app_id = get_app_id()
        private_key = get_private_key()
        
        # Create GitHub App authentication
        auth = Auth.AppAuth(app_id, private_key)
        gi = GithubIntegration(auth=auth)
        
        # Get installation access token
        installation_auth = gi.get_access_token(installation_id)
        token = installation_auth.token
        expires_at = installation_auth.expires_at
        
        # Cache the token
        if use_cache and expires_at:
            _token_cache.set(installation_id, token, expires_at)
        
        return token
        
    except GitHubAppAuthError:
        raise
    except Exception as e:
        raise GitHubAppAuthError(
            f"Failed to get installation token for installation {installation_id}: {e}"
        )


def get_authenticated_github_client(installation_id: int) -> Github:
    """
    Get an authenticated PyGithub client for an installation.
    
    Args:
        installation_id: The GitHub App installation ID
        
    Returns:
        Authenticated Github client instance
        
    Example:
        gh = get_authenticated_github_client(12345678)
        repo = gh.get_repo("owner/repo")
        pr = repo.get_pull(123)
    """
    token = get_installation_token(installation_id)
    return Github(token)


def get_clone_url_with_token(repo_url: str, installation_id: int) -> str:
    """
    Get a clone URL with embedded access token for private repositories.
    
    Converts a GitHub URL to an authenticated clone URL using x-access-token.
    
    Args:
        repo_url: Original repository URL (HTTPS or git@)
        installation_id: The GitHub App installation ID
        
    Returns:
        Authenticated HTTPS clone URL
        
    Example:
        url = get_clone_url_with_token(
            "https://github.com/owner/repo",
            12345678
        )
        # Returns: https://x-access-token:{token}@github.com/owner/repo.git
    """
    token = get_installation_token(installation_id)
    
    # Normalize URL to HTTPS format
    if repo_url.startswith("git@github.com:"):
        # Convert SSH URL to HTTPS
        repo_path = repo_url.replace("git@github.com:", "").rstrip(".git")
        repo_url = f"https://github.com/{repo_path}"
    
    # Ensure .git suffix
    if not repo_url.endswith(".git"):
        repo_url = f"{repo_url}.git"
    
    # Parse URL and inject token
    if "github.com" in repo_url:
        # Replace https://github.com with authenticated URL
        authenticated_url = repo_url.replace(
            "https://github.com",
            f"https://x-access-token:{token}@github.com"
        )
        return authenticated_url
    
    raise GitHubAppAuthError(
        f"Unsupported repository URL format: {repo_url}"
    )


def verify_installation_access(installation_id: int, repo_full_name: str) -> bool:
    """
    Verify that an installation has access to a specific repository.
    
    Args:
        installation_id: The GitHub App installation ID
        repo_full_name: Repository full name (owner/repo)
        
    Returns:
        True if access is granted, False otherwise
    """
    try:
        gh = get_authenticated_github_client(installation_id)
        repo = gh.get_repo(repo_full_name)
        # Try to access repo metadata to verify access
        _ = repo.full_name
        return True
    except Exception:
        return False


def get_app_installations() -> list[dict]:
    """
    List all installations of the GitHub App.
    
    Returns:
        List of installation dictionaries with id, account, and permissions
        
    Raises:
        GitHubAppAuthError: If authentication fails
    """
    try:
        app_id = get_app_id()
        private_key = get_private_key()
        
        auth = Auth.AppAuth(app_id, private_key)
        gi = GithubIntegration(auth=auth)
        
        installations = []
        for installation in gi.get_installations():
            installations.append({
                "id": installation.id,
                "account": {
                    "login": installation.account.login if installation.account else None,
                    "type": installation.account.type if installation.account else None,
                },
                "app_id": installation.app_id,
                "target_type": installation.target_type,
                "permissions": installation.permissions,
            })
        
        return installations
        
    except GitHubAppAuthError:
        raise
    except Exception as e:
        raise GitHubAppAuthError(f"Failed to list installations: {e}")


def clear_token_cache(installation_id: Optional[int] = None):
    """
    Clear cached installation tokens.
    
    Args:
        installation_id: Specific installation to clear, or None for all
    """
    _token_cache.clear(installation_id)
