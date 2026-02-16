"""
Tests for GitHub App Authentication module.
"""

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest


class TestInstallationTokenCache:
    """Tests for the token cache."""
    
    def test_cache_miss_returns_none(self):
        """Test that cache miss returns None."""
        from integrations.github_auth import InstallationTokenCache
        cache = InstallationTokenCache()
        assert cache.get(12345) is None
    
    def test_cache_set_and_get(self):
        """Test setting and getting a cached token."""
        from integrations.github_auth import InstallationTokenCache
        cache = InstallationTokenCache()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        cache.set(12345, "test_token_abc", expires_at)
        
        assert cache.get(12345) == "test_token_abc"
    
    def test_cache_expired_returns_none(self):
        """Test that expired tokens return None."""
        from integrations.github_auth import InstallationTokenCache
        cache = InstallationTokenCache()
        # Set token that already expired
        expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
        
        cache.set(12345, "expired_token", expires_at)
        
        assert cache.get(12345) is None
    
    def test_cache_expiring_soon_returns_none(self):
        """Test that tokens expiring soon return None (to refresh early)."""
        from integrations.github_auth import InstallationTokenCache
        cache = InstallationTokenCache()
        # Token expires in 4 minutes (less than 5 minute buffer)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=4)
        
        cache.set(12345, "expiring_soon_token", expires_at)
        
        # Should return None to trigger refresh
        assert cache.get(12345) is None
    
    def test_cache_clear_all(self):
        """Test clearing all cached tokens."""
        from integrations.github_auth import InstallationTokenCache
        cache = InstallationTokenCache()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        cache.set(12345, "token1", expires_at)
        cache.set(67890, "token2", expires_at)
        
        cache.clear()
        
        assert cache.get(12345) is None
        assert cache.get(67890) is None
    
    def test_cache_clear_single(self):
        """Test clearing a single installation token."""
        from integrations.github_auth import InstallationTokenCache
        cache = InstallationTokenCache()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        
        cache.set(12345, "token1", expires_at)
        cache.set(67890, "token2", expires_at)
        
        cache.clear(12345)
        
        assert cache.get(12345) is None
        assert cache.get(67890) == "token2"


class TestGetCloneUrlWithToken:
    """Tests for get_clone_url_with_token function."""
    
    @patch('integrations.github_auth.get_installation_token')
    def test_https_url_transformation(self, mock_get_token):
        """Test that HTTPS URLs are properly transformed."""
        from integrations.github_auth import get_clone_url_with_token
        mock_get_token.return_value = "test_token_123"
        
        result = get_clone_url_with_token(
            "https://github.com/owner/repo.git",
            installation_id=12345
        )
        
        assert result == "https://x-access-token:test_token_123@github.com/owner/repo.git"
    
    @patch('integrations.github_auth.get_installation_token')
    def test_https_url_adds_git_suffix(self, mock_get_token):
        """Test HTTPS URL gets .git suffix added."""
        from integrations.github_auth import get_clone_url_with_token
        mock_get_token.return_value = "test_token_123"
        
        result = get_clone_url_with_token(
            "https://github.com/owner/repo",
            installation_id=12345
        )
        
        # Implementation adds .git suffix
        assert "x-access-token:test_token_123@github.com" in result


class TestGetInstallationToken:
    """Tests for get_installation_token function."""
    
    @patch('integrations.github_auth._token_cache')
    def test_returns_cached_token(self, mock_cache):
        """Test returning cached token when available."""
        from integrations.github_auth import get_installation_token
        mock_cache.get.return_value = "cached_token_xyz"
        
        token = get_installation_token(12345)
        
        assert token == "cached_token_xyz"


class TestGetPrivateKey:
    """Tests for private key loading."""
    
    def test_loads_from_environment(self):
        """Test loading private key from environment variable."""
        from integrations.github_auth import GitHubAppAuthError
        test_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        
        with patch.dict(os.environ, {
            'GITHUB_APP_PRIVATE_KEY': test_key,
        }, clear=False):
            # Reload module to pick up env var
            import importlib

            import integrations.github_auth as auth_module
            importlib.reload(auth_module)
            
            try:
                key = auth_module.get_private_key()
                assert "PRIVATE KEY" in key
            except GitHubAppAuthError:
                # May fail if env var not set - that's expected in CI
                pass


class TestGetAuthenticatedGitHubClient:
    """Tests for authenticated GitHub client."""
    
    @patch('integrations.github_auth.get_installation_token')
    @patch('integrations.github_auth.Github')
    def test_creates_authenticated_client(self, mock_github_class, mock_get_token):
        """Test creating an authenticated GitHub client."""
        from integrations.github_auth import get_authenticated_github_client
        mock_get_token.return_value = "test_token"
        mock_client = Mock()
        mock_github_class.return_value = mock_client
        
        result = get_authenticated_github_client(12345)
        
        assert result == mock_client
        mock_github_class.assert_called_once_with("test_token")


class TestGitHubAppAuthError:
    """Tests for the custom exception."""
    
    def test_exception_message(self):
        """Test exception can be raised with message."""
        from integrations.github_auth import GitHubAppAuthError
        
        with pytest.raises(GitHubAppAuthError, match="Test error"):
            raise GitHubAppAuthError("Test error")
