"""
GitHub API service for team synchronization.

This module provides a service class for interacting with GitHub API
to fetch repository details and collaborators for team management.
"""

import re
from typing import Dict, List

import httpx
from fastapi import HTTPException


class GitHubService:
    """Service for interacting with GitHub API."""
    
    def __init__(self, access_token: str):
        """
        Initialize GitHub service with access token.
        
        Args:
            access_token: GitHub OAuth access token
        """
        self.access_token = access_token
        self.base_url = "https://api.github.com"
        self.headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    async def get_repo_details(self, owner: str, repo: str) -> Dict:
        """
        Get repository metadata including ID.
        
        Args:
            owner: Repository owner (username or organization)
            repo: Repository name
        
        Returns:
            Dictionary containing repository details:
            {
                "id": 123456,
                "name": "repo",
                "full_name": "owner/repo",
                "private": false,
                "permissions": {...}
            }
        
        Raises:
            HTTPException: If repository not found or access denied
        """
        url = f"{self.base_url}/repos/{owner}/{repo}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            
            if response.status_code == 404:
                raise HTTPException(status_code=404, detail="Repository not found on GitHub")
            elif response.status_code == 403:
                raise HTTPException(status_code=403, detail="Access denied to repository")
            
            response.raise_for_status()
            return response.json()
    
    async def get_repo_collaborators(self, owner: str, repo: str) -> List[Dict]:
        """
        Fetch all collaborators for a repository.
        
        Args:
            owner: Repository owner (username or organization)
            repo: Repository name
        
        Returns:
            List of collaborator dictionaries:
            [
                {
                    "login": "username",
                    "id": 123,
                    "avatar_url": "https://...",
                    "permissions": {
                        "admin": true,
                        "push": true,
                        "pull": true
                    }
                },
                ...
            ]
        
        Raises:
            HTTPException: If insufficient permissions or API error
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/collaborators"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            
            if response.status_code == 403:
                raise HTTPException(
                    status_code=403, 
                    detail="You need admin access to this repository to sync team members"
                )
            
            response.raise_for_status()
            return response.json()
    
    async def check_user_access(self, owner: str, repo: str, username: str) -> bool:
        """
        Check if a user is a collaborator on a repo.
        
        Args:
            owner: Repository owner (username or organization)
            repo: Repository name
            username: GitHub username to check
        
        Returns:
            True if user has access, False otherwise
        """
        url = f"{self.base_url}/repos/{owner}/{repo}/collaborators/{username}"
        
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=self.headers)
            return response.status_code == 204


def parse_github_url(url: str) -> tuple[str, str]:
    """
    Extract owner/repo from GitHub URL.
    
    Supports various GitHub URL formats:
    - https://github.com/owner/repo
    - git@github.com:owner/repo.git
    - https://github.com/owner/repo.git
    
    Args:
        url: GitHub repository URL
    
    Returns:
        Tuple of (owner, repo)
    
    Raises:
        ValueError: If URL format is invalid
    
    Examples:
        >>> parse_github_url("https://github.com/owner/repo")
        ('owner', 'repo')
        >>> parse_github_url("git@github.com:owner/repo.git")
        ('owner', 'repo')
    """
    pattern = r"github\.com[:/]([^/]+)/([^/\.]+?)(?:\.git)?$"
    match = re.search(pattern, url)
    
    if not match:
        raise ValueError(f"Invalid GitHub URL: {url}")
    
    return match.group(1), match.group(2)
