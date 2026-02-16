"""
GitHub OAuth authentication routes.

This module provides FastAPI endpoints for GitHub OAuth authentication
and JWT token management.
"""

from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
import httpx
import os
from pydantic import BaseModel
from typing import Generator

from database.models import User, Tenant
from server.auth_utils import create_access_token, get_current_user_from_token

router = APIRouter(prefix="/auth", tags=["authentication"])

GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")


class GitHubCallbackRequest(BaseModel):
    """Request model for GitHub OAuth callback."""
    code: str


def get_db() -> Generator[Session, None, None]:
    """
    Get database session.
    This is a placeholder that will be overridden when the router is included.
    """
    # Import at runtime to avoid circular dependency
    from server.api import get_db as api_get_db
    yield from api_get_db()


def get_token_from_header(request: Request) -> str:
    """
    Extract JWT token from Authorization header.
    
    Args:
        request: FastAPI request object
        
    Returns:
        JWT token string
        
    Raises:
        HTTPException: If authorization header is missing or invalid
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401, 
            detail="Missing or invalid authorization header"
        )
    return auth_header.replace("Bearer ", "")


@router.get("/github/login")
async def github_login():
    """
    Redirect user to GitHub OAuth.
    
    Returns:
        Dictionary containing the GitHub OAuth URL
    """
    if not GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth not configured. Set GITHUB_CLIENT_ID environment variable."
        )
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={FRONTEND_URL}/auth/callback"
        f"&scope=read:user user:email"
    )
    return {"url": github_auth_url}


@router.post("/github/callback")
async def github_callback(request: GitHubCallbackRequest, db: Session = Depends(get_db)):
    """
    Exchange GitHub code for access token and create/login user.
    
    Args:
        request: GitHub callback request with authorization code
        db: Database session
        
    Returns:
        Dictionary containing JWT access token and user information
        
    Raises:
        HTTPException: If GitHub authentication fails
    """
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth not configured"
        )
    
    # 1. Exchange code for GitHub access token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": request.code
            },
            headers={"Accept": "application/json"}
        )
        token_data = token_response.json()
        github_token = token_data.get("access_token")
        
        if not github_token:
            raise HTTPException(
                status_code=400, 
                detail="Failed to get GitHub access token"
            )
        
        # 2. Get user info from GitHub
        user_response = await client.get(
            "https://api.github.com/user",
            headers={
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/json"
            }
        )
        github_user = user_response.json()
    
    # 3. Create or update user in database
    user = db.query(User).filter(User.github_id == github_user["id"]).first()
    
    if not user:
        # New user - create tenant and user
        tenant = Tenant(name=f"{github_user['login']}'s Organization")
        db.add(tenant)
        db.flush()  # Get tenant.id
        
        user = User(
            github_id=github_user["id"],
            github_login=github_user["login"],
            email=github_user.get("email"),
            name=github_user.get("name"),
            avatar_url=github_user.get("avatar_url"),
            tenant_id=tenant.id
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Existing user - update info
        user.name = github_user.get("name")
        user.email = github_user.get("email")
        user.avatar_url = github_user.get("avatar_url")
        db.commit()
        db.refresh(user)
    
    # 4. Generate JWT token
    access_token = create_access_token(data={
        "user_id": user.id,
        "tenant_id": user.tenant_id,
        "github_login": user.github_login
    })
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "github_login": user.github_login,
            "email": user.email,
            "name": user.name,
            "avatar_url": user.avatar_url
        },
        "tenant_id": user.tenant_id
    }


@router.get("/me")
async def get_current_user(
    request: Request,
    token: str = Depends(get_token_from_header), 
    db: Session = Depends(get_db)
):
    """
    Get current user info from JWT token.
    
    Args:
        request: FastAPI request object
        token: JWT token from Authorization header
        db: Database session
        
    Returns:
        Dictionary containing user information
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    try:
        payload = get_current_user_from_token(token)
        user = db.query(User).filter(User.id == payload["user_id"]).first()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "id": user.id,
            "github_login": user.github_login,
            "email": user.email,
            "name": user.name,
            "avatar_url": user.avatar_url,
            "tenant_id": user.tenant_id
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
