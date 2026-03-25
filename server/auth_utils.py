"""
JWT utilities for user authentication.

This module provides functions to create and validate JWT tokens
for user authentication with GitHub OAuth.

Also provides reject_preview_writes — a FastAPI dependency that blocks
non-safe-method requests when using an admin preview token. Lives here
(not api.py) to avoid circular imports: both api.py and stripe_routes.py
can import from this leaf module safely.
"""

import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Request

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30  # 30 days


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Generate JWT token with user data.
    
    Args:
        data: Dictionary containing user information (user_id, tenant_id, github_login)
        expires_delta: Optional custom expiration time
        
    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and validate JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary containing decoded token payload
        
    Raises:
        ValueError: If token is expired or invalid
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except (jwt.DecodeError, jwt.InvalidTokenError, Exception):
        raise ValueError("Invalid token")


def get_current_user_from_token(token: str) -> dict:
    """
    Extract user info from JWT token.

    Minimal JWT: only authorization data, no PII.

    Args:
        token: JWT token string

    Returns:
        Dictionary with user_id and tenant_id

    Raises:
        ValueError: If token is invalid or missing required fields
    """
    payload = decode_access_token(token)
    return {
        "user_id": payload.get("user_id"),
        "tenant_id": payload.get("tenant_id"),
    }


async def reject_preview_writes(request: Request):
    """Block non-safe-method requests when using an admin preview token.

    Uses decode_access_token() (NOT get_current_user_from_token) to get
    the full JWT payload including the admin_preview claim.
    """
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return  # safe methods always allowed

    from server.auth_routes import get_token_from_header

    try:
        token = get_token_from_header(request)
        payload = decode_access_token(token)
    except Exception:
        return  # no valid token = not a preview request, let other deps handle auth

    if payload.get("admin_preview", False):
        raise HTTPException(status_code=403, detail="Preview mode is read-only")
