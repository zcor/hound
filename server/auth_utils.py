"""
JWT utilities for user authentication.

This module provides functions to create and validate JWT tokens
for user authentication with GitHub OAuth.
"""

import os
import jwt
from datetime import datetime, timedelta
from typing import Optional

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
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
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
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
    
    Args:
        token: JWT token string
        
    Returns:
        Dictionary with user_id, tenant_id, and github_login
        
    Raises:
        ValueError: If token is invalid or missing required fields
    """
    payload = decode_access_token(token)
    return {
        "user_id": payload.get("user_id"),
        "tenant_id": payload.get("tenant_id"),
        "github_login": payload.get("github_login")
    }
