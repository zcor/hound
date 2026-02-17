"""
Token encryption utilities using Fernet symmetric encryption.

Provides encrypt/decrypt functions for storing GitHub OAuth tokens
securely in the database.

The encryption key is read from the TOKEN_ENCRYPTION_KEY environment variable.
In development, a deterministic fallback key is used with a warning.
"""

import base64
import hashlib
import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    """
    Get a Fernet instance using the configured encryption key.
    
    The key is derived from TOKEN_ENCRYPTION_KEY env var.
    If not set, falls back to a dev key (with a warning).
    """
    raw_key = os.getenv("TOKEN_ENCRYPTION_KEY")
    if not raw_key:
        logger.warning(
            "TOKEN_ENCRYPTION_KEY not set — using insecure dev key. "
            "Set this variable in production!"
        )
        raw_key = "hound-dev-token-key-change-me"
    
    # Derive a valid 32-byte Fernet key from the raw string
    key_bytes = hashlib.sha256(raw_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_token(plain_token: str) -> str:
    """
    Encrypt a plaintext token string.
    
    Args:
        plain_token: The raw GitHub access token.
        
    Returns:
        Base64-encoded encrypted string suitable for database storage.
    """
    f = _get_fernet()
    return f.encrypt(plain_token.encode()).decode()


def decrypt_token(encrypted_token: str) -> str:
    """
    Decrypt an encrypted token string.
    
    Args:
        encrypted_token: The encrypted token from the database.
        
    Returns:
        The original plaintext token.
        
    Raises:
        ValueError: If decryption fails (corrupted data or wrong key).
    """
    f = _get_fernet()
    try:
        return f.decrypt(encrypted_token.encode()).decode()
    except InvalidToken:
        raise ValueError("Failed to decrypt token — key may have changed or data is corrupted")
