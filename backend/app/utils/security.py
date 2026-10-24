"""
Security Utilities — TrustVault
Password hashing (Argon2id), JWT creation/verification, file encryption (AES-256-GCM).
"""
import uuid
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import (
    JWT_SECRET_KEY, JWT_ALGORITHM,
    ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    FILE_ENCRYPTION_KEY,
)

# ─── Password Hashing ───────────────────────────────────────

_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM,
)


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its Argon2id hash."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def check_password_strength(password: str) -> tuple[bool, str]:
    """Validate password meets minimum complexity requirements."""
    if len(password) < 10:
        return False, "Password must be at least 10 characters"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"


# ─── JWT Tokens ──────────────────────────────────────────────

def create_access_token(
    user_id: str,
    email: str,
    role: str,
    token_generation: int,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a short-lived JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "tg": token_generation,  # Token generation for revocation
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid.uuid4()),  # Unique token ID
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token() -> tuple[str, str]:
    """Create a refresh token. Returns (raw_token, token_hash)."""
    raw_token = secrets.token_urlsafe(64)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(
            token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM]
        )
        if payload.get("type") != "access":
            raise jwt.InvalidTokenError("Not an access token")
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {e}")


def hash_refresh_token(raw_token: str) -> str:
    """Hash a raw refresh token for storage/lookup."""
    return hashlib.sha256(raw_token.encode()).hexdigest()


# ─── File Encryption ─────────────────────────────────────────

def _get_encryption_key() -> bytes:
    """Get the file encryption key as bytes."""
    return bytes.fromhex(FILE_ENCRYPTION_KEY)


def encrypt_file(data: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt file data with AES-256-GCM.
    Returns (encrypted_data, iv, tag).
    The tag is appended to encrypted_data by AESGCM, so we extract it.
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    iv = secrets.token_bytes(12)  # 96-bit IV for GCM
    # AESGCM.encrypt returns ciphertext + tag (16 bytes)
    encrypted = aesgcm.encrypt(iv, data, None)
    # Extract tag (last 16 bytes)
    ciphertext = encrypted[:-16]
    tag = encrypted[-16:]
    return ciphertext + tag, iv, tag


def decrypt_file(encrypted_data: bytes, iv: bytes) -> bytes:
    """
    Decrypt file data with AES-256-GCM.
    encrypted_data includes the auth tag (last 16 bytes).
    """
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, encrypted_data, None)
