"""
Auth Service — TrustVault
Handles user registration, login, token refresh, and logout.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import REFRESH_TOKEN_EXPIRE_DAYS, ACCESS_TOKEN_EXPIRE_MINUTES
from app.models.user import User
from app.models.audit import RefreshToken
from app.utils.security import (
    hash_password, verify_password, check_password_strength,
    create_access_token, create_refresh_token, hash_refresh_token,
)


class AuthService:
    """Authentication business logic."""

    @staticmethod
    async def register_user(
        db: AsyncSession,
        email: str,
        full_name: str,
        password: str,
        role: str = "viewer",
    ) -> User:
        """Register a new user."""
        # Check if email already exists
        result = await db.execute(
            select(User).where(User.email == email.lower())
        )
        if result.scalar_one_or_none():
            raise ValueError("Email already registered")

        # Validate password strength
        is_strong, msg = check_password_strength(password)
        if not is_strong:
            raise ValueError(msg)

        user = User(
            email=email.lower().strip(),
            full_name=full_name.strip(),
            password_hash=hash_password(password),
            role=role,
            is_active=True,
        )
        db.add(user)
        await db.flush()
        return user

    @staticmethod
    async def authenticate(
        db: AsyncSession,
        email: str,
        password: str,
    ) -> Optional[User]:
        """Authenticate a user by email and password."""
        result = await db.execute(
            select(User).where(User.email == email.lower().strip())
        )
        user = result.scalar_one_or_none()

        if not user:
            # Still hash to prevent timing attacks
            hash_password("dummy-password-to-prevent-timing-attack")
            return None

        if not user.is_active:
            return None

        if not verify_password(password, user.password_hash):
            return None

        return user

    @staticmethod
    async def create_tokens(
        db: AsyncSession,
        user: User,
    ) -> tuple[str, str]:
        """Create access and refresh tokens for a user."""
        # Access token (JWT)
        access_token = create_access_token(
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            token_generation=user.token_generation,
        )

        # Refresh token (opaque, stored in DB)
        raw_refresh, refresh_hash = create_refresh_token()

        refresh_record = RefreshToken(
            user_id=user.id,
            token_hash=refresh_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        )
        db.add(refresh_record)
        await db.flush()

        return access_token, raw_refresh

    @staticmethod
    async def refresh_access_token(
        db: AsyncSession,
        raw_refresh_token: str,
    ) -> tuple[str, User]:
        """Validate refresh token and issue new access token."""
        token_hash = hash_refresh_token(raw_refresh_token)

        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.is_revoked == False,
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
        )
        refresh_record = result.scalar_one_or_none()

        if not refresh_record:
            raise ValueError("Invalid or expired refresh token")

        # Get the user
        result = await db.execute(
            select(User).where(User.id == refresh_record.user_id)
        )
        user = result.scalar_one_or_none()

        if not user or not user.is_active:
            raise ValueError("User not found or deactivated")

        # Create new access token
        access_token = create_access_token(
            user_id=str(user.id),
            email=user.email,
            role=user.role,
            token_generation=user.token_generation,
        )

        return access_token, user

    @staticmethod
    async def logout(
        db: AsyncSession,
        user_id: UUID,
        raw_refresh_token: Optional[str] = None,
    ):
        """Revoke refresh token(s) on logout."""
        if raw_refresh_token:
            token_hash = hash_refresh_token(raw_refresh_token)
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.token_hash == token_hash)
                .values(is_revoked=True)
            )
        else:
            # Revoke all refresh tokens for this user
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.user_id == user_id)
                .values(is_revoked=True)
            )

    @staticmethod
    async def change_password(
        db: AsyncSession,
        user: User,
        current_password: str,
        new_password: str,
    ):
        """Change a user's password."""
        if not verify_password(current_password, user.password_hash):
            raise ValueError("Current password is incorrect")

        is_strong, msg = check_password_strength(new_password)
        if not is_strong:
            raise ValueError(msg)

        user.password_hash = hash_password(new_password)
        # Increment token generation to invalidate all existing tokens
        user.token_generation += 1

        # Revoke all refresh tokens
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id)
            .values(is_revoked=True)
        )

    @staticmethod
    async def revoke_all_tokens(db: AsyncSession, user_id: UUID):
        """
        Revoke all tokens for a user — used when permissions are revoked
        to ensure immediate effect.
        """
        # Increment token generation to invalidate all JWTs
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        if user:
            user.token_generation += 1
            # Revoke all refresh tokens too
            await db.execute(
                update(RefreshToken)
                .where(RefreshToken.user_id == user_id)
                .values(is_revoked=True)
            )

    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Look up a user by email."""
        result = await db.execute(
            select(User).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_all_users(db: AsyncSession):
        """Get all users (admin function)."""
        result = await db.execute(
            select(User).order_by(User.created_at.desc())
        )
        return result.scalars().all()
