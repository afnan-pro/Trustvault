"""
Permission Service — TrustVault
The critical security layer. Every document access check goes through here.
Default deny: if no active permission exists, access is refused.
"""
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.permission import Permission
from app.models.document import Document
from app.models.user import User
from app.services.auth_service import AuthService


class PermissionService:
    """
    Permission checking and management.
    This is THE security gate. Every access decision goes through check_access().
    """

    @staticmethod
    async def check_access(
        db: AsyncSession,
        user: User,
        document_id: UUID,
        required_level: str = "read",  # "read" or "edit"
    ) -> bool:
        """
        Check if a user has the required access level to a document.
        
        Access is granted if ANY of these are true:
        1. The user is the document owner
        2. The user has an active, non-expired, non-revoked permission
           with the required level (edit includes read)
        
        This method NEVER grants access implicitly.
        """
        # First check: is the user the owner?
        result = await db.execute(
            select(Document).where(
                Document.id == document_id,
                Document.is_deleted == False,
            )
        )
        document = result.scalar_one_or_none()

        if not document:
            return False

        if document.owner_id == user.id:
            return True  # Owner always has full access

        # Second check: does user have a valid permission?
        now = datetime.now(timezone.utc)

        # Build level check: edit permission includes read
        if required_level == "read":
            level_check = Permission.level.in_(["read", "edit"])
        else:
            level_check = Permission.level == "edit"

        result = await db.execute(
            select(Permission).where(
                and_(
                    Permission.document_id == document_id,
                    Permission.user_id == user.id,
                    Permission.is_revoked == False,
                    level_check,
                    or_(
                        Permission.expires_at == None,  # Never expires
                        Permission.expires_at > now,     # Not yet expired
                    ),
                )
            )
        )
        permission = result.scalar_one_or_none()

        return permission is not None

    @staticmethod
    async def get_user_permission_level(
        db: AsyncSession,
        user: User,
        document_id: UUID,
    ) -> Optional[str]:
        """Get the user's permission level for a document. Returns None if no access."""
        # Check if owner
        result = await db.execute(
            select(Document).where(
                Document.id == document_id,
                Document.is_deleted == False,
            )
        )
        document = result.scalar_one_or_none()

        if not document:
            return None

        if document.owner_id == user.id:
            return "owner"

        # Check permission
        now = datetime.now(timezone.utc)
        result = await db.execute(
            select(Permission).where(
                and_(
                    Permission.document_id == document_id,
                    Permission.user_id == user.id,
                    Permission.is_revoked == False,
                    or_(
                        Permission.expires_at == None,
                        Permission.expires_at > now,
                    ),
                )
            )
        )
        permission = result.scalar_one_or_none()

        if permission:
            return permission.level
        return None

    @staticmethod
    async def grant_permission(
        db: AsyncSession,
        document_id: UUID,
        user_id: UUID,
        level: str,
        granted_by: UUID,
        expires_at: Optional[datetime] = None,
    ) -> Permission:
        """
        Grant permission to a user for a document.
        If an active permission already exists, update it.
        """
        # Check for existing active permission
        result = await db.execute(
            select(Permission).where(
                and_(
                    Permission.document_id == document_id,
                    Permission.user_id == user_id,
                    Permission.is_revoked == False,
                )
            )
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing permission
            existing.level = level
            existing.expires_at = expires_at
            existing.granted_by = granted_by
            await db.flush()
            return existing

        # Create new permission
        permission = Permission(
            document_id=document_id,
            user_id=user_id,
            level=level,
            granted_by=granted_by,
            expires_at=expires_at,
        )
        db.add(permission)
        await db.flush()
        return permission

    @staticmethod
    async def revoke_permission(
        db: AsyncSession,
        permission_id: UUID,
        document_id: UUID,
        revoker: User,
    ) -> Permission:
        """
        Revoke a permission. Also invalidates the target user's tokens
        so the revocation takes effect immediately.
        """
        result = await db.execute(
            select(Permission).where(
                and_(
                    Permission.id == permission_id,
                    Permission.document_id == document_id,
                )
            )
        )
        permission = result.scalar_one_or_none()

        if not permission:
            raise ValueError("Permission not found")

        # Verify the revoker is the document owner
        doc_result = await db.execute(
            select(Document).where(Document.id == document_id)
        )
        document = doc_result.scalar_one_or_none()

        if not document or (document.owner_id != revoker.id and revoker.role != "admin"):
            raise ValueError("Not authorized to revoke this permission")

        # Revoke the permission
        permission.is_revoked = True
        permission.revoked_at = datetime.now(timezone.utc)

        # CRITICAL: Invalidate the target user's tokens immediately
        # This ensures they can't use cached tokens to access the document
        await AuthService.revoke_all_tokens(db, permission.user_id)

        await db.flush()
        return permission

    @staticmethod
    async def get_document_permissions(
        db: AsyncSession,
        document_id: UUID,
    ):
        """Get all permissions (active and revoked) for a document."""
        result = await db.execute(
            select(Permission)
            .where(Permission.document_id == document_id)
            .order_by(Permission.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get_accessible_document_ids(
        db: AsyncSession,
        user: User,
    ) -> list[UUID]:
        """
        Get IDs of all documents a user can access.
        Used for listing — each access is still checked individually on fetch.
        """
        now = datetime.now(timezone.utc)

        # Documents the user owns
        owned_result = await db.execute(
            select(Document.id).where(
                Document.owner_id == user.id,
                Document.is_deleted == False,
            )
        )
        owned_ids = [row[0] for row in owned_result.all()]

        # Documents with active permissions
        permitted_result = await db.execute(
            select(Permission.document_id).where(
                and_(
                    Permission.user_id == user.id,
                    Permission.is_revoked == False,
                    or_(
                        Permission.expires_at == None,
                        Permission.expires_at > now,
                    ),
                )
            )
        )
        permitted_ids = [row[0] for row in permitted_result.all()]

        # Combine and deduplicate
        return list(set(owned_ids + permitted_ids))
