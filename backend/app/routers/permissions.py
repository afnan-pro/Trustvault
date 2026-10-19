"""
Permissions Router — TrustVault
Handles granting and revoking document permissions.
Document owners and admins can manage permissions.
Taking access away invalidates sessions and takes effect immediately.
"""
from uuid import UUID
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.user import User
from app.models.document import Document
from app.models.permission import Permission
from app.schemas.permission import PermissionGrant, PermissionResponse, PermissionRevoke
from app.services.permission_service import PermissionService
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/documents/{document_id}/permissions", tags=["Permissions"])


def _check_manage_authority(doc: Document, user: User):
    """Only document owner or system admin can manage permissions."""
    if doc.owner_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner or an administrator can manage permissions.",
        )


@router.get("", response_model=List[PermissionResponse])
async def list_permissions(
    document_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all permissions for a document. Owner or admin only."""
    doc_result = await db.execute(
        select(Document).where(Document.id == document_id, Document.is_deleted == False)
    )
    doc = doc_result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    _check_manage_authority(doc, current_user)

    permissions = await PermissionService.get_document_permissions(db, document_id)

    response_list = []
    for perm in permissions:
        # Load user info
        u_res = await db.execute(select(User).where(User.id == perm.user_id))
        target_u = u_res.scalar_one_or_none()
        g_res = await db.execute(select(User).where(User.id == perm.granted_by))
        granter_u = g_res.scalar_one_or_none()

        response_list.append(PermissionResponse(
            id=perm.id,
            document_id=perm.document_id,
            user_id=perm.user_id,
            user_email=target_u.email if target_u else "unknown",
            user_name=target_u.full_name if target_u else "Unknown",
            level=perm.level,
            granted_by=perm.granted_by,
            granted_by_email=granter_u.email if granter_u else None,
            expires_at=perm.expires_at,
            is_revoked=perm.is_revoked,
            created_at=perm.created_at,
            revoked_at=perm.revoked_at,
        ))

    return response_list


@router.post("", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def grant_permission(
    document_id: UUID,
    data: PermissionGrant,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Grant permission to a named person by email.
    Owner or admin only.
    """
    doc_result = await db.execute(
        select(Document).where(Document.id == document_id, Document.is_deleted == False)
    )
    doc = doc_result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    _check_manage_authority(doc, current_user)

    # Find target user
    target_user = await AuthService.get_user_by_email(db, data.user_email)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email '{data.user_email}' does not exist.",
        )

    # Cannot grant to the owner (they already have full control)
    if target_user.id == doc.owner_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The document owner already has full access.",
        )

    permission = await PermissionService.grant_permission(
        db=db,
        document_id=document_id,
        user_id=target_user.id,
        level=data.level,
        granted_by=current_user.id,
        expires_at=data.expires_at,
    )

    # Log to tamper-evident audit trail
    await AuditService.log(
        db=db,
        action="PERMISSION_GRANT",
        user_id=current_user.id,
        document_id=document_id,
        target_user_id=target_user.id,
        details={
            "target_email": target_user.email,
            "level": data.level,
            "expires_at": data.expires_at.isoformat() if data.expires_at else None,
            "document_name": doc.original_filename,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    )

    return PermissionResponse(
        id=permission.id,
        document_id=permission.document_id,
        user_id=permission.user_id,
        user_email=target_user.email,
        user_name=target_user.full_name,
        level=permission.level,
        granted_by=permission.granted_by,
        granted_by_email=current_user.email,
        expires_at=permission.expires_at,
        is_revoked=permission.is_revoked,
        created_at=permission.created_at,
        revoked_at=permission.revoked_at,
    )


@router.delete("/{permission_id}")
async def revoke_permission(
    document_id: UUID,
    permission_id: UUID,
    request: Request,
    body: Optional[PermissionRevoke] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Immediately revoke a permission.
    Taking access away works instantly:
    1. Permission is marked revoked in database
    2. Target user's token generation counter is incremented, immediately revoking active sessions.
    """
    doc_result = await db.execute(
        select(Document).where(Document.id == document_id, Document.is_deleted == False)
    )
    doc = doc_result.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    _check_manage_authority(doc, current_user)

    try:
        revoked_perm = await PermissionService.revoke_permission(
            db=db,
            permission_id=permission_id,
            document_id=document_id,
            revoker=current_user,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    reason = body.reason if body else None

    # Audit log
    await AuditService.log(
        db=db,
        action="PERMISSION_REVOKE",
        user_id=current_user.id,
        document_id=document_id,
        target_user_id=revoked_perm.user_id,
        details={
            "permission_id": str(permission_id),
            "reason": reason,
            "document_name": doc.original_filename,
            "immediate_session_invalidation": True,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    )

    return {
        "message": "Permission revoked successfully. Access has been terminated immediately.",
        "permission_id": str(permission_id),
        "revoked_at": revoked_perm.revoked_at.isoformat() if revoked_perm.revoked_at else None,
    }
