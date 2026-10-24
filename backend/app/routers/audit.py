"""
Audit Router — TrustVault
Cryptographically verified, tamper-evident audit trail endpoints.
The record can be inspected and mathematically proven unaltered.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.user import User
from app.models.document import Document
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogResponse, AuditListResponse, AuditIntegrityResponse
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/audit", tags=["Audit Trail"])


@router.get("", response_model=AuditListResponse)
async def list_audit_logs(
    action: Optional[str] = None,
    user_id: Optional[UUID] = None,
    document_id: Optional[UUID] = None,
    success: Optional[bool] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    page: int = 1,
    page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List audit logs.
    Admins can view all logs.
    Owners can only view logs related to documents they own or actions they performed.
    Viewers can only see their own actions.
    """
    # Enforce access scope
    scoped_user_id = user_id
    scoped_doc_id = document_id

    if current_user.role == "viewer":
        # Viewers can strictly only see their own activity
        scoped_user_id = current_user.id
    elif current_user.role == "owner":
        # If not admin, restrict to their owned documents or their own user ID
        if not document_id and not user_id:
            # Show logs where they are the actor
            scoped_user_id = current_user.id
        elif document_id:
            doc_res = await db.execute(select(Document).where(Document.id == document_id))
            doc = doc_res.scalar_one_or_none()
            if not doc or doc.owner_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cannot view audit logs for documents you do not own.",
                )

    logs, total = await AuditService.get_logs(
        db=db,
        action=action,
        user_id=scoped_user_id,
        document_id=scoped_doc_id,
        success=success,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
    )

    log_responses = []
    for log in logs:
        # Resolve names
        u_email = None
        if log.user_id:
            u_res = await db.execute(select(User.email).where(User.id == log.user_id))
            u_email = u_res.scalar_one_or_none()

        doc_name = None
        if log.document_id:
            d_res = await db.execute(select(Document.original_filename).where(Document.id == log.document_id))
            doc_name = d_res.scalar_one_or_none()

        target_email = None
        if log.target_user_id:
            t_res = await db.execute(select(User.email).where(User.id == log.target_user_id))
            target_email = t_res.scalar_one_or_none()

        log_responses.append(AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            user_email=u_email,
            action=log.action,
            document_id=log.document_id,
            document_name=doc_name,
            target_user_id=log.target_user_id,
            target_user_email=target_email,
            details=log.details,
            ip_address=log.ip_address,
            success=log.success,
            created_at=log.created_at,
        ))

    return AuditListResponse(
        logs=log_responses,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/verify", response_model=AuditIntegrityResponse)
async def verify_audit_integrity(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "owner")),
):
    """
    Cryptographically verify the entire audit log hash chain.
    Iterates through all entries and verifies that:
    1. prev_hash matches the actual entry_hash of the previous row
    2. entry_hash equals SHA256(prev_hash + action + user + doc + details + timestamp)
    Any altered or deleted record causes the check to fail and flags the exact ID.
    """
    is_valid, total, checked, broken_id, message = await AuditService.verify_integrity(db)

    return AuditIntegrityResponse(
        is_valid=is_valid,
        total_entries=total,
        checked_entries=checked,
        first_broken_entry_id=broken_id,
        message=message,
    )


@router.get("/stats")
async def get_audit_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Admin dashboard stats regarding security operations and refutals."""
    # Total actions
    total_q = await db.execute(select(func.count(AuditLog.id)))
    total_actions = total_q.scalar_one()

    # Refusals (VIEW_DENIED, DOWNLOAD_DENIED, EDIT_DENIED, DELETE_DENIED, LOGIN_FAILED)
    refusals_q = await db.execute(
        select(func.count(AuditLog.id)).where(
            AuditLog.action.in_([
                "VIEW_DENIED", "DOWNLOAD_DENIED", "EDIT_DENIED", "DELETE_DENIED", "LOGIN_FAILED"
            ])
        )
    )
    total_refusals = refusals_q.scalar_one()

    # Active grants vs revocations
    grants_q = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "PERMISSION_GRANT")
    )
    total_grants = grants_q.scalar_one()

    revocations_q = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "PERMISSION_REVOKE")
    )
    total_revocations = revocations_q.scalar_one()

    # Failed logins
    failed_logins_q = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "LOGIN_FAILED")
    )
    failed_logins = failed_logins_q.scalar_one()

    # Cryptographic integrity status
    is_valid, total, _, broken_id, msg = await AuditService.verify_integrity(db)

    return {
        "total_actions": total_actions,
        "total_refusals": total_refusals,
        "total_grants": total_grants,
        "total_revocations": total_revocations,
        "failed_logins": failed_logins,
        "chain_integrity": {
            "is_valid": is_valid,
            "total_entries": total,
            "first_broken_entry_id": broken_id,
            "message": msg,
        }
    }
