"""
Users Router — TrustVault
User directory and administration.
"""
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.user import User
from app.schemas.auth import UserResponse
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

router = APIRouter(prefix="/api/users", tags=["Users"])


class UserStatusUpdate(BaseModel):
    is_active: bool
    reason: Optional[str] = Field(None, max_length=255)


class UserRoleUpdate(BaseModel):
    role: str = Field(..., pattern="^(admin|owner|viewer)$")


@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List users in the system.
    All authenticated users can see active user emails/names for sharing selection.
    Admins can see all users including deactivated accounts.
    """
    if current_user.role == "admin":
        users = await AuthService.get_all_users(db)
    else:
        result = await db.execute(
            select(User).where(User.is_active == True).order_by(User.full_name)
        )
        users = result.scalars().all()

    return [UserResponse.model_validate(u) for u in users]


@router.put("/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: UUID,
    data: UserStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """
    Activate or deactivate a user account. Admin only.
    Deactivating an account immediately increments token_generation and revokes
    all refresh tokens so their access is killed instantly.
    """
    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.id == current_user.id and not data.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot deactivate yourself")

    user.is_active = data.is_active
    if not data.is_active:
        # Immediate session invalidation
        user.token_generation += 1

    await db.flush()

    # Audit log
    action = "USER_ACTIVATE" if data.is_active else "USER_DEACTIVATE"
    await AuditService.log(
        db=db,
        action=action,
        user_id=current_user.id,
        target_user_id=user.id,
        details={"reason": data.reason, "email": user.email},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    )

    return UserResponse.model_validate(user)


@router.put("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: UUID,
    data: UserRoleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """Update user role. Admin only."""
    res = await db.execute(select(User).where(User.id == user_id))
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    old_role = user.role
    user.role = data.role
    # Invalidate tokens to force new role claims on next login
    user.token_generation += 1

    await db.flush()

    await AuditService.log(
        db=db,
        action="ROLE_CHANGE",
        user_id=current_user.id,
        target_user_id=user.id,
        details={"old_role": old_role, "new_role": data.role},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    )

    return UserResponse.model_validate(user)
