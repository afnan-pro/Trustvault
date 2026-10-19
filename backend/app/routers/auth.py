"""
Auth Router — TrustVault
Handles login, registration, token refresh, logout, and password changes.
"""
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.user import User
from app.schemas.auth import (
    UserCreate, UserLogin, UserResponse, TokenResponse, PasswordChange, UserUpdate,
)
from app.services.auth_service import AuthService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(
    data: UserLogin,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate user and return tokens.
    Rate limited to 5 attempts per minute.
    """
    user = await AuthService.authenticate(db, data.email, data.password)

    if not user:
        # Log failed attempt
        await AuditService.log(
            db, action="LOGIN_FAILED",
            details={"email": data.email},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    access_token, refresh_token = await AuthService.create_tokens(db, user)

    # Log successful login
    await AuditService.log(
        db, action="LOGIN",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        success=True,
    )

    # Set refresh token as httpOnly cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=False,  # Set True in production with HTTPS
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path="/api/auth",
    )

    return TokenResponse(
        access_token=access_token,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


@router.post("/register", response_model=UserResponse)
async def register(
    data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
):
    """
    Register a new user. Admin only.
    """
    try:
        user = await AuthService.register_user(
            db, data.email, data.full_name, data.password, data.role,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Audit log
    await AuditService.log(
        db, action="USER_CREATE",
        user_id=current_user.id,
        target_user_id=user.id,
        details={"email": user.email, "role": user.role},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return UserResponse.model_validate(user)


@router.post("/refresh", response_model=dict)
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Refresh the access token using the refresh token cookie."""
    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided",
        )

    try:
        access_token, user = await AuthService.refresh_access_token(db, raw_refresh)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Logout and revoke tokens."""
    raw_refresh = request.cookies.get("refresh_token")
    await AuthService.logout(db, current_user.id, raw_refresh)

    # Clear cookie
    response.delete_cookie(key="refresh_token", path="/api/auth")

    # Audit
    await AuditService.log(
        db, action="LOGOUT",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return {"message": "Logged out successfully"}


@router.put("/password")
async def change_password(
    data: PasswordChange,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Change the current user's password. Invalidates all existing tokens."""
    try:
        await AuthService.change_password(
            db, current_user, data.current_password, data.new_password,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Audit
    await AuditService.log(
        db, action="PASSWORD_CHANGE",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return {"message": "Password changed. Please log in again."}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
):
    """Get the current authenticated user's info."""
    return UserResponse.model_validate(current_user)
