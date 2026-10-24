"""
Permission Schemas — TrustVault
"""
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, EmailStr


class PermissionGrant(BaseModel):
    user_email: EmailStr  # Grant by email, not ID, for usability
    level: str = Field(default="read", pattern="^(read|edit)$")
    expires_at: Optional[datetime] = None  # None = never expires


class PermissionResponse(BaseModel):
    id: UUID
    document_id: UUID
    user_id: UUID
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    level: str
    granted_by: UUID
    granted_by_email: Optional[str] = None
    expires_at: Optional[datetime]
    is_revoked: bool
    created_at: datetime
    revoked_at: Optional[datetime]

    model_config = {"from_attributes": True}


class PermissionRevoke(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)
