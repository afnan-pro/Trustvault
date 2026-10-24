"""
Audit Schemas — TrustVault
"""
from datetime import datetime
from typing import Optional, List, Any
from uuid import UUID
from pydantic import BaseModel, Field


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[UUID]
    user_email: Optional[str] = None
    action: str
    document_id: Optional[UUID]
    document_name: Optional[str] = None
    target_user_id: Optional[UUID]
    target_user_email: Optional[str] = None
    details: Optional[dict] = None
    ip_address: Optional[str]
    success: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditListResponse(BaseModel):
    logs: List[AuditLogResponse]
    total: int
    page: int
    page_size: int


class AuditSearchParams(BaseModel):
    action: Optional[str] = None
    user_id: Optional[UUID] = None
    document_id: Optional[UUID] = None
    success: Optional[bool] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)


class AuditIntegrityResponse(BaseModel):
    is_valid: bool
    total_entries: int
    checked_entries: int
    first_broken_entry_id: Optional[int] = None
    message: str
