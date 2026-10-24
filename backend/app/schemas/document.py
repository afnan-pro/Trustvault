"""
Document Schemas — TrustVault
"""
from datetime import datetime
from typing import Optional, List
from uuid import UUID
from pydantic import BaseModel, Field


class DocumentUpload(BaseModel):
    category: Optional[str] = Field(default="general", max_length=100)
    description: Optional[str] = Field(default=None, max_length=2000)


class DocumentResponse(BaseModel):
    id: UUID
    owner_id: UUID
    owner_name: Optional[str] = None
    original_filename: str
    mime_type: str
    file_size: int
    category: Optional[str]
    description: Optional[str]
    is_deleted: bool
    created_at: datetime
    updated_at: datetime
    permission_level: Optional[str] = None  # The requesting user's permission

    model_config = {"from_attributes": True}


class DocumentUpdate(BaseModel):
    category: Optional[str] = Field(None, max_length=100)
    description: Optional[str] = Field(None, max_length=2000)


class DocumentSearchParams(BaseModel):
    query: Optional[str] = Field(None, max_length=255)
    category: Optional[str] = Field(None, max_length=100)
    owner_id: Optional[UUID] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class DocumentListResponse(BaseModel):
    documents: List[DocumentResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
