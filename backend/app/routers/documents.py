"""
Documents Router — TrustVault
Every endpoint checks permissions through the PermissionService.
The server decides access, not the client.
"""
import math
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form, status
from fastapi.responses import StreamingResponse
import io, json
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_role
from app.models.user import User
from app.schemas.document import (
    DocumentResponse, DocumentUpdate, DocumentListResponse,
)
from app.services.document_service import DocumentService
from app.services.permission_service import PermissionService
from app.services.audit_service import AuditService
from app.utils.validators import validate_file_upload, sanitize_filename, validate_category

router = APIRouter(prefix="/api/documents", tags=["Documents"])


def _build_doc_response(doc, permission_level=None):
    """Build a DocumentResponse with owner info."""
    owner_name = None
    if doc.owner:
        owner_name = doc.owner.full_name
    return DocumentResponse(
        id=doc.id,
        owner_id=doc.owner_id,
        owner_name=owner_name,
        original_filename=doc.original_filename,
        mime_type=doc.mime_type,
        file_size=doc.file_size,
        category=doc.category,
        description=doc.description,
        is_deleted=doc.is_deleted,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        permission_level=permission_level,
    )


@router.post("", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    category: str = Form(default="general"),
    description: str = Form(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("admin", "owner")),
):
    """
    Upload a new document. Only admins and owners can upload.
    The file is encrypted at rest with AES-256-GCM.
    """
    # Read file data
    file_data = await file.read()

    # Validate
    is_valid, msg = validate_file_upload(
        file.filename or "unknown",
        file.content_type or "application/octet-stream",
        len(file_data),
    )
    if not is_valid:
        await AuditService.log(
            db, action="UPLOAD",
            user_id=current_user.id,
            details={"filename": file.filename, "error": msg},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    if category:
        is_valid_cat, cat_msg = validate_category(category)
        if not is_valid_cat:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=cat_msg)

    safe_filename = sanitize_filename(file.filename or "unknown")

    document = await DocumentService.upload(
        db=db,
        owner=current_user,
        file_data=file_data,
        original_filename=safe_filename,
        mime_type=file.content_type or "application/octet-stream",
        category=category,
        description=description,
    )

    # Audit
    await AuditService.log(
        db, action="UPLOAD",
        user_id=current_user.id,
        document_id=document.id,
        details={
            "filename": safe_filename,
            "size": len(file_data),
            "mime_type": file.content_type,
            "category": category,
        },
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return _build_doc_response(document, "owner")


@router.get("", response_model=DocumentListResponse)
async def list_documents(
    request: Request,
    query: str = None,
    category: str = None,
    owner_id: UUID = None,
    page: int = 1,
    page_size: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List documents the current user has access to.
    Only returns documents the user owns or has been granted access to.
    """
    accessible_ids = await PermissionService.get_accessible_document_ids(db, current_user)

    if not accessible_ids:
        return DocumentListResponse(
            documents=[], total=0, page=page,
            page_size=page_size, total_pages=0,
        )

    documents, total = await DocumentService.search_documents(
        db=db,
        accessible_ids=accessible_ids,
        query=query,
        category=category,
        owner_id=owner_id,
        page=page,
        page_size=page_size,
    )

    # Add permission level to each document
    doc_responses = []
    for doc in documents:
        level = await PermissionService.get_user_permission_level(db, current_user, doc.id)
        doc_responses.append(_build_doc_response(doc, level))

    return DocumentListResponse(
        documents=doc_responses,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=math.ceil(total / page_size) if total > 0 else 0,
    )

@router.get("/export", response_class=StreamingResponse, tags=["Documents"])
async def export_documents(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    """Export all accessible documents as a JSON file."""
    # Get IDs the user can access
    accessible_ids = await PermissionService.get_accessible_document_ids(db, current_user)
    # Retrieve all documents (large page size to capture all)
    docs, _ = await DocumentService.search_documents(
        db=db,
        accessible_ids=accessible_ids,
        query=None,
        category=None,
        owner_id=None,
        page=1,
        page_size=10000,
    )
    docs_data = [_build_doc_response(doc).dict() for doc in docs]
    json_bytes = json.dumps(docs_data, default=str).encode("utf-8")
    await AuditService.log(
        db,
        action="EXPORT",
        user_id=current_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return StreamingResponse(
        io.BytesIO(json_bytes),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="documents_export.json"'},
    )


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get document metadata. Requires read access."""
    # PERMISSION CHECK — server-side, every time
    has_access = await PermissionService.check_access(db, current_user, document_id, "read")

    if not has_access:
        # Log the denied attempt
        await AuditService.log(
            db, action="VIEW_DENIED",
            user_id=current_user.id,
            document_id=document_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this document",
        )

    document = await DocumentService.get_document(db, document_id)
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    level = await PermissionService.get_user_permission_level(db, current_user, document_id)

    # Audit
    await AuditService.log(
        db, action="VIEW",
        user_id=current_user.id,
        document_id=document_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return _build_doc_response(document, level)


@router.get("/{document_id}/download")
async def download_document(
    document_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Download a document file. Requires read access.
    The file is decrypted on-the-fly and sent to the client.
    """
    # PERMISSION CHECK
    has_access = await PermissionService.check_access(db, current_user, document_id, "read")

    if not has_access:
        await AuditService.log(
            db, action="DOWNLOAD_DENIED",
            user_id=current_user.id,
            document_id=document_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to download this document",
        )

    document = await DocumentService.get_document(db, document_id)
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    try:
        file_data = await DocumentService.download(db, document)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="File not found on server",
        )

    # Audit
    await AuditService.log(
        db, action="DOWNLOAD",
        user_id=current_user.id,
        document_id=document_id,
        details={"filename": document.original_filename},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return StreamingResponse(
        io.BytesIO(file_data),
        media_type=document.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{document.original_filename}"',
            "Content-Length": str(len(file_data)),
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


@router.put("/{document_id}", response_model=DocumentResponse)
async def update_document(
    document_id: UUID,
    data: DocumentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update document metadata. Requires edit access."""
    # PERMISSION CHECK — edit required
    has_access = await PermissionService.check_access(db, current_user, document_id, "edit")

    if not has_access:
        await AuditService.log(
            db, action="EDIT_DENIED",
            user_id=current_user.id,
            document_id=document_id,
            details={"attempted_changes": data.model_dump(exclude_none=True)},
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have edit access to this document",
        )

    document = await DocumentService.get_document(db, document_id)
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    document = await DocumentService.update_document(
        db, document, data.category, data.description,
    )

    # Audit
    await AuditService.log(
        db, action="EDIT",
        user_id=current_user.id,
        document_id=document_id,
        details=data.model_dump(exclude_none=True),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    level = await PermissionService.get_user_permission_level(db, current_user, document_id)
    return _build_doc_response(document, level)


@router.put("/{document_id}/file", response_model=DocumentResponse)
async def replace_document_file(
    document_id: UUID,
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Replace the file content of a document. Requires edit access."""
    has_access = await PermissionService.check_access(db, current_user, document_id, "edit")

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have edit access to this document",
        )

    document = await DocumentService.get_document(db, document_id)
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    file_data = await file.read()
    is_valid, msg = validate_file_upload(
        file.filename or "unknown",
        file.content_type or "application/octet-stream",
        len(file_data),
    )
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    safe_filename = sanitize_filename(file.filename or "unknown")

    document = await DocumentService.replace_file(
        db, document, file_data, safe_filename, file.content_type or "application/octet-stream",
    )

    await AuditService.log(
        db, action="FILE_REPLACE",
        user_id=current_user.id,
        document_id=document_id,
        details={"new_filename": safe_filename, "new_size": len(file_data)},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    level = await PermissionService.get_user_permission_level(db, current_user, document_id)
    return _build_doc_response(document, level)


@router.delete("/{document_id}")
async def delete_document(
    document_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Soft-delete a document. Owner only."""
    document = await DocumentService.get_document(db, document_id)
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    # Only the owner can delete
    if document.owner_id != current_user.id:
        await AuditService.log(
            db, action="DELETE_DENIED",
            user_id=current_user.id,
            document_id=document_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can delete it",
        )

    await DocumentService.soft_delete(db, document)

    await AuditService.log(
        db, action="DELETE",
        user_id=current_user.id,
        document_id=document_id,
        details={"filename": document.original_filename},
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return {"message": "Document deleted"}
