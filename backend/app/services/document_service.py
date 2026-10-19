"""
Document Service — TrustVault
Handles document CRUD with encryption at rest.
"""
import uuid
import aiofiles
from pathlib import Path
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import UPLOAD_DIR
from app.models.document import Document
from app.models.user import User
from app.utils.security import encrypt_file, decrypt_file


class DocumentService:
    """Document storage and retrieval with encryption."""

    @staticmethod
    async def upload(
        db: AsyncSession,
        owner: User,
        file_data: bytes,
        original_filename: str,
        mime_type: str,
        category: Optional[str] = "general",
        description: Optional[str] = None,
    ) -> Document:
        """Upload and encrypt a document."""
        # Generate a unique storage filename
        stored_filename = f"{uuid.uuid4().hex}"

        # Encrypt the file data
        encrypted_data, iv, tag = encrypt_file(file_data)

        # Write encrypted data to disk
        file_path = UPLOAD_DIR / stored_filename
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(encrypted_data)

        # Create database record
        document = Document(
            owner_id=owner.id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            mime_type=mime_type,
            file_size=len(file_data),
            category=category,
            description=description,
            encryption_iv=iv.hex(),
            encryption_tag=tag.hex(),
        )
        db.add(document)
        await db.flush()

        return document

    @staticmethod
    async def get_document(
        db: AsyncSession,
        document_id: UUID,
    ) -> Optional[Document]:
        """Get a document by ID (metadata only, does not check permissions)."""
        result = await db.execute(
            select(Document).where(
                Document.id == document_id,
                Document.is_deleted == False,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def download(
        db: AsyncSession,
        document: Document,
    ) -> bytes:
        """Read and decrypt a document file from disk."""
        file_path = UPLOAD_DIR / document.stored_filename

        if not file_path.exists():
            raise FileNotFoundError(f"File not found on disk: {document.stored_filename}")

        async with aiofiles.open(file_path, 'rb') as f:
            encrypted_data = await f.read()

        iv = bytes.fromhex(document.encryption_iv)

        return decrypt_file(encrypted_data, iv)

    @staticmethod
    async def update_document(
        db: AsyncSession,
        document: Document,
        category: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Document:
        """Update document metadata."""
        if category is not None:
            document.category = category
        if description is not None:
            document.description = description
        await db.flush()
        return document

    @staticmethod
    async def soft_delete(
        db: AsyncSession,
        document: Document,
    ) -> Document:
        """Soft-delete a document. File remains encrypted on disk."""
        document.is_deleted = True
        await db.flush()
        return document

    @staticmethod
    async def search_documents(
        db: AsyncSession,
        accessible_ids: list[UUID],
        query: Optional[str] = None,
        category: Optional[str] = None,
        owner_id: Optional[UUID] = None,
        date_from=None,
        date_to=None,
        page: int = 1,
        page_size: int = 20,
    ):
        """Search documents the user has access to."""
        base_query = select(Document).where(
            Document.id.in_(accessible_ids),
            Document.is_deleted == False,
        )
        count_query = select(func.count(Document.id)).where(
            Document.id.in_(accessible_ids),
            Document.is_deleted == False,
        )

        if query:
            search_filter = or_(
                Document.original_filename.ilike(f"%{query}%"),
                Document.description.ilike(f"%{query}%"),
                Document.category.ilike(f"%{query}%"),
            )
            base_query = base_query.where(search_filter)
            count_query = count_query.where(search_filter)

        if category:
            base_query = base_query.where(Document.category == category)
            count_query = count_query.where(Document.category == category)

        if owner_id:
            base_query = base_query.where(Document.owner_id == owner_id)
            count_query = count_query.where(Document.owner_id == owner_id)

        if date_from:
            base_query = base_query.where(Document.created_at >= date_from)
            count_query = count_query.where(Document.created_at >= date_from)

        if date_to:
            base_query = base_query.where(Document.created_at <= date_to)
            count_query = count_query.where(Document.created_at <= date_to)

        total = (await db.execute(count_query)).scalar_one()

        base_query = base_query.order_by(Document.created_at.desc())
        base_query = base_query.offset((page - 1) * page_size).limit(page_size)

        result = await db.execute(base_query)
        documents = result.scalars().all()

        return documents, total

    @staticmethod
    async def replace_file(
        db: AsyncSession,
        document: Document,
        file_data: bytes,
        original_filename: str,
        mime_type: str,
    ) -> Document:
        """Replace the file content of an existing document (edit permission required)."""
        # Encrypt new data
        encrypted_data, iv, tag = encrypt_file(file_data)

        # Remove old file
        old_path = UPLOAD_DIR / document.stored_filename
        if old_path.exists():
            old_path.unlink()

        # Generate new stored filename
        new_stored = f"{uuid.uuid4().hex}"
        file_path = UPLOAD_DIR / new_stored
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(encrypted_data)

        # Update record
        document.stored_filename = new_stored
        document.original_filename = original_filename
        document.mime_type = mime_type
        document.file_size = len(file_data)
        document.encryption_iv = iv.hex()
        document.encryption_tag = tag.hex()

        await db.flush()
        return document
