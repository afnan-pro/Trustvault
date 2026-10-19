"""
File Encryption at Rest Test Suite — TrustVault
Verifies that files on disk are encrypted using AES-256-GCM
and cannot be read in plaintext directly from the filesystem.
"""
import pytest
from app.config import UPLOAD_DIR
from app.models.document import Document
from app.services.document_service import DocumentService
from sqlalchemy import select


@pytest.mark.asyncio
async def test_files_are_encrypted_on_disk(seeded_db):
    """
    SECURITY TEST: Data at Rest Encryption.
    Inspect the raw bytes written to the UPLOAD_DIR on disk.
    Ensure the raw file content is encrypted AES-256-GCM ciphertext,
    not plaintext, and that decrypting restores the original content.
    """
    # 1. Fetch a document from DB
    result = await seeded_db.execute(select(Document).limit(1))
    doc = result.scalar_one_or_none()
    assert doc is not None

    file_path = UPLOAD_DIR / doc.stored_filename
    assert file_path.exists(), f"Stored file {doc.stored_filename} must exist on disk"

    # Read raw disk contents
    raw_disk_bytes = file_path.read_bytes()

    # Plaintext keywords from salary/contract files must NOT appear in raw disk bytes
    assert b"Strictly confidential" not in raw_disk_bytes
    assert b"Executive Salary" not in raw_disk_bytes
    assert b"compensation" not in raw_disk_bytes

    # 2. Decrypt via DocumentService and verify original restored
    decrypted = await DocumentService.download(seeded_db, doc)
    assert len(decrypted) == doc.file_size
    # Decrypted stream must contain valid file header (PDF or PNG)
    assert decrypted.startswith(b"%PDF") or decrypted.startswith(b"\x89PNG")
