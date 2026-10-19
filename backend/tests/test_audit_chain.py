"""
Cryptographic Audit Chain Test Suite — TrustVault
Proves that the audit trail is tamper-evident and that any direct database alteration
is detected mathematically.
"""
import pytest
from sqlalchemy import select, update
from app.models.audit import AuditLog
from app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_audit_hash_chain_intact(seeded_db):
    """Verify that a legitimate series of actions passes mathematical verification."""
    is_valid, total, checked, broken_id, msg = await AuditService.verify_integrity(seeded_db)
    assert is_valid is True, f"Integrity check failed: {msg}"
    assert total > 0, "Seeded database should have audit records"
    assert broken_id is None


@pytest.mark.asyncio
async def test_audit_log_tampering_is_detected(seeded_db):
    """
    SECURITY TEST: Tamper-Evident Audit Trail.
    An attacker with direct database access alters an audit record
    (e.g., changes 'VIEW_DENIED' to 'VIEW' to hide an intrusion).
    The cryptographic verification algorithm MUST flag the tampering
    and return the exact row ID that was corrupted.
    """
    # 1. Locate an existing audit record
    result = await seeded_db.execute(
        select(AuditLog).where(AuditLog.action == "VIEW_DENIED").limit(1)
    )
    tamper_entry = result.scalar_one_or_none()
    assert tamper_entry is not None, "Expected a VIEW_DENIED audit log from seed data"

    tampered_id = tamper_entry.id

    # 2. Tamper with the record directly in the database without recomputing the cryptographic hash
    await seeded_db.execute(
        update(AuditLog)
        .where(AuditLog.id == tampered_id)
        .values(action="VIEW", success=True)
    )
    await seeded_db.commit()

    # 3. Run cryptographic chain verification
    is_valid, total, checked, broken_id, msg = await AuditService.verify_integrity(seeded_db)

    # MUST be detected as tampered
    assert is_valid is False, "Tampered audit log MUST fail verification"
    assert broken_id == tampered_id, f"Verification must detect exactly entry #{tampered_id}, but reported #{broken_id}"
    assert "tampered with" in msg.lower() or "mismatch" in msg.lower() or "chain broken" in msg.lower()
