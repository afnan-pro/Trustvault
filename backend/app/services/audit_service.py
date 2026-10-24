"""
Audit Service — TrustVault
Handles audit log creation with cryptographic hash chaining.
Every significant action passes through here.
"""
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog


class AuditService:
    """Service for creating and querying audit log entries."""

    @staticmethod
    async def log(
        db: AsyncSession,
        action: str,
        user_id: Optional[UUID] = None,
        document_id: Optional[UUID] = None,
        target_user_id: Optional[UUID] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
    ) -> AuditLog:
        """
        Create an audit log entry with hash chaining.
        Each entry's hash includes the previous entry's hash.
        """
        # Get the previous entry's hash for chaining
        result = await db.execute(
            select(AuditLog.entry_hash)
            .order_by(desc(AuditLog.id))
            .limit(1)
        )
        prev_hash = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        # Compute the hash for this entry
        entry_hash = AuditLog.compute_hash(
            prev_hash=prev_hash,
            action=action,
            user_id=str(user_id) if user_id else None,
            document_id=str(document_id) if document_id else None,
            details=details,
            timestamp=now.isoformat(),
        )

        entry = AuditLog(
            user_id=user_id,
            action=action,
            document_id=document_id,
            target_user_id=target_user_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            created_at=now,
        )

        db.add(entry)
        await db.flush()
        return entry

    @staticmethod
    async def get_logs(
        db: AsyncSession,
        action: Optional[str] = None,
        user_id: Optional[UUID] = None,
        document_id: Optional[UUID] = None,
        success: Optional[bool] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        page: int = 1,
        page_size: int = 50,
    ):
        """Query audit logs with filtering."""
        query = select(AuditLog)
        count_query = select(func.count(AuditLog.id))

        if action:
            query = query.where(AuditLog.action == action)
            count_query = count_query.where(AuditLog.action == action)
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
            count_query = count_query.where(AuditLog.user_id == user_id)
        if document_id:
            query = query.where(AuditLog.document_id == document_id)
            count_query = count_query.where(AuditLog.document_id == document_id)
        if success is not None:
            query = query.where(AuditLog.success == success)
            count_query = count_query.where(AuditLog.success == success)
        if date_from:
            query = query.where(AuditLog.created_at >= date_from)
            count_query = count_query.where(AuditLog.created_at >= date_from)
        if date_to:
            query = query.where(AuditLog.created_at <= date_to)
            count_query = count_query.where(AuditLog.created_at <= date_to)

        total = (await db.execute(count_query)).scalar_one()

        query = query.order_by(desc(AuditLog.created_at))
        query = query.offset((page - 1) * page_size).limit(page_size)

        result = await db.execute(query)
        logs = result.scalars().all()

        return logs, total

    @staticmethod
    async def verify_integrity(db: AsyncSession):
        """
        Verify the integrity of the audit log hash chain.
        Returns (is_valid, total_entries, checked, first_broken_id, message).
        """
        result = await db.execute(
            select(AuditLog).order_by(AuditLog.id)
        )
        entries = result.scalars().all()

        if not entries:
            return True, 0, 0, None, "No audit entries to verify"

        prev_hash = None
        for i, entry in enumerate(entries):
            # Verify the chain
            if entry.prev_hash != prev_hash:
                return (
                    False, len(entries), i,
                    entry.id,
                    f"Chain broken at entry #{entry.id}: expected prev_hash "
                    f"'{prev_hash}' but found '{entry.prev_hash}'"
                )

            # Recompute this entry's hash
            expected_hash = AuditLog.compute_hash(
                prev_hash=entry.prev_hash,
                action=entry.action,
                user_id=str(entry.user_id) if entry.user_id else None,
                document_id=str(entry.document_id) if entry.document_id else None,
                details=entry.details,
                timestamp=entry.created_at.isoformat(),
            )

            if entry.entry_hash != expected_hash:
                return (
                    False, len(entries), i,
                    entry.id,
                    f"Hash mismatch at entry #{entry.id}: entry has been tampered with"
                )

            prev_hash = entry.entry_hash

        return (
            True, len(entries), len(entries), None,
            f"All {len(entries)} entries verified — chain is intact"
        )
