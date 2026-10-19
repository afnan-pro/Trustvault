"""
Audit Log Model — TrustVault
Append-only audit trail with cryptographic hash chaining.
Each entry's hash includes the previous entry's hash, making tampering detectable.

The application database role should only have INSERT permission on this table.
"""
import uuid
import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Text, DateTime, ForeignKey, Integer, JSON, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True
    )  # Nullable for system actions
    action: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    # Actions: LOGIN, LOGIN_FAILED, LOGOUT, UPLOAD, DOWNLOAD, DOWNLOAD_DENIED,
    #          VIEW, VIEW_DENIED, EDIT, DELETE, PERMISSION_GRANT, PERMISSION_REVOKE,
    #          USER_CREATE, USER_DEACTIVATE, PASSWORD_CHANGE
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("documents.id"), nullable=True, index=True
    )
    target_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=True
    )  # For permission changes: who was affected
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    prev_hash: Mapped[str] = mapped_column(
        String(64), nullable=True
    )  # SHA-256 of previous entry
    entry_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # SHA-256 of this entry including prev_hash
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships (read-only references)
    user = relationship("User", foreign_keys=[user_id])
    document = relationship("Document", foreign_keys=[document_id])
    target_user = relationship("User", foreign_keys=[target_user_id])

    @staticmethod
    def normalize_timestamp(dt) -> str:
        """Format timestamp canonically across all DB engines and drivers."""
        if dt is None:
            return ""
        if isinstance(dt, str):
            try:
                clean = dt.replace(" ", "T").replace("Z", "")
                if "+" in clean:
                    clean = clean.split("+")[0]
                dt = datetime.fromisoformat(clean)
            except Exception:
                return str(dt)
        if hasattr(dt, "tzinfo"):
            dt = dt.replace(microsecond=0)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        return str(dt)

    @staticmethod
    def compute_hash(prev_hash: str | None, action: str, user_id: str | None,
                     document_id: str | None, details: dict | None,
                     timestamp) -> str:
        """Compute SHA-256 hash for this audit entry including the chain."""
        canonical_ts = AuditLog.normalize_timestamp(timestamp)
        data = json.dumps({
            "prev_hash": prev_hash or "",
            "action": action,
            "user_id": str(user_id) if user_id else "",
            "document_id": str(document_id) if document_id else "",
            "details": details or {},
            "timestamp": canonical_ts,
        }, sort_keys=True, default=str)
        return hashlib.sha256(data.encode()).hexdigest()

    def __repr__(self):
        return f"<AuditLog #{self.id} {self.action} by {self.user_id}>"


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    token_hash: Mapped[str] = mapped_column(
        String(128), unique=True, nullable=False
    )  # SHA-256 of token, never store raw
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")

    def __repr__(self):
        return f"<RefreshToken {self.id} for {self.user_id}>"
