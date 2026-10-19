"""
Document Model — TrustVault
Stores document metadata. Actual files are encrypted on disk, referenced by stored_filename (UUID).
"""
import uuid
from datetime import datetime
from sqlalchemy import String, BigInteger, Text, Boolean, DateTime, ForeignKey, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True
    )
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_filename: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )  # UUID-based name on disk
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    category: Mapped[str] = mapped_column(
        String(100), nullable=True, default="general", index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=True)
    encryption_iv: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # IV for AES-GCM, hex encoded
    encryption_tag: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # Auth tag for AES-GCM, hex encoded
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    owner = relationship("User", back_populates="documents", lazy="selectin")
    permissions = relationship("Permission", back_populates="document", lazy="selectin")

    def __repr__(self):
        return f"<Document {self.original_filename} ({self.id})>"
