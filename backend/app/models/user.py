"""
User Model — TrustVault
Stores user credentials, roles, and token generation counter for immediate revocation.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, Integer, DateTime, func, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="viewer"
    )  # admin, owner, viewer
    token_generation: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )  # Increment to invalidate all tokens
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    documents = relationship("Document", back_populates="owner", lazy="selectin")
    permissions = relationship("Permission", foreign_keys="Permission.user_id", back_populates="user", lazy="selectin")
    refresh_tokens = relationship("RefreshToken", back_populates="user", lazy="selectin")

    def __repr__(self):
        return f"<User {self.email} ({self.role})>"
