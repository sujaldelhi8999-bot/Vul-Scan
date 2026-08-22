from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index, Enum as SQLEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class VerificationMethod(str, PyEnum):
    DNS = "dns"
    HTTP = "http"


class VerificationStatus(str, PyEnum):
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class AuthorizedTarget(Base):
    __tablename__ = "authorized_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    target_origin: Mapped[str] = mapped_column(String(512), nullable=False)
    verification_method: Mapped[VerificationMethod] = mapped_column(
        SQLEnum(VerificationMethod, native_enum=False), nullable=False
    )
    verification_token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    challenge_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[VerificationStatus] = mapped_column(
        SQLEnum(VerificationStatus, native_enum=False), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    user: Mapped["User"] = relationship(back_populates="authorized_targets")
    scans: Mapped[list["Scan"]] = relationship(back_populates="authorization")

    __table_args__ = (
        Index("idx_authorized_targets_lookup", "user_id", "target_origin", "status"),
    )
