from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, REAL, Enum as SQLEnum, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class AIFixStatus(str, PyEnum):
    PENDING = "pending"
    APPLIED = "applied"
    VERIFIED = "verified"
    REJECTED = "rejected"


class AIFixType(str, PyEnum):
    PARAMETERIZED_QUERY = "parameterized_query"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    AUTH_CHECK = "auth_check"
    CONFIG_CHANGE = "config_change"
    DEPENDENCY_UPDATE = "dependency_update"
    CUSTOM = "custom"


class AICodeFix(Base):
    __tablename__ = "ai_code_fixes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    patch: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False)
    fix_type: Mapped[AIFixType] = mapped_column(SQLEnum(AIFixType, native_enum=False), nullable=False)
    verification_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    related_cwe: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    estimated_effort: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[AIFixStatus] = mapped_column(SQLEnum(AIFixStatus, native_enum=False), default=AIFixStatus.PENDING, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="ai_code_fixes")

    __table_args__ = (
        Index("idx_ai_code_fixes_finding_id", "finding_id"),
    )
