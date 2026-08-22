from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, REAL, Enum as SQLEnum, Index, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class LearningKind(str, PyEnum):
    MODULE = "module"
    SCAN = "scan"


class LearningStatus(str, PyEnum):
    PENDING = "pending"
    APPLIED = "applied"
    DISMISSED = "dismissed"


class LearningInsight(Base):
    __tablename__ = "learning_insights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    kind: Mapped[LearningKind] = mapped_column(SQLEnum(LearningKind, native_enum=False), default=LearningKind.MODULE, nullable=False)
    total_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    true_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unrated_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    true_positive_rate: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    recommendation_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[LearningStatus] = mapped_column(SQLEnum(LearningStatus, native_enum=False), default=LearningStatus.PENDING, nullable=False)
    applied_settings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_learning_insights_scan", "scan_id"),
        Index("idx_learning_insights_module", "module", "status"),
        UniqueConstraint("scan_id", "module", "kind", name="uq_learning_insights_scan_module_kind"),
    )
