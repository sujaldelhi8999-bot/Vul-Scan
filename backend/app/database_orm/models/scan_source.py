from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, REAL, Enum as SQLEnum, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class SourceType(str, PyEnum):
    LOCAL = "local"
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    LIVE = "live"
    API_SPEC = "api_spec"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"


class ScanSourceStatus(str, PyEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScanSource(Base):
    __tablename__ = "scan_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type: Mapped[SourceType] = mapped_column(SQLEnum(SourceType, native_enum=False), nullable=False)
    source_config: Mapped[str] = mapped_column(Text, nullable=False)
    source_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ScanSourceStatus] = mapped_column(SQLEnum(ScanSourceStatus, native_enum=False), default=ScanSourceStatus.PENDING, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scan_duration_seconds: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    artifacts: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_scan_sources_scan_id", "scan_id"),
    )
