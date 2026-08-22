from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class JobStatus(str, PyEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AuthorizedTestJob(Base):
    __tablename__ = "authorized_test_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    authorization_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("authorized_targets.id"), nullable=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_target_origin: Mapped[str] = mapped_column(Text, nullable=False)
    selected_modules: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    status: Mapped[JobStatus] = mapped_column(SQLEnum(JobStatus, native_enum=False), default=JobStatus.QUEUED, nullable=False)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_module: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    current_phase: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    surfaces_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    surfaces_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    raw_surfaces_discovered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    testable_surfaces: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    surface_groups: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    result_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scans.id"), nullable=True)

    authorization: Mapped[Optional["AuthorizedTarget"]] = relationship()
    scan: Mapped[Optional["Scan"]] = relationship()
    events: Mapped[list["JobEvent"]] = relationship(back_populates="job", cascade="all, delete-orphan")
    evidence_records: Mapped[list["EvidenceRecord"]] = relationship(back_populates="job", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_authorized_test_jobs_status", "status"),
        Index("idx_authorized_test_jobs_target", "normalized_target_origin", "status"),
    )
