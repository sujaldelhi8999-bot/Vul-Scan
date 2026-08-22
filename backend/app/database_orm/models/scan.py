from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index, Enum as SQLEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class ScanMode(str, PyEnum):
    DEFEND = "defend"
    PENTEST = "pentest"
    MULTI_AGENT = "multi_agent"


class ScanIntensity(str, PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScanStatus(str, PyEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    COMPLETE = "complete"
    ERROR = "error"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    mode: Mapped[ScanMode] = mapped_column(SQLEnum(ScanMode, native_enum=False), nullable=False)
    intensity: Mapped[ScanIntensity] = mapped_column(SQLEnum(ScanIntensity, native_enum=False), default=ScanIntensity.MEDIUM, nullable=False)
    selected_tests: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    user_id: Mapped[str] = mapped_column(String(64), ForeignKey("users.id"), nullable=False, default="local-user", index=True)
    authorization_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("authorized_targets.id"), nullable=True)
    authorization_confirmed: Mapped[bool] = mapped_column(default=False, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus, native_enum=False), default=ScanStatus.QUEUED, nullable=False)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sandbox_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User"] = relationship(back_populates="scans")
    authorization: Mapped[Optional["AuthorizedTarget"]] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    artifacts: Mapped[Optional["ScanArtifact"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    agent_runs: Mapped[list["AgentRun"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    scan_event_logs: Mapped[list["ScanEventLog"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
