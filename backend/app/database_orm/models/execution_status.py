from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, Enum as SQLEnum
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database_orm.base import Base


class ExecutionType(str, PyEnum):
    DEFEND_SCAN = "DEFEND_SCAN"
    AUTHORIZED_TEST = "AUTHORIZED_TEST"
    SELF_AUDIT = "SELF_AUDIT"
    LAB_OPERATION = "LAB_OPERATION"


class ExecutionLifecycle(str, PyEnum):
    IDLE = "IDLE"
    QUEUED = "QUEUED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ExecutionStatus(Base):
    __tablename__ = "execution_status"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    execution_type: Mapped[Optional[ExecutionType]] = mapped_column(SQLEnum(ExecutionType, native_enum=False), nullable=True)
    lifecycle: Mapped[ExecutionLifecycle] = mapped_column(SQLEnum(ExecutionLifecycle, native_enum=False), default=ExecutionLifecycle.IDLE, nullable=False)
    job_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    target_url: Mapped[str] = mapped_column(Text, default="", nullable=False)
    progress_percent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_module: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    current_phase: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    surfaces_total: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    surfaces_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    agent_states: Mapped[str] = mapped_column(Text, default="[]", nullable=False)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error_code: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_lab: Mapped[bool] = mapped_column(default=False, nullable=False)
    authorization_status: Mapped[str] = mapped_column(String(64), default="", nullable=False)
