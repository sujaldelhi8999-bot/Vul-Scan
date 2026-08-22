from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    authorization_status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    selected_module: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    start_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    request_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sandbox_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_logs_scan_id", "scan_id"),
        Index("idx_audit_logs_agent_name", "agent_name", "id"),
    )
