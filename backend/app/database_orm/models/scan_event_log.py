from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class ScanEventLog(Base):
    __tablename__ = "scan_event_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agent_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="scan_event_logs")

    __table_args__ = (
        Index("idx_scan_event_logs_scan_id", "scan_id"),
        Index("idx_scan_event_logs_event_type", "event_type"),
    )
