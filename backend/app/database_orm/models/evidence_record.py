from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class EvidenceRecord(Base):
    __tablename__ = "evidence_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    job_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("authorized_test_jobs.id"), nullable=True, index=True)
    scan_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scans.id"), nullable=True, index=True)
    module: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    surface: Mapped[str] = mapped_column(Text, default="", nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="", nullable=False)
    request_url: Mapped[str] = mapped_column(Text, default="", nullable=False)
    safe_test_marker: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    request_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    response_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    response_observed: Mapped[bool] = mapped_column(default=False, nullable=False)
    detection_result: Mapped[str] = mapped_column(String(30), default="INCONCLUSIVE", nullable=False)
    evidence_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    finding_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("findings.id"), nullable=True, index=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    job: Mapped[Optional["AuthorizedTestJob"]] = relationship(back_populates="evidence_records")
    scan: Mapped[Optional["Scan"]] = relationship()
    finding: Mapped[Optional["Finding"]] = relationship(back_populates="evidence_records")

    __table_args__ = (
        Index("idx_evidence_job_id", "job_id"),
        Index("idx_evidence_request_id", "request_id"),
        Index("idx_evidence_finding_id", "finding_id"),
    )
