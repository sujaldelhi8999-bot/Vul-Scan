from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class ScanArtifact(Base):
    __tablename__ = "scan_artifacts"

    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True)
    scanner_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    shadow_recon_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    markdown_report: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notification_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    active_security_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    browser_security_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_analyst_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    exploitation_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tci_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_consultation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ports_open: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    technologies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    server_header: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    waf_detected: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cdn_detected: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    dns_records: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tls_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tls_cipher: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tls_expiry: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tls_valid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    body_technologies: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="artifacts")
