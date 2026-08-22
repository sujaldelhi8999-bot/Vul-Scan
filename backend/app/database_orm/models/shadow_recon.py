from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class ShadowReconResult(Base):
    __tablename__ = "shadow_recon_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    emails: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    internal_ips: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    js_source_maps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    html_comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sensitive_files: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    robots_txt_content: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sitemap_urls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    wayback_urls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    crtsh_subdomains: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    all_subdomains: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_shadow_recon_scan_id", "scan_id"),
    )
