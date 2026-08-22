from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, REAL, Enum as SQLEnum, Index, UniqueConstraint
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


class CorrelationType(str, PyEnum):
    EXACT_MATCH = "exact_match"
    SAME_FILE = "same_file"
    SAME_ENDPOINT = "same_endpoint"
    DATA_FLOW = "data_flow"
    VULNERABILITY_CHAIN = "vulnerability_chain"


class SourceCorrelation(Base):
    __tablename__ = "source_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    unified_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    correlation_type: Mapped[CorrelationType] = mapped_column(SQLEnum(CorrelationType, native_enum=False), nullable=False)
    confidence: Mapped[float] = mapped_column(REAL, nullable=False)
    source_types: Mapped[str] = mapped_column(Text, nullable=False)
    finding_ids: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_source_correlations_scan_id", "scan_id"),
        Index("idx_source_correlations_unified_id", "unified_id"),
    )
