from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum, Index
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


class FindingSource(Base):
    __tablename__ = "finding_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    source_type: Mapped[SourceType] = mapped_column(SQLEnum(SourceType, native_enum=False), nullable=False)
    source_identifier: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    rule_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    commit_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    branch: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    pr_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    finding: Mapped["Finding"] = relationship(back_populates="finding_sources")

    __table_args__ = (
        Index("idx_finding_sources_finding_id", "finding_id"),
    )
