from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class PRDescriptionStatus(str, PyEnum):
    GENERATED = "generated"
    SUBMITTED = "submitted"
    MERGED = "merged"
    REJECTED = "rejected"


class PRDescription(Base):
    __tablename__ = "pr_descriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_ids: Mapped[str] = mapped_column(Text, nullable=False)
    base_branch: Mapped[str] = mapped_column(String(120), nullable=False)
    head_branch: Mapped[str] = mapped_column(String(120), nullable=False)
    repo_url: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    labels: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reviewers: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    related_issues: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[PRDescriptionStatus] = mapped_column(SQLEnum(PRDescriptionStatus, native_enum=False), default=PRDescriptionStatus.GENERATED, nullable=False)
    pr_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pr_number: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
