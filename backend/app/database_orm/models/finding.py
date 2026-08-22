from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Index, Enum as SQLEnum, REAL, JSON
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class FindingSeverity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingConfidence(str, PyEnum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    POTENTIAL = "POTENTIAL"


class RemediationStatus(str, PyEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class VerificationStatus(str, PyEnum):
    NOT_VERIFIED = "NOT_VERIFIED"
    FIX_VERIFIED = "FIX_VERIFIED"
    ISSUE_STILL_PRESENT = "ISSUE_STILL_PRESENT"
    VERIFY_FAILED = "VERIFY_FAILED"


class RiskStatus(str, PyEnum):
    ACTIVE = "ACTIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(SQLEnum(FindingSeverity, native_enum=False), nullable=False)
    confidence: Mapped[FindingConfidence] = mapped_column(SQLEnum(FindingConfidence, native_enum=False), nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False)
    endpoint: Mapped[str] = mapped_column(Text, default="", nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    impact: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    verification: Mapped[str] = mapped_column(Text, default="", nullable=False)
    agent: Mapped[str] = mapped_column(String(120), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    how_exploited: Mapped[str] = mapped_column(Text, default="", nullable=False)
    fix: Mapped[str] = mapped_column(Text, default="", nullable=False)
    cve_id: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(REAL, nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    version_affected: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    parameter: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    module: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    recommended_fix: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_status: Mapped[RemediationStatus] = mapped_column(SQLEnum(RemediationStatus, native_enum=False), default=RemediationStatus.OPEN, nullable=False)
    verification_status: Mapped[VerificationStatus] = mapped_column(SQLEnum(VerificationStatus, native_enum=False), default=VerificationStatus.NOT_VERIFIED, nullable=False)
    risk_status: Mapped[RiskStatus] = mapped_column(SQLEnum(RiskStatus, native_enum=False), default=RiskStatus.ACTIVE, nullable=False)
    exploited: Mapped[bool] = mapped_column(default=False, nullable=False)
    exploitation_result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    poc: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    sources: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    correlation: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    primary_source: Mapped[str] = mapped_column(String(32), default="live", nullable=False)
    sast_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    secret_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    iac_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    sca_details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    patch: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    patch_status: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    patch_applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fix_commit_sha: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fix_pr_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    exploitation_results: Mapped[list["ExploitationResult"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    evidence_records: Mapped[list["EvidenceRecord"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    ai_code_fixes: Mapped[list["AICodeFix"]] = relationship(back_populates="finding", cascade="all, delete-orphan")
    finding_sources: Mapped[list["FindingSource"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
    )
