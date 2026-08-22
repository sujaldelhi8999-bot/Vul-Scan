from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, REAL, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class SCAFinding(Base):
    __tablename__ = "sca_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    package_version: Mapped[str] = mapped_column(String(120), nullable=False)
    ecosystem: Mapped[str] = mapped_column(String(64), nullable=False)
    vulnerability_id: Mapped[str] = mapped_column(String(64), nullable=False)
    vulnerable_versions: Mapped[str] = mapped_column(Text, nullable=False)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(REAL, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    license: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    is_direct: Mapped[bool] = mapped_column(default=True, nullable=False)
    dependency_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    advisory_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
