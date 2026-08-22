from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, REAL, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class SecretFinding(Base):
    __tablename__ = "secret_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    secret_type: Mapped[str] = mapped_column(String(64), nullable=False)
    detector_name: Mapped[str] = mapped_column(String(120), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_number: Mapped[int] = mapped_column(Integer, nullable=False)
    matched_content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    entropy: Mapped[Optional[float]] = mapped_column(REAL, nullable=True)
    is_validated: Mapped[bool] = mapped_column(default=False, nullable=False)
    validation_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
