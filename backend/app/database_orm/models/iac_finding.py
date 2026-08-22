from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class IaCPlatform(str, PyEnum):
    TERRAFORM = "terraform"
    KUBERNETES = "kubernetes"
    CLOUDFORMATION = "cloudformation"
    HELM = "helm"
    DOCKERFILE = "dockerfile"


class IaCFinding(Base):
    __tablename__ = "iac_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    resource_type: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    misconfiguration_type: Mapped[str] = mapped_column(String(120), nullable=False)
    platform: Mapped[IaCPlatform] = mapped_column(SQLEnum(IaCPlatform, native_enum=False), nullable=False)
