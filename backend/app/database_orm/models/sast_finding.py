from datetime import datetime
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, ForeignKey, Enum as SQLEnum, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database_orm.base import Base


class Language(str, PyEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    GO = "go"
    PHP = "php"
    CSHARP = "csharp"
    RUBY = "ruby"
    RUST = "rust"
    KOTLIN = "kotlin"
    SWIFT = "swift"
    SCALA = "scala"


class Framework(str, PyEnum):
    DJANGO = "django"
    FLASK = "flask"
    FASTAPI = "fastapi"
    EXPRESS = "express"
    NEXTJS = "nextjs"
    NESTJS = "nestjs"
    SPRING = "spring"
    RAILS = "rails"
    LARAVEL = "laravel"
    DOTNET = "dotnet"
    GIN = "gin"
    ECHO = "echo"
    ACTIX = "actix"
    SYMFONY = "symfony"
    CODEIGNITER = "codeigniter"


class SastTool(str, PyEnum):
    SEMGREP = "semgrep"
    CODEQL = "codeql"
    BANDIT = "bandit"
    ESLINT = "eslint"
    SPOTBUGS = "spotbugs"
    GOSEC = "gosec"
    PHPSTAN = "phpstan"
    PSALM = "psalm"
    BRAKEMAN = "brakeman"
    RUBOCOP = "rubocop"
    CLIPPY = "clippy"
    DETEKT = "detekt"
    CUSTOM = "custom"


class SASTFinding(Base):
    __tablename__ = "sast_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    language: Mapped[Language] = mapped_column(SQLEnum(Language, native_enum=False), nullable=False)
    framework: Mapped[Optional[Framework]] = mapped_column(SQLEnum(Framework, native_enum=False), nullable=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    start_column: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    end_column: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    function_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    class_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    code_snippet: Mapped[str] = mapped_column(Text, default="", nullable=False)
    rule_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    rule_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    rule_severity: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    tool: Mapped[SastTool] = mapped_column(SQLEnum(SastTool, native_enum=False), nullable=False)
    references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cwe_ids: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owasp_category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    fix_suggestion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fix_example: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("idx_sast_findings_file_path", "file_path"),
        Index("idx_sast_findings_rule_id", "rule_id"),
    )
