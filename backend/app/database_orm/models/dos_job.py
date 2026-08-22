from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, REAL, Index
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database_orm.base import Base


class DosJob(Base):
    __tablename__ = "dos_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    intensity: Mapped[str] = mapped_column(String(32), nullable=False)
    duration: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    requests_sent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    responses_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    errors: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    baseline_latency: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    peak_latency: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    avg_latency_during: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    recovery_latency: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    impact_score: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    effective: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    website_status: Mapped[str] = mapped_column(String(32), default="unknown", nullable=False)
    health_score: Mapped[float] = mapped_column(REAL, default=100.0, nullable=False)
    p95_latency: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    p99_latency: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    jitter_ms: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    error_rate: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    throughput_mbps: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    total_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_2xx: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_3xx: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_4xx: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status_5xx: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_data_mb: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    avg_dns_ms: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    avg_tcp_ms: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    avg_tls_ms: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    avg_ttfb_ms: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    packet_loss: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    recovery_ratio: Mapped[float] = mapped_column(REAL, default=0.0, nullable=False)
    recovered: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    attack_mode: Mapped[str] = mapped_column(String(32), default="get_flood", nullable=False)
    endpoint: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    target_class: Mapped[str] = mapped_column(String(32), default="external", nullable=False)
    workers: Mapped[int] = mapped_column(Integer, default=8, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    stopped_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("idx_dos_jobs_status", "status"),
        Index("idx_dos_jobs_target", "target_url"),
    )
