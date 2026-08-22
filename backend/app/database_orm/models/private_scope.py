from datetime import datetime
from typing import Optional
from sqlalchemy import (
    String, Text, Integer, DateTime, Index
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database_orm.base import Base


class PrivateScope(Base):
    __tablename__ = "private_scope"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_url: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)
    added_by: Mapped[str] = mapped_column(String(64), default="admin", nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    last_used: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_private_scope_target_url", "target_url"),
    )
