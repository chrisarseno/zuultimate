"""SQLAlchemy model for persisted security audit events."""

from sqlalchemy import Column, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin


class SecurityEventModel(Base, TimestampMixin):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    agent_code: Mapped[str] = mapped_column(String(20), default="")
    tool_name: Mapped[str] = mapped_column(String(100), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
