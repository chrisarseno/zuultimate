"""SQLAlchemy model for persisted security audit events."""

from sqlalchemy import Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class SecurityEventModel(Base, TimestampMixin):
    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    event_type: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    agent_code: Mapped[str] = mapped_column(String(20), default="", index=True)
    tool_name: Mapped[str] = mapped_column(String(100), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
