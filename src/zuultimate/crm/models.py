"""CRM SQLAlchemy models."""

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class CRMConfig(Base, TimestampMixin):
    __tablename__ = "crm_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    api_url: Mapped[str] = mapped_column(String(500), default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class SyncJob(Base, TimestampMixin):
    __tablename__ = "sync_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    config_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="pending")
    records_synced: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")


class FieldMapping(Base, TimestampMixin):
    __tablename__ = "field_mappings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    config_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_field: Mapped[str] = mapped_column(String(255), nullable=False)
    target_field: Mapped[str] = mapped_column(String(255), nullable=False)
    transform: Mapped[str] = mapped_column(String(100), default="")
