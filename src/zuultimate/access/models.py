"""SQLAlchemy models for access control -- roles, permissions, policies, audit."""

from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class Role(Base, TimestampMixin):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)


class Permission(Base, TimestampMixin):
    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    resource: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text, default="")


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(255))
    effect: Mapped[str] = mapped_column(String(20))  # "allow" or "deny"
    resource_pattern: Mapped[str] = mapped_column(String(500))
    action_pattern: Mapped[str] = mapped_column(String(200))
    priority: Mapped[int] = mapped_column(Integer, default=0)


class RoleAssignment(Base, TimestampMixin):
    __tablename__ = "role_assignments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    role_id: Mapped[str] = mapped_column(String(255))
    user_id: Mapped[str] = mapped_column(String(255))
    assigned_by: Mapped[str | None] = mapped_column(String(255), nullable=True)


class AuditEntry(Base, TimestampMixin):
    __tablename__ = "audit_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(255))
    result: Mapped[str] = mapped_column(String(20))  # "allow" or "deny"
    detail: Mapped[str] = mapped_column(Text, default="")
