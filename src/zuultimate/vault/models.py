"""Vault SQLAlchemy models -- encrypted blobs, tokens, key versions."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from zuultimate.common.models import Base, TimestampMixin, generate_uuid


class EncryptedBlob(TimestampMixin, Base):
    __tablename__ = "encrypted_blobs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    owner_id: Mapped[str] = mapped_column(String(255))
    label: Mapped[str] = mapped_column(String(255))
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    tag: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer, default=1)


class VaultToken(TimestampMixin, Base):
    __tablename__ = "vault_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    original_hash: Mapped[str] = mapped_column(String(255))
    token_value: Mapped[str] = mapped_column(String(255), unique=True)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class KeyVersion(TimestampMixin, Base):
    __tablename__ = "key_versions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=generate_uuid)
    version: Mapped[int] = mapped_column(Integer, unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255), default="")
