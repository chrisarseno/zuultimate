"""Zuultimate configuration via pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class ZuulSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ZUUL_")

    environment: str = "development"
    secret_key: str = "insecure-dev-key-change-me"

    # Database URLs
    identity_db_url: str = "sqlite+aiosqlite:///./data/identity.db"
    credential_db_url: str = "sqlite+aiosqlite:///./data/credentials.db"
    session_db_url: str = "sqlite+aiosqlite:///./data/sessions.db"
    transaction_db_url: str = "sqlite+aiosqlite:///./data/transactions.db"
    audit_db_url: str = "sqlite+aiosqlite:///./data/audit.db"
    crm_db_url: str = "sqlite+aiosqlite:///./data/crm.db"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # AI Security
    redteam_passphrase: str = ""

    # API
    api_title: str = "Zuultimate"
    api_version: str = "0.1.0"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]

    # Limits
    max_audit_events: int = 10000
    threat_score_threshold: float = 0.3


@lru_cache
def get_settings() -> ZuulSettings:
    return ZuulSettings()
