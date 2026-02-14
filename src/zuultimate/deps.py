"""FastAPI dependency injection."""

from zuultimate.ai_security.service import AISecurityService
from zuultimate.common.config import ZuulSettings, get_settings
from zuultimate.common.database import DatabaseManager

_db: DatabaseManager | None = None
_ai_svc: AISecurityService | None = None


async def get_db() -> DatabaseManager:
    global _db
    if _db is None:
        _db = DatabaseManager()
        await _db.init()
    return _db


def get_ai_security_service() -> AISecurityService:
    global _ai_svc
    if _ai_svc is None:
        _ai_svc = AISecurityService()
    return _ai_svc


def get_config() -> ZuulSettings:
    return get_settings()
