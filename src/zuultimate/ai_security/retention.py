"""Audit log retention — TTL-based cleanup and archival."""

import json
from datetime import datetime, timedelta

from sqlalchemy import delete as sa_delete, func, select

from zuultimate.common.database import DatabaseManager
from zuultimate.common.logging import get_logger
from zuultimate.ai_security.models import SecurityEventModel

_log = get_logger("zuultimate.retention")
_DB_KEY = "audit"


class AuditRetentionService:
    def __init__(self, db: DatabaseManager, retention_days: int = 90):
        self.db = db
        self.retention_days = retention_days

    async def get_stats(self) -> dict:
        """Return audit log statistics."""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)

        async with self.db.get_session(_DB_KEY) as session:
            total = await session.execute(
                select(func.count()).select_from(SecurityEventModel)
            )
            expired = await session.execute(
                select(func.count()).select_from(SecurityEventModel).where(
                    SecurityEventModel.created_at < cutoff
                )
            )

        return {
            "total_events": total.scalar() or 0,
            "expired_events": expired.scalar() or 0,
            "retention_days": self.retention_days,
            "cutoff_date": cutoff.isoformat(),
        }

    async def archive_expired(self) -> dict:
        """Export expired events as JSON and return them for archival.

        Returns the events that would be archived. The caller is responsible
        for persisting the archive (e.g. to S3/file). Events are NOT deleted
        by this method — use ``purge_expired()`` after successful archival.
        """
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(SecurityEventModel).where(
                    SecurityEventModel.created_at < cutoff
                ).order_by(SecurityEventModel.created_at)
            )
            events = result.scalars().all()

        archived = [
            {
                "id": e.id,
                "event_type": e.event_type,
                "severity": e.severity,
                "agent_code": e.agent_code,
                "tool_name": e.tool_name,
                "detail": e.detail,
                "threat_score": e.threat_score,
                "created_at": str(e.created_at),
            }
            for e in events
        ]

        return {
            "archived_count": len(archived),
            "events": archived,
            "archive_json": json.dumps(archived),
        }

    async def purge_expired(self) -> dict:
        """Delete events older than the retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)

        async with self.db.get_session(_DB_KEY) as session:
            result = await session.execute(
                select(func.count()).select_from(SecurityEventModel).where(
                    SecurityEventModel.created_at < cutoff
                )
            )
            count = result.scalar() or 0

            if count > 0:
                await session.execute(
                    sa_delete(SecurityEventModel).where(
                        SecurityEventModel.created_at < cutoff
                    )
                )
                _log.info("Purged %d expired audit events (>%d days)", count, self.retention_days)

        return {"purged": count, "retention_days": self.retention_days}
