"""Async DB persistence for security audit events."""

from sqlalchemy import select
from sqlalchemy.sql import func

from zuultimate.ai_security.audit_log import SecurityEvent, SecurityEventType
from zuultimate.ai_security.models import SecurityEventModel
from zuultimate.common.database import DatabaseManager

_DB_KEY = "audit"


async def persist_event(db: DatabaseManager, event: SecurityEvent) -> None:
    """Write a single SecurityEvent to the audit database."""
    async with db.get_session(_DB_KEY) as session:
        row = SecurityEventModel(
            event_type=event.event_type.value,
            severity=event.severity,
            agent_code=event.agent_code,
            tool_name=event.tool_name,
            detail=event.detail,
            threat_score=event.threat_score,
        )
        session.add(row)


async def query_events(
    db: DatabaseManager,
    event_type: SecurityEventType | None = None,
    severity: str | None = None,
    agent_code: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Query persisted audit events. Returns (items, total_count)."""
    async with db.get_session(_DB_KEY) as session:
        query = select(SecurityEventModel).order_by(
            SecurityEventModel.created_at.desc()
        )
        count_query = select(func.count()).select_from(SecurityEventModel)

        if event_type:
            query = query.where(SecurityEventModel.event_type == event_type.value)
            count_query = count_query.where(
                SecurityEventModel.event_type == event_type.value
            )
        if severity:
            query = query.where(SecurityEventModel.severity == severity)
            count_query = count_query.where(
                SecurityEventModel.severity == severity
            )
        if agent_code:
            query = query.where(SecurityEventModel.agent_code == agent_code)
            count_query = count_query.where(
                SecurityEventModel.agent_code == agent_code
            )

        total_result = await session.execute(count_query)
        total = total_result.scalar() or 0

        query = query.offset(offset).limit(limit)
        result = await session.execute(query)
        rows = result.scalars().all()

    return [
        {
            "event_type": r.event_type,
            "severity": r.severity,
            "agent_code": r.agent_code,
            "tool_name": r.tool_name,
            "detail": r.detail,
            "threat_score": r.threat_score,
            "timestamp": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ], total
