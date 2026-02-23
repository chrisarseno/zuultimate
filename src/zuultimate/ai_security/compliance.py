"""Compliance report generation from security audit data."""

from datetime import datetime, timezone
from collections import Counter

from sqlalchemy import select, func

from zuultimate.ai_security.models import SecurityEventModel
from zuultimate.common.database import DatabaseManager

_DB_KEY = "audit"


class ComplianceReporter:
    def __init__(self, db: DatabaseManager):
        self.db = db

    async def generate_report(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> dict:
        """Generate a comprehensive compliance report from audit data."""
        async with self.db.get_session(_DB_KEY) as session:
            query = select(SecurityEventModel)
            if start_date:
                query = query.where(SecurityEventModel.created_at >= start_date)
            if end_date:
                query = query.where(SecurityEventModel.created_at <= end_date)

            result = await session.execute(query.order_by(SecurityEventModel.created_at.desc()))
            events = result.scalars().all()

        total = len(events)
        if total == 0:
            return {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "period": {
                    "start": start_date.isoformat() if start_date else None,
                    "end": end_date.isoformat() if end_date else None,
                },
                "summary": {"total_events": 0},
                "by_type": {},
                "by_severity": {},
                "threat_analysis": {"total_threats": 0, "avg_threat_score": 0.0},
                "agent_activity": {},
                "policy_violations": 0,
            }

        # Aggregate by type
        type_counts = Counter(e.event_type for e in events)

        # Aggregate by severity
        severity_counts = Counter(e.severity for e in events)

        # Threat analysis
        threats = [e for e in events if e.event_type in ("threat_detected", "guard_block")]
        threat_scores = [e.threat_score for e in events if e.threat_score and e.threat_score > 0]
        avg_score = sum(threat_scores) / len(threat_scores) if threat_scores else 0.0

        # Agent activity
        agent_counts = Counter(e.agent_code for e in events if e.agent_code)

        # Policy violations (guard_block + permission_denied)
        violations = sum(
            1 for e in events
            if e.event_type in ("guard_block", "permission_denied")
        )

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": {
                "start": start_date.isoformat() if start_date else None,
                "end": end_date.isoformat() if end_date else None,
            },
            "summary": {
                "total_events": total,
                "unique_agents": len(agent_counts),
                "unique_event_types": len(type_counts),
            },
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
            "threat_analysis": {
                "total_threats": len(threats),
                "avg_threat_score": round(avg_score, 4),
                "max_threat_score": round(max(threat_scores), 4) if threat_scores else 0.0,
            },
            "agent_activity": dict(agent_counts.most_common(20)),
            "policy_violations": violations,
        }
