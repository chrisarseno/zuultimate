"""Append-only security audit log with in-memory deque + optional DB persist."""

from __future__ import annotations

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List


class SecurityEventType(str, Enum):
    SCAN = "scan"
    GUARD_CHECK = "guard_check"
    GUARD_BLOCK = "guard_block"
    PERMISSION_DENIED = "permission_denied"
    RED_TEAM_RUN = "red_team_run"
    RED_TEAM_AUTH_FAIL = "red_team_auth_fail"
    THREAT_DETECTED = "threat_detected"


@dataclass
class SecurityEvent:
    event_type: SecurityEventType
    severity: str = "info"
    agent_code: str = ""
    tool_name: str = ""
    detail: str = ""
    threat_score: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict = field(default_factory=dict)


class SecurityAuditLog:
    """Thread-safe, bounded, append-only audit log."""

    def __init__(self, maxlen: int = 10000):
        self._events: deque[SecurityEvent] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def record(self, event: SecurityEvent) -> None:
        with self._lock:
            self._events.append(event)

    def record_scan(self, scan_result, agent_code: str = "", text_preview: str = "") -> None:
        self.record(SecurityEvent(
            event_type=SecurityEventType.THREAT_DETECTED if scan_result.is_threat else SecurityEventType.SCAN,
            severity=scan_result.max_severity.value if scan_result.max_severity else "info",
            agent_code=agent_code,
            threat_score=scan_result.threat_score,
            detail=f"detections={len(scan_result.detections)}, preview={text_preview[:100]}",
        ))

    def record_guard_decision(self, decision, tool_name: str = "", agent_code: str = "") -> None:
        self.record(SecurityEvent(
            event_type=SecurityEventType.GUARD_BLOCK if not decision.allowed else SecurityEventType.GUARD_CHECK,
            severity="high" if not decision.allowed else "info",
            tool_name=tool_name,
            agent_code=agent_code,
            detail=decision.reason or "",
        ))

    def query(
        self,
        event_type: SecurityEventType | None = None,
        severity: str | None = None,
        agent_code: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        with self._lock:
            events = list(self._events)

        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if severity:
            events = [e for e in events if e.severity == severity]
        if agent_code:
            events = [e for e in events if e.agent_code == agent_code]
        if since:
            events = [e for e in events if e.timestamp >= since]

        return events[-limit:]

    def export_json(self) -> str:
        with self._lock:
            events = list(self._events)
        return json.dumps([asdict(e) for e in events], indent=2)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
