"""AISecurityService -- orchestrator that wires detector, guard, permissions, audit, red team."""

from __future__ import annotations

from zuultimate.ai_security.audit_log import SecurityAuditLog
from zuultimate.ai_security.injection_detector import InjectionDetector, ScanResult
from zuultimate.ai_security.permissions import ExecutivePermissions
from zuultimate.ai_security.red_team import RedTeamResult, RedTeamTool
from zuultimate.ai_security.tool_guard import GuardDecision, ToolGuard
from zuultimate.common.config import get_settings


class AISecurityService:
    """Central orchestrator for AI security features."""

    def __init__(self):
        settings = get_settings()
        self.detector = InjectionDetector(threshold=settings.threat_score_threshold)
        self.permissions = ExecutivePermissions()
        self.audit_log = SecurityAuditLog(maxlen=settings.max_audit_events)
        self.guard = ToolGuard(self.detector, self.permissions, self.audit_log)
        self.red_team = RedTeamTool(self.detector, self.audit_log)
        if settings.redteam_passphrase:
            self.red_team.set_passphrase(settings.redteam_passphrase)

    def scan(self, text: str, agent_code: str = "") -> ScanResult:
        result = self.detector.scan(text)
        self.audit_log.record_scan(result, agent_code, text[:200])
        return result

    async def guard_check(
        self,
        tool_name: str,
        agent_code: str,
        params: dict,
        tool_category: str = "general",
    ) -> GuardDecision:
        return await self.guard.pre_check(tool_name, agent_code, params, tool_category)

    async def red_team_execute(
        self,
        passphrase: str,
        categories: list[str] | None = None,
        custom_payloads: list[str] | None = None,
    ) -> RedTeamResult:
        return await self.red_team.execute(passphrase, categories, custom_payloads)
