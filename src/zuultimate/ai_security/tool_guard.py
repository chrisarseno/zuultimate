"""ToolGuard -- pre/post execution pipeline: RBAC check + injection scan + audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from zuultimate.ai_security.audit_log import SecurityAuditLog
from zuultimate.ai_security.injection_detector import InjectionDetector, ScanResult
from zuultimate.ai_security.permissions import ExecutivePermissions
from zuultimate.common.licensing import license_gate


@dataclass
class GuardDecision:
    allowed: bool
    reason: str = ""
    scan_result: ScanResult | None = None
    stage: str = ""  # "pre" or "post"


class ToolGuard:
    """Pre/post execution guard: RBAC + injection detection + audit trail."""

    def __init__(
        self,
        detector: InjectionDetector | None = None,
        permissions: ExecutivePermissions | None = None,
        audit_log: SecurityAuditLog | None = None,
    ):
        license_gate.gate("zul.toolguard.pipeline", "ToolGuard Pipeline")
        self.detector = detector or InjectionDetector()
        self.permissions = permissions or ExecutivePermissions()
        self.audit_log = audit_log or SecurityAuditLog()

    async def pre_check(
        self,
        tool_name: str,
        agent_code: str,
        params: dict[str, Any],
        tool_category: str = "general",
    ) -> GuardDecision:
        # 1. RBAC check
        if not self.permissions.check(agent_code, tool_name, tool_category):
            decision = GuardDecision(
                allowed=False,
                reason=f"Agent '{agent_code}' not permitted for category '{tool_category}'",
                stage="pre",
            )
            self.audit_log.record_guard_decision(decision, tool_name, agent_code)
            return decision

        # 2. Scan parameters for injection
        text = _params_to_text(params)
        scan_result = self.detector.scan(text)

        if scan_result.is_threat:
            decision = GuardDecision(
                allowed=False,
                reason=f"Injection detected in parameters: score={scan_result.threat_score}",
                scan_result=scan_result,
                stage="pre",
            )
            self.audit_log.record_guard_decision(decision, tool_name, agent_code)
            self.audit_log.record_scan(scan_result, agent_code, text[:200])
            return decision

        decision = GuardDecision(allowed=True, scan_result=scan_result, stage="pre")
        self.audit_log.record_guard_decision(decision, tool_name, agent_code)
        return decision

    async def post_check(
        self,
        tool_name: str,
        agent_code: str,
        result: Any,
    ) -> GuardDecision:
        text = str(result) if result is not None else ""
        scan_result = self.detector.scan(text)

        if scan_result.is_threat:
            decision = GuardDecision(
                allowed=False,
                reason=f"Indirect injection in tool result: score={scan_result.threat_score}",
                scan_result=scan_result,
                stage="post",
            )
            self.audit_log.record_guard_decision(decision, tool_name, agent_code)
            self.audit_log.record_scan(scan_result, agent_code, text[:200])
            return decision

        decision = GuardDecision(allowed=True, scan_result=scan_result, stage="post")
        self.audit_log.record_guard_decision(decision, tool_name, agent_code)
        return decision

    async def guard(
        self,
        tool_name: str,
        agent_code: str,
        params: dict[str, Any],
        execute_fn: Callable[..., Awaitable[Any]],
        tool_category: str = "general",
    ) -> tuple[Any, GuardDecision]:
        """Full pre -> execute -> post pipeline."""
        pre = await self.pre_check(tool_name, agent_code, params, tool_category)
        if not pre.allowed:
            return None, pre

        result = await execute_fn(**params)

        post = await self.post_check(tool_name, agent_code, result)
        return result, post


def _params_to_text(params: dict[str, Any]) -> str:
    """Flatten params dict to scannable text."""
    parts = []
    for v in params.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, tuple)):
            parts.extend(str(i) for i in v)
        elif isinstance(v, dict):
            parts.append(_params_to_text(v))
        else:
            parts.append(str(v))
    return " ".join(parts)
