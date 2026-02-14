"""FastAPI router for AI security endpoints."""

from fastapi import APIRouter, HTTPException

from zuultimate.ai_security.audit_log import SecurityEventType
from zuultimate.ai_security.schemas import (
    AuditEventItem,
    AuditQueryParams,
    DetectionItem,
    GuardRequest,
    GuardResponse,
    RedTeamRequest,
    RedTeamResponse,
    ScanRequest,
    ScanResponse,
)
from zuultimate.ai_security.service import AISecurityService

router = APIRouter(prefix="/ai", tags=["ai-security"])

_service: AISecurityService | None = None


def _get_service() -> AISecurityService:
    global _service
    if _service is None:
        _service = AISecurityService()
    return _service


@router.post("/scan", response_model=ScanResponse)
async def scan_text(req: ScanRequest):
    svc = _get_service()
    result = svc.scan(req.text, req.agent_code)
    return ScanResponse(
        is_threat=result.is_threat,
        threat_score=result.threat_score,
        detections=[
            DetectionItem(
                pattern_name=d.pattern_name,
                category=d.category.value,
                severity=d.severity.value,
                matched_text=d.matched_text,
                description=d.description,
            )
            for d in result.detections
        ],
        heuristic_flags=result.heuristic_flags,
    )


@router.post("/guard/check", response_model=GuardResponse)
async def guard_check(req: GuardRequest):
    svc = _get_service()
    decision = await svc.guard_check(req.tool_name, req.agent_code, req.parameters, req.tool_category)
    return GuardResponse(
        allowed=decision.allowed,
        reason=decision.reason,
        stage=decision.stage,
        threat_score=decision.scan_result.threat_score if decision.scan_result else 0.0,
    )


@router.post("/redteam/execute", response_model=RedTeamResponse)
async def red_team_execute(req: RedTeamRequest):
    svc = _get_service()
    try:
        result = await svc.red_team_execute(req.passphrase, req.categories, req.custom_payloads)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Red team authentication failed")
    return RedTeamResponse(
        total_attacks=result.total_attacks,
        detected=result.detected,
        bypassed=result.bypassed,
        detection_rate=result.detection_rate,
        bypassed_payloads=result.bypassed_payloads,
    )


@router.get("/audit", response_model=list[AuditEventItem])
async def query_audit(
    event_type: str | None = None,
    severity: str | None = None,
    agent_code: str | None = None,
    since: str | None = None,
    limit: int = 100,
):
    svc = _get_service()
    evt_type = None
    if event_type:
        try:
            evt_type = SecurityEventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid event_type: {event_type}")

    events = svc.audit_log.query(evt_type, severity, agent_code, since, limit)
    return [
        AuditEventItem(
            event_type=e.event_type.value,
            severity=e.severity,
            agent_code=e.agent_code,
            tool_name=e.tool_name,
            detail=e.detail,
            threat_score=e.threat_score,
            timestamp=e.timestamp,
        )
        for e in events
    ]
