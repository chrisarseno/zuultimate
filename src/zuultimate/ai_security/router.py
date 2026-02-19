"""FastAPI router for AI security endpoints."""

import math

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from zuultimate.ai_security.audit_log import SecurityEventType
from zuultimate.ai_security.audit_store import persist_event, query_events
from zuultimate.ai_security.compliance import ComplianceReporter
from zuultimate.ai_security.retention import AuditRetentionService
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
from zuultimate.common.auth import get_current_user
from zuultimate.common.schemas import Pagination, PaginatedResponse, STANDARD_ERRORS

router = APIRouter(
    prefix="/ai",
    tags=["ai-security"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)

_service: AISecurityService | None = None


def _get_service() -> AISecurityService:
    global _service
    if _service is None:
        _service = AISecurityService()
    return _service


@router.post("/scan", response_model=ScanResponse)
async def scan_text(req: ScanRequest, request: Request):
    svc = _get_service()
    result = svc.scan(req.text, req.agent_code)

    # Persist latest audit event to DB
    if svc.audit_log.count > 0:
        latest = svc.audit_log.query(limit=1)
        if latest:
            db = getattr(request.app.state, "db", None)
            if db:
                await persist_event(db, latest[-1])

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
async def guard_check(req: GuardRequest, request: Request):
    svc = _get_service()
    decision = await svc.guard_check(req.tool_name, req.agent_code, req.parameters, req.tool_category)

    # Persist latest audit event to DB
    if svc.audit_log.count > 0:
        latest = svc.audit_log.query(limit=1)
        if latest:
            db = getattr(request.app.state, "db", None)
            if db:
                await persist_event(db, latest[-1])

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


@router.get("/audit", response_model=PaginatedResponse[AuditEventItem])
async def query_audit(
    request: Request,
    event_type: str | None = None,
    severity: str | None = None,
    agent_code: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    evt_type = None
    if event_type:
        try:
            evt_type = SecurityEventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid event_type: {event_type}")

    # Try DB first; fall back to in-memory
    db = getattr(request.app.state, "db", None)
    if db:
        offset = (page - 1) * page_size
        items_raw, total = await query_events(
            db,
            event_type=evt_type,
            severity=severity,
            agent_code=agent_code,
            limit=page_size,
            offset=offset,
        )
        items = [AuditEventItem(**r) for r in items_raw]
        total_pages = math.ceil(total / page_size) if total > 0 else 0
        return {
            "items": items,
            "pagination": Pagination(
                page=page,
                page_size=page_size,
                total=total,
                total_pages=total_pages,
            ),
        }

    # Fallback to in-memory
    svc = _get_service()
    events = svc.audit_log.query(evt_type, severity, agent_code, limit=1000)
    all_items = [
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
    from zuultimate.common.pagination import paginate_list
    return paginate_list(all_items, page=page, page_size=page_size)


@router.get("/compliance/report")
async def compliance_report(request: Request):
    """Generate a compliance report from security audit data."""
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    reporter = ComplianceReporter(db)
    return await reporter.generate_report()


@router.get("/retention/stats")
async def retention_stats(
    request: Request,
    retention_days: int = Query(default=90, ge=1, le=3650),
):
    """Get audit log retention statistics."""
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    svc = AuditRetentionService(db, retention_days=retention_days)
    return await svc.get_stats()


@router.post("/retention/archive")
async def retention_archive(
    request: Request,
    retention_days: int = Query(default=90, ge=1, le=3650),
):
    """Archive expired audit events (returns JSON for external storage)."""
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    svc = AuditRetentionService(db, retention_days=retention_days)
    result = await svc.archive_expired()
    return {
        "archived_count": result["archived_count"],
        "events": result["events"],
    }


@router.post("/retention/purge")
async def retention_purge(
    request: Request,
    retention_days: int = Query(default=90, ge=1, le=3650),
):
    """Permanently delete audit events older than the retention period."""
    db = getattr(request.app.state, "db", None)
    if not db:
        raise HTTPException(status_code=503, detail="Database not available")
    svc = AuditRetentionService(db, retention_days=retention_days)
    return await svc.purge_expired()
