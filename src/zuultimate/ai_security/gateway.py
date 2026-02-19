"""AI Security Gateway — standalone middleware for LLM pipelines.

Deploy as a sidecar or proxy to scan all LLM inputs/outputs for injection,
enforce tool-use RBAC, and audit security events.

Usage as middleware::

    from zuultimate.ai_security.gateway import SecurityGatewayMiddleware
    app.add_middleware(SecurityGatewayMiddleware)

Usage as standalone service::

    python -m zuultimate.ai_security.gateway  # runs on port 8765
"""

import json
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from zuultimate.ai_security.injection_detector import InjectionDetector
from zuultimate.ai_security.audit_log import SecurityAuditLog
from zuultimate.common.config import get_settings
from zuultimate.common.logging import get_logger

_log = get_logger("zuultimate.ai_gateway")


class SecurityGatewayMiddleware(BaseHTTPMiddleware):
    """Scans all POST request bodies for prompt injection before forwarding.

    If a threat is detected above the threshold, the request is blocked with 403.
    Safe requests pass through with an X-Security-Score header.
    """

    def __init__(self, app, threshold: float | None = None, scan_response: bool = False):
        super().__init__(app)
        settings = get_settings()
        self.threshold = threshold or settings.threat_score_threshold
        self.detector = InjectionDetector(threshold=self.threshold)
        self.audit_log = SecurityAuditLog(maxlen=settings.max_audit_events)
        self.scan_response = scan_response

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Only scan POST/PUT/PATCH with body
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        body = await request.body()
        if not body:
            return await call_next(request)

        # Extract text content to scan
        text_to_scan = self._extract_text(body)
        if not text_to_scan:
            return await call_next(request)

        # Scan for threats
        result = self.detector.scan(text_to_scan)
        self.audit_log.record_scan(result, agent_code="gateway", text_preview=request.url.path)

        if result.is_threat:
            _log.warning(
                "Gateway blocked request to %s (score=%.2f, detections=%d)",
                request.url.path,
                result.threat_score,
                len(result.detections),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Request blocked by AI security gateway",
                    "code": "GATEWAY_THREAT_DETECTED",
                    "threat_score": result.threat_score,
                    "detections": len(result.detections),
                },
            )

        response = await call_next(request)
        response.headers["X-Security-Score"] = f"{result.threat_score:.3f}"
        return response

    @staticmethod
    def _extract_text(body: bytes) -> str:
        """Extract text content from request body for scanning."""
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return body.decode("utf-8", errors="ignore")

        # Walk JSON and concatenate string values
        texts = []

        def _walk(obj):
            if isinstance(obj, str):
                texts.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)

        _walk(data)
        return " ".join(texts)


def create_gateway_app():
    """Create a standalone AI security gateway FastAPI application."""
    from fastapi import FastAPI

    gateway = FastAPI(
        title="Zuultimate AI Security Gateway",
        version="0.1.0",
        description="Standalone AI security scanning proxy",
    )

    settings = get_settings()
    detector = InjectionDetector(threshold=settings.threat_score_threshold)
    audit_log = SecurityAuditLog(maxlen=settings.max_audit_events)

    @gateway.post("/gateway/scan")
    async def gateway_scan(request: Request):
        """Scan arbitrary text for AI security threats."""
        body = await request.json()
        text = body.get("text", "")
        result = detector.scan(text)
        audit_log.record_scan(result, agent_code=body.get("agent_code", ""), text_preview=text[:200])
        return {
            "is_threat": result.is_threat,
            "threat_score": result.threat_score,
            "detections": [
                {
                    "pattern_name": d.pattern_name,
                    "category": d.category.value,
                    "severity": d.severity.value,
                    "matched_text": d.matched_text,
                }
                for d in result.detections
            ],
        }

    @gateway.get("/gateway/health")
    async def gateway_health():
        return {
            "status": "ok",
            "service": "ai-security-gateway",
            "patterns_loaded": len(detector._patterns),
            "events_recorded": audit_log.count,
        }

    @gateway.get("/gateway/stats")
    async def gateway_stats():
        return {
            "total_events": audit_log.count,
            "recent_events": [
                {
                    "event_type": e.event_type.value,
                    "severity": e.severity,
                    "threat_score": e.threat_score,
                    "timestamp": e.timestamp,
                }
                for e in audit_log.query(limit=20)
            ],
        }

    return gateway


if __name__ == "__main__":
    import uvicorn

    app = create_gateway_app()
    uvicorn.run(app, host="0.0.0.0", port=8765)
