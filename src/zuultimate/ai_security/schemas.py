"""Pydantic schemas for AI Security API."""

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1)
    agent_code: str = ""


class DetectionItem(BaseModel):
    pattern_name: str
    category: str
    severity: str
    matched_text: str
    description: str


class ScanResponse(BaseModel):
    is_threat: bool
    threat_score: float
    detections: list[DetectionItem] = Field(default_factory=list)
    heuristic_flags: list[str] = Field(default_factory=list)


class GuardRequest(BaseModel):
    tool_name: str
    agent_code: str
    tool_category: str = "general"
    parameters: dict = Field(default_factory=dict)


class GuardResponse(BaseModel):
    allowed: bool
    reason: str = ""
    stage: str = ""
    threat_score: float = 0.0


class RedTeamRequest(BaseModel):
    passphrase: str
    categories: list[str] | None = None
    custom_payloads: list[str] | None = None


class RedTeamResponse(BaseModel):
    total_attacks: int
    detected: int
    bypassed: int
    detection_rate: float
    bypassed_payloads: list[str] = Field(default_factory=list)


class AuditQueryParams(BaseModel):
    event_type: str | None = None
    severity: str | None = None
    agent_code: str | None = None
    since: str | None = None
    limit: int = Field(100, ge=1, le=1000)


class AuditEventItem(BaseModel):
    event_type: str
    severity: str
    agent_code: str = ""
    tool_name: str = ""
    detail: str = ""
    threat_score: float = 0.0
    timestamp: str = ""
