"""Backup & resilience Pydantic schemas."""

from pydantic import BaseModel


class SnapshotCreate(BaseModel):
    name: str
    source: str


class RestoreRequest(BaseModel):
    snapshot_id: str
    target: str


class IntegrityCheckRequest(BaseModel):
    target: str


class IntegrityCheckResponse(BaseModel):
    id: str
    target: str
    passed: bool | None = None
    status: str
