"""Backup & resilience Pydantic schemas."""

from pydantic import BaseModel


class SnapshotCreate(BaseModel):
    name: str
    source: str


class SnapshotResponse(BaseModel):
    id: str
    name: str
    source: str
    checksum: str
    status: str


class RestoreRequest(BaseModel):
    snapshot_id: str
    target: str


class RestoreResponse(BaseModel):
    id: str
    snapshot_id: str
    target: str
    status: str


class IntegrityCheckRequest(BaseModel):
    target: str


class IntegrityCheckResponse(BaseModel):
    id: str
    target: str
    passed: bool | None = None
    status: str
