"""CRM Pydantic schemas."""

from pydantic import BaseModel


class CRMConfigCreate(BaseModel):
    provider: str
    api_url: str = ""


class CRMConfigResponse(BaseModel):
    id: str
    provider: str
    api_url: str
    is_active: bool


class SyncStartRequest(BaseModel):
    config_id: str


class SyncJobResponse(BaseModel):
    id: str
    config_id: str
    status: str
    records_synced: int


