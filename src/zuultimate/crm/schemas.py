"""CRM Pydantic schemas."""

from pydantic import BaseModel


class CRMConfigCreate(BaseModel):
    provider: str
    api_url: str = ""


class SyncJobResponse(BaseModel):
    id: str
    config_id: str
    status: str
    records_synced: int


class FieldMappingCreate(BaseModel):
    source_field: str
    target_field: str
    transform: str = ""
