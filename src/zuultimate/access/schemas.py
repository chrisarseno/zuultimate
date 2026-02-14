"""Pydantic schemas for access control API."""

from pydantic import BaseModel


class AccessCheckRequest(BaseModel):
    user_id: str
    resource: str
    action: str


class AccessCheckResponse(BaseModel):
    allowed: bool
    reason: str = ""


class PolicySchema(BaseModel):
    name: str
    effect: str
    resource_pattern: str
    action_pattern: str
    priority: int = 0


class RoleAssignRequest(BaseModel):
    role_id: str
    user_id: str


class RoleResponse(BaseModel):
    id: str
    name: str
    description: str = ""
