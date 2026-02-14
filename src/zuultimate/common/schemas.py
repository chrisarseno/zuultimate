"""Shared Pydantic schemas for Zuultimate API."""

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Pagination(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=200)
    total: int = 0
    total_pages: int = 0


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T] = []
    pagination: Pagination = Pagination()


class ErrorResponse(BaseModel):
    error: str
    code: str = "ZUUL_ERROR"
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    environment: str = "development"
    timestamp: datetime | None = None


class StubResponse(BaseModel):
    """Response for unimplemented modules."""
    error: str = "Module not yet implemented"
    code: str = "NOT_IMPLEMENTED"
    module: str = ""
