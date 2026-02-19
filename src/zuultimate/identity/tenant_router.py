"""Tenant management router."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.identity.schemas import TenantCreateRequest, TenantResponse
from zuultimate.identity.tenant_service import TenantService

router = APIRouter(prefix="/tenants", tags=["tenants"], responses=STANDARD_ERRORS)


def _get_service(request: Request) -> TenantService:
    return TenantService(request.app.state.db)


@router.post("", response_model=TenantResponse)
async def create_tenant(
    body: TenantCreateRequest,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.create_tenant(name=body.name, slug=body.slug)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("", response_model=list[TenantResponse])
async def list_tenants(
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    return await svc.list_tenants()


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: str,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.get_tenant(tenant_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/{tenant_id}/deactivate", response_model=TenantResponse)
async def deactivate_tenant(
    tenant_id: str,
    request: Request,
    _user: dict = Depends(get_current_user),
):
    svc = _get_service(request)
    try:
        return await svc.deactivate_tenant(tenant_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
