"""Access control router -- stub endpoints returning HTTP 501."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from zuultimate.common.schemas import StubResponse

router = APIRouter(prefix="/access", tags=["access"])


@router.post("/check")
async def check_access() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="access").model_dump(),
    )


@router.post("/policies")
async def create_policy() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="access").model_dump(),
    )


@router.post("/roles/assign")
async def assign_role() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="access").model_dump(),
    )
