"""Backup & resilience router -- stub endpoints returning HTTP 501."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from zuultimate.common.schemas import StubResponse

router = APIRouter(prefix="/backup", tags=["backup"])


@router.post("/snapshots")
async def create_snapshot() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="backup_resilience").model_dump(),
    )


@router.post("/restore")
async def restore() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="backup_resilience").model_dump(),
    )


@router.post("/integrity-check")
async def check_integrity() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="backup_resilience").model_dump(),
    )
