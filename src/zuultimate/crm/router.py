"""CRM router -- stub endpoints returning HTTP 501."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from zuultimate.common.schemas import StubResponse

router = APIRouter(prefix="/crm", tags=["crm"])


@router.post("/configs")
async def create_config() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="crm").model_dump(),
    )


@router.post("/sync")
async def start_sync() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="crm").model_dump(),
    )


@router.get("/sync/{job_id}")
async def get_sync_status(job_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="crm").model_dump(),
    )
