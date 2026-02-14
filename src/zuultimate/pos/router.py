"""POS router -- stub endpoints returning HTTP 501."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from zuultimate.common.schemas import StubResponse

router = APIRouter(prefix="/pos", tags=["pos"])


@router.post("/terminals")
async def register_terminal() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="pos").model_dump(),
    )


@router.post("/transactions")
async def create_transaction() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="pos").model_dump(),
    )


@router.get("/fraud-alerts")
async def get_fraud_alerts() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="pos").model_dump(),
    )
