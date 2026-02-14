"""Identity router -- stub endpoints returning HTTP 501."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from zuultimate.common.schemas import StubResponse

router = APIRouter(prefix="/identity", tags=["identity"])


@router.post("/register")
async def register() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="identity").model_dump(),
    )


@router.post("/login")
async def login() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="identity").model_dump(),
    )


@router.get("/users/{user_id}")
async def get_user(user_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="identity").model_dump(),
    )


@router.post("/refresh")
async def refresh_token() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="identity").model_dump(),
    )
