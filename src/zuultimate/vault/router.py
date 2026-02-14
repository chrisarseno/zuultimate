"""Vault router -- stub endpoints returning HTTP 501."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from zuultimate.common.schemas import StubResponse

router = APIRouter(prefix="/vault", tags=["vault"])


@router.post("/encrypt")
async def encrypt() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="vault").model_dump(),
    )


@router.post("/decrypt")
async def decrypt() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="vault").model_dump(),
    )


@router.post("/tokenize")
async def tokenize() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="vault").model_dump(),
    )


@router.post("/detokenize")
async def detokenize() -> JSONResponse:
    return JSONResponse(
        status_code=501,
        content=StubResponse(module="vault").model_dump(),
    )
