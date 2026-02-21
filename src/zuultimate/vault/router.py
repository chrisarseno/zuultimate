"""Vault router -- encrypt/decrypt, tokenize/detokenize."""

from fastapi import APIRouter, Depends, HTTPException, Request

from zuultimate.common.auth import get_current_user
from zuultimate.common.exceptions import ZuulError
from zuultimate.common.schemas import STANDARD_ERRORS
from zuultimate.vault.schemas import (
    DecryptRequest,
    DecryptResponse,
    DetokenizeRequest,
    DetokenizeResponse,
    EncryptRequest,
    EncryptResponse,
    StoreSecretRequest,
    TokenizeRequest,
    TokenizeResponse,
)
from zuultimate.vault.password_vault import PasswordVaultService
from zuultimate.vault.service import VaultService

router = APIRouter(
    prefix="/vault",
    tags=["vault"],
    dependencies=[Depends(get_current_user)],
    responses=STANDARD_ERRORS,
)


def _get_service(request: Request) -> VaultService:
    return VaultService(request.app.state.db, request.app.state.settings)


@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt(body: EncryptRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.encrypt(
            plaintext=body.plaintext, label=body.label, owner_id=body.owner_id
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt(body: DecryptRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.decrypt(blob_id=body.blob_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/tokenize", response_model=TokenizeResponse)
async def tokenize(body: TokenizeRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.tokenize(value=body.value)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/detokenize", response_model=DetokenizeResponse)
async def detokenize(body: DetokenizeRequest, request: Request):
    svc = _get_service(request)
    try:
        return await svc.detokenize(token=body.token)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/rotate/{blob_id}")
async def rotate_blob(blob_id: str, request: Request):
    svc = _get_service(request)
    try:
        return await svc.rotate_blob(blob_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.post("/rotate-all")
async def rotate_all(request: Request):
    svc = _get_service(request)
    return await svc.rotate_all()


# ── Password Vault (user-scoped secrets) ──


def _get_pw_vault(request: Request) -> PasswordVaultService:
    return PasswordVaultService(request.app.state.db, request.app.state.settings)


@router.post("/secrets")
async def store_secret(
    request: Request,
    body: StoreSecretRequest,
    user: dict = Depends(get_current_user),
):
    svc = _get_pw_vault(request)
    try:
        return await svc.store_secret(
            user_id=user["user_id"],
            name=body.name,
            value=body.value,
            category=body.category,
            notes=body.notes,
        )
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.get("/secrets")
async def list_secrets(
    request: Request,
    user: dict = Depends(get_current_user),
):
    svc = _get_pw_vault(request)
    return await svc.list_secrets(user["user_id"])


@router.get("/secrets/{secret_id}")
async def get_secret(
    secret_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
):
    svc = _get_pw_vault(request)
    try:
        return await svc.get_secret(user["user_id"], secret_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


@router.delete("/secrets/{secret_id}")
async def delete_secret(
    secret_id: str,
    request: Request,
    user: dict = Depends(get_current_user),
):
    svc = _get_pw_vault(request)
    try:
        return await svc.delete_secret(user["user_id"], secret_id)
    except ZuulError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)
