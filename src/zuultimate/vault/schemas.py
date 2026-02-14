"""Vault Pydantic schemas for request/response validation."""

from pydantic import BaseModel


class EncryptRequest(BaseModel):
    plaintext: str
    label: str = ""
    owner_id: str = ""


class EncryptResponse(BaseModel):
    blob_id: str
    label: str


class DecryptRequest(BaseModel):
    blob_id: str


class DecryptResponse(BaseModel):
    plaintext: str


class TokenizeRequest(BaseModel):
    value: str


class TokenizeResponse(BaseModel):
    token: str


class DetokenizeRequest(BaseModel):
    token: str


class DetokenizeResponse(BaseModel):
    value: str
