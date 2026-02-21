"""Vault Pydantic schemas for request/response validation."""

from pydantic import BaseModel, Field


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


class StoreSecretRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    value: str = Field(min_length=1, max_length=10000)
    category: str = Field(default="password", max_length=50)
    notes: str = Field(default="", max_length=1000)
