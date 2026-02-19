"""Identity Pydantic schemas."""

import re

from pydantic import BaseModel, Field, field_validator


class RegisterRequest(BaseModel):
    email: str
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8)
    display_name: str = ""

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid email format")
        return v.lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not re.search(r"[a-zA-Z]", v):
            raise ValueError("Password must contain at least one letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str = ""
    token_type: str = "bearer"
    expires_in: int = 3600


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    display_name: str
    is_active: bool
    is_verified: bool
    tenant_id: str | None = None


class MFASetupResponse(BaseModel):
    device_id: str
    secret: str
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class MFAChallengeRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=6)


class EmailVerifyRequest(BaseModel):
    token: str = Field(min_length=1)


class EmailVerificationResponse(BaseModel):
    user_id: str
    email: str
    verified: bool


class VerificationTokenResponse(BaseModel):
    user_id: str
    email: str
    token: str
    expires_at: str


class SSOProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    protocol: str = Field(pattern=r"^(oidc|saml)$")
    issuer_url: str = Field(min_length=1, max_length=500)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = ""
    metadata_url: str = ""
    tenant_id: str | None = None


class SSOProviderResponse(BaseModel):
    id: str
    name: str
    protocol: str
    issuer_url: str
    client_id: str
    metadata_url: str | None = None
    tenant_id: str | None = None
    is_active: bool


class SSOLoginInitResponse(BaseModel):
    redirect_url: str
    state: str
    provider_id: str


class SSOCallbackRequest(BaseModel):
    provider_id: str
    code: str
    state: str


class TenantCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")


class TenantResponse(BaseModel):
    id: str
    name: str
    slug: str
    is_active: bool
