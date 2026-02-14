"""Identity Pydantic schemas."""

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    email: str
    username: str
    password: str = Field(min_length=8)
    display_name: str = ""


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 3600


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    display_name: str
    is_active: bool
    is_verified: bool
