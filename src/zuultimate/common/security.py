"""Security utilities: password hashing, JWT tokens."""

from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, password)
    except VerifyMismatchError:
        return False


def create_jwt(
    payload: dict,
    secret_key: str,
    expires_minutes: int = 60,
    algorithm: str = "HS256",
) -> str:
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    data["iat"] = datetime.now(timezone.utc)
    return jwt.encode(data, secret_key, algorithm=algorithm)


def decode_jwt(token: str, secret_key: str, algorithm: str = "HS256") -> dict:
    return jwt.decode(token, secret_key, algorithms=[algorithm])
