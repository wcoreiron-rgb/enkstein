"""
Enkstein — Security utilities: password hashing + JWT creation/verification.

In DEBUG mode (settings.DEBUG = True, the default) auth is a no-op so that
local dev still works without credentials.  Set DEBUG=False (and a real
SECRET_KEY) when deploying to staging/production.
"""
from __future__ import annotations

import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt as pyjwt
from jwt.exceptions import InvalidTokenError as JWTError  # noqa: F401 — re-exported for deps.py
from passlib.context import CryptContext

from app.core.config import settings

# passlib 1.7.4 is not compatible with bcrypt 4.x (__about__ removed).
# We stay on bcrypt 3.2.2 but work around the 72-char truncation limit by
# pre-hashing passwords with SHA-256 → base64 before passing to bcrypt.
# This guarantees any-length passwords are unique inputs to bcrypt.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _prehash(plain: str) -> str:
    """SHA-256 + base64 prehash so bcrypt never silently truncates at 72 bytes."""
    digest = hashlib.sha256(plain.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


# ── Password helpers ──────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return pwd_context.hash(_prehash(plain))


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(_prehash(plain), hashed)


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(
    data: dict[str, Any],
    expires_delta: timedelta | None = None,
) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    # PyJWT — explicit algorithm, no alg:none confusion possible
    return pyjwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Raises jwt.InvalidTokenError on invalid/expired tokens."""
    return pyjwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["exp", "sub"]},  # enforce mandatory claims
    )
