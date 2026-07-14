"""
RegentClaw — FastAPI dependencies.

get_current_user:
  In DEBUG mode → returns a synthetic admin user (no token required).
  In production → requires a valid Bearer JWT obtained from POST /api/v1/auth/token.

Usage:
  from app.core.deps import get_current_user

  @router.get("/protected")
  async def protected(user = Depends(get_current_user)):
      return {"user": user}
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from jwt.exceptions import InvalidTokenError as JWTError
from starlette.requests import HTTPConnection

from app.core.config import settings
from app.core.security import decode_access_token

# Synthetic admin used in dev/debug bypass
_DEV_USER = {
    "sub": "dev-admin",
    "role": "admin",
    "email": "redacted_user",
    "debug_bypass": True,
}


# Paths that never require authentication.
# Keep this list minimal — anything here is fully public.
_PUBLIC_PATHS: frozenset[str] = frozenset({
    "/api/v1/auth/token",
    "/api/v1/auth/register",
    "/api/v1/auth/email/status",
    "/api/v1/auth/email/request",
    "/api/v1/auth/email/verify",
    "/api/v1/auth/owner/status",
    "/api/v1/auth/owner/setup",
    "/api/v1/auth/owner/setup/confirm",
    "/api/v1/auth/owner/login",
    "/api/v1/auth/owner/recovery",
    # The WebSocket route performs its own JWT validation and protocol-level
    # rejection. Letting the global HTTP dependency reject it produces an
    # incomplete ASGI handshake instead of a clean WebSocket close.
    "/api/v1/ws",
    "/health",
    "/",
    "/docs",
    "/redoc",
    "/openapi.json",
})


async def get_current_user(
    connection: HTTPConnection,
) -> dict:
    """
    Resolve the current user from a Bearer JWT.

    Public paths (auth/token, health, docs) are exempted so the login
    endpoint is never locked behind the token it issues — fixing the
    production auth deadlock.

    In DEBUG mode (settings.DEBUG = True) this returns a synthetic admin
    so that local development and all existing tests work without credentials.

    This dependency is installed globally on the FastAPI app, so it must support
    both normal HTTP requests and WebSocket upgrades.
    """
    # Always allow public endpoints — never require a token here
    if connection.url.path in _PUBLIC_PATHS:
        return {"sub": "anonymous", "role": "anonymous", "public": True}

    if settings.DEBUG:
        return _DEV_USER

    auth_header = connection.headers.get("authorization", "")
    token = ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
        sub: str = payload.get("sub", "")
        if not sub:
            raise ValueError("empty sub")
        if payload.get("role") == "viewer" and connection.scope.get("type") == "http":
            method = str(connection.scope.get("method", "GET")).upper()
            if method not in {"GET", "HEAD", "OPTIONS"}:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Verified email sessions are read-only; owner approval is required for changes",
                )
        return payload
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    """Dependency that enforces role=admin."""
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin required")
    return user
