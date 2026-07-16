"""
Enkstein — Auth Routes
POST /api/v1/auth/token  → exchange credentials for a Bearer JWT
GET  /api/v1/auth/me     → return the current user (requires valid token)

Default superadmin credentials (change via env vars):
  username: admin
  password: regentclaw-admin

Set ADMIN_USERNAME / ADMIN_PASSWORD in your .env to override.
In production also set SECRET_KEY and DEBUG=false.
"""
from __future__ import annotations

import threading
import time
import hashlib
import hmac
import json
import secrets
from collections import defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.core.deps import get_current_user
from app.models.connector import Connector, ConnectorStatus
from app.services import secrets_manager
from app.services.channels.email_provider import send_email
from app.services import owner_auth

router = APIRouter(prefix="/auth", tags=["Auth"])

# ── In-process rate limiter for /auth/token (Finding 12) ─────────────────────
# Uses a sliding-window counter keyed by client IP.
# For multi-replica deployments, replace with Redis-backed slowapi.
_RATE_WINDOW   = 60    # seconds
_RATE_MAX      = 10    # attempts per window per IP
_rate_store: dict[str, list[float]] = defaultdict(list)
_rate_lock  = threading.Lock()


def _auth_rate_limit(request: Request) -> None:
    """Dependency: raises 429 if the caller IP exceeds 10 login attempts / minute."""
    ip  = request.client.host if request.client else "unknown"
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW
    with _rate_lock:
        window = [t for t in _rate_store[ip] if t > cutoff]
        if len(window) >= _RATE_MAX:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts — please wait 60 seconds before retrying.",
                headers={"Retry-After": "60"},
            )
        window.append(now)
        _rate_store[ip] = window


# ── Configurable credentials ──────────────────────────────────────────────────
# In production store these hashed in a DB; for now use env-configured pair.

import os as _os

_ADMIN_USERNAME = _os.getenv("ADMIN_USERNAME", "admin")
_ADMIN_PASSWORD = _os.getenv("ADMIN_PASSWORD", "regentclaw-admin")

# Pre-hash at startup so login doesn't do plaintext comparison
_ADMIN_HASH = hash_password(_ADMIN_PASSWORD)

_USERS: dict[str, dict] = {
    _ADMIN_USERNAME: {
        "sub":      _ADMIN_USERNAME,
        "role":     "admin",
        "email":    _os.getenv("ADMIN_EMAIL", "redacted_user"),
        "hashed_password": _ADMIN_HASH,
    },
}


# ── Schemas ───────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type:   str = "bearer"
    expires_in:   int


class UserResponse(BaseModel):
    sub:   str
    role:  str
    email: str


class EmailCodeRequest(BaseModel):
    email: EmailStr


class EmailCodeVerify(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class EmailAuthStatus(BaseModel):
    enabled: bool
    delivery_configured: bool


class EmailCodeAccepted(BaseModel):
    accepted: bool = True
    message: str = "If the address can receive mail, a sign-in code has been sent."


class OwnerAuthStatus(BaseModel):
    setup_required: bool
    totp_enabled: bool


class OwnerSetupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)


class OwnerEnrollment(BaseModel):
    enrollment_token: str
    otpauth_uri: str
    secret: str
    expires_in: int


class OwnerSetupConfirm(BaseModel):
    enrollment_token: str = Field(min_length=32, max_length=128)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class OwnerSetupComplete(TokenResponse):
    recovery_codes: list[str]


class OwnerTotpLogin(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class OwnerRecoveryLogin(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    recovery_code: str = Field(min_length=8, max_length=16)


def _normalized_email(value: str) -> str:
    return value.strip().lower()


def _email_key(email: str) -> str:
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()
    return f"auth:email-code:{digest}"


def _code_digest(email: str, code: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        f"{email}:{code}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def _email_config(db: AsyncSession) -> dict | None:
    if settings.EMAIL_AUTH_SMTP_HOST and settings.EMAIL_AUTH_FROM:
        return {
            "smtp_host": settings.EMAIL_AUTH_SMTP_HOST,
            "smtp_port": settings.EMAIL_AUTH_SMTP_PORT,
            "username": settings.EMAIL_AUTH_SMTP_USERNAME,
            "password": settings.EMAIL_AUTH_SMTP_PASSWORD,
            "from_addr": settings.EMAIL_AUTH_FROM,
        }

    result = await db.execute(
        select(Connector).where(
            Connector.connector_type == "email",
            Connector.status == ConnectorStatus.APPROVED,
        )
    )
    for connector in result.scalars().all():
        credentials = secrets_manager.get_credential(str(connector.id)) or {}
        host = credentials.get("smtp_host")
        from_addr = credentials.get("from_addr") or credentials.get("from_email")
        if host and from_addr:
            return {
                "smtp_host": host,
                "smtp_port": int(credentials.get("smtp_port") or 587),
                "username": credentials.get("username", ""),
                "password": credentials.get("password", ""),
                "from_addr": from_addr,
            }
    return None


async def _redis_client() -> Redis:
    try:
        client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        await client.ping()
        return client
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Email sign-in is temporarily unavailable",
        ) from exc


async def _limit_email_request(client: Redis, request: Request, email: str) -> None:
    ip = request.client.host if request.client else "unknown"
    ip_digest = hashlib.sha256(ip.encode("utf-8")).hexdigest()
    windows = (
        (f"auth:email-rate:address:{hashlib.sha256(email.encode()).hexdigest()}", 3, 900),
        (f"auth:email-rate:ip:{ip_digest}", 20, 3600),
    )
    for key, maximum, ttl in windows:
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, ttl)
        if count > maximum:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many email sign-in requests; try again later",
                headers={"Retry-After": str(ttl)},
            )


def _owner_token(username: str, auth_method: str) -> TokenResponse:
    token = create_access_token(
        data={
            "sub": username,
            "role": "admin",
            "email": "",
            "mfa_verified": True,
            "auth_method": auth_method,
            "mfa_verified_at": int(time.time()),
        },
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(access_token=token, expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/token", response_model=TokenResponse)
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    _rl: None = Depends(_auth_rate_limit),
):
    """
    Exchange username + password for a Bearer JWT.
    Rate limited to 10 attempts/minute per IP (Finding 12).
    Use with Authorization: Bearer <token> on protected endpoints.
    In DEBUG mode all endpoints bypass auth automatically.
    """
    configured_owner = owner_auth.get_owner()
    if configured_owner:
        raise HTTPException(status_code=428, detail="Authenticator code required")
    if not settings.DEBUG:
        raise HTTPException(status_code=410, detail="Complete local owner setup to authenticate")

    user = _USERS.get(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(
        data={"sub": user["sub"], "role": user["role"], "email": user["email"]},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/owner/status", response_model=OwnerAuthStatus)
async def owner_status():
    configured = owner_auth.owner_is_configured()
    return OwnerAuthStatus(setup_required=not configured, totp_enabled=configured)


@router.post("/owner/setup", response_model=OwnerEnrollment)
async def start_owner_setup(payload: OwnerSetupRequest, request: Request):
    _auth_rate_limit(request)
    if owner_auth.owner_is_configured():
        raise HTTPException(status_code=409, detail="Local owner is already configured")
    token = secrets.token_urlsafe(32)
    secret = owner_auth.generate_totp_secret()
    pending = {
        "username": payload.username.strip(),
        "password_hash": hash_password(payload.password),
        "totp_secret": secret,
    }
    client = await _redis_client()
    try:
        token_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        await client.set(
            f"auth:owner-setup:{token_digest}",
            json.dumps(pending),
            ex=settings.OWNER_SETUP_TTL_SECONDS,
        )
    finally:
        await client.aclose()
    return OwnerEnrollment(
        enrollment_token=token,
        otpauth_uri=owner_auth.enrollment_uri(pending["username"], secret),
        secret=secret,
        expires_in=settings.OWNER_SETUP_TTL_SECONDS,
    )


@router.post("/owner/setup/confirm", response_model=OwnerSetupComplete)
async def confirm_owner_setup(payload: OwnerSetupConfirm, request: Request):
    _auth_rate_limit(request)
    if owner_auth.owner_is_configured():
        raise HTTPException(status_code=409, detail="Local owner is already configured")
    token_digest = hashlib.sha256(payload.enrollment_token.encode("utf-8")).hexdigest()
    key = f"auth:owner-setup:{token_digest}"
    client = await _redis_client()
    try:
        raw = await client.get(key)
        if not raw:
            raise HTTPException(status_code=401, detail="Owner enrollment expired; start again")
        pending = json.loads(raw)
        if owner_auth.verify_totp(pending["totp_secret"], payload.code) is None:
            raise HTTPException(status_code=401, detail="Invalid Authenticator code")
        consumed = await client.getdel(key)
        if consumed != raw:
            raise HTTPException(status_code=409, detail="Owner enrollment was already completed")
    finally:
        await client.aclose()

    recovery_codes = owner_auth.persist_owner_hash(
        pending["username"], pending["password_hash"], pending["totp_secret"]
    )
    token_response = _owner_token(pending["username"], "password_totp_setup")
    return OwnerSetupComplete(**token_response.model_dump(), recovery_codes=recovery_codes)


@router.post("/owner/login", response_model=TokenResponse)
async def login_owner_totp(payload: OwnerTotpLogin, request: Request):
    _auth_rate_limit(request)
    owner = owner_auth.get_owner()
    if not owner or payload.username != owner.get("username") or not owner_auth.verify_owner_password(owner, payload.password):
        raise HTTPException(status_code=401, detail="Invalid owner credentials")
    counter = owner_auth.verify_totp(owner["totp_secret"], payload.code)
    if counter is None:
        raise HTTPException(status_code=401, detail="Invalid Authenticator code")
    client = await _redis_client()
    replay_key = f"auth:owner-totp-used:{hashlib.sha256(payload.username.encode()).hexdigest()}:{counter}"
    try:
        if not await client.set(replay_key, "1", ex=owner_auth.TOTP_PERIOD_SECONDS * 2, nx=True):
            raise HTTPException(status_code=401, detail="Authenticator code was already used")
    finally:
        await client.aclose()
    return _owner_token(payload.username, "password_totp")


@router.post("/owner/recovery", response_model=TokenResponse)
async def login_owner_recovery(payload: OwnerRecoveryLogin, request: Request):
    _auth_rate_limit(request)
    owner = owner_auth.get_owner()
    if not owner or payload.username != owner.get("username") or not owner_auth.verify_owner_password(owner, payload.password):
        raise HTTPException(status_code=401, detail="Invalid owner credentials")
    if not owner_auth.consume_recovery_code(owner, payload.recovery_code):
        raise HTTPException(status_code=401, detail="Invalid or already-used recovery code")
    return _owner_token(payload.username, "password_recovery_code")


@router.get("/email/status", response_model=EmailAuthStatus)
async def email_auth_status(db: AsyncSession = Depends(get_db)):
    config = await _email_config(db) if settings.EMAIL_AUTH_ENABLED else None
    return EmailAuthStatus(
        enabled=settings.EMAIL_AUTH_ENABLED,
        delivery_configured=config is not None,
    )


@router.post("/email/request", response_model=EmailCodeAccepted, status_code=202)
async def request_email_code(
    payload: EmailCodeRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    if not settings.EMAIL_AUTH_ENABLED:
        raise HTTPException(status_code=503, detail="Email sign-in is disabled")
    config = await _email_config(db)
    if not config:
        raise HTTPException(status_code=503, detail="Configure and approve an Email connector before using email sign-in")

    email = _normalized_email(str(payload.email))
    client = await _redis_client()
    try:
        await _limit_email_request(client, request, email)
        code = f"{secrets.randbelow(1_000_000):06d}"
        challenge = json.dumps({"digest": _code_digest(email, code), "attempts": 0})
        await client.set(_email_key(email), challenge, ex=settings.EMAIL_AUTH_CODE_TTL_SECONDS)
        minutes = max(1, settings.EMAIL_AUTH_CODE_TTL_SECONDS // 60)
        delivered = await send_email(
            **config,
            to_addrs=[email],
            subject="Your Enkstein sign-in code",
            body=(
                f"Your Enkstein sign-in code is {code}.\n\n"
                f"It expires in {minutes} minutes and can be used once.\n"
                "If you did not request this code, ignore this message."
            ),
            html_body=(
                "<p>Your Enkstein sign-in code is:</p>"
                f"<p style=\"font-size:28px;font-weight:700;letter-spacing:6px\">{code}</p>"
                f"<p>It expires in {minutes} minutes and can be used once.</p>"
            ),
        )
        if not delivered:
            await client.delete(_email_key(email))
            raise HTTPException(status_code=503, detail="The sign-in email could not be delivered")
        return EmailCodeAccepted()
    finally:
        await client.aclose()


@router.post("/email/verify", response_model=TokenResponse)
async def verify_email_code(payload: EmailCodeVerify):
    if not settings.EMAIL_AUTH_ENABLED:
        raise HTTPException(status_code=503, detail="Email sign-in is disabled")
    email = _normalized_email(str(payload.email))
    client = await _redis_client()
    key = _email_key(email)
    try:
        raw = await client.get(key)
        if not raw:
            raise HTTPException(status_code=401, detail="Invalid or expired sign-in code")
        try:
            challenge = json.loads(raw)
        except (TypeError, ValueError):
            await client.delete(key)
            raise HTTPException(status_code=401, detail="Invalid or expired sign-in code")

        expected = str(challenge.get("digest", ""))
        if not hmac.compare_digest(expected, _code_digest(email, payload.code)):
            attempts = int(challenge.get("attempts", 0)) + 1
            if attempts >= settings.EMAIL_AUTH_MAX_ATTEMPTS:
                await client.delete(key)
            else:
                challenge["attempts"] = attempts
                await client.set(key, json.dumps(challenge), keepttl=True)
            raise HTTPException(status_code=401, detail="Invalid or expired sign-in code")

        consumed = await client.getdel(key)
        if consumed != raw:
            raise HTTPException(status_code=401, detail="Invalid or expired sign-in code")
    finally:
        await client.aclose()

    subject = "email:" + hashlib.sha256(email.encode("utf-8")).hexdigest()[:24]
    token = create_access_token(
        data={
            "sub": subject,
            "role": "viewer",
            "email": email,
            "email_verified": True,
            "auth_method": "email_otp",
        },
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(access_token=token, expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)


@router.get("/me", response_model=UserResponse)
async def me(user: dict = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return UserResponse(
        sub=user.get("sub", "unknown"),
        role=user.get("role", "viewer"),
        email=user.get("email", ""),
    )
