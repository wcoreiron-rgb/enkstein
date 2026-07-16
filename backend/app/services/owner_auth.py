"""Local owner password, TOTP, and recovery-code security for Enkstein."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from urllib.parse import quote

from app.core.config import settings
from app.core.security import hash_password, verify_password
from app.services import secrets_manager


OWNER_CREDENTIAL_ID = "marcellus-local-owner"
TOTP_PERIOD_SECONDS = 30
TOTP_DIGITS = 6
_recovery_lock = threading.Lock()


def get_owner() -> dict[str, str] | None:
    owner = secrets_manager.get_credential(OWNER_CREDENTIAL_ID)
    if not owner or not owner.get("password_hash") or not owner.get("totp_secret"):
        return None
    return owner


def owner_is_configured() -> bool:
    return get_owner() is not None


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def enrollment_uri(username: str, secret: str) -> str:
    issuer = "Enkstein"
    label = quote(f"{issuer}:{username}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    )


def _totp_at(secret: str, counter: int) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, *, now: float | None = None) -> int | None:
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return None
    current = int((now if now is not None else time.time()) // TOTP_PERIOD_SECONDS)
    for counter in range(current - 1, current + 2):
        if hmac.compare_digest(_totp_at(secret, counter), code):
            return counter
    return None


def verify_owner_password(owner: dict[str, str], password: str) -> bool:
    return verify_password(password, owner.get("password_hash", ""))


def _recovery_digest(code: str) -> str:
    normalized = code.strip().upper().replace("-", "")
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_recovery_codes(count: int = 10) -> tuple[list[str], list[str]]:
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(4).upper()
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes, [_recovery_digest(code) for code in codes]


def persist_owner_hash(username: str, password_hash: str, totp_secret: str) -> list[str]:
    recovery_codes, recovery_hashes = generate_recovery_codes()
    secrets_manager.store_credential(
        OWNER_CREDENTIAL_ID,
        {
            "username": username.strip(),
            "password_hash": password_hash,
            "totp_secret": totp_secret,
            "recovery_hashes": json.dumps(recovery_hashes),
        },
    )
    return recovery_codes


def persist_owner(username: str, password: str, totp_secret: str) -> list[str]:
    return persist_owner_hash(username, hash_password(password), totp_secret)


def consume_recovery_code(owner: dict[str, str], code: str) -> bool:
    with _recovery_lock:
        current = get_owner() or owner
        try:
            hashes = json.loads(current.get("recovery_hashes", "[]"))
        except (TypeError, ValueError):
            return False
        digest = _recovery_digest(code)
        matched = next((value for value in hashes if hmac.compare_digest(str(value), digest)), None)
        if matched is None:
            return False
        hashes.remove(matched)
        secrets_manager.store_credential(
            OWNER_CREDENTIAL_ID,
            {
                "username": current["username"],
                "password_hash": current["password_hash"],
                "totp_secret": current["totp_secret"],
                "recovery_hashes": json.dumps(hashes),
            },
        )
        return True
