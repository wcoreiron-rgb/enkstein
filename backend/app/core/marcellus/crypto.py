"""Encryption and signing helpers for Marcellus runtime state."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.fabric.security import get_agent_signer

logger = logging.getLogger("marcellus.crypto")

_SECRETS_DIR = Path(__file__).resolve().parents[3] / ".secrets"
_KEY_FILE = _SECRETS_DIR / ".marcellus_runtime_key"
_KEY_ENV = "MARCELLUS_DATA_ENCRYPTION_KEY"


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _load_or_create_key() -> bytes:
    configured = os.getenv(_KEY_ENV, "").strip().encode("ascii")
    if configured:
        try:
            Fernet(configured)
            return configured
        except Exception as exc:
            raise RuntimeError("MARCELLUS_DATA_ENCRYPTION_KEY is invalid") from exc

    if _KEY_FILE.exists():
        stored = _KEY_FILE.read_bytes().strip()
        try:
            Fernet(stored)
            return stored
        except Exception as exc:
            raise RuntimeError("Stored Marcellus runtime encryption key is invalid") from exc

    key = Fernet.generate_key()
    _SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    _SECRETS_DIR.chmod(0o700)
    _KEY_FILE.write_bytes(key)
    _KEY_FILE.chmod(0o600)
    return key


def _fernet() -> Fernet:
    return Fernet(_load_or_create_key())


def encrypt_json(value: Any) -> tuple[str, str]:
    raw = canonical_json(value).encode("utf-8")
    return _fernet().encrypt(raw).decode("ascii"), hashlib.sha256(raw).hexdigest()


def decrypt_json(ciphertext: str, expected_digest: str | None = None) -> Any:
    try:
        raw = _fernet().decrypt(ciphertext.encode("ascii"))
    except InvalidToken as exc:
        raise ValueError("Encrypted runtime data could not be authenticated") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if expected_digest and digest != expected_digest:
        raise ValueError("Encrypted runtime data digest mismatch")
    return json.loads(raw.decode("utf-8"))


def sign_envelope(envelope: dict[str, Any]) -> tuple[str, str, str, str]:
    envelope_json = canonical_json(envelope)
    signer = get_agent_signer()
    return envelope_json, signer.sign(envelope_json.encode("utf-8")), signer.algorithm, signer.key_id


def verify_envelope(envelope_json: str, signature: str, key_id: str) -> bool:
    return get_agent_signer().verify(envelope_json.encode("utf-8"), signature, key_id=key_id)
