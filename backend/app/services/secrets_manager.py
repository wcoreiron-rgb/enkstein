"""
Enkstein — Secrets Manager
==============================
Encrypts connector credentials at rest using Fernet symmetric encryption.
Credentials are NEVER stored in plaintext — not in the DB, not in logs.

Architecture:
  - Encryption key: SECRETS_ENCRYPTION_KEY in backend/.env
    (auto-generated on first run if not set)
  - Storage: backend/.secrets/connectors.json (encrypted JSON)
  - The DB only stores a reference (connector_id) — never the raw value
  - API responses never include credential values — only a masked hint
"""

from __future__ import annotations

import os
import json
import base64
import secrets
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Key management ─────────────────────────────────────────────────────────────

_SECRETS_DIR  = Path(__file__).parent.parent.parent / ".secrets"
_SECRETS_FILE = _SECRETS_DIR / "connectors.json"
_KEY_FILE     = _SECRETS_DIR / ".encryption_key"   # persisted fallback key
_KEY_ENV      = "SECRETS_ENCRYPTION_KEY"


def _get_or_create_key() -> bytes:
    """
    Load the Fernet encryption key using this priority order:
      1. SECRETS_ENCRYPTION_KEY env var (explicit override — use in production)
      2. .secrets/.encryption_key file  (auto-persisted — survives container restarts)
      3. Generate a new key and persist it to #2 for future restarts

    IMPORTANT: Fernet.generate_key() returns a base64url-encoded key, and
    Fernet(key) expects that same encoded form — do NOT decode it before passing.
    The key file stores the raw output of Fernet.generate_key() as-is.

    The key file lives inside ./backend/.secrets/ which is volume-mounted
    (./backend:/app in docker-compose), so it survives `docker compose restart`.
    """
    from cryptography.fernet import Fernet

    # 1. Explicit env var — value should be the output of Fernet.generate_key()
    raw = os.getenv(_KEY_ENV, "")
    if raw:
        key_bytes = raw.strip().encode()
        try:
            Fernet(key_bytes)          # validate before use
            return key_bytes
        except Exception:
            logger.warning("SECRETS_ENCRYPTION_KEY in env is malformed — ignoring")

    # 2. Persisted key file (survives restarts via volume mount)
    if _KEY_FILE.exists():
        try:
            stored = _KEY_FILE.read_bytes().strip()
            Fernet(stored)             # validate — raises if corrupt/wrong format
            return stored              # pass as-is; Fernet decodes internally
        except Exception:
            logger.warning("Stored encryption key is invalid — regenerating")

    # 3. Generate new key and persist so future restarts can decrypt existing creds
    key = Fernet.generate_key()        # returns base64url-encoded bytes already
    try:
        _SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        _KEY_FILE.write_bytes(key)     # store encoded form exactly as Fernet gave it
        # Restrict permissions — key must not be world-readable (Finding 11)
        _KEY_FILE.chmod(0o600)
        _SECRETS_DIR.chmod(0o700)
    except Exception:
        logger.error("Could not persist encryption key")

    return key                         # return encoded form; Fernet decodes internally


def _fernet():
    from cryptography.fernet import Fernet
    return Fernet(_get_or_create_key())


def _load_store() -> dict:
    if not _SECRETS_FILE.exists():
        return {}
    try:
        raw = _SECRETS_FILE.read_text()
        return json.loads(raw)
    except Exception as exc:
        # Returning {} here is what made this dangerous: every caller that
        # loads, mutates and saves would then write an empty store back over
        # a file that still held every credential in the deployment. A read
        # failure must not be indistinguishable from "no credentials exist".
        raise RuntimeError(
            f"Credential store at {_SECRETS_FILE} could not be read: {exc}"
        ) from exc


def _save_store(store: dict, *, allow_empty: bool = False):
    # Refuse to empty a store that currently holds credentials. Nothing in
    # normal operation clears every connector at once, so an empty write over
    # populated data is a bug somewhere upstream, and silently obeying it
    # destroys the operator's sign-ins.
    #
    # ``allow_empty`` is for the one legitimate case: deliberately deleting
    # the last remaining credential.
    if not store and not allow_empty and _SECRETS_FILE.exists():
        try:
            existing = json.loads(_SECRETS_FILE.read_text())
        except Exception:
            existing = None
        if existing:
            raise RuntimeError(
                "Refusing to overwrite a populated credential store with an "
                "empty one; this indicates a load failure upstream."
            )
    _SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    # Write to a temporary file and rename, so a crash mid-write leaves the
    # previous store intact rather than a truncated one that fails to parse.
    tmp = _SECRETS_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, indent=2))
    # Restrict permissions — credential store must not be world-readable (Finding 11)
    tmp.chmod(0o600)
    tmp.replace(_SECRETS_FILE)
    _SECRETS_DIR.chmod(0o700)


# ── Public API ─────────────────────────────────────────────────────────────────

# Reserved top-level key holding connector_id -> tenant_id bindings. Real
# entries are keyed by connector UUID, so this name can never collide with one.
_TENANT_INDEX_KEY = "__tenants__"


class CrossTenantCredentialAccess(RuntimeError):
    """Raised when a caller asks for a credential owned by another tenant."""


def _tenant_index(store: dict) -> dict[str, str]:
    index = store.get(_TENANT_INDEX_KEY)
    return index if isinstance(index, dict) else {}


def _check_tenant(store: dict, connector_id: str, tenant_id: Optional[str]) -> None:
    """Enforce the recorded tenant binding for ``connector_id``.

    ``tenant_id=None`` means an unscoped/admin caller and is always permitted,
    matching the platform-wide tenancy rule. A credential with no recorded
    binding predates tenant scoping and stays readable, so upgrading does not
    strand an operator's existing sign-ins.
    """
    if tenant_id is None:
        return
    owner = _tenant_index(store).get(connector_id)
    if owner is not None and owner != tenant_id:
        raise CrossTenantCredentialAccess(
            f"Credential {connector_id} is not owned by tenant {tenant_id}"
        )


def store_credential(
    connector_id: str,
    fields: dict[str, str],
    *,
    tenant_id: Optional[str] = None,
) -> str:
    """
    Encrypt and store credential fields for a connector.
    Returns a masked hint (e.g. "sk-...abc") for display.
    Never stores plaintext.
    """
    f = _fernet()
    encrypted = {}
    for key, value in fields.items():
        if value:
            encrypted[key] = f.encrypt(value.encode()).decode()

    store = _load_store()
    _check_tenant(store, connector_id, tenant_id)
    store[connector_id] = encrypted
    if tenant_id is not None:
        index = dict(_tenant_index(store))
        index[connector_id] = tenant_id
        store[_TENANT_INDEX_KEY] = index
    _save_store(store)

    # Return a masked hint from the first non-empty value
    first_val = next((v for v in fields.values() if v), "")
    if len(first_val) > 8:
        return f"{first_val[:4]}...{first_val[-4:]}"
    elif first_val:
        return "****"
    return ""


def get_credential(
    connector_id: str,
    *,
    tenant_id: Optional[str] = None,
) -> Optional[dict[str, str]]:
    """Decrypt and return credential fields for a connector.

    Pass ``tenant_id`` to confine the read to one tenant; omitting it keeps the
    unscoped behaviour used by internal/admin callers.
    """
    store = _load_store()
    _check_tenant(store, connector_id, tenant_id)
    entry = store.get(connector_id)
    if not entry:
        return None

    f = _fernet()
    result = {}
    for key, enc_value in entry.items():
        try:
            result[key] = f.decrypt(enc_value.encode()).decode()
        except Exception:
            result[key] = ""
    return result


def is_configured(connector_id: str) -> bool:
    """Check if credentials exist for this connector."""
    if connector_id == _TENANT_INDEX_KEY:
        return False
    store = _load_store()
    return connector_id in store and bool(store[connector_id])


def delete_credential(connector_id: str, *, tenant_id: Optional[str] = None):
    """Remove stored credentials for a connector."""
    store = _load_store()
    _check_tenant(store, connector_id, tenant_id)
    store.pop(connector_id, None)
    index = _tenant_index(store)
    if connector_id in index:
        remaining = {key: value for key, value in index.items() if key != connector_id}
        if remaining:
            store[_TENANT_INDEX_KEY] = remaining
        else:
            store.pop(_TENANT_INDEX_KEY, None)
    # An explicit delete may legitimately empty the store.
    _save_store(store, allow_empty=True)


def list_configured() -> list[str]:
    """Return list of connector IDs that have stored credentials."""
    return [key for key in _load_store().keys() if key != _TENANT_INDEX_KEY]
