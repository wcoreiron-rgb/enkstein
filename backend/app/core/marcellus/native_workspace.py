from __future__ import annotations

import base64
import json
import os
import posixpath
import re
import uuid
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus.crypto import decrypt_json, encrypt_json
from app.core.marcellus.workspace_schemas import CortexArtifactBatchCreate, CortexArtifactItem
from app.core.modelclaw.brain_bridge import invoke_native_workspace


_STATE_FILE = Path("/app/.state/native_workspace_bindings.json")

# Defense-in-depth blocklist mirrored from the native broker's own guard
# (packaging/macos/MarcellusBrainBridge.swift) so a project-relative path is
# rejected in the backend before it is ever forwarded to the host, even if a
# future broker regression weakened the native check. These directories can
# hold credentials, key material, or unbounded vendored trees.
_BLOCKED_PATH_PARTS = {
    ".git",
    ".secrets",
    ".secret",
    "node_modules",
    ".marcellus-trash",
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".docker",
    ".npmrc",
    ".netrc",
}
# Hidden files whose basename commonly carries secrets; blocked as a leaf even
# when the containing directory is otherwise allowed.
_BLOCKED_SECRET_LEAVES = {".env", ".env.local", ".env.production", ".pypirc", ".htpasswd"}


def validate_contained_relpath(path: str) -> str:
    """Return a normalized project-relative path or raise 422.

    Rejects absolute paths, Windows drive/UNC roots, parent-directory
    traversal, empty/dot targets, and any component that names a protected or
    secret-bearing directory/file. This is the backend guard that runs *before*
    any filesystem-affecting bridge call (rename/move/trash/write); the native
    broker and its security-scoped bookmark remain the authoritative boundary.
    """
    raw = (path or "").strip().replace("\\", "/")
    if not raw:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="A project-relative path is required")
    head = raw.split("/", 1)[0]
    if raw.startswith("/") or raw.startswith("~") or ":" in head:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Only project-relative paths are permitted")
    normalized = posixpath.normpath(raw).lstrip("/")
    parts = normalized.split("/")
    if normalized in {"", "."} or normalized == ".." or ".." in parts:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Path escapes the approved project root")
    for part in parts:
        if part in _BLOCKED_PATH_PARTS:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Path targets a protected project directory")
    if parts[-1] in _BLOCKED_SECRET_LEAVES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Path targets a protected secret file")
    return normalized


def _binding_key(tenant_id: str, project_id: uuid.UUID) -> str:
    return f"{tenant_id}:{project_id}"


def _load_bindings() -> dict[str, dict[str, str]]:
    if not _STATE_FILE.exists():
        return {}
    try:
        envelope = json.loads(_STATE_FILE.read_text(encoding="utf-8"))
        return decrypt_json(envelope["ciphertext"], envelope["digest"])
    except Exception as exc:
        raise RuntimeError("Native workspace binding state could not be authenticated") from exc


def _save_bindings(bindings: dict[str, dict[str, str]]) -> None:
    ciphertext, digest = encrypt_json(bindings)
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.parent.chmod(0o700)
    temporary = _STATE_FILE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"ciphertext": ciphertext, "digest": digest}), encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, _STATE_FILE)


def get_binding(tenant_id: str, project_id: uuid.UUID) -> dict[str, str] | None:
    return _load_bindings().get(_binding_key(tenant_id, project_id))


def set_binding(
    tenant_id: str,
    project_id: uuid.UUID,
    *,
    token: str,
    name: str,
    path_alias: str | None = None,
) -> None:
    bindings = _load_bindings()
    record = {"token": token, "name": name[:255]}
    if path_alias:
        # A short, non-reversible alias (folder name + last path segments) so
        # the UI can confirm the approved root without persisting or exposing
        # the absolute host path.
        record["path_alias"] = path_alias[:255]
    bindings[_binding_key(tenant_id, project_id)] = record
    _save_bindings(bindings)


_TOKEN_RE = re.compile(r"^[a-f0-9-]{36}$")


async def pick_native_root() -> dict[str, str]:
    """Open the host's native folder picker and register the chosen directory.

    The broker returns an opaque per-root token plus a display name and a safe
    path alias; the absolute host path never crosses the bridge boundary. Only
    those three opaque fields are ever forwarded — any raw ``path`` the broker
    might include is stripped here as defense-in-depth before it can reach a
    schema, the DB, or the UI.
    """
    result = await invoke_native_workspace("pick", {})
    token = str(result.get("token") or "") if isinstance(result, dict) else ""
    if not _TOKEN_RE.match(token):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No folder was approved")
    name = str(result.get("name") or "").strip()[:255]
    if not name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No folder was approved")
    path_alias = str(result.get("path_alias") or "").strip()[:255] or None
    return {"token": token, "name": name, "path_alias": path_alias}


async def mirror_rename(tenant_id: str, project_id: uuid.UUID, *, path: str, new_path: str) -> None:
    binding = get_binding(tenant_id, project_id)
    if not binding:
        return
    validate_contained_relpath(path)
    validate_contained_relpath(new_path)
    try:
        await invoke_native_workspace(
            "rename", {"token": binding["token"], "path": path, "new_path": new_path}
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The local file could not be renamed") from exc


async def list_native_files(tenant_id: str, project_id: uuid.UUID) -> list[dict[str, str]]:
    binding = get_binding(tenant_id, project_id)
    if not binding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No local folder is connected")
    try:
        result = await invoke_native_workspace("list", {"token": binding["token"]})
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The local folder bridge is unavailable") from exc
    files = result.get("files")
    if not isinstance(files, list):
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The local folder bridge returned invalid data")
    return files


async def mirror_write(
    tenant_id: str,
    project_id: uuid.UUID,
    *,
    path: str,
    content: str,
    binary: bytes | None = None,
) -> None:
    binding = get_binding(tenant_id, project_id)
    if not binding:
        return
    validate_contained_relpath(path)
    payload: dict[str, Any] = {"token": binding["token"], "path": path}
    if binary is None:
        payload["content"] = content
    else:
        # Office documents are binary and cannot survive a UTF-8 round trip.
        payload["content_base64"] = base64.b64encode(binary).decode("ascii")
    try:
        await invoke_native_workspace("write", payload)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The local file could not be saved") from exc


async def mirror_trash(tenant_id: str, project_id: uuid.UUID, *, path: str) -> None:
    binding = get_binding(tenant_id, project_id)
    if not binding:
        return
    validate_contained_relpath(path)
    try:
        await invoke_native_workspace("trash", {"token": binding["token"], "path": path})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The local file could not be moved to trash") from exc


def native_files_payload(
    *, tenant_id: str, project_id: uuid.UUID, files: list[dict[str, Any]], classification: str
) -> CortexArtifactBatchCreate:
    try:
        items = [CortexArtifactItem.model_validate(item) for item in files]
        return CortexArtifactBatchCreate(
            tenant_id=tenant_id,
            project_id=project_id,
            classification=classification,
            files=items,
        )
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="The selected folder contains unsupported data") from exc
