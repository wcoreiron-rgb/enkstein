from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.marcellus.crypto import decrypt_json, encrypt_json
from app.core.marcellus.workspace_schemas import CortexArtifactBatchCreate, CortexArtifactItem
from app.core.modelclaw.brain_bridge import invoke_native_workspace


_STATE_FILE = Path("/app/.state/native_workspace_bindings.json")


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


def set_binding(tenant_id: str, project_id: uuid.UUID, *, token: str, name: str) -> None:
    bindings = _load_bindings()
    bindings[_binding_key(tenant_id, project_id)] = {"token": token, "name": name[:255]}
    _save_bindings(bindings)


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


async def mirror_write(tenant_id: str, project_id: uuid.UUID, *, path: str, content: str) -> None:
    binding = get_binding(tenant_id, project_id)
    if not binding:
        return
    try:
        await invoke_native_workspace("write", {"token": binding["token"], "path": path, "content": content})
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The local file could not be saved") from exc


async def mirror_trash(tenant_id: str, project_id: uuid.UUID, *, path: str) -> None:
    binding = get_binding(tenant_id, project_id)
    if not binding:
        return
    try:
        await invoke_native_workspace("trash", {"token": binding["token"], "path": path})
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
