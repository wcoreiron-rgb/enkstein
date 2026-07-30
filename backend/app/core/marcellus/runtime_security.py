from __future__ import annotations

import json
import re
from typing import Any

from fastapi import HTTPException, status


_TENANT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SENSITIVE_KEYS = (
    "password",
    "secret",
    "token",
    "private_key",
    "credential",
    "api_key",
    "access_key",
)
_ADMIN_ROLES = {"admin", "security_admin", "super_admin"}
_OPERATOR_ROLES = _ADMIN_ROLES | {"operator", "security_operator"}

# Public alias: platform-side tenancy helpers (app.core.tenancy) apply the same
# admin-role semantics and should not reach into a private name to do it.
ADMIN_ROLES = _ADMIN_ROLES


def resolve_tenant(user: dict[str, Any], requested_tenant: str) -> str:
    if not _TENANT_PATTERN.fullmatch(requested_tenant):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid tenant identifier")

    claimed = str(user.get("tenant_id") or user.get("tid") or "").strip()
    if claimed and claimed != requested_tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant access denied")
    if not claimed and str(user.get("role", "")).lower() not in _ADMIN_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant-bound identity required")
    return claimed or requested_tenant


def actor_id(user: dict[str, Any]) -> str:
    return str(user.get("sub") or user.get("id") or "unknown")[:255]


def actor_name(user: dict[str, Any]) -> str:
    return str(user.get("email") or user.get("sub") or user.get("id") or "unknown")[:255]


def require_approver(user: dict[str, Any], requester: str) -> str:
    approver = actor_id(user)
    if str(user.get("role", "")).lower() not in _ADMIN_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Security administrator approval required")
    if approver == requester:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Self-approval is not permitted")
    return approver


def require_node_or_admin(user: dict[str, Any], node_id: str) -> None:
    role = str(user.get("role", "")).lower()
    if role in _ADMIN_ROLES:
        return
    claimed_node = str(user.get("node_id") or user.get("agent_id") or "")
    if claimed_node != node_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Capability Node identity required")


def require_message_participant_or_admin(
    user: dict[str, Any],
    sender_node_id: str,
    recipient_node_id: str,
) -> None:
    role = str(user.get("role", "")).lower()
    if role in _ADMIN_ROLES:
        return
    claimed_node = str(user.get("node_id") or user.get("agent_id") or "")
    if claimed_node not in {sender_node_id, recipient_node_id}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Plexus participant identity required")


def require_runtime_operator(user: dict[str, Any]) -> None:
    role = str(user.get("role", "")).lower()
    claimed_node = str(user.get("node_id") or user.get("agent_id") or "")
    if role not in _OPERATOR_ROLES and not claimed_node:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Runtime operator or Capability Node required")


def ensure_json_size(value: Any, maximum_bytes: int, label: str) -> None:
    try:
        size = len(json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{label} must be JSON serializable") from exc
    if size > maximum_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"{label} exceeds {maximum_bytes} bytes",
        )


def sensitive_paths(value: Any, prefix: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            normalized = str(key).lower().replace("-", "_")
            if any(marker in normalized for marker in _SENSITIVE_KEYS):
                found.append(path)
            found.extend(sensitive_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(sensitive_paths(child, f"{prefix}[{index}]"))
    return found
