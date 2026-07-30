"""Shared tenant-scoping helpers for platform (non-Cortex) routes.

The Cortex/Marcellus layer resolves tenancy through
``app.core.marcellus.runtime_security.resolve_tenant``, which requires the
caller to name the tenant it is acting on. The older platform routes
(audit, findings, connectors) have no such parameter and historically
returned every row to every authenticated caller.

These helpers apply the same claim semantics without changing those routes'
signatures: an identity carrying a tenant claim is confined to that tenant,
an admin identity without a claim keeps full visibility, and any other
identity is refused rather than silently shown everything.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, status

from app.core.marcellus.runtime_security import ADMIN_ROLES


#: Ownership marker used when an internal caller (for example a swarm task
#: whose job predates tenant scoping) has no resolvable tenant. It can never
#: match a real tenant identifier, so scoped queries return nothing instead of
#: falling back to unfiltered access.
NO_TENANT_SENTINEL = "__no_tenant__"


def caller_tenant(user: dict[str, Any]) -> str | None:
    """Return the caller's tenant claim, or ``None`` for an unscoped admin.

    Raises 403 for a non-admin identity that carries no tenant claim, so a
    missing claim can never be read as "allowed to see everything".
    """
    claimed = str(user.get("tenant_id") or user.get("tid") or "").strip()
    if claimed:
        return claimed
    if str(user.get("role", "")).lower() in ADMIN_ROLES:
        return None
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Tenant-bound identity required",
    )


def assert_tenant_visible(user: dict[str, Any], owner_tenant: str | None) -> None:
    """Raise 404 when ``owner_tenant`` is outside the caller's tenant.

    404 rather than 403 so a single-record lookup cannot be used to probe
    which identifiers exist in another tenant.
    """
    scope = caller_tenant(user)
    if scope is None:
        return
    if str(owner_tenant or "") != scope:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
