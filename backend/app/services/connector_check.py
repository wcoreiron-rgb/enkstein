"""
Shared connector configuration checker.
All Claws use this to determine whether a real data source is connected
rather than hardcoding `configured: False`.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.connector import Connector
from app.services import secrets_manager


async def is_connector_configured(db: AsyncSession, connector_type: str) -> bool:
    """
    Return True if ANY connector of the given type exists in the DB
    AND has stored credentials (encrypted in the secrets manager).

    Uses scalars().all() instead of scalar_one_or_none() so that having
    both a seeded placeholder AND a user-added connector doesn't raise
    MultipleResultsFound.
    """
    try:
        result = await db.execute(
            select(Connector).where(Connector.connector_type == connector_type)
        )
        connectors = result.scalars().all()
        for connector in connectors:
            creds = secrets_manager.get_credential(str(connector.id))
            if creds:
                return True
        return False
    except Exception:
        return False


async def check_providers(
    db: AsyncSession,
    provider_map: list[dict],
) -> list[dict]:
    """
    Given a list of provider dicts with a 'connector_type' key,
    return the same list with 'configured' set to the real DB value.
    """
    output = []
    for p in provider_map:
        raw = p.get("connector_types") or p.get("connector_type") or []
        # A provider may name one connector type or several aliases; normalise
        # both shapes so a list value is not wrapped into a nested list.
        connector_types = raw if isinstance(raw, (list, tuple)) else [raw]
        configured = any([await is_connector_configured(db, ct) for ct in connector_types])
        # Whether this provider could return live tenant data if it were
        # configured. Surfacing it means an operator can tell a provider that
        # is merely unconfigured apart from one that cannot scan yet at all,
        # rather than configuring a credential and wondering why nothing
        # changed.
        state = _coverage(connector_types)
        output.append({
            "provider":   p["provider"],
            "label":      p["label"],
            "configured": configured,
            "coverage":   state,
            "live_capable": state in ("declarative", "native"),
        })
    return output


def _coverage(connector_types: list[str]) -> str:
    """Best coverage state across the connector types a provider may use."""
    # Imported here because the adapter registry imports provider modules that
    # transitively import this checker.
    from app.claws.adapters import registry

    best = "missing"
    ranking = {"missing": 0, "action_only": 1, "declarative": 2, "native": 3}
    for connector_type in connector_types:
        if not isinstance(connector_type, str):
            continue
        state = registry.coverage_state(connector_type)
        if ranking.get(state, 0) > ranking.get(best, 0):
            best = state
    return best
