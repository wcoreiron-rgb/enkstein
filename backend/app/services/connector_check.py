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
        connector_types = p.get("connector_types") or ([p.get("connector_type")] if p.get("connector_type") else [])
        configured = any([await is_connector_configured(db, ct) for ct in connector_types])
        output.append({
            "provider":   p["provider"],
            "label":      p["label"],
            "configured": configured,
        })
    return output
