"""
Trust Fabric — Containment & Blast Radius Control
Isolate, suspend, revoke, or kill a module/connector when risk is detected.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.models.module import Module, ModuleStatus
from app.models.connector import Connector, ConnectorStatus
from app.models.identity import Identity, IdentityStatus
from app.services.audit_service import log_action


async def isolate_module(
    db: AsyncSession,
    module_name: str,
    reason: str,
    triggered_by: str,
    tenant_id: str | None = None,
) -> bool:
    """Set a module to QUARANTINED status and audit the action."""
    stmt = select(Module).where(Module.name == module_name)
    result = await db.execute(stmt)
    module = result.scalar_one_or_none()
    if not module:
        return False

    module.status = ModuleStatus.QUARANTINED
    await log_action(
        db=db,
        actor=triggered_by,
        actor_type="system",
        action="isolate_module",
        outcome="executed",
        resource_type="module",
        resource_id=str(module.id),
        resource_name=module_name,
        reason=reason,
        module="trust_fabric",
        compliance_relevant=True,
        tenant_id=tenant_id,
    )
    await db.commit()
    return True


async def suspend_identity(
    db: AsyncSession,
    identity_id: UUID,
    reason: str,
    triggered_by: str,
    tenant_id: str | None = None,
) -> bool:
    """Suspend an identity to prevent further actions."""
    stmt = select(Identity).where(Identity.id == identity_id)
    result = await db.execute(stmt)
    identity = result.scalar_one_or_none()
    if not identity:
        return False

    identity.status = IdentityStatus.SUSPENDED
    await log_action(
        db=db,
        actor=triggered_by,
        actor_type="system",
        action="suspend_identity",
        outcome="executed",
        resource_type="identity",
        resource_id=str(identity_id),
        resource_name=identity.name,
        reason=reason,
        module="trust_fabric",
        compliance_relevant=True,
        tenant_id=tenant_id,
    )
    await db.commit()
    return True


async def block_connector(
    db: AsyncSession,
    connector_id: UUID,
    reason: str,
    triggered_by: str,
    tenant_id: str | None = None,
) -> bool:
    """Block a connector from being used."""
    stmt = select(Connector).where(Connector.id == connector_id)
    result = await db.execute(stmt)
    connector = result.scalar_one_or_none()
    if not connector:
        return False

    connector.status = ConnectorStatus.BLOCKED
    await log_action(
        db=db,
        actor=triggered_by,
        actor_type="system",
        action="block_connector",
        outcome="executed",
        resource_type="connector",
        resource_id=str(connector_id),
        resource_name=connector.name,
        reason=reason,
        module="trust_fabric",
        compliance_relevant=True,
        # Containment inherits the connector's own tenant when the caller
        # did not name one, so the record is never globally scoped.
        tenant_id=tenant_id or connector.tenant_id,
    )
    await db.commit()
    return True
