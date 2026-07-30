"""
CoreOS — Audit Service
Every action is logged with full context, actor, decision, and policy applied.
"""
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from app.models.audit import AuditLog


async def log_action(
    db: AsyncSession,
    actor: str,
    actor_type: str,
    action: str,
    outcome: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_name: Optional[str] = None,
    policy_applied: Optional[str] = None,
    reason: Optional[str] = None,
    module: Optional[str] = None,
    ip_address: Optional[str] = None,
    detail_json: Optional[str] = None,
    compliance_relevant: bool = False,
    frameworks: Optional[list[str]] = None,
    tenant_id: Optional[str] = None,
) -> AuditLog:
    """Create a permanent audit log entry."""
    entry = AuditLog(
        timestamp=datetime.utcnow(),
        tenant_id=tenant_id,
        actor=actor,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_name=resource_name,
        outcome=outcome,
        policy_applied=policy_applied,
        reason=reason,
        module=module,
        ip_address=ip_address,
        detail_json=detail_json,
        compliance_relevant=compliance_relevant,
        frameworks=",".join(frameworks) if frameworks else None,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry
