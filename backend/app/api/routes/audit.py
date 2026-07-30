"""CoreOS — Audit Log routes."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel, ConfigDict
from uuid import UUID
from datetime import datetime
from typing import Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import caller_tenant
from app.models.audit import AuditLog

router = APIRouter(prefix="/audit", tags=["CoreOS — Audit"])


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    timestamp: datetime
    actor: str
    actor_type: str
    action: str
    resource_type: Optional[str]
    resource_name: Optional[str]
    outcome: str
    policy_applied: Optional[str]
    reason: Optional[str]
    module: Optional[str]
    compliance_relevant: bool
    frameworks: Optional[str]


@router.get("", response_model=list[AuditLogRead])
async def list_audit_logs(
    limit: int = 100,
    offset: int = 0,
    compliance_only: bool = False,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    stmt = select(AuditLog)
    # A tenant-bound caller sees only its own trail; an unscoped admin keeps
    # full visibility. Without this the whole platform audit log was readable
    # by any authenticated identity. Filters are applied before limit/offset
    # so pagination counts scoped rows, not the global table.
    scope = caller_tenant(user)
    if scope is not None:
        stmt = stmt.where(AuditLog.tenant_id == scope)
    if compliance_only:
        stmt = stmt.where(AuditLog.compliance_relevant == True)
    stmt = stmt.order_by(desc(AuditLog.timestamp)).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return result.scalars().all()
