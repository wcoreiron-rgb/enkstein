"""
Enkstein — Event Trigger Routes
CRUD for EventTrigger definitions + inbound webhook endpoint.

GET    /triggers           — list all triggers (filterable)
POST   /triggers           — create a trigger
GET    /triggers/{id}      — get single trigger
PATCH  /triggers/{id}      — update trigger
DELETE /triggers/{id}      — delete trigger
POST   /triggers/{id}/test — evaluate conditions against a sample payload without firing
POST   /triggers/webhook/{id} — inbound webhook (public — used by external systems)
"""
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import assert_tenant_visible, caller_tenant
from app.models.trigger import EventTrigger
from app.schemas.trigger import TriggerCreate, TriggerUpdate, TriggerRead
from app.services.trigger_engine import _matches_conditions, handle_webhook_trigger

router = APIRouter(prefix="/triggers", tags=["CoreOS — Event Triggers"])


async def _scoped_trigger(
    db: AsyncSession,
    trigger_id: UUID,
    user: dict,
) -> EventTrigger:
    """Load a trigger the caller owns, else 404."""
    result = await db.execute(select(EventTrigger).where(EventTrigger.id == trigger_id))
    trigger = result.scalar_one_or_none()
    if not trigger:
        raise HTTPException(status_code=404, detail="Trigger not found")
    assert_tenant_visible(user, trigger.tenant_id)
    return trigger


# ─── CRUD ─────────────────────────────────────────────────────────────────────

@router.get("", response_model=list[TriggerRead])
async def list_triggers(
    trigger_type: str | None = None,
    is_active: bool | None = None,
    category: str | None = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    scope = caller_tenant(user)
    stmt = select(EventTrigger).order_by(desc(EventTrigger.created_at)).limit(limit)
    if scope is not None:
        stmt = stmt.where(EventTrigger.tenant_id == scope)
    if trigger_type:
        stmt = stmt.where(EventTrigger.trigger_type == trigger_type)
    if is_active is not None:
        stmt = stmt.where(EventTrigger.is_active == is_active)
    if category:
        stmt = stmt.where(EventTrigger.category == category)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("", response_model=TriggerRead, status_code=201)
async def create_trigger(
    body: TriggerCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    # Ownership comes from the authenticated caller, not the request body.
    trigger = EventTrigger(**body.model_dump(), tenant_id=caller_tenant(user))
    db.add(trigger)
    await db.commit()
    await db.refresh(trigger)
    return trigger


@router.get("/{trigger_id}", response_model=TriggerRead)
async def get_trigger(
    trigger_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return await _scoped_trigger(db, trigger_id, user)


@router.patch("/{trigger_id}", response_model=TriggerRead)
async def update_trigger(
    trigger_id: UUID,
    body: TriggerUpdate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    trigger = await _scoped_trigger(db, trigger_id, user)

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(trigger, field, value)
    trigger.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(trigger)
    return trigger


@router.delete("/{trigger_id}", status_code=204)
async def delete_trigger(
    trigger_id: UUID,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    trigger = await _scoped_trigger(db, trigger_id, user)
    await db.delete(trigger)
    await db.commit()


# ─── Test a trigger without firing ───────────────────────────────────────────

@router.post("/{trigger_id}/test")
async def test_trigger(
    trigger_id: UUID,
    sample_payload: dict = Body(...),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Evaluate trigger conditions against a sample payload without actually firing it.
    Useful for verifying trigger logic before enabling it.
    """
    trigger = await _scoped_trigger(db, trigger_id, user)

    import json
    try:
        conditions = json.loads(trigger.conditions_json)
    except Exception:
        conditions = []

    matched = _matches_conditions(sample_payload, trigger.conditions_json)

    return {
        "trigger_id":    str(trigger_id),
        "trigger_name":  trigger.name,
        "conditions":    conditions,
        "payload":       sample_payload,
        "matched":       matched,
        "would_fire":    matched and trigger.is_active,
        "action_type":   trigger.action_type,
        "workflow_id":   str(trigger.workflow_id) if trigger.workflow_id else None,
    }


# ─── Inbound webhook endpoint ─────────────────────────────────────────────────

@router.post("/webhook/{trigger_id}")
async def inbound_webhook(
    trigger_id: str,
    payload: dict = Body(default={}),
    db: AsyncSession = Depends(get_db),
):
    """
    External webhook endpoint.
    POST JSON to this URL from any system (Sentinel, Defender, GitHub, etc.)
    to fire a trigger.

    Example:
        curl -X POST https://regentclaw.example.com/api/v1/triggers/webhook/<id> \
             -H 'Content-Type: application/json' \
             -d '{"severity": "high", "source": "microsoft_defender"}'
    """
    result = await handle_webhook_trigger(db, trigger_id, payload)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


# ─── Stats endpoint ───────────────────────────────────────────────────────────

@router.get("/stats/summary")
async def trigger_stats(
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """Summary counts by type and status."""
    from sqlalchemy import func
    scope = caller_tenant(user)
    stmt = select(
        EventTrigger.trigger_type,
        EventTrigger.is_active,
        func.count(EventTrigger.id).label("count"),
        func.sum(EventTrigger.trigger_count).label("total_fires"),
    )
    if scope is not None:
        stmt = stmt.where(EventTrigger.tenant_id == scope)
    result = await db.execute(stmt.group_by(EventTrigger.trigger_type, EventTrigger.is_active))
    rows = result.all()
    return [
        {
            "trigger_type": r.trigger_type,
            "is_active": r.is_active,
            "count": r.count,
            "total_fires": r.total_fires or 0,
        }
        for r in rows
    ]
