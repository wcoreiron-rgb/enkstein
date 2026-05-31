"""
RegentClaw — Memory / State Layer API Routes
"""
import logging
import json
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.memory import IncidentMemory, AssetMemory, TenantMemory, RiskTrendSnapshot
from app.services.memory_service import (
    append_incident_timeline,
    close_incident,
    upsert_asset_memory,
    get_or_create_tenant_memory,
    refresh_tenant_memory,
    capture_risk_snapshot,
    get_risk_trend,
    get_top_risky_assets,
)

logger = logging.getLogger("regentclaw.memory_api")
router = APIRouter(prefix="/memory", tags=["Memory"])


# ─── Schemas ──────────────────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str | None = None
    severity: str = "medium"
    source_claw: str | None = None
    source_finding_id: str | None = None
    affected_assets: list[str] = []
    affected_users: list[str] = []
    mitre_tactics: str | None = None
    mitre_techniques: str | None = None
    assigned_to: str | None = None
    created_by: str | None = "system"


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    assigned_to: str | None = None
    root_cause: str | None = None
    remediation_notes: str | None = None
    mitre_tactics: str | None = None
    mitre_techniques: str | None = None


class TimelineEntryCreate(BaseModel):
    actor: str = "analyst"
    action: str
    detail: str = ""
    event_type: str = "note"


class IncidentCloseRequest(BaseModel):
    root_cause: str = ""
    closed_by: str = "analyst"


class AssetUpsert(BaseModel):
    asset_id: str
    asset_type: str = "unknown"
    display_name: str | None = None
    claw: str | None = None
    risk_score: float | None = None
    risk_level: str | None = None
    risk_event: str | None = None
    tags: str | None = None


# ─── Incidents ────────────────────────────────────────────────────────────────

@router.post("/incidents", summary="Create an incident")
async def create_incident(body: IncidentCreate, db: AsyncSession = Depends(get_db)):
    incident = IncidentMemory(
        title=body.title,
        description=body.description,
        severity=body.severity,
        source_claw=body.source_claw,
        source_finding_id=body.source_finding_id,
        affected_assets=json.dumps(body.affected_assets),
        affected_users=json.dumps(body.affected_users),
        mitre_tactics=body.mitre_tactics,
        mitre_techniques=body.mitre_techniques,
        assigned_to=body.assigned_to,
        created_by=body.created_by,
    )
    db.add(incident)
    await db.flush()

    await append_incident_timeline(
        db, str(incident.id),
        actor=body.created_by or "system",
        action="Incident opened",
        detail=body.description or "",
        event_type="opened",
    )
    await db.commit()
    return _incident_out(incident)


@router.get("/incidents", summary="List incidents")
async def list_incidents(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = select(IncidentMemory).order_by(desc(IncidentMemory.opened_at)).limit(limit)
    if status:
        q = q.where(IncidentMemory.status == status)
    if severity:
        q = q.where(IncidentMemory.severity == severity)
    result = await db.execute(q)
    return [_incident_out(i) for i in result.scalars().all()]


@router.get("/incidents/{incident_id}", summary="Get incident detail")
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    incident = await db.get(IncidentMemory, UUID(incident_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _incident_out(incident, full=True)


@router.patch("/incidents/{incident_id}", summary="Update incident")
async def update_incident(incident_id: str, body: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    from uuid import UUID
    incident = await db.get(IncidentMemory, UUID(incident_id))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    updates = {k: v for k, v in body.dict().items() if v is not None}
    for k, v in updates.items():
        setattr(incident, k, v)
    incident.updated_at = datetime.utcnow()
    await db.commit()
    return _incident_out(incident)


@router.post("/incidents/{incident_id}/timeline", summary="Append timeline entry")
async def add_timeline_entry(
    incident_id: str, body: TimelineEntryCreate, db: AsyncSession = Depends(get_db)
):
    try:
        entry = await append_incident_timeline(
            db, incident_id,
            actor=body.actor,
            action=body.action,
            detail=body.detail,
            event_type=body.event_type,
        )
        return entry
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")


@router.post("/incidents/{incident_id}/close", summary="Close an incident")
async def close_incident_endpoint(
    incident_id: str, body: IncidentCloseRequest, db: AsyncSession = Depends(get_db)
):
    try:
        incident = await close_incident(db, incident_id, body.root_cause, body.closed_by)
        return _incident_out(incident, full=True)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found")


# ─── Asset Memory ─────────────────────────────────────────────────────────────

@router.get("/assets", summary="List tracked assets by risk score")
async def list_assets(limit: int = Query(50, le=200), db: AsyncSession = Depends(get_db)):
    assets = await get_top_risky_assets(db, limit=limit)
    return [_asset_out(a) for a in assets]


@router.post("/assets", summary="Create or update an asset memory entry")
async def upsert_asset(body: AssetUpsert, db: AsyncSession = Depends(get_db)):
    asset = await upsert_asset_memory(
        db,
        asset_id=body.asset_id,
        asset_type=body.asset_type,
        display_name=body.display_name,
        claw=body.claw,
        risk_score=body.risk_score,
        risk_level=body.risk_level,
        risk_event=body.risk_event,
        tags=body.tags,
    )
    return _asset_out(asset, full=True)


@router.get("/assets/{asset_id}", summary="Get an asset's memory and risk history")
async def get_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AssetMemory).where(AssetMemory.asset_id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_out(asset, full=True)


# ─── Tenant Memory ────────────────────────────────────────────────────────────

@router.get("/tenant", summary="Get platform-wide threat context")
async def get_tenant_memory(db: AsyncSession = Depends(get_db)):
    mem = await get_or_create_tenant_memory(db)
    return _tenant_out(mem)


@router.post("/tenant/refresh", summary="Refresh tenant memory from current DB state")
async def refresh_tenant(db: AsyncSession = Depends(get_db)):
    mem = await refresh_tenant_memory(db)
    return _tenant_out(mem)


@router.patch("/tenant/notes", summary="Append analyst notes to tenant memory")
async def update_tenant_notes(notes: str, db: AsyncSession = Depends(get_db)):
    mem = await get_or_create_tenant_memory(db)
    existing = mem.analyst_notes or ""
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    mem.analyst_notes = existing + f"\n\n[{now_str}] {notes}".strip()
    mem.updated_at = datetime.utcnow()
    await db.commit()
    return _tenant_out(mem)


# ─── Risk Trends ──────────────────────────────────────────────────────────────

@router.get("/trends", summary="Get risk trend data for charts")
async def get_trends(
    granularity: str = Query("daily", regex="^(hourly|daily|weekly)$"),
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    data = await get_risk_trend(db, granularity=granularity, days=days)
    return {"granularity": granularity, "days": days, "count": len(data), "data": data}


@router.post("/trends/snapshot", summary="Capture a manual risk snapshot")
async def manual_snapshot(
    granularity: str = "daily",
    db: AsyncSession = Depends(get_db),
):
    snap = await capture_risk_snapshot(db, granularity=granularity)
    return {
        "id": str(snap.id),
        "snapshot_at": snap.snapshot_at.isoformat(),
        "overall_risk_score": snap.overall_risk_score,
        "open_findings": snap.open_findings,
    }


# ─── Summary endpoint ─────────────────────────────────────────────────────────

@router.get("/summary", summary="Memory layer health summary")
async def memory_summary(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    mem = await get_or_create_tenant_memory(db)

    inc_q = await db.execute(select(func.count()).select_from(IncidentMemory))
    asset_q = await db.execute(select(func.count()).select_from(AssetMemory))
    snap_q = await db.execute(select(func.count()).select_from(RiskTrendSnapshot))

    return {
        "tenant_risk_level": mem.overall_risk_level,
        "tenant_risk_score": mem.overall_risk_score,
        "active_incidents": mem.active_incident_count,
        "open_findings": mem.open_finding_count,
        "total_incidents_tracked": inc_q.scalar_one() or 0,
        "total_assets_tracked": asset_q.scalar_one() or 0,
        "total_snapshots": snap_q.scalar_one() or 0,
        "last_refreshed": mem.last_ingested_at.isoformat() if mem.last_ingested_at else None,
    }


# ─── Serialisation helpers ────────────────────────────────────────────────────

def _incident_out(i: IncidentMemory, full: bool = False) -> dict:
    base = {
        "id": str(i.id),
        "title": i.title,
        "severity": i.severity,
        "status": i.status,
        "source_claw": i.source_claw,
        "affected_assets_count": len(json.loads(i.affected_assets or "[]")),
        "timeline_count": i.timeline_count,
        "assigned_to": i.assigned_to,
        "opened_at": i.opened_at.isoformat() if i.opened_at else None,
        "closed_at": i.closed_at.isoformat() if i.closed_at else None,
        "mttr_minutes": i.mttr_minutes,
        "mitre_tactics": i.mitre_tactics,
        "mitre_techniques": i.mitre_techniques,
    }
    if full:
        base["description"]        = i.description
        base["affected_assets"]    = json.loads(i.affected_assets or "[]")
        base["affected_users"]     = json.loads(i.affected_users or "[]")
        base["timeline"]           = json.loads(i.timeline_json or "[]")
        base["linked_runs"]        = json.loads(i.linked_runs or "[]")
        base["root_cause"]         = i.root_cause
        base["remediation_notes"]  = i.remediation_notes
        base["risk_score_at_open"] = i.risk_score_at_open
    return base


def _asset_out(a: AssetMemory, full: bool = False) -> dict:
    base = {
        "id": str(a.id),
        "asset_id": a.asset_id,
        "asset_type": a.asset_type,
        "display_name": a.display_name,
        "claw": a.claw,
        "risk_score": a.risk_score,
        "risk_level": a.risk_level,
        "total_findings": a.total_findings,
        "open_findings": a.open_findings,
        "critical_findings": a.critical_findings,
        "incidents_involved": a.incidents_involved,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "tags": a.tags,
    }
    if full:
        base["risk_history"] = json.loads(a.risk_history_json or "[]")
        base["context_notes"] = a.context_notes
        base["first_seen_at"] = a.first_seen_at.isoformat() if a.first_seen_at else None
    return base


def _tenant_out(m: TenantMemory) -> dict:
    return {
        "overall_risk_level": m.overall_risk_level,
        "overall_risk_score": m.overall_risk_score,
        "active_incident_count": m.active_incident_count,
        "open_finding_count": m.open_finding_count,
        "critical_finding_count": m.critical_finding_count,
        "active_threats": json.loads(m.active_threats_json or "[]"),
        "high_risk_assets": json.loads(m.high_risk_assets_json or "[]"),
        "threat_context": json.loads(m.threat_context_json or "[]"),
        "analyst_notes": m.analyst_notes,
        "risk_delta_7d": m.risk_delta_7d,
        "risk_delta_30d": m.risk_delta_30d,
        "updated_at": m.updated_at.isoformat() if m.updated_at else None,
        "last_ingested_at": m.last_ingested_at.isoformat() if m.last_ingested_at else None,
    }
