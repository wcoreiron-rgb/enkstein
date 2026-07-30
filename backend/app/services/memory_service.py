"""
Enkstein — Memory Service
Helpers for reading and writing structured memory:
  - Incident timeline management
  - Asset risk history updates
  - Tenant memory refresh
  - Risk trend snapshot capture
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Any
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.memory import (
    IncidentMemory, AssetMemory, TenantMemory, RiskTrendSnapshot,
)

logger = logging.getLogger("regentclaw.memory")


# ─── Incident helpers ─────────────────────────────────────────────────────────

async def append_incident_timeline(
    db: AsyncSession,
    incident_id: str,
    actor: str,
    action: str,
    detail: str = "",
    event_type: str = "note",
) -> dict:
    """Append a timeline entry to an incident."""
    from uuid import UUID
    incident = await db.get(IncidentMemory, UUID(incident_id))
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    timeline = json.loads(incident.timeline_json or "[]")
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "actor": actor,
        "action": action,
        "detail": detail,
        "type": event_type,
    }
    timeline.append(entry)
    incident.timeline_json = json.dumps(timeline)
    incident.timeline_count = len(timeline)
    incident.updated_at = datetime.utcnow()
    await db.commit()
    return entry


async def close_incident(
    db: AsyncSession,
    incident_id: str,
    root_cause: str = "",
    closed_by: str = "system",
) -> IncidentMemory:
    from uuid import UUID
    incident = await db.get(IncidentMemory, UUID(incident_id))
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    now = datetime.utcnow()
    incident.status = "closed"
    incident.closed_at = now
    incident.root_cause = root_cause

    if incident.opened_at:
        delta = now - incident.opened_at.replace(tzinfo=None)
        incident.mttr_minutes = delta.total_seconds() / 60

    await append_incident_timeline(
        db, incident_id, closed_by, "Incident closed", root_cause, "closure"
    )
    await db.commit()
    return incident


# ─── Asset memory helpers ─────────────────────────────────────────────────────

async def upsert_asset_memory(
    db: AsyncSession,
    asset_id: str,
    asset_type: str,
    display_name: str | None = None,
    claw: str | None = None,
    risk_score: float | None = None,
    risk_level: str | None = None,
    risk_event: str | None = None,
    tenant_id: str | None = None,
    **kwargs,
) -> AssetMemory:
    """Create or update an asset's memory entry."""
    if not tenant_id:
        raise ValueError("Asset memory updates require tenant context")
    query = select(AssetMemory).where(AssetMemory.asset_id == asset_id)
    if tenant_id is not None:
        query = query.where(AssetMemory.tenant_id == tenant_id)
    result = await db.execute(query)
    asset = result.scalar_one_or_none()

    if asset is None:
        asset = AssetMemory(
            tenant_id=tenant_id,
            asset_id=asset_id,
            asset_type=asset_type,
            display_name=display_name,
            claw=claw,
        )
        db.add(asset)
    else:
        if display_name:
            asset.display_name = display_name
        if claw:
            asset.claw = claw

    if risk_score is not None:
        old_score = asset.risk_score
        asset.risk_score = risk_score
        if risk_level:
            asset.risk_level = risk_level

        # Append to risk history (keep last 90 entries)
        history = json.loads(asset.risk_history_json or "[]")
        history.append({
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "score": risk_score,
            "level": risk_level or asset.risk_level,
            "event": risk_event or f"score changed {old_score:.1f}→{risk_score:.1f}",
        })
        if len(history) > 90:
            history = history[-90:]
        asset.risk_history_json = json.dumps(history)

    # Apply any additional kwargs
    for k, v in kwargs.items():
        if hasattr(asset, k):
            setattr(asset, k, v)

    asset.last_seen_at = datetime.utcnow()
    asset.updated_at   = datetime.utcnow()
    await db.commit()
    return asset


# ─── Tenant memory helpers ────────────────────────────────────────────────────

async def get_or_create_tenant_memory(db: AsyncSession, tenant_id: str) -> TenantMemory:
    """Return this tenant's memory row, creating it on first use.

    Previously this was a single global row keyed on ``id=1``, so every tenant
    shared one posture summary.
    """
    tenant_id = str(tenant_id or "").strip()
    if not tenant_id:
        raise ValueError("Tenant memory requires tenant context")

    result = await db.execute(select(TenantMemory).where(TenantMemory.tenant_id == tenant_id))
    mem = result.scalar_one_or_none()
    if mem is None:
        mem = TenantMemory(tenant_id=tenant_id)
        db.add(mem)
        await db.commit()
        await db.refresh(mem)
    return mem


async def refresh_tenant_memory(db: AsyncSession, tenant_id: str) -> TenantMemory:
    """Recalculate this tenant's memory from its own rows only."""
    from app.models.finding import Finding

    mem = await get_or_create_tenant_memory(db, tenant_id)

    # Finding counts
    open_q = await db.execute(
        select(func.count()).where(
            Finding.status.in_(["open", "in_progress"]),
            Finding.tenant_id == tenant_id,
        )
    )
    mem.open_finding_count = open_q.scalar_one() or 0

    crit_q = await db.execute(
        select(func.count()).where(
            Finding.status.in_(["open", "in_progress"]),
            Finding.severity == "critical",
            Finding.tenant_id == tenant_id,
        )
    )
    mem.critical_finding_count = crit_q.scalar_one() or 0

    # Incident counts
    inc_q = await db.execute(
        select(func.count()).where(
            IncidentMemory.status.in_(["open", "investigating", "contained"]),
            IncidentMemory.tenant_id == tenant_id,
        )
    )
    mem.active_incident_count = inc_q.scalar_one() or 0

    # Derive overall risk level
    if mem.critical_finding_count > 0 or mem.active_incident_count > 3:
        mem.overall_risk_level = "critical"
        mem.overall_risk_score = min(100.0, mem.critical_finding_count * 10 + mem.active_incident_count * 5)
    elif mem.open_finding_count > 20:
        mem.overall_risk_level = "high"
        mem.overall_risk_score = min(80.0, mem.open_finding_count * 2)
    elif mem.open_finding_count > 5:
        mem.overall_risk_level = "medium"
        mem.overall_risk_score = min(50.0, mem.open_finding_count * 2)
    else:
        mem.overall_risk_level = "low"
        mem.overall_risk_score = max(0.0, mem.open_finding_count * 2)

    mem.updated_at = datetime.utcnow()
    mem.last_ingested_at = datetime.utcnow()
    await db.commit()
    return mem


# ─── Risk trend snapshots ─────────────────────────────────────────────────────

async def capture_risk_snapshot(
    db: AsyncSession, tenant_id: str, granularity: str = "hourly"
) -> RiskTrendSnapshot:
    """Capture this tenant's current state as a trend snapshot."""
    mem = await get_or_create_tenant_memory(db, tenant_id)
    from app.models.finding import Finding

    # Per-severity counts
    for sev in ("critical", "high", "medium", "low"):
        q = await db.execute(
            select(func.count()).where(
                Finding.status.in_(["open", "in_progress"]),
                Finding.severity == sev,
                Finding.tenant_id == tenant_id,
            )
        )

    snap = RiskTrendSnapshot(
        snapshot_at=datetime.utcnow(),
        tenant_id=tenant_id,
        granularity=granularity,
        overall_risk_score=mem.overall_risk_score,
        open_findings=mem.open_finding_count,
        critical_findings=mem.critical_finding_count,
        active_incidents=mem.active_incident_count,
    )
    db.add(snap)
    await db.commit()
    return snap


async def get_risk_trend(
    db: AsyncSession,
    tenant_id: str,
    granularity: str = "daily",
    days: int = 30,
) -> list[dict]:
    """Return this tenant's trend snapshots for charting."""
    since = datetime.utcnow() - timedelta(days=days)
    result = await db.execute(
        select(RiskTrendSnapshot)
        .where(
            RiskTrendSnapshot.granularity == granularity,
            RiskTrendSnapshot.snapshot_at >= since,
            RiskTrendSnapshot.tenant_id == tenant_id,
        )
        .order_by(RiskTrendSnapshot.snapshot_at)
    )
    snaps = result.scalars().all()
    return [
        {
            "date": s.snapshot_at.isoformat(),
            "risk_score": s.overall_risk_score,
            "open_findings": s.open_findings,
            "critical": s.critical_findings,
            "incidents": s.active_incidents,
        }
        for s in snaps
    ]


async def get_top_risky_assets(db: AsyncSession, limit: int = 10) -> list[AssetMemory]:
    result = await db.execute(
        select(AssetMemory)
        .order_by(desc(AssetMemory.risk_score))
        .limit(limit)
    )
    return result.scalars().all()
