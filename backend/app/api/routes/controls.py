"""Read-only control catalog and CISA Zero Trust posture summaries."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.control import Control
from app.core.zero_trust import PILLAR_LABELS

router = APIRouter(prefix="/controls", tags=["CoreOS — Controls"])


@router.get("")
async def list_controls(
    pillar: str | None = Query(None),
    source: str | None = Query(None),
    claw: str | None = Query(None),
    limit: int = Query(500, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
):
    statement = select(Control).order_by(desc(Control.updated_at)).limit(limit)
    if pillar:
        statement = statement.where(Control.zt_pillar == pillar)
    if source:
        statement = statement.where(Control.source == source)
    if claw:
        statement = statement.where(Control.claw == claw)
    result = await db.execute(statement)
    rows = result.scalars().all()
    return [
        {
            "id": str(row.id),
            "control_id": row.control_id,
            "source": row.source,
            "source_version": row.source_version,
            "title": row.title,
            "description": row.description,
            "zt_pillar": row.zt_pillar,
            "zt_pillar_label": PILLAR_LABELS.get(row.zt_pillar, row.zt_pillar),
            "claw": row.claw,
            "provider": row.provider,
            "frameworks": row.frameworks,
            "severity": row.severity,
            "automated": row.automated,
            "status": row.status,
            "remediation_action": row.remediation_action,
            "reference_url": row.reference_url,
        }
        for row in rows
    ]


@router.get("/summary")
async def controls_summary(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Control))
    rows = result.scalars().all()
    pillars = Counter(row.zt_pillar for row in rows)
    sources = Counter(row.source for row in rows)
    nodes = Counter(row.claw for row in rows if row.claw)
    return {
        "total": len(rows),
        "automated": sum(1 for row in rows if row.automated),
        "active": sum(1 for row in rows if row.status == "active"),
        "pending_review": sum(1 for row in rows if row.status == "pending_review"),
        "by_pillar": [
            {
                "pillar": pillar,
                "label": PILLAR_LABELS.get(pillar, pillar),
                "controls": pillars.get(pillar, 0),
            }
            for pillar in PILLAR_LABELS
        ],
        "by_source": dict(sources),
        "by_node": dict(nodes),
    }
