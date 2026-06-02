"""
RegentClaw — Universal Findings Routes
Aggregated view across all Claws. Filter by claw, provider, severity, status.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from uuid import UUID
from typing import Optional

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.schemas.finding import FindingCreate, FindingRead, FindingUpdate

router = APIRouter(prefix="/findings", tags=["Findings — Universal"])


def _parse_severity(value: str) -> FindingSeverity:
    try:
        return FindingSeverity(value)
    except ValueError:
        allowed = ", ".join(s.value for s in FindingSeverity)
        raise HTTPException(status_code=400, detail=f"Invalid severity. Allowed values: {allowed}")


def _parse_status(value: str) -> FindingStatus:
    try:
        return FindingStatus(value)
    except ValueError:
        allowed = ", ".join(s.value for s in FindingStatus)
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed values: {allowed}")


@router.get("", response_model=list[FindingRead])
async def list_findings(
    claw: Optional[str] = Query(None, description="Filter by claw name (e.g. cloudclaw)"),
    provider: Optional[str] = Query(None, description="Filter by provider (e.g. aws, azure)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    search: Optional[str] = Query(None, description="Search in title"),
    sort: str = Query("risk", pattern="^(risk|recent|last_seen)$", description="Sort by risk, recent creation, or last_seen"),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    """List all findings with optional filters."""
    stmt = select(Finding)

    if claw:
        stmt = stmt.where(Finding.claw == claw)
    if provider:
        stmt = stmt.where(Finding.provider == provider)
    if severity:
        stmt = stmt.where(Finding.severity == _parse_severity(severity))
    if status:
        stmt = stmt.where(Finding.status == _parse_status(status))
    if search:
        stmt = stmt.where(Finding.title.ilike(f"%{search}%"))

    if sort == "recent":
        stmt = stmt.order_by(desc(Finding.created_at), desc(Finding.risk_score))
    elif sort == "last_seen":
        stmt = stmt.order_by(desc(Finding.last_seen), desc(Finding.created_at), desc(Finding.risk_score))
    else:
        stmt = stmt.order_by(desc(Finding.risk_score), desc(Finding.created_at))

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/stats")
async def get_findings_stats(db: AsyncSession = Depends(get_db)):
    """
    Aggregate finding counts grouped by claw and severity.
    Returns: {by_claw: {cloudclaw: {critical: 5, high: 12, ...}}, totals: {...}, open_count: N, critical_count: N}
    """
    # Query all findings grouped by claw + severity
    stmt = select(Finding.claw, Finding.severity, func.count(Finding.id)).group_by(
        Finding.claw, Finding.severity
    )
    result = await db.execute(stmt)
    rows = result.all()

    by_claw: dict = {}
    totals: dict = {s.value: 0 for s in FindingSeverity}

    for claw_name, severity, count in rows:
        if claw_name not in by_claw:
            by_claw[claw_name] = {s.value: 0 for s in FindingSeverity}
        by_claw[claw_name][severity] = count
        totals[severity] = totals.get(severity, 0) + count

    # Open count
    open_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.status == FindingStatus.OPEN)
    )
    open_count = open_result.scalar() or 0

    # Critical count
    critical_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.severity == FindingSeverity.CRITICAL)
    )
    critical_count = critical_result.scalar() or 0

    return {
        "by_claw": by_claw,
        "totals": totals,
        "open_count": open_count,
        "critical_count": critical_count,
    }


@router.post("", response_model=FindingRead, status_code=201)
async def create_finding(payload: FindingCreate, db: AsyncSession = Depends(get_db)):
    """Create a new finding. Used by provider adapters."""
    finding = Finding(**payload.model_dump())
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/{finding_id}", response_model=FindingRead)
async def update_finding(
    finding_id: str,
    payload: FindingUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update finding status or remediation_effort."""
    try:
        parsed_id = UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding id")

    result = await db.execute(select(Finding).where(Finding.id == parsed_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(finding, field, value)

    await db.commit()
    await db.refresh(finding)
    return finding
