"""API Routes."""
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from pydantic import BaseModel, ConfigDict, Field
from uuid import UUID
from typing import Optional

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.tenancy import caller_tenant
from app.models.identity import Identity, IdentityType, IdentityStatus
from app.schemas.identity import IdentityCreate, IdentityRead, IdentityUpdate
from app.claws.identityclaw.models import IdentityRiskEvent, PrivilegedAction, IdentityRiskLevel
from app.services.risk_scoring import calculate_event_risk
from app.services.audit_service import log_action
from app.services.secrets_manager import get_credential
from app.models.connector import Connector, ConnectorStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.claws.accessclaw.providers import entra as entra_adapter
from app.services.claw_scan import fetch_via_adapter, run_claw_scan

router = APIRouter(prefix="/identityclaw", tags=["Identity Security"])


def _scope(statement, model, user: dict):
    """Apply tenant visibility; unscoped admins retain legacy-row access."""
    tenant_id = caller_tenant(user)
    return statement.where(model.tenant_id == tenant_id) if tenant_id is not None else statement


# ── Schemas ────────────────────────────────────────────────────────────────────

class RiskEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    timestamp: datetime
    identity_id: str
    identity_name: Optional[str]
    identity_type: Optional[str]
    risk_type: str
    risk_level: IdentityRiskLevel
    risk_score: float
    description: Optional[str]
    is_resolved: bool


class PrivilegedActionCreate(BaseModel):
    requestor_id: str
    requestor_name: Optional[str] = None
    action: str
    target_identity_id: Optional[str] = None
    justification: Optional[str] = None


class PrivilegedActionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: UUID
    timestamp: datetime
    requestor_id: str
    requestor_name: Optional[str]
    action: str
    target_identity_id: Optional[str]
    justification: Optional[str]
    status: str
    reviewed_by: Optional[str]
    reviewed_at: Optional[datetime]


class IdentityClawStats(BaseModel):
    total_identities: int
    human_identities: int
    non_human_identities: int
    orphaned_identities: int
    high_risk_identities: int
    pending_approvals: int


class IdentityTaskRequest(BaseModel):
    swarm_job_id: Optional[str] = None
    task_type: str = "investigate_identity_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: Optional[str] = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


IDENTITY_PROVIDER_CONFIG = [
    {
        "provider": "entra_id",
        "connector_type": "entra_id",
        "label": "Microsoft Entra ID",
        "adapter": entra_adapter,
    },
]
# Shared name used by health/coverage tooling. The original constant stays for
# compatibility with the focused identity task implementation below.
PROVIDER_MAP = IDENTITY_PROVIDER_CONFIG

_SCAN_DEMO_FINDINGS = [
    {
        "provider": "identity_inventory",
        "title": "Identity posture baseline pending a live directory scan",
        "description": "Connect Microsoft Entra ID to replace this labelled demonstration baseline with tenant findings.",
        "category": "identity",
        "severity": "medium",
        "resource_id": "identity-posture-baseline",
        "resource_type": "identity_directory",
        "resource_name": "Identity Security",
        "external_id": "IDENTITY-POSTURE-BASELINE",
        "remediation": "Connect a directory provider and rerun the Identity Security scan.",
    }
]


async def _get_identity_provider_credentials(
    db: AsyncSession, connector_type: str, *, tenant_id: str | None = None
) -> Optional[dict]:
    statement = select(Connector).where(
        Connector.connector_type == connector_type,
        Connector.status == ConnectorStatus.APPROVED,
    )
    if tenant_id is not None:
        statement = statement.where(Connector.tenant_id == tenant_id)
    result = await db.execute(statement)
    connector = result.scalar_one_or_none()
    if not connector:
        return None
    return get_credential(str(connector.id), tenant_id=connector.tenant_id)


# ── Routes ─────────────────────────────────────────────────────────────────────

@router.get("/identities", response_model=list[IdentityRead], summary="Identity inventory")
async def list_identities(
    identity_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    stmt = _scope(select(Identity), Identity, user)
    if identity_type:
        stmt = stmt.where(Identity.type == IdentityType(identity_type))
    if status:
        stmt = stmt.where(Identity.status == IdentityStatus(status))
    result = await db.execute(stmt.order_by(desc(Identity.risk_score)).limit(limit))
    return result.scalars().all()


@router.post("/identities", response_model=IdentityRead, summary="Register identity")
async def register_identity(
    payload: IdentityCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    identity = Identity(**payload.model_dump(), tenant_id=caller_tenant(user))
    db.add(identity)
    await log_action(
        db=db, actor="system", actor_type="system",
        action="register_identity", outcome="allowed",
        resource_type="identity", resource_name=payload.name,
        module="identityclaw",
        tenant_id=caller_tenant(user),
    )
    await db.commit()
    await db.refresh(identity)
    return identity


@router.get("/identities/{identity_id}", response_model=IdentityRead, summary="Get identity detail")
async def get_identity(
    identity_id: str, db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)
):
    stmt = _scope(select(Identity).where(Identity.id == UUID(identity_id)), Identity, user)
    result = await db.execute(stmt)
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    return identity


@router.patch("/identities/{identity_id}", response_model=IdentityRead, summary="Update identity")
async def update_identity(
    identity_id: str,
    payload: IdentityUpdate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    stmt = _scope(select(Identity).where(Identity.id == UUID(identity_id)), Identity, user)
    result = await db.execute(stmt)
    identity = result.scalar_one_or_none()
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    for field, value in payload.model_dump(exclude_none=True).items():
        setattr(identity, field, value)
    await db.commit()
    await db.refresh(identity)
    return identity


@router.get("/orphaned", response_model=list[IdentityRead], summary="Orphaned identities")
async def get_orphaned_identities(
    db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)
):
    """Identities with no owner that are agents/connectors — high risk."""
    stmt = (
        select(Identity)
        .where(Identity.owner_id.is_(None))
        .where(Identity.type.in_([IdentityType.AGENT, IdentityType.CONNECTOR, IdentityType.SERVICE]))
        .where(Identity.status == IdentityStatus.ACTIVE)
    )
    result = await db.execute(_scope(stmt, Identity, user))
    return result.scalars().all()


@router.get("/risk-events", response_model=list[RiskEventRead], summary="Identity risk events")
async def list_risk_events(
    limit: int = 50,
    unresolved_only: bool = False,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    stmt = _scope(select(IdentityRiskEvent), IdentityRiskEvent, user)
    if unresolved_only:
        stmt = stmt.where(IdentityRiskEvent.is_resolved == False)
    result = await db.execute(stmt.order_by(desc(IdentityRiskEvent.timestamp)).limit(limit))
    return result.scalars().all()


@router.post("/approvals", response_model=PrivilegedActionRead, summary="Request privileged action approval")
async def request_approval(
    payload: PrivilegedActionCreate,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    action = PrivilegedAction(**payload.model_dump(), tenant_id=caller_tenant(user))
    db.add(action)
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/approvals", response_model=list[PrivilegedActionRead], summary="List approval requests")
async def list_approvals(
    status: Optional[str] = "pending",
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    stmt = _scope(select(PrivilegedAction).where(PrivilegedAction.status == status), PrivilegedAction, user)
    stmt = stmt.order_by(desc(PrivilegedAction.timestamp))
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/approvals/{action_id}/review", response_model=PrivilegedActionRead, summary="Approve or deny")
async def review_approval(
    action_id: str,
    decision: str,      # "approved" or "denied"
    reviewed_by: str,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    stmt = _scope(select(PrivilegedAction).where(PrivilegedAction.id == UUID(action_id)), PrivilegedAction, user)
    result = await db.execute(stmt)
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Approval request not found")
    action.status = decision
    action.reviewed_by = reviewed_by
    action.reviewed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(action)
    return action


@router.get("/stats", response_model=IdentityClawStats, summary="Identity Security summary")
async def get_stats(
    db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)
):
    total = await db.execute(_scope(select(func.count(Identity.id)), Identity, user))
    humans = await db.execute(_scope(select(func.count(Identity.id)).where(Identity.type == IdentityType.HUMAN), Identity, user))
    non_humans = await db.execute(_scope(
        select(func.count(Identity.id)).where(
            Identity.type.in_([IdentityType.AGENT, IdentityType.CONNECTOR, IdentityType.SERVICE, IdentityType.MODULE])
        ), Identity, user
    ))
    orphaned = await db.execute(_scope(
        select(func.count(Identity.id))
        .where(Identity.owner_id.is_(None))
        .where(Identity.type != IdentityType.HUMAN), Identity, user
    ))
    high_risk = await db.execute(_scope(select(func.count(Identity.id)).where(Identity.risk_score >= 50), Identity, user))
    pending = await db.execute(_scope(select(func.count(PrivilegedAction.id)).where(PrivilegedAction.status == "pending"), PrivilegedAction, user))

    return IdentityClawStats(
        total_identities=total.scalar() or 0,
        human_identities=humans.scalar() or 0,
        non_human_identities=non_humans.scalar() or 0,
        orphaned_identities=orphaned.scalar() or 0,
        high_risk_identities=high_risk.scalar() or 0,
        pending_approvals=pending.scalar() or 0,
    )


@router.get("/findings", summary="Identity Security findings compatibility endpoint")
async def get_identity_findings(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    """
    Findings for this Capability Node.

    A connector scan writes to the shared ``Finding`` table, but this endpoint
    only ever read the identity registry -- so a scan could create findings and
    this node would still report none, which made a working Entra connector
    look broken. Connector findings are authoritative here; registry risk is
    then appended so directory signal that never becomes a Finding row is still
    visible on the same screen.
    """
    findings: list[dict] = []

    scanned_statement = _scope(
        select(Finding)
        .where(Finding.claw == "identityclaw")
        .order_by(desc(Finding.risk_score), desc(Finding.created_at))
        , Finding, user
    ).limit(limit)
    scanned = await db.execute(scanned_statement)
    for f in scanned.scalars().all():
        findings.append({
            "id": str(f.id),
            "claw": "identityclaw",
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "title": f.title,
            "description": f.description,
            "resource": f.resource_name or f.resource_id,
            "provider": f.provider,
            "status": f.status.value if hasattr(f.status, "value") else str(f.status),
            "risk_score": float(f.risk_score or 0.0),
            "remediation": f.remediation,
            "data_origin": f.data_origin,
            "timestamp": f.created_at.isoformat() if f.created_at else None,
        })

    if len(findings) >= limit:
        return findings

    risk_events = await db.execute(_scope(
        select(IdentityRiskEvent)
        .order_by(desc(IdentityRiskEvent.timestamp))
        , IdentityRiskEvent, user
    ).limit(limit - len(findings)))
    for e in risk_events.scalars().all():
        findings.append({
            "id": str(e.id),
            "claw": "identityclaw",
            "severity": e.risk_level.value if hasattr(e.risk_level, "value") else str(e.risk_level),
            "title": e.risk_type,
            "resource": e.identity_name or e.identity_id,
            "status": "resolved" if e.is_resolved else "open",
            "risk_score": float(e.risk_score or 0.0),
            "data_origin": "registry",
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
        })

    if not findings:
        identities = await db.execute(_scope(
            select(Identity), Identity, user
        ).order_by(desc(Identity.risk_score)).limit(limit))
        for i in identities.scalars().all():
            sev = "high" if (i.risk_score or 0) >= 70 else "medium" if (i.risk_score or 0) >= 40 else "low"
            findings.append({
                "id": str(i.id),
                "claw": "identityclaw",
                "severity": sev,
                "title": f"Identity risk: {i.name}",
                "resource": i.name,
                "status": "open" if i.status == IdentityStatus.ACTIVE else "resolved",
                "risk_score": float(i.risk_score or 0.0),
                "data_origin": "registry",
                "timestamp": i.updated_at.isoformat() if i.updated_at else None,
            })

    return findings


@router.post("/scan", summary="Run an Identity Security connector scan")
async def run_identity_scan(db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)):
    """Run configured directory providers through the shared live-scan path."""
    return await run_claw_scan(
        db,
        claw="identityclaw",
        provider_config=IDENTITY_PROVIDER_CONFIG,
        demo_findings=_SCAN_DEMO_FINDINGS,
        tenant_id=caller_tenant(user),
    )


@router.get("/providers", summary="Identity Security provider connection status")
async def get_identity_providers(
    db: AsyncSession = Depends(get_db), user: dict = Depends(get_current_user)
):
    result = await db.execute(_scope(
        select(Connector).where(
            Connector.connector_type.in_(["okta", "entra_id", "cyberark"])
        ), Connector, user
    ))
    providers = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "provider": c.connector_type,
            "name": c.name,
            "status": c.status.value if hasattr(c.status, "value") else str(c.status),
            "trust_score": c.trust_score,
            "risk_level": c.risk_level.value if hasattr(c.risk_level, "value") else str(c.risk_level),
        }
        for c in providers
    ]


@router.post("/task", summary="Execute focused Identity Security swarm task")
async def run_identity_task(
    payload: IdentityTaskRequest,
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    started = datetime.utcnow()
    tenant_id = caller_tenant(user)
    connector_state = "unconfigured"
    finding_statement = (
        select(Finding)
        .where(Finding.claw == "identityclaw", Finding.data_origin == "live")
        .order_by(desc(Finding.risk_score))
        .limit(5)
    )
    if tenant_id is not None:
        finding_statement = finding_statement.where(Finding.tenant_id == tenant_id)
    top = (await db.execute(finding_statement)).scalars().all()
    live_rows = []
    live_risks = []
    live_providers = []
    connector_errors = []
    for cfg in IDENTITY_PROVIDER_CONFIG:
        creds = await _get_identity_provider_credentials(
            db, cfg["connector_type"], tenant_id=tenant_id
        )
        if not creds:
            continue
        connector_state = "configured"
        try:
            raw_findings = await fetch_via_adapter(cfg["adapter"], creds)
        except Exception as exc:
            connector_errors.append({"provider": cfg["provider"], "error": type(exc).__name__})
            continue
        for row in raw_findings[:3]:
            live_rows.append(
                {
                    "title": row.get("title") or f"{cfg['label']} identity finding",
                    "detail": (row.get("description") or "Connector-backed identity task finding")[:240],
                    "provider": cfg["provider"],
                }
            )
            live_risks.append(float(row.get("risk_score") or 0.0))
        live_providers.append(cfg["provider"])
        break
    high = [i for i in top if (i.risk_score or 0) >= 70]
    max_risk = max([float(i.risk_score or 0.0) for i in top], default=0.0)
    if live_risks:
        max_risk = max(max_risk, max(live_risks))
    confidence = 0.9 if high else 0.72
    if live_rows:
        confidence = 0.91
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

    findings = [
        {
            "title": f"High-risk identity: {i.resource_name or i.resource_id or i.title}",
            "detail": f"Identity finding risk {float(i.risk_score or 0.0)} with severity {i.severity.value if hasattr(i.severity, 'value') else i.severity}",
        }
        for i in high[:3]
    ]
    if not findings and (top or live_providers):
        findings = [{"title": "No high-risk identity found", "detail": "Top identities are below high-risk threshold."}]
    elif not findings:
        findings = []
    if live_rows:
        findings = live_rows

    return {
        "task_id": f"identity-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "identityclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": findings,
        "evidence": [],
        "recommended_actions": [
            "Review privileged assignments for top-risk identities",
            "Enforce step-up auth on high-risk identities",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["NIST AC-2", "ISO27001 A.5.16"],
        "execution_time_ms": elapsed_ms,
        "data_source": "live_connector" if live_providers else ("persisted_db" if top else "no_data_source"),
        "connector_state": connector_state,
        "providers_used": live_providers,
        "connector_errors": connector_errors,
        "execution_outcome": (
            "live_detection_completed" if live_providers
            else "persisted_evidence_analyzed" if top
            else "identity_connector_required"
        ),
    }
