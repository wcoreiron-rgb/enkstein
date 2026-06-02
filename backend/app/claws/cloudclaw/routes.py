"""
CloudClaw — Cloud Security Posture Management Routes
Supports AWS Security Hub, Azure Defender for Cloud, GCP Security Command Center.
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.connector import Connector
from app.schemas.finding import FindingRead
from app.services.secrets_manager import get_credential

from app.claws.cloudclaw.providers import aws as aws_adapter
from app.claws.cloudclaw.providers import azure as azure_adapter
from app.claws.cloudclaw.providers import gcp as gcp_adapter
from pydantic import BaseModel, Field

logger = logging.getLogger("cloudclaw")

router = APIRouter(prefix="/cloudclaw", tags=["CloudClaw — Cloud Security"])

CLAW_NAME = "cloudclaw"

# Maps connector_type values to provider labels
PROVIDER_CONFIG = [
    {
        "provider": "aws",
        "connector_type": "aws_security_hub",
        "connector_types": ["aws_security_hub", "aws_iam"],
        "label": "AWS Security Hub",
        "adapter": aws_adapter,
    },
    {
        "provider": "azure",
        "connector_type": "azure_defender",
        "label": "Azure Defender for Cloud",
        "adapter": azure_adapter,
    },
    {
        "provider": "gcp",
        "connector_type": "gcp_scc",
        "label": "GCP Security Command Center",
        "adapter": gcp_adapter,
    },
]


class CloudTaskRequest(BaseModel):
    swarm_job_id: Optional[str] = None
    task_type: str = "investigate_cloud_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: Optional[str] = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


# ─── Helper: look up connector + credentials ─────────────────────────────────

async def _get_provider_credentials(db: AsyncSession, connector_type: str | list[str]) -> Optional[dict]:
    """
    Check if a connector of the given type exists and has stored credentials.
    Returns the decrypted credential dict, or None if not configured.
    """
    connector_types = connector_type if isinstance(connector_type, list) else [connector_type]
    for ct in connector_types:
        result = await db.execute(
            select(Connector).where(Connector.connector_type == ct)
        )
        connectors = result.scalars().all()
        for connector in connectors:
            creds = get_credential(str(connector.id))
            if creds:
                return creds
    return None


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_cloudclaw_stats(db: AsyncSession = Depends(get_db)):
    """
    CloudClaw summary: finding counts by severity and provider, open/critical totals,
    and which cloud providers are connected.
    """
    # Base query: only cloudclaw findings
    base = select(Finding).where(Finding.claw == CLAW_NAME)

    # By severity
    sev_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .group_by(Finding.severity)
    )
    by_severity = {s.value: 0 for s in FindingSeverity}
    for sev, count in sev_result.all():
        by_severity[sev] = count

    # By provider
    prov_result = await db.execute(
        select(Finding.provider, func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .group_by(Finding.provider)
    )
    by_provider = {}
    for provider, count in prov_result.all():
        by_provider[provider] = count

    # Total findings
    total_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.claw == CLAW_NAME)
    )
    total_findings = total_result.scalar() or 0

    # Open count
    open_result = await db.execute(
        select(func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .where(Finding.status == FindingStatus.OPEN)
    )
    open_count = open_result.scalar() or 0

    # Critical count
    critical_result = await db.execute(
        select(func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .where(Finding.severity == FindingSeverity.CRITICAL)
    )
    critical_count = critical_result.scalar() or 0

    # Which providers appear in the findings
    providers_connected = list(by_provider.keys())

    return {
        "total_findings": total_findings,
        "by_severity": by_severity,
        "by_provider": by_provider,
        "open_count": open_count,
        "critical_count": critical_count,
        "providers_connected": providers_connected,
    }


@router.get("/findings", response_model=list[FindingRead])
async def get_cloudclaw_findings(
    severity: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List CloudClaw findings with optional filters."""
    stmt = (
        select(Finding)
        .where(Finding.claw == CLAW_NAME)
        .order_by(desc(Finding.risk_score), desc(Finding.created_at))
    )

    if severity:
        stmt = stmt.where(Finding.severity == FindingSeverity(severity))
    if provider:
        stmt = stmt.where(Finding.provider == provider)
    if status:
        stmt = stmt.where(Finding.status == FindingStatus(status))

    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/providers")
async def get_configured_providers(db: AsyncSession = Depends(get_db)):
    """
    Return which cloud providers are configured (have a registered connector + stored credentials).
    """
    output = []
    for cfg in PROVIDER_CONFIG:
        creds = await _get_provider_credentials(db, cfg.get("connector_types", cfg["connector_type"]))
        output.append({
            "provider": cfg["provider"],
            "label": cfg["label"],
            "configured": creds is not None,
        })
    return output


@router.post("/scan")
async def trigger_scan(db: AsyncSession = Depends(get_db)):
    """
    Trigger a cloud security scan across all configured providers.
    Uses the finding pipeline for deduplication, policy evaluation, and alert routing.
    """
    from app.services.finding_pipeline import ingest_findings

    provider_results = {}
    errors = []
    total_created = 0
    total_updated = 0

    for cfg in PROVIDER_CONFIG:
        provider_name = cfg["provider"]
        creds = await _get_provider_credentials(db, cfg.get("connector_types", cfg["connector_type"]))

        try:
            raw_findings = await cfg["adapter"].get_findings(credentials=creds)

            # Ensure each finding has the correct claw/provider fields
            for f in raw_findings:
                f.setdefault("claw", CLAW_NAME)
                f.setdefault("provider", provider_name)

            summary = await ingest_findings(db, CLAW_NAME, raw_findings)

            provider_results[provider_name] = {
                "status": "success",
                "created": summary["created"],
                "updated": summary["updated"],
                "critical": summary["critical"],
                "high": summary["high"],
                "simulated": creds is None,
            }
            total_created += summary["created"]
            total_updated += summary["updated"]

        except Exception:
            logger.error("CloudClaw scan failed for provider=%s", provider_name)
            errors.append({"provider": provider_name, "error": "provider scan failed"})
            provider_results[provider_name] = {"status": "error", "error": "provider scan failed"}

    status_msg = "completed" if not errors else "completed_with_errors"
    return {
        "status": status_msg,
        "findings_created": total_created,
        "findings_updated": total_updated,
        "providers": provider_results,
        "errors": errors,
        "message": (
            f"CloudClaw scan complete. {total_created} new findings, "
            f"{total_updated} updated across {len(PROVIDER_CONFIG)} providers."
        ),
    }


@router.post("/task", summary="Execute focused CloudClaw swarm task")
async def run_cloud_task(payload: CloudTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    stmt = (
        select(Finding)
        .where(Finding.claw == CLAW_NAME)
        .order_by(desc(Finding.risk_score), desc(Finding.created_at))
        .limit(5)
    )
    result = await db.execute(stmt)
    findings = result.scalars().all()
    live_rows = []
    live_risks = []
    connector_configured = False
    if not findings:
        for cfg in PROVIDER_CONFIG:
            creds = await _get_provider_credentials(db, cfg["connector_type"])
            if not creds:
                continue
            connector_configured = True
            try:
                raw_findings = await cfg["adapter"].get_findings(credentials=creds)
            except Exception:
                continue
            for row in raw_findings[:2]:
                live_rows.append(
                    {
                        "title": row.get("title") or f"{cfg['provider']} live finding",
                        "detail": (row.get("description") or "Connector-backed task finding")[:220],
                    }
                )
                live_risks.append(float(row.get("risk_score") or 0.0))
            if live_rows:
                break

    max_risk = max([float(f.risk_score or 0.0) for f in findings], default=0.0)
    if live_risks:
        max_risk = max(max_risk, max(live_risks))
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.9 if live_rows else (0.88 if findings else 0.7)
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

    persisted_rows = [
        {
            "title": f.title,
            "detail": f"{f.provider or 'cloud'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}",
        }
        for f in findings[:3]
    ]
    finding_rows = live_rows or persisted_rows or [{"title": "No cloud findings persisted yet", "detail": "Run /cloudclaw/scan or configure providers."}]
    data_source = "live_connector" if live_rows else ("persisted_db" if persisted_rows else "seeded_fallback")
    connector_state = "configured" if (connector_configured or bool(live_rows)) else "unconfigured"

    return {
        "task_id": f"cloud-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": "cloudclaw",
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": finding_rows,
        "evidence": [],
        "recommended_actions": [
            "Review public exposure and IAM misconfiguration findings",
            "Validate cloud provider guardrail baselines",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["CIS Cloud Controls", "NIST AC-6"],
        "execution_time_ms": elapsed_ms,
        "data_source": data_source,
        "connector_state": connector_state,
    }
