"""Read-only control catalog and CISA Zero Trust posture summaries."""
from __future__ import annotations

from collections import Counter

import hashlib
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.control import Control
from app.models.finding import Finding
from app.core.zero_trust import PILLAR_LABELS
from app.core.modelclaw.gateway import execute_cortex_gateway
from app.core.modelclaw.schemas import CortexGatewayRequest, CortexMessage
from app.trust_fabric import ActionRequest, enforce
from app.services.control_packs import bootstrap_baseline_controls
from app.services.oscal_sync import sync_nist_catalog
from app.core.swarm.orchestrator import create_swarm_job, run_swarm_job
from app.core.swarm.schemas import SwarmJobCreate

router = APIRouter(prefix="/controls", tags=["CoreOS — Controls"])


class ControlAnalysisRequest(BaseModel):
    classification: str = Field(default="internal", max_length=64)
    requested_by: str = Field(default="operator", max_length=128)
    control_id: str | None = Field(default=None, max_length=128)


@router.post("/bootstrap")
async def bootstrap_controls(db: AsyncSession = Depends(get_db)):
    """Install the reviewed Enkstein baseline pack for all 26 nodes."""
    return await bootstrap_baseline_controls(db)


@router.post("/sync/nist")
async def sync_nist(request: Request, db: AsyncSession = Depends(get_db)):
    """Import the public NIST SP 800-53 OSCAL catalog."""
    decision = await enforce(
        db,
        ActionRequest(
            module="coreos",
            actor_id="control-sync",
            actor_name="Control Sync",
            actor_type="automation",
            action="sync_control_catalog",
            target="nist_800_53",
            target_type="control_catalog",
            context={"source": "nist_800_53", "network_access": True},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)
    return await sync_nist_catalog(db)


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
            "remediation_mode": row.remediation_mode,
            "recommendation_only": row.recommendation_only,
            "evidence_method": row.evidence_method,
            "evaluator_key": row.evaluator_key,
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


@router.post("/analyze")
async def analyze_controls(
    body: ControlAnalysisRequest,
    db: AsyncSession = Depends(get_db),
):
    """Use Model Cortex to correlate control evidence across Security Arms."""
    statement = select(Finding).where(Finding.status == "open").order_by(desc(Finding.risk_score)).limit(40)
    if body.control_id:
        statement = statement.where(Finding.control_id == body.control_id)
    result = await db.execute(statement)
    findings = result.scalars().all()
    evidence = [
        {
            "id": str(item.id),
            "claw": item.claw,
            "provider": item.provider,
            "title": item.title,
            "severity": str(item.severity),
            "risk_score": item.risk_score,
            "control_id": item.control_id,
            "zt_pillar": item.zt_pillar,
            "data_origin": item.data_origin,
            "remediation": item.remediation,
        }
        for item in findings
    ]
    prompt = (
        "Analyze these security control findings for an operator. Separate facts from hypotheses, "
        "identify cross-node relationships, recommend the safest next steps, and never claim an action "
        "was executed. Return concise Markdown with evidence IDs.\n"
        + json.dumps(evidence, separators=(",", ":"))[:14000]
    )
    routed = await execute_cortex_gateway(
        db,
        CortexGatewayRequest(
            mode="security",
            messages=[CortexMessage(role="user", content=prompt)],
            source="profile:swarm_judge_profile",
            capability="control_analysis",
            data_classification=body.classification,
            context={"purpose": "cross_node_control_analysis", "control_id": body.control_id},
        ),
    )
    return {
        "control_id": body.control_id,
        "finding_count": len(evidence),
        "security_arms": sorted({item["claw"] for item in evidence}),
        "evidence": evidence,
        "analysis": routed.get("response"),
        "governance": routed.get("governance"),
        "ai_used": bool(routed.get("response")),
        "swarm_plan": {
            "orchestrator": "Model Cortex",
            "specialists": sorted({item["claw"] for item in evidence}),
            "requires_human_approval": True,
        },
    }


@router.post("/investigate/swarm")
async def investigate_controls_with_swarm(
    body: ControlAnalysisRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create a governed cross-Arm investigation for a control or its findings."""
    statement = select(Finding.claw).where(Finding.status == "open")
    if body.control_id:
        statement = statement.where(Finding.control_id == body.control_id)
    result = await db.execute(statement)
    participants = sorted({row[0] for row in result.all() if row[0]})
    participants = participants or ["identityclaw", "cloudclaw", "endpointclaw", "complianceclaw"]
    job = await create_swarm_job(
        db,
        SwarmJobCreate(
            name=f"Control investigation: {body.control_id or 'open findings'}",
            profile="DEEP_INVESTIGATION",
            requested_by=body.requested_by,
            trigger_type="control_investigation",
            classification=body.classification,
            participants=participants[:8],
            task_type="investigate_control",
            input={"control_id": body.control_id, "requested_by": body.requested_by},
            parallelism=min(8, max(1, len(participants))),
            model_profile="swarm_judge_profile",
        ),
    )
    background_tasks.add_task(run_swarm_job, job.id)
    return {"job_id": str(job.id), "participants": participants[:8], "status": "queued"}


@router.get("/{control_id:path}/verification")
async def verify_control(control_id: str, db: AsyncSession = Depends(get_db)):
    """Return PASS, FAIL, or UNKNOWN from the latest observed evidence."""
    result = await db.execute(
        select(Finding).where(Finding.control_id == control_id).order_by(desc(Finding.last_seen)).limit(100)
    )
    findings = result.scalars().all()
    if any((f.status.value if hasattr(f.status, "value") else f.status) == "open" for f in findings):
        status = "fail"
    elif findings:
        status = "pass"
    else:
        status = "unknown"
    return {
        "control_id": control_id,
        "status": status,
        "evidence_count": len(findings),
        "verified_at": datetime.utcnow().isoformat(),
        "note": "PASS requires a fresh successful evaluator result; absence of evidence is UNKNOWN.",
    }


@router.post("/evidence/export")
async def export_control_evidence(
    body: ControlAnalysisRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Export control definitions and evidence with Trust Fabric and hash chain."""
    decision = await enforce(
        db,
        ActionRequest(
            module="coreos",
            actor_id=body.requested_by,
            actor_name=body.requested_by,
            actor_type="human",
            action="export_control_evidence",
            target="control_evidence_bundle",
            target_type="evidence_export",
            context={"classification": body.classification},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not decision.allowed:
        raise HTTPException(status_code=403, detail=decision.reason)
    controls = await list_controls(db=db, limit=2000)
    evidence = await analyze_controls(body, db)
    bundle = {
        "bundle_id": f"control-evidence-{uuid.uuid4()}",
        "generated_at": datetime.utcnow().isoformat(),
        "requested_by": body.requested_by,
        "classification": body.classification,
        "controls": controls,
        "evidence_analysis": evidence,
        "policy_decision": {"outcome": decision.outcome.value, "policy_name": decision.policy_name},
    }
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
    bundle["chain_of_custody"] = {
        "hash_algorithm": "sha256",
        "bundle_hash": hashlib.sha256(canonical.encode()).hexdigest(),
    }
    return bundle
