"""
Runtime memory helpers for Swarm/Claw execution.

These helpers keep MemoryClaw integration conservative:
- expose only short, redacted context snippets to tasks
- block memory writes that look like secrets or prompt-injection payloads
- store high-risk swarm outcomes as incident memory for analyst review
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.memory import IncidentMemory, TenantMemory
from app.models.swarm import SwarmJob

_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|password|secret|token|private[_-]?key)\s*[:=]\s*[\w.\-]{8,}"
)
_POISON_RE = re.compile(
    r"(?i)(ignore\s+previous\s+instructions|system\s+prompt|developer\s+message|bypass\s+policy|disable\s+guardrails)"
)


def _redact(value: str | None, limit: int = 480) -> str:
    text = (value or "")[:limit]
    text = _SECRET_RE.sub(r"\1=[REDACTED]", text)
    return text


def _memory_text_is_safe(value: str | None) -> bool:
    text = value or ""
    return not (_SECRET_RE.search(text) or _POISON_RE.search(text))


async def build_swarm_memory_context(
    db: AsyncSession,
    task_input: dict[str, Any],
    claw: str,
) -> dict[str, Any]:
    identity = str(task_input.get("identity") or task_input.get("user_id") or "").lower()
    tenant = await db.get(TenantMemory, 1)

    stmt = (
        select(IncidentMemory)
        .where(IncidentMemory.status.in_(["open", "investigating", "contained", "false_positive"]))
        .order_by(desc(IncidentMemory.updated_at))
        .limit(10)
    )
    result = await db.execute(stmt)
    incidents = []
    for incident in result.scalars().all():
        haystack = " ".join(
            [
                incident.title or "",
                incident.description or "",
                incident.affected_users or "",
                incident.affected_assets or "",
            ]
        ).lower()
        if identity and identity not in haystack:
            continue
        if not _memory_text_is_safe(haystack):
            continue
        incidents.append(
            {
                "id": str(incident.id),
                "title": _redact(incident.title, 180),
                "severity": incident.severity,
                "status": incident.status,
                "source_claw": incident.source_claw,
                "false_positive": bool(incident.false_positive),
            }
        )
        if len(incidents) >= 3:
            break

    notes = _redact(tenant.analyst_notes if tenant else "", 360)
    return {
        "loaded": bool(notes or incidents),
        "claw": claw,
        "tenant_risk_level": tenant.overall_risk_level if tenant else "unknown",
        "tenant_risk_score": float(tenant.overall_risk_score or 0.0) if tenant else 0.0,
        "analyst_notes_excerpt": notes,
        "relevant_incidents": incidents,
    }


async def propose_swarm_memory_update(
    db: AsyncSession,
    job: SwarmJob,
    judged: dict[str, Any],
    aggregate: dict[str, Any],
) -> dict[str, Any]:
    severity = str(judged.get("overall_severity") or "low").lower()
    if severity not in {"high", "critical"}:
        return {"status": "skipped", "reason": "severity_below_memory_threshold"}

    summary = str(judged.get("executive_summary") or "")
    if not _memory_text_is_safe(summary):
        return {"status": "blocked", "reason": "memory_safety_scan_failed"}

    try:
        job_input = json.loads(job.input_json or "{}")
    except Exception:
        job_input = {}

    identity = job_input.get("identity") or job_input.get("user_id") or job_input.get("principal")
    affected_users = [identity] if identity else []
    top_findings = aggregate.get("top_findings") or aggregate.get("findings") or []
    affected_assets = []
    for finding in top_findings[:5]:
        if isinstance(finding, dict):
            title = finding.get("title")
            if title:
                affected_assets.append(str(title)[:120])

    incident = IncidentMemory(
        title=f"Swarm review proposed: {job.name}"[:255],
        description=_redact(summary, 1200),
        severity=severity,
        status="investigating",
        source_claw="swarmclaw",
        affected_users=json.dumps(affected_users),
        affected_assets=json.dumps(affected_assets),
        linked_runs=json.dumps([str(job.id)]),
        risk_score_at_open=float(judged.get("confidence") or 0.0) * 100,
        created_by="swarm_memory_runtime",
        timeline_json=json.dumps(
            [
                {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "actor": "swarmclaw",
                    "action": "Proposed memory update",
                    "detail": _redact(summary, 500),
                    "type": "memory_proposal",
                }
            ]
        ),
        timeline_count=1,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return {"status": "created", "incident_id": str(incident.id), "severity": severity}
