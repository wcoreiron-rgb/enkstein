"""
Enkstein — Finding Pipeline
Central upsert/dedup pipeline used by ALL 23 Claw adapters.

Usage:
    from app.services.finding_pipeline import ingest_findings

    summary = await ingest_findings(db, claw="cloudclaw", findings=[...])

Each item in `findings` is a plain dict with keys matching Finding columns.
The pipeline:
  1. Deduplicates by (claw + external_id) — updates last_seen on repeat
  2. Tracks first_seen vs last_seen for trend analysis
  3. Emits an Event record for every NEW finding (creation event)
  4. Emits an Event record when severity escalates on an existing finding
  5. Calls finding_policy_evaluator for critical/high findings
  6. Calls alert_router for findings above the alert threshold
  7. Returns a summary dict: {created, updated, skipped, critical, high}
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.control import Control, ControlStatus
from app.models.event import Event, EventSeverity, EventOutcome

logger = logging.getLogger("finding_pipeline")

# Severity ordering (higher index = more severe)
_SEV_RANK: dict[str, int] = {
    FindingSeverity.INFO:     0,
    FindingSeverity.LOW:      1,
    FindingSeverity.MEDIUM:   2,
    FindingSeverity.HIGH:     3,
    FindingSeverity.CRITICAL: 4,
}

_ALERT_THRESHOLD_RISK = 70.0   # route to alert_router above this risk score
_POLICY_SEVERITY_MIN  = FindingSeverity.HIGH   # evaluate policies for HIGH+


def _sev_from_str(raw: str) -> FindingSeverity:
    """Safely map string → FindingSeverity enum."""
    try:
        return FindingSeverity(raw.lower())
    except (ValueError, AttributeError):
        return FindingSeverity.MEDIUM


def _event_severity_from_finding(sev: FindingSeverity) -> EventSeverity:
    mapping = {
        FindingSeverity.CRITICAL: EventSeverity.CRITICAL,
        FindingSeverity.HIGH:     EventSeverity.HIGH,
        FindingSeverity.MEDIUM:   EventSeverity.MEDIUM,
        FindingSeverity.LOW:      EventSeverity.LOW,
        FindingSeverity.INFO:     EventSeverity.INFO,
    }
    return mapping.get(sev, EventSeverity.INFO)


_VALID_ORIGINS = {"live", "simulated", "unknown"}


def _normalize_origin(raw: Any) -> str:
    """Constrain adapter-declared origin to the known vocabulary.

    Defaults to "unknown" rather than "live": an adapter that forgets to
    declare its origin must never have its output presented to an operator as
    verified data from their own environment.
    """
    value = str(raw or "").strip().lower()
    return value if value in _VALID_ORIGINS else "unknown"


def _build_finding(claw: str, data: dict[str, Any]) -> Finding:
    """Construct a Finding ORM object from raw adapter dict."""
    severity = _sev_from_str(data.get("severity", "medium"))
    now = datetime.utcnow()
    return Finding(
        claw=claw,
        provider=data.get("provider", "unknown"),
        title=str(data.get("title", "Untitled Finding"))[:512],
        description=data.get("description"),
        category=data.get("category"),
        severity=severity,
        resource_id=data.get("resource_id"),
        resource_type=data.get("resource_type"),
        resource_name=data.get("resource_name"),
        region=data.get("region"),
        account_id=data.get("account_id"),
        cvss_score=data.get("cvss_score"),
        epss_score=data.get("epss_score"),
        risk_score=float(data.get("risk_score", 50.0)),
        actively_exploited=bool(data.get("actively_exploited", False)),
        status=FindingStatus.OPEN,
        remediation=data.get("remediation"),
        remediation_effort=data.get("remediation_effort"),
        external_id=data.get("external_id"),
        reference_url=data.get("reference_url"),
        raw_data=json.dumps(data.get("raw_data", {})) if isinstance(data.get("raw_data"), dict) else data.get("raw_data"),
        data_origin=_normalize_origin(data.get("data_origin")),
        source_connector=(str(data["source_connector"])[:64] if data.get("source_connector") else None),
        control_id=(str(data["control_id"])[:128] if data.get("control_id") else None),
        control_source=(str(data["control_source"])[:32] if data.get("control_source") else None),
        zt_pillar=(str(data["zt_pillar"])[:32] if data.get("zt_pillar") else None),
        first_seen=now,
        last_seen=now,
        created_at=now,
    )


async def _ensure_control(db: AsyncSession, claw: str, data: dict[str, Any]) -> None:
    """Materialize a control carried by scanner output."""
    control_id = data.get("control_id")
    source = data.get("control_source")
    if not control_id or not source:
        return
    result = await db.execute(
        select(Control).where(
            Control.control_id == str(control_id),
            Control.source == str(source),
        )
    )
    if result.scalar_one_or_none():
        return
    frameworks = data.get("frameworks")
    if isinstance(frameworks, str):
        try:
            frameworks = json.loads(frameworks)
        except json.JSONDecodeError:
            frameworks = {"references": [frameworks]}
    tenets = data.get("zt_tenets")
    if isinstance(tenets, str):
        try:
            tenets = json.loads(tenets)
        except json.JSONDecodeError:
            tenets = [tenets]
    db.add(
        Control(
            control_id=str(control_id)[:128],
            source=str(source)[:32],
            source_version=data.get("source_version"),
            title=str(data.get("control_title") or data.get("title") or control_id)[:512],
            description=data.get("control_description") or data.get("description"),
            zt_pillar=str(data.get("zt_pillar") or "governance")[:32],
            zt_tenets=tenets,
            claw=claw,
            provider=data.get("provider"),
            resource_type=data.get("resource_type"),
            frameworks=frameworks,
            severity=str(data.get("severity") or "medium"),
            remediation=data.get("remediation"),
            remediation_action=data.get("remediation_action"),
            status=ControlStatus.ACTIVE,
            automated=True,
            reference_url=data.get("reference_url"),
        )
    )


def _update_finding(existing: Finding, data: dict[str, Any]) -> dict:
    """
    Update mutable fields on an existing finding.
    Returns a change summary dict for event emission.
    """
    changes: dict[str, Any] = {}
    now = datetime.utcnow()

    existing.last_seen = now

    # Severity escalation
    new_sev = _sev_from_str(data.get("severity", existing.severity))
    if _SEV_RANK.get(new_sev, 0) > _SEV_RANK.get(existing.severity, 0):
        changes["severity_escalated"] = {
            "from": existing.severity,
            "to": new_sev,
        }
        existing.severity = new_sev

    # Risk score update (always take the latest)
    new_risk = float(data.get("risk_score", existing.risk_score))
    if abs(new_risk - existing.risk_score) >= 5.0:
        changes["risk_score_changed"] = {
            "from": existing.risk_score,
            "to": new_risk,
        }
    existing.risk_score = new_risk

    # KEV status escalation
    if data.get("actively_exploited") and not existing.actively_exploited:
        changes["kev_added"] = True
        existing.actively_exploited = True

    # Re-open if it was resolved and is now seen again
    if existing.status == FindingStatus.RESOLVED:
        changes["reopened"] = True
        existing.status = FindingStatus.OPEN
        existing.resolved_at = None

    # Update scoring fields
    if data.get("cvss_score") is not None:
        existing.cvss_score = data["cvss_score"]
    if data.get("epss_score") is not None:
        existing.epss_score = data["epss_score"]
    if data.get("remediation") and not existing.remediation:
        existing.remediation = data["remediation"]

    # Control identity backfills onto findings that predate control tagging.
    # Without this a re-scan updates an existing row and the control mapping
    # never lands, so a tenant would have to delete its findings to gain it.
    if data.get("control_id") and not existing.control_id:
        existing.control_id = str(data["control_id"])[:128]
        changes["control_mapped"] = existing.control_id
    if data.get("control_source") and not existing.control_source:
        existing.control_source = str(data["control_source"])[:32]
    if data.get("zt_pillar") and not existing.zt_pillar:
        existing.zt_pillar = str(data["zt_pillar"])[:32]

    # Origin can legitimately change once a tenant configures a real connector
    # and a previously simulated finding is confirmed against live data.
    new_origin = _normalize_origin(data.get("data_origin"))
    if new_origin != "unknown" and new_origin != existing.data_origin:
        changes["data_origin_changed"] = {"from": existing.data_origin, "to": new_origin}
        existing.data_origin = new_origin
    if data.get("source_connector"):
        existing.source_connector = str(data["source_connector"])[:64]

    return changes


async def _emit_new_finding_event(
    db: AsyncSession,
    finding: Finding,
) -> None:
    """Create an Event record for a newly ingested finding."""
    event = Event(
        timestamp=datetime.utcnow(),
        source_module=finding.claw,
        actor_id=finding.provider,
        actor_name=finding.provider,
        actor_type="data_source",
        action="finding_created",
        target=finding.title[:512],
        target_type="finding",
        outcome=EventOutcome.FLAGGED if finding.severity in (FindingSeverity.HIGH, FindingSeverity.CRITICAL) else EventOutcome.ALLOWED,
        severity=_event_severity_from_finding(finding.severity),
        risk_score=finding.risk_score,
        description=f"New {finding.severity} finding ingested from {finding.provider}: {finding.title[:200]}",
        metadata_json=json.dumps({
            "finding_id": str(finding.id),
            "claw": finding.claw,
            "provider": finding.provider,
            "external_id": finding.external_id,
            "category": finding.category,
            "actively_exploited": finding.actively_exploited,
        }),
        is_anomaly=finding.actively_exploited,
        requires_review=finding.severity == FindingSeverity.CRITICAL,
    )
    db.add(event)


async def _emit_change_event(
    db: AsyncSession,
    finding: Finding,
    changes: dict,
) -> None:
    """Create an Event record when an existing finding changes materially."""
    if not changes:
        return

    action = "finding_escalated" if "severity_escalated" in changes else "finding_updated"
    description_parts = []
    if "severity_escalated" in changes:
        c = changes["severity_escalated"]
        description_parts.append(f"Severity escalated {c['from']} → {c['to']}")
    if "kev_added" in changes:
        description_parts.append("Added to CISA KEV (actively exploited)")
    if "reopened" in changes:
        description_parts.append("Finding reopened after previously being resolved")
    if "risk_score_changed" in changes:
        c = changes["risk_score_changed"]
        description_parts.append(f"Risk score changed {c['from']:.1f} → {c['to']:.1f}")

    event = Event(
        timestamp=datetime.utcnow(),
        source_module=finding.claw,
        actor_id=finding.provider,
        actor_name=finding.provider,
        actor_type="data_source",
        action=action,
        target=finding.title[:512],
        target_type="finding",
        outcome=EventOutcome.FLAGGED,
        severity=_event_severity_from_finding(finding.severity),
        risk_score=finding.risk_score,
        description="; ".join(description_parts) or "Finding updated",
        metadata_json=json.dumps({
            "finding_id": str(finding.id),
            "claw": finding.claw,
            "changes": changes,
        }),
        is_anomaly="kev_added" in changes,
        requires_review="severity_escalated" in changes and finding.severity == FindingSeverity.CRITICAL,
    )
    db.add(event)


async def ingest_findings(
    db: AsyncSession,
    claw: str,
    findings: list[dict[str, Any]],
    run_policy_eval: bool = True,
    run_alerts: bool = True,
) -> dict[str, Any]:
    """
    Main entry point for all Claw adapters.

    Args:
        db: AsyncSession from FastAPI dependency injection
        claw: The claw name (e.g. "cloudclaw", "exposureclaw")
        findings: List of raw finding dicts from adapters
        run_policy_eval: Whether to evaluate policies for high/critical findings
        run_alerts: Whether to trigger alert routing for findings above threshold

    Returns:
        Summary dict: {created, updated, skipped, critical, high, errors}
    """
    summary = {
        "claw": claw,
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "critical": 0,
        "high": 0,
        "policy_violations": 0,
        "alerts_sent": 0,
        "errors": 0,
    }

    policy_eval_queue: list[Finding] = []
    alert_queue: list[Finding] = []

    for raw in findings:
        try:
            await _ensure_control(db, claw, raw)
            external_id = raw.get("external_id")
            is_new = False
            finding_obj: Finding

            if external_id:
                # Look up by (claw, external_id)
                result = await db.execute(
                    select(Finding)
                    .where(Finding.claw == claw)
                    .where(Finding.external_id == external_id)
                )
                existing = result.scalar_one_or_none()

                if existing:
                    changes = _update_finding(existing, raw)
                    finding_obj = existing
                    if changes:
                        await _emit_change_event(db, existing, changes)
                        summary["updated"] += 1
                    else:
                        summary["skipped"] += 1
                        continue   # No meaningful changes — skip policy/alert
                else:
                    finding_obj = _build_finding(claw, raw)
                    db.add(finding_obj)
                    await db.flush()   # Get ID assigned
                    await _emit_new_finding_event(db, finding_obj)
                    summary["created"] += 1
                    is_new = True
            else:
                # No external_id: always create (e.g., log anomalies, ephemeral findings)
                finding_obj = _build_finding(claw, raw)
                db.add(finding_obj)
                await db.flush()
                await _emit_new_finding_event(db, finding_obj)
                summary["created"] += 1
                is_new = True

            # Track severity counts
            if finding_obj.severity == FindingSeverity.CRITICAL:
                summary["critical"] += 1
            elif finding_obj.severity == FindingSeverity.HIGH:
                summary["high"] += 1

            # Queue for policy evaluation (high/critical only)
            if run_policy_eval and _SEV_RANK.get(finding_obj.severity, 0) >= _SEV_RANK[_POLICY_SEVERITY_MIN]:
                policy_eval_queue.append(finding_obj)

            # Queue for alert routing (above risk threshold)
            if run_alerts and finding_obj.risk_score >= _ALERT_THRESHOLD_RISK:
                alert_queue.append(finding_obj)

        except Exception as exc:
            logger.error("Error ingesting finding for claw=%s: %s — %s", claw, raw.get("title", "?"), exc, exc_info=True)
            summary["errors"] += 1

    # Commit all findings + events
    if summary["created"] + summary["updated"] > 0:
        await db.commit()

    # Policy evaluation (import here to avoid circular)
    if policy_eval_queue:
        try:
            from app.services.finding_policy_evaluator import evaluate_findings
            violations = await evaluate_findings(db, policy_eval_queue)
            summary["policy_violations"] = violations
        except Exception as exc:
            logger.error("Policy evaluation error for claw=%s: %s", claw, exc, exc_info=True)

    # Alert routing
    if alert_queue:
        try:
            from app.services.alert_router import route_findings
            sent = await route_findings(db, claw, alert_queue)
            summary["alerts_sent"] = sent
        except Exception as exc:
            logger.error("Alert routing error for claw=%s: %s", claw, exc, exc_info=True)

    # Auto-trigger remediation playbooks for critical/high findings
    remediation_queue = [f for f in (policy_eval_queue + alert_queue)
                         if f.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH)]
    for finding_obj in remediation_queue:
        try:
            from app.services.remediation.playbooks import check_and_trigger
            await check_and_trigger(finding_obj, db)
        except Exception as rem_err:
            logger.warning("Remediation auto-trigger failed (non-fatal): %s", rem_err)

    # Event Trigger evaluation — fire any matching reactive triggers
    # We evaluate new/escalated findings separately
    trigger_fires = 0
    for finding_obj in policy_eval_queue + alert_queue:
        try:
            from app.services.trigger_engine import evaluate_finding_triggers
            # Determine if this was a creation or escalation based on whether it's in the summary
            fires = await evaluate_finding_triggers(db, finding_obj, "finding_created")
            trigger_fires += fires
        except Exception as exc:
            logger.warning("Trigger evaluation error for finding: %s", exc)

    if trigger_fires:
        summary["triggers_fired"] = trigger_fires
        try:
            await db.commit()
        except Exception:
            pass

    logger.info(
        "Finding pipeline [%s]: created=%d updated=%d skipped=%d critical=%d high=%d",
        claw, summary["created"], summary["updated"], summary["skipped"],
        summary["critical"], summary["high"],
    )

    # Broadcast to live dashboard clients
    if summary["created"] + summary["updated"] > 0:
        try:
            from app.services.ws_manager import broadcast_finding, broadcast_dashboard_refresh
            # Broadcast the highest-severity new finding as a representative event
            if findings:
                top = max(findings, key=lambda f: f.get("risk_score") or 0)
                await broadcast_finding(
                    claw=claw,
                    severity=top.get("severity", "info"),
                    title=top.get("title", "New finding"),
                    risk_score=top.get("risk_score"),
                    is_new=summary["created"] > 0,
                )
            await broadcast_dashboard_refresh()
        except Exception:
            pass   # WS broadcast must never break the pipeline

    return summary
