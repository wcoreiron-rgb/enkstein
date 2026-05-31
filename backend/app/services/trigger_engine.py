"""
RegentClaw — Trigger Engine
Evaluates all active triggers whenever a Finding or Event is written.
Fires the configured action (workflow launch, claw scan, alert) when conditions match.

Integration points:
  - finding_pipeline.py: calls evaluate_finding_triggers() after ingest
  - events route: calls evaluate_event_triggers() after Event creation

Cooldown enforcement prevents trigger storms — a trigger won't fire more than
once per cooldown_seconds for the same trigger ID.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.trigger import EventTrigger
from app.models.finding import Finding, FindingSeverity
from app.models.event import Event, EventSeverity
from app.core.swarm.schemas import SwarmJobCreate
from app.core.swarm.orchestrator import create_swarm_job, run_swarm_job_in_session

logger = logging.getLogger("trigger_engine")

# ─── Severity rank for gte/lte comparisons ────────────────────────────────────

_SEV_RANK: dict[str, int] = {
    "info":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}


# ─── Condition evaluator ─────────────────────────────────────────────────────

def _get_nested(obj: dict, field: str) -> Any:
    """Support dot-notation for nested fields: 'raw_data.cvss_score'"""
    parts = field.split(".", 1)
    val = obj.get(parts[0])
    if len(parts) == 2 and isinstance(val, dict):
        return _get_nested(val, parts[1])
    return val


def _compare(actual: Any, op: str, expected: Any) -> bool:
    """
    Evaluate a single condition.
    For severity fields, uses rank-based comparison (gte high = high, critical).
    """
    # Normalise severity strings
    if isinstance(actual, str) and actual.lower() in _SEV_RANK and str(expected).lower() in _SEV_RANK:
        a_rank = _SEV_RANK[actual.lower()]
        e_rank = _SEV_RANK[str(expected).lower()]
        if op == "gte":  return a_rank >= e_rank
        if op == "gt":   return a_rank >  e_rank
        if op == "lte":  return a_rank <= e_rank
        if op == "lt":   return a_rank <  e_rank
        if op == "eq":   return a_rank == e_rank
        if op == "neq":  return a_rank != e_rank

    # Generic comparisons
    try:
        if op == "eq":           return str(actual).lower() == str(expected).lower()
        if op == "neq":          return str(actual).lower() != str(expected).lower()
        if op == "contains":     return str(expected).lower() in str(actual).lower()
        if op == "not_contains": return str(expected).lower() not in str(actual).lower()
        if op == "in":
            choices = expected if isinstance(expected, list) else str(expected).split(",")
            return str(actual).lower() in [str(c).strip().lower() for c in choices]
        if op == "not_in":
            choices = expected if isinstance(expected, list) else str(expected).split(",")
            return str(actual).lower() not in [str(c).strip().lower() for c in choices]
        if op == "gt":   return float(actual) >  float(expected)
        if op == "gte":  return float(actual) >= float(expected)
        if op == "lt":   return float(actual) <  float(expected)
        if op == "lte":  return float(actual) <= float(expected)
    except (TypeError, ValueError):
        return False

    return False


def _matches_conditions(obj_dict: dict, conditions_json: str) -> bool:
    """
    Evaluate all conditions as AND logic.
    Returns True only if every condition passes.
    Empty conditions list → always fires.
    """
    try:
        conditions = json.loads(conditions_json)
    except Exception:
        return True   # malformed JSON → treat as no filter

    if not conditions:
        return True

    for cond in conditions:
        field   = cond.get("field", "")
        op      = cond.get("op", "eq")
        expected = cond.get("value")
        actual  = _get_nested(obj_dict, field)
        if actual is None:
            return False
        if not _compare(actual, op, expected):
            return False

    return True


def _is_cooled_down(trigger: EventTrigger) -> bool:
    """Return True if we're still within the cooldown window (should NOT fire)."""
    if not trigger.last_triggered_at:
        return False
    now = datetime.now(timezone.utc)
    last = trigger.last_triggered_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    elapsed = (now - last).total_seconds()
    return elapsed < trigger.cooldown_seconds


# ─── Action dispatcher ────────────────────────────────────────────────────────

async def _fire_trigger(
    db: AsyncSession,
    trigger: EventTrigger,
    context: dict,
    triggered_by: str,
) -> None:
    """Execute the trigger's configured action."""
    now = datetime.now(timezone.utc)
    trigger.last_triggered_at = now
    trigger.trigger_count = (trigger.trigger_count or 0) + 1

    action = trigger.action_type

    if action == "fire_workflow" and trigger.workflow_id:
        try:
            from app.services.workflow_runner import execute_workflow
            run = await execute_workflow(
                workflow_id=trigger.workflow_id,
                triggered_by=f"trigger:{trigger.name}:{triggered_by}",
                db=db,
            )
            logger.info(
                "Trigger '%s' fired workflow %s → run %s status=%s",
                trigger.name, trigger.workflow_id, run.id, run.status,
            )
        except Exception as exc:
            logger.error("Trigger '%s' workflow fire failed: %s", trigger.name, exc)

    elif action == "fire_scan" and trigger.target_claw:
        try:
            from app.services.auto_scanner import _run_claw_scan
            result = await _run_claw_scan(db, trigger.target_claw)
            logger.info("Trigger '%s' fired scan for %s → %s", trigger.name, trigger.target_claw, result)
        except Exception as exc:
            logger.error("Trigger '%s' scan fire failed: %s", trigger.name, exc)

    elif action == "fire_alert":
        try:
            from app.services.alert_router import route_event_alert
            cfg = json.loads(trigger.alert_config_json or "{}")
            payload = {
                "title": cfg.get("title") or f"RegentClaw Trigger: {trigger.name}",
                "description": cfg.get("description") or f"Trigger '{trigger.name}' fired. Context: {json.dumps(context)[:300]}",
                "severity": cfg.get("severity", "medium"),
                "claw": context.get("claw", "coreos"),
                "risk_score": context.get("risk_score", 0.0),
            }
            sent = await route_event_alert(db, payload)
            logger.info("Trigger '%s' fired alert → %d channels", trigger.name, sent)
        except Exception as exc:
            logger.error("Trigger '%s' alert fire failed: %s", trigger.name, exc)

    elif action in {"start_swarm", "fire_swarm"}:
        try:
            cfg = json.loads(trigger.alert_config_json or "{}")
            participants = cfg.get("participants") or []
            if not participants and trigger.target_claw:
                participants = [c.strip() for c in trigger.target_claw.split(",") if c.strip()]
            swarm_input = cfg.get("input") or {}
            if isinstance(context, dict):
                swarm_input = {**swarm_input, "trigger_context": context}
            payload = SwarmJobCreate(
                name=cfg.get("name") or f"Trigger Swarm: {trigger.name}",
                profile=cfg.get("profile", "INCIDENT_RESPONSE"),
                requested_by=trigger.created_by or "trigger_engine",
                trigger_type=f"trigger:{trigger.trigger_type}",
                classification=cfg.get("classification", "internal"),
                participants=participants,
                task_type=cfg.get("task_type", "analyze"),
                input=swarm_input,
                parallelism=int(cfg.get("parallelism", 3)),
                model_profile=cfg.get("model_profile"),
            )
            job = await create_swarm_job(db, payload)
            await run_swarm_job_in_session(db, job.id)
            logger.info("Trigger '%s' started swarm job %s", trigger.name, job.id)
        except Exception as exc:
            logger.error("Trigger '%s' swarm fire failed: %s", trigger.name, exc)

    else:
        logger.warning("Trigger '%s' has unknown action_type '%s'", trigger.name, action)


# ─── Public evaluation API ────────────────────────────────────────────────────

async def evaluate_finding_triggers(
    db: AsyncSession,
    finding: Finding,
    event_type: str = "finding_created",
) -> int:
    """
    Check all active finding-type triggers against this finding.
    Called by finding_pipeline after ingest.

    Args:
        finding: The newly created or escalated Finding ORM object
        event_type: "finding_created" or "finding_escalated"

    Returns:
        Number of triggers fired
    """
    stmt = select(EventTrigger).where(
        EventTrigger.is_active == True,
        EventTrigger.trigger_type == event_type,
    )
    result = await db.execute(stmt)
    triggers = result.scalars().all()

    if not triggers:
        return 0

    # Build a flat dict from the finding for condition evaluation
    finding_dict = {
        "claw":               finding.claw,
        "provider":           finding.provider,
        "title":              finding.title,
        "severity":           str(finding.severity.value if hasattr(finding.severity, 'value') else finding.severity),
        "risk_score":         finding.risk_score,
        "category":           finding.category or "",
        "resource_type":      finding.resource_type or "",
        "resource_name":      finding.resource_name or "",
        "actively_exploited": finding.actively_exploited,
        "status":             str(finding.status.value if hasattr(finding.status, 'value') else finding.status),
        "external_id":        finding.external_id or "",
    }

    fired = 0
    for trigger in triggers:
        # Pre-filter: source_filter
        if trigger.source_filter and finding.claw != trigger.source_filter:
            continue

        # Pre-filter: severity_min
        if trigger.severity_min:
            f_rank = _SEV_RANK.get(finding_dict["severity"], 0)
            min_rank = _SEV_RANK.get(trigger.severity_min.lower(), 0)
            if f_rank < min_rank:
                continue

        # Cooldown check
        if _is_cooled_down(trigger):
            logger.debug("Trigger '%s' is in cooldown, skipping", trigger.name)
            continue

        # Full condition evaluation
        if _matches_conditions(finding_dict, trigger.conditions_json):
            logger.info(
                "Trigger '%s' (type=%s) matched finding '%s' (claw=%s sev=%s)",
                trigger.name, event_type, finding.title[:80], finding.claw, finding_dict["severity"],
            )
            await _fire_trigger(db, trigger, finding_dict, f"finding:{finding.id}")
            fired += 1

    return fired


async def evaluate_event_triggers(
    db: AsyncSession,
    event: Event,
) -> int:
    """
    Check all active event_created triggers against a new platform Event.
    Called by the events route after Event creation.

    Returns:
        Number of triggers fired
    """
    stmt = select(EventTrigger).where(
        EventTrigger.is_active == True,
        EventTrigger.trigger_type == "event_created",
    )
    result = await db.execute(stmt)
    triggers = result.scalars().all()

    if not triggers:
        return 0

    event_dict = {
        "source_module": event.source_module,
        "actor_id":      event.actor_id or "",
        "actor_name":    event.actor_name or "",
        "actor_type":    event.actor_type or "",
        "action":        event.action,
        "target":        event.target or "",
        "target_type":   event.target_type or "",
        "outcome":       str(event.outcome.value if hasattr(event.outcome, 'value') else event.outcome),
        "severity":      str(event.severity.value if hasattr(event.severity, 'value') else event.severity),
        "risk_score":    event.risk_score,
        "is_anomaly":    event.is_anomaly,
        "requires_review": event.requires_review,
    }

    fired = 0
    for trigger in triggers:
        if trigger.source_filter and event.source_module != trigger.source_filter:
            continue
        if trigger.severity_min:
            e_rank   = _SEV_RANK.get(event_dict["severity"], 0)
            min_rank = _SEV_RANK.get(trigger.severity_min.lower(), 0)
            if e_rank < min_rank:
                continue
        if _is_cooled_down(trigger):
            continue
        if _matches_conditions(event_dict, trigger.conditions_json):
            logger.info(
                "Trigger '%s' matched event action='%s' module='%s'",
                trigger.name, event.action, event.source_module,
            )
            await _fire_trigger(db, trigger, event_dict, f"event:{event.id}")
            fired += 1

    return fired


async def handle_webhook_trigger(
    db: AsyncSession,
    trigger_id: str,
    payload: dict,
) -> dict:
    """
    Called when an external webhook POST arrives.
    Looks up the trigger, validates it's a webhook type, checks conditions, fires.
    """
    from uuid import UUID
    try:
        result = await db.execute(
            select(EventTrigger).where(EventTrigger.id == UUID(trigger_id))
        )
        trigger = result.scalar_one_or_none()
    except Exception:
        return {"error": "invalid trigger id"}

    if not trigger:
        return {"error": "trigger not found"}
    if not trigger.is_active:
        return {"error": "trigger is inactive"}
    if trigger.trigger_type != "webhook_inbound":
        return {"error": "trigger is not webhook type"}
    if _is_cooled_down(trigger):
        return {"status": "cooldown", "message": f"Trigger in cooldown for {trigger.cooldown_seconds}s"}

    matched = _matches_conditions(payload, trigger.conditions_json)
    if matched:
        await _fire_trigger(db, trigger, payload, "webhook")
        await db.commit()
        return {
            "status": "fired",
            "trigger_name": trigger.name,
            "action_type": trigger.action_type,
            "trigger_count": trigger.trigger_count,
        }

    return {
        "status": "conditions_not_met",
        "trigger_name": trigger.name,
    }
