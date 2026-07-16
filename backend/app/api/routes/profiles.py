"""
Enkstein — Memory Cortex: Entity Behavioral Profiling API

GET  /memory/profiles                  — list entity profiles (sorted by anomaly)
GET  /memory/profiles/anomalous        — entities actively drifting from baseline
GET  /memory/profiles/{entity_id}      — full profile + context
DELETE /memory/profiles/{entity_id}    — remove profile (right-to-forget / purge)

POST /memory/profiles/score            — pre-flight anomaly check without logging
GET  /memory/profiles/{entity_id}/context  — enriched context for claws/policies
POST /memory/profiles/{entity_id}/recompute — force baseline recomputation

POST /memory/behavior-events           — log a behavior event
GET  /memory/behavior-events           — browse logged events
GET  /memory/behavior-events/{id}      — event detail

GET  /memory/profiles/stats            — aggregate stats across all profiles
"""
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.entity_profile import EntityProfile, BehaviorEvent
from app.services.profile_service import (
    log_behavior_event,
    recompute_baseline,
    score_anomaly,
    get_entity_context,
    get_anomalous_entities,
    _anomaly_level,
    _get_or_create_profile,
)

router = APIRouter(prefix="/memory", tags=["Memory Cortex-Profiles"])


# ─── output helpers ───────────────────────────────────────────────────────────

def _profile_out(p: EntityProfile) -> dict:
    return {
        "entity_id":             p.entity_id,
        "entity_type":           p.entity_type,
        "display_name":          p.display_name,
        "source_claw":           p.source_claw,
        "event_count":           p.event_count,
        "anomalous_event_count": p.anomalous_event_count,
        "first_seen_at":         p.first_seen_at.isoformat()  if p.first_seen_at  else None,
        "last_event_at":         p.last_event_at.isoformat()  if p.last_event_at  else None,
        "last_anomaly_at":       p.last_anomaly_at.isoformat() if p.last_anomaly_at else None,
        "baseline_established":  p.baseline_established,
        "baseline_established_at": p.baseline_established_at.isoformat() if p.baseline_established_at else None,
        "baseline_event_count":  p.baseline_event_count,
        "risk_score":            p.risk_score,
        "anomaly_score":         p.anomaly_score,
        "anomaly_level":         p.anomaly_level,
        "anomaly_flags":         p.anomaly_flags or [],
        "events_last_1h":        p.events_last_1h,
        "events_last_24h":       p.events_last_24h,
        "avg_events_1h":         round(p.avg_events_1h  or 0.0, 2),
        "avg_events_24h":        round(p.avg_events_24h or 0.0, 2),
        "typical_claws":         p.typical_claws_json    or [],
        "action_freq":           p.action_freq_json      or {},
        "typical_resources":     p.typical_resources_json or [],
        "outcome_dist":          p.outcome_dist_json     or {},
        "hourly_dist":           p.hourly_dist_json      or [0]*24,
        "dow_dist":              p.dow_dist_json         or [0]*7,
        "tags":                  p.tags                  or [],
        "context_notes":         p.context_notes,
        "updated_at":            p.updated_at.isoformat() if p.updated_at else None,
    }


def _event_out(ev: BehaviorEvent) -> dict:
    return {
        "id":              ev.id,
        "entity_id":       ev.entity_id,
        "entity_type":     ev.entity_type,
        "claw":            ev.claw,
        "action":          ev.action,
        "resource":        ev.resource,
        "outcome":         ev.outcome,
        "is_anomalous":    ev.is_anomalous,
        "anomaly_score":   ev.anomaly_score,
        "anomaly_reasons": ev.anomaly_reasons or [],
        "risk_delta":      ev.risk_delta,
        "occurred_at":     ev.occurred_at.isoformat() if ev.occurred_at else None,
        "hour_of_day":     ev.hour_of_day,
        "day_of_week":     ev.day_of_week,
        "workflow_run_id": ev.workflow_run_id,
        "agent_id":        ev.agent_id,
        "finding_id":      ev.finding_id,
        "incident_id":     ev.incident_id,
        "metadata_json":   ev.metadata_json or {},
    }


# ─── profiles ────────────────────────────────────────────────────────────────

@router.get("/profiles")
def list_profiles(
    entity_type:   Optional[str]   = Query(None),
    anomaly_level: Optional[str]   = Query(None),
    source_claw:   Optional[str]   = Query(None),
    min_risk:      Optional[float] = Query(None),
    sort:          str             = Query("anomaly"),  # anomaly|risk|events|recent
    limit:         int             = Query(50, ge=1, le=500),
    offset:        int             = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(EntityProfile)
    if entity_type:   q = q.filter(EntityProfile.entity_type   == entity_type)
    if anomaly_level: q = q.filter(EntityProfile.anomaly_level == anomaly_level)
    if source_claw:   q = q.filter(EntityProfile.source_claw   == source_claw)
    if min_risk is not None: q = q.filter(EntityProfile.risk_score >= min_risk)

    if sort == "anomaly": q = q.order_by(EntityProfile.anomaly_score.desc())
    elif sort == "risk":  q = q.order_by(EntityProfile.risk_score.desc())
    elif sort == "events":q = q.order_by(EntityProfile.event_count.desc())
    elif sort == "recent":q = q.order_by(EntityProfile.last_event_at.desc())

    total   = q.count()
    results = q.offset(offset).limit(limit).all()
    return {"total": total, "profiles": [_profile_out(p) for p in results]}


@router.get("/profiles/anomalous")
def list_anomalous(
    min_score:   float          = Query(40.0),
    entity_type: Optional[str]  = Query(None),
    limit:       int            = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Entities currently drifting from their behavioral baseline."""
    return get_anomalous_entities(db, min_score=min_score, entity_type=entity_type, limit=limit)


@router.get("/profiles/stats")
def profile_stats(db: Session = Depends(get_db)):
    """Aggregate stats across all behavioral profiles."""
    total           = db.query(EntityProfile).count()
    with_baseline   = db.query(EntityProfile).filter(EntityProfile.baseline_established == True).count()
    anomalous       = db.query(EntityProfile).filter(EntityProfile.anomaly_score >= 40).count()
    high_risk       = db.query(EntityProfile).filter(EntityProfile.risk_score    >= 70).count()
    total_events    = db.query(BehaviorEvent).count()
    anomalous_events = db.query(BehaviorEvent).filter(BehaviorEvent.is_anomalous == True).count()

    # Type breakdown
    type_breakdown: dict[str, int] = {}
    for row in db.query(EntityProfile.entity_type).distinct():
        t = row[0]
        type_breakdown[t] = db.query(EntityProfile).filter(EntityProfile.entity_type == t).count()

    # Anomaly level breakdown
    level_breakdown: dict[str, int] = {}
    for lvl in ("none", "low", "medium", "high", "critical"):
        level_breakdown[lvl] = db.query(EntityProfile).filter(EntityProfile.anomaly_level == lvl).count()

    return {
        "total_profiles":     total,
        "with_baseline":      with_baseline,
        "anomalous_entities": anomalous,
        "high_risk_entities": high_risk,
        "total_events":       total_events,
        "anomalous_events":   anomalous_events,
        "anomaly_event_rate": round(anomalous_events / max(total_events, 1) * 100, 1),
        "type_breakdown":     type_breakdown,
        "level_breakdown":    level_breakdown,
    }


@router.get("/profiles/{entity_id}")
def get_profile(entity_id: str, db: Session = Depends(get_db)):
    p = db.query(EntityProfile).filter(EntityProfile.entity_id == entity_id).first()
    if not p:
        raise HTTPException(404, "Entity profile not found")
    return _profile_out(p)


@router.delete("/profiles/{entity_id}")
def delete_profile(entity_id: str, db: Session = Depends(get_db)):
    """Remove all behavioral memory for an entity (right-to-forget / purge)."""
    p = db.query(EntityProfile).filter(EntityProfile.entity_id == entity_id).first()
    if not p:
        raise HTTPException(404, "Entity profile not found")
    # Delete all events
    db.query(BehaviorEvent).filter(BehaviorEvent.entity_id == entity_id).delete()
    db.delete(p)
    db.commit()
    return {"message": f"All behavioral memory for '{entity_id}' has been purged"}


@router.get("/profiles/{entity_id}/context")
def entity_context(entity_id: str, db: Session = Depends(get_db)):
    """
    Full contextual summary for a claw or policy engine to use in decisions.
    Returns baseline, recent anomalies, risk level, top actions — everything
    needed to answer "is this action unusual for this entity?"
    """
    return get_entity_context(db, entity_id)


@router.post("/profiles/{entity_id}/recompute")
def force_recompute(entity_id: str, db: Session = Depends(get_db)):
    """Force a full baseline recomputation from the last 500 events."""
    profile = recompute_baseline(db, entity_id)
    if not profile:
        raise HTTPException(404, "Entity profile not found")
    return {"message": "Baseline recomputed", "entity_id": entity_id,
            "baseline_event_count": profile.baseline_event_count}


# ─── anomaly pre-flight scoring ───────────────────────────────────────────────

@router.post("/profiles/score")
def preflight_score(body: dict, db: Session = Depends(get_db)):
    """
    Score how anomalous a proposed action would be WITHOUT logging an event.
    Use this in policy engines before execution to enrich decisions.

    Body: { entity_id, action, claw, resource?, hour?, dow? }
    """
    for f in ("entity_id", "action", "claw"):
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")
    return score_anomaly(
        db,
        entity_id = body["entity_id"],
        action    = body["action"],
        claw      = body["claw"],
        resource  = body.get("resource", ""),
        hour      = body.get("hour", -1),
        dow       = body.get("dow", -1),
    )


# ─── behavior events ─────────────────────────────────────────────────────────

@router.post("/behavior-events")
def post_behavior_event(body: dict, db: Session = Depends(get_db)):
    """
    Log a security-relevant event for an entity.
    Required: entity_id, entity_type, claw, action
    Optional: resource, outcome, display_name, source_claw,
              workflow_run_id, agent_id, finding_id, incident_id, metadata
    """
    for f in ("entity_id", "entity_type", "claw", "action"):
        if f not in body:
            raise HTTPException(400, f"Missing field: {f}")
    return log_behavior_event(
        db,
        entity_id    = body["entity_id"],
        entity_type  = body["entity_type"],
        claw         = body["claw"],
        action       = body["action"],
        resource     = body.get("resource", ""),
        outcome      = body.get("outcome", "allowed"),
        display_name = body.get("display_name", ""),
        source_claw  = body.get("source_claw", ""),
        workflow_run_id = body.get("workflow_run_id", ""),
        agent_id     = body.get("agent_id", ""),
        finding_id   = body.get("finding_id", ""),
        incident_id  = body.get("incident_id", ""),
        metadata     = body.get("metadata", {}),
    )


@router.get("/behavior-events")
def list_events(
    entity_id:   Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    claw:        Optional[str] = Query(None),
    action:      Optional[str] = Query(None),
    anomalous_only: bool       = Query(False),
    limit:       int           = Query(100, ge=1, le=1000),
    offset:      int           = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(BehaviorEvent)
    if entity_id:      q = q.filter(BehaviorEvent.entity_id   == entity_id)
    if entity_type:    q = q.filter(BehaviorEvent.entity_type == entity_type)
    if claw:           q = q.filter(BehaviorEvent.claw        == claw)
    if action:         q = q.filter(BehaviorEvent.action      == action)
    if anomalous_only: q = q.filter(BehaviorEvent.is_anomalous == True)
    total   = q.count()
    results = q.order_by(BehaviorEvent.occurred_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "events": [_event_out(ev) for ev in results]}


@router.get("/behavior-events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    ev = db.query(BehaviorEvent).filter(BehaviorEvent.id == event_id).first()
    if not ev:
        raise HTTPException(404, "Event not found")
    return _event_out(ev)
