"""
Enkstein — Memory Cortex: Entity Behavioral Profile Service

Core functions:
    log_behavior_event()    — record an event and update the entity's profile
    recompute_baseline()    — rebuild baseline from recent events
    score_anomaly()         — score how anomalous a proposed action would be
    get_entity_context()    — return full contextual summary for a claw/policy decision
    get_anomalous_entities() — surface entities currently drifting from baseline

Design principles (governed memory):
    - Sensitive fields (email, resource paths) are stored as-is but the API
      redacts them based on caller context
    - Baselines are recalculated from the last BASELINE_WINDOW events to ensure
      they stay current without unbounded memory growth
    - Anomaly scores are capped and smoothed to avoid alert fatigue
"""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.entity_profile import EntityProfile, BehaviorEvent

# ── Constants ────────────────────────────────────────────────────────────────
BASELINE_WINDOW      = 500    # events used to build baseline
MIN_EVENTS_BASELINE  = 20     # minimum events before baseline is "established"
ANOMALY_DECAY        = 0.85   # per-event decay for anomaly score (smoothing)
VELOCITY_WINDOW_1H   = timedelta(hours=1)
VELOCITY_WINDOW_24H  = timedelta(hours=24)
MAX_TYPICAL_RESOURCES = 50


# ── Internal helpers ──────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.utcnow()


def _get_or_create_profile(
    db: Session,
    entity_id: str,
    entity_type: str,
    display_name: str = "",
    source_claw: str  = "",
) -> EntityProfile:
    profile = db.query(EntityProfile).filter(
        EntityProfile.entity_id == entity_id
    ).first()
    if not profile:
        profile = EntityProfile(
            entity_id     = entity_id,
            entity_type   = entity_type,
            display_name  = display_name or entity_id,
            source_claw   = source_claw,
            first_seen_at = _now(),
            hourly_dist_json = [0] * 24,
            dow_dist_json    = [0] * 7,
        )
        db.add(profile)
        db.flush()
    elif display_name and not profile.display_name:
        profile.display_name = display_name
    return profile


def _anomaly_level(score: float) -> str:
    if score >= 80:  return "critical"
    if score >= 60:  return "high"
    if score >= 40:  return "medium"
    if score >= 20:  return "low"
    return "none"


def _compute_action_anomaly(
    profile: EntityProfile, action: str
) -> tuple[float, str | None]:
    """
    Returns (score 0-100, reason|None).
    Score = how unusual this action is for this entity.
    """
    freq: dict = profile.action_freq_json or {}
    if not freq:
        return 0.0, None

    total  = sum(freq.values())
    count  = freq.get(action, 0)
    if count == 0:
        return 70.0, f"Action '{action}' has never been seen for this entity"
    # relative rarity: rare actions score higher
    rate   = count / total
    score  = max(0.0, (1.0 - rate) * 60.0)
    return round(score, 1), None


def _compute_time_anomaly(
    profile: EntityProfile, hour: int, dow: int
) -> tuple[float, str | None]:
    """Returns (score 0-100, reason|None) for unusual time-of-day / day-of-week."""
    hourly: list = profile.hourly_dist_json or [0] * 24
    dow_d:  list = profile.dow_dist_json    or [0] * 7

    if len(hourly) != 24 or not sum(hourly):
        return 0.0, None

    hour_count = hourly[hour]
    hour_total = sum(hourly)
    hour_rate  = hour_count / hour_total if hour_total else 0
    # An hour with < 2% of activity is unusual
    hour_score = max(0.0, (0.02 - hour_rate) / 0.02 * 50.0) if hour_rate < 0.02 else 0.0

    dow_count = dow_d[dow] if len(dow_d) > dow else 0
    dow_total = sum(dow_d) if dow_d else 0
    dow_rate  = dow_count / dow_total if dow_total else 0
    dow_score = max(0.0, (0.03 - dow_rate) / 0.03 * 30.0) if dow_rate < 0.03 else 0.0

    score  = min(80.0, hour_score + dow_score)
    reason = None
    if score >= 30:
        reason = f"Unusual activity time: hour={hour:02d}:00, day={dow} — outside baseline pattern"
    return round(score, 1), reason


def _compute_claw_anomaly(
    profile: EntityProfile, claw: str
) -> tuple[float, str | None]:
    """Returns score for touching an unfamiliar claw."""
    typical: list = profile.typical_claws_json or []
    if not typical:
        return 0.0, None
    if claw not in typical:
        return 55.0, f"Entity has not previously interacted with {claw}"
    return 0.0, None


def _compute_velocity_anomaly(
    profile: EntityProfile, events_1h: int
) -> tuple[float, str | None]:
    """Detects unusual spikes in event rate."""
    avg = profile.avg_events_1h or 0.0
    if avg < 1:
        return 0.0, None
    ratio = events_1h / avg
    if ratio > 5:
        score  = min(90.0, (ratio - 5) * 10)
        reason = f"Event rate spike: {events_1h}/h vs baseline avg {avg:.1f}/h ({ratio:.1f}×)"
        return round(score, 1), reason
    return 0.0, None


# ── Public API ───────────────────────────────────────────────────────────────

def log_behavior_event(
    db:           Session,
    entity_id:    str,
    entity_type:  str,
    claw:         str,
    action:       str,
    *,
    resource:     str     = "",
    outcome:      str     = "allowed",
    display_name: str     = "",
    source_claw:  str     = "",
    workflow_run_id: str  = "",
    agent_id:     str     = "",
    finding_id:   str     = "",
    incident_id:  str     = "",
    metadata:     dict    = None,
) -> dict[str, Any]:
    """
    Record a security-relevant event for an entity.
    Updates the entity's profile in real time.
    Returns the event record + anomaly assessment.
    """
    now      = _now()
    hour     = now.hour
    dow      = now.weekday()

    # Ensure profile exists
    profile  = _get_or_create_profile(db, entity_id, entity_type, display_name, source_claw)

    # ── Count velocity ────────────────────────────────────────────────────────
    cutoff_1h  = now - VELOCITY_WINDOW_1H
    cutoff_24h = now - VELOCITY_WINDOW_24H
    ev_1h  = db.query(BehaviorEvent).filter(
        BehaviorEvent.entity_id  == entity_id,
        BehaviorEvent.occurred_at >= cutoff_1h,
    ).count()
    ev_24h = db.query(BehaviorEvent).filter(
        BehaviorEvent.entity_id  == entity_id,
        BehaviorEvent.occurred_at >= cutoff_24h,
    ).count()

    # ── Score anomaly components ──────────────────────────────────────────────
    reasons: list[str] = []
    sub_scores: list[float] = []

    if profile.baseline_established:
        a_score, a_reason = _compute_action_anomaly(profile, action)
        t_score, t_reason = _compute_time_anomaly(profile, hour, dow)
        c_score, c_reason = _compute_claw_anomaly(profile, claw)
        v_score, v_reason = _compute_velocity_anomaly(profile, ev_1h + 1)
        for s, r in [(a_score, a_reason), (t_score, t_reason),
                     (c_score, c_reason), (v_score, v_reason)]:
            sub_scores.append(s)
            if r:
                reasons.append(r)
    else:
        sub_scores = [0.0]

    # Combine: max component + 25% of second-highest
    sub_scores.sort(reverse=True)
    anomaly_score = sub_scores[0] + (sub_scores[1] * 0.25 if len(sub_scores) > 1 else 0)
    anomaly_score = min(100.0, round(anomaly_score, 1))
    is_anomalous  = anomaly_score >= 40.0

    # Outcome override
    if outcome == "blocked":
        anomaly_score = max(anomaly_score, 30.0)
        is_anomalous  = True

    # Risk delta: anomalous events contribute positively to risk
    risk_delta = (anomaly_score / 100.0) * 15.0 if is_anomalous else -0.5

    # ── Persist event ─────────────────────────────────────────────────────────
    event = BehaviorEvent(
        entity_id       = entity_id,
        entity_type     = entity_type,
        claw            = claw,
        action          = action,
        resource        = resource[:512] if resource else "",
        outcome         = outcome,
        is_anomalous    = is_anomalous,
        anomaly_score   = anomaly_score,
        anomaly_reasons = reasons,
        risk_delta      = risk_delta,
        occurred_at     = now,
        hour_of_day     = hour,
        day_of_week     = dow,
        workflow_run_id = workflow_run_id,
        agent_id        = agent_id,
        finding_id      = finding_id,
        incident_id     = incident_id,
        metadata_json   = metadata or {},
    )
    db.add(event)

    # ── Update profile ────────────────────────────────────────────────────────
    # Action frequency
    freq = dict(profile.action_freq_json or {})
    freq[action] = freq.get(action, 0) + 1
    profile.action_freq_json = freq

    # Hourly distribution
    hourly = list(profile.hourly_dist_json or [0] * 24)
    if len(hourly) == 24:
        hourly[hour] += 1
    profile.hourly_dist_json = hourly

    # Day-of-week distribution
    dow_d = list(profile.dow_dist_json or [0] * 7)
    if len(dow_d) == 7:
        dow_d[dow] += 1
    profile.dow_dist_json = dow_d

    # Typical claws
    typical_claws = list(profile.typical_claws_json or [])
    if claw not in typical_claws:
        typical_claws.append(claw)
    profile.typical_claws_json = typical_claws

    # Typical resources (keep top MAX_TYPICAL_RESOURCES by recency)
    if resource:
        resources = list(profile.typical_resources_json or [])
        if resource not in resources:
            resources.insert(0, resource)
            profile.typical_resources_json = resources[:MAX_TYPICAL_RESOURCES]

    # Outcome distribution
    outcome_dist = dict(profile.outcome_dist_json or {})
    outcome_dist[outcome] = outcome_dist.get(outcome, 0) + 1
    profile.outcome_dist_json = outcome_dist

    # Event counters
    profile.event_count           = (profile.event_count or 0) + 1
    profile.anomalous_event_count = (profile.anomalous_event_count or 0) + (1 if is_anomalous else 0)
    profile.last_event_at         = now
    profile.events_last_1h        = ev_1h + 1
    profile.events_last_24h       = ev_24h + 1

    # Smoothed anomaly score on profile
    prev_anomaly = profile.anomaly_score or 0.0
    new_profile_anomaly = (prev_anomaly * ANOMALY_DECAY) + (anomaly_score * (1 - ANOMALY_DECAY))
    profile.anomaly_score = round(new_profile_anomaly, 1)
    profile.anomaly_level = _anomaly_level(profile.anomaly_score)

    if is_anomalous:
        profile.last_anomaly_at = now
        # Keep last 10 active anomaly flags
        flags = list(profile.anomaly_flags or [])
        flags = (reasons + [f for f in flags if f not in reasons])[:10]
        profile.anomaly_flags = flags

    # Risk score: cumulative, capped 0-100
    profile.risk_score = round(
        min(100.0, max(0.0, (profile.risk_score or 0.0) + risk_delta)), 1
    )

    # Establish baseline once we have enough events
    if not profile.baseline_established and profile.event_count >= MIN_EVENTS_BASELINE:
        profile.baseline_established    = True
        profile.baseline_established_at = now
        profile.baseline_event_count    = profile.event_count

    profile.avg_events_1h  = max(profile.avg_events_1h  or 0.0, (ev_1h  + 1) * 0.1 +
                                  (profile.avg_events_1h  or 0.0) * 0.9)
    profile.avg_events_24h = max(profile.avg_events_24h or 0.0, (ev_24h + 1) * 0.1 +
                                  (profile.avg_events_24h or 0.0) * 0.9)
    profile.updated_at = now

    db.commit()
    db.refresh(event)

    return {
        "event_id":      event.id,
        "entity_id":     entity_id,
        "is_anomalous":  is_anomalous,
        "anomaly_score": anomaly_score,
        "anomaly_level": _anomaly_level(anomaly_score),
        "reasons":       reasons,
        "risk_delta":    round(risk_delta, 2),
    }


def recompute_baseline(db: Session, entity_id: str) -> EntityProfile | None:
    """
    Rebuild the profile baseline from the last BASELINE_WINDOW events.
    Call this periodically (e.g. from a scheduler) or on demand.
    """
    profile = db.query(EntityProfile).filter(
        EntityProfile.entity_id == entity_id
    ).first()
    if not profile:
        return None

    events = (
        db.query(BehaviorEvent)
        .filter(BehaviorEvent.entity_id == entity_id)
        .order_by(BehaviorEvent.occurred_at.desc())
        .limit(BASELINE_WINDOW)
        .all()
    )
    if len(events) < MIN_EVENTS_BASELINE:
        return profile

    action_counter  = Counter()
    hourly          = [0] * 24
    dow_d           = [0] * 7
    claws: set      = set()
    resources: list = []
    outcome_dist    = Counter()
    total_1h        = 0
    total_24h       = 0
    now             = _now()
    cutoff_1h       = now - VELOCITY_WINDOW_1H
    cutoff_24h      = now - VELOCITY_WINDOW_24H

    for ev in events:
        action_counter[ev.action] += 1
        if ev.hour_of_day is not None and 0 <= ev.hour_of_day < 24:
            hourly[ev.hour_of_day] += 1
        if ev.day_of_week is not None and 0 <= ev.day_of_week < 7:
            dow_d[ev.day_of_week] += 1
        if ev.claw:
            claws.add(ev.claw)
        if ev.resource and ev.resource not in resources:
            resources.append(ev.resource)
        outcome_dist[ev.outcome] += 1
        if ev.occurred_at and ev.occurred_at >= cutoff_1h:
            total_1h += 1
        if ev.occurred_at and ev.occurred_at >= cutoff_24h:
            total_24h += 1

    profile.action_freq_json      = dict(action_counter)
    profile.hourly_dist_json      = hourly
    profile.dow_dist_json         = dow_d
    profile.typical_claws_json    = list(claws)
    profile.typical_resources_json = resources[:MAX_TYPICAL_RESOURCES]
    profile.outcome_dist_json     = dict(outcome_dist)
    profile.baseline_established  = True
    profile.baseline_established_at = _now()
    profile.baseline_event_count  = len(events)
    profile.avg_events_1h         = total_1h
    profile.avg_events_24h        = total_24h
    profile.updated_at            = _now()

    db.commit()
    db.refresh(profile)
    return profile


def score_anomaly(
    db:          Session,
    entity_id:   str,
    action:      str,
    claw:        str,
    resource:    str = "",
    hour:        int = -1,
    dow:         int = -1,
) -> dict[str, Any]:
    """
    Pre-flight anomaly check — score how suspicious a proposed action would be
    WITHOUT actually logging an event. Used by policy engines before execution.
    """
    if hour < 0:
        hour = _now().hour
    if dow < 0:
        dow  = _now().weekday()

    profile = db.query(EntityProfile).filter(
        EntityProfile.entity_id == entity_id
    ).first()

    if not profile or not profile.baseline_established:
        return {
            "entity_id":        entity_id,
            "has_baseline":     False,
            "anomaly_score":    0.0,
            "anomaly_level":    "none",
            "reasons":          [],
            "recommendation":   "No baseline established — insufficient history",
        }

    reasons: list[str] = []
    sub_scores: list[float] = []

    a_score, a_reason = _compute_action_anomaly(profile, action)
    t_score, t_reason = _compute_time_anomaly(profile, hour, dow)
    c_score, c_reason = _compute_claw_anomaly(profile, claw)

    for s, r in [(a_score, a_reason), (t_score, t_reason), (c_score, c_reason)]:
        sub_scores.append(s)
        if r:
            reasons.append(r)

    sub_scores.sort(reverse=True)
    anomaly_score = sub_scores[0] + (sub_scores[1] * 0.25 if len(sub_scores) > 1 else 0)
    anomaly_score = min(100.0, round(anomaly_score, 1))
    level = _anomaly_level(anomaly_score)

    recommendation = (
        "Block and investigate"        if level == "critical" else
        "Require approval"             if level in ("high", "medium") else
        "Proceed with audit log entry" if level == "low" else
        "Normal — proceed"
    )

    return {
        "entity_id":      entity_id,
        "has_baseline":   True,
        "anomaly_score":  anomaly_score,
        "anomaly_level":  level,
        "reasons":        reasons,
        "recommendation": recommendation,
        "profile_summary": {
            "event_count":      profile.event_count,
            "risk_score":       profile.risk_score,
            "typical_claws":    profile.typical_claws_json or [],
            "top_actions":      sorted(
                (profile.action_freq_json or {}).items(),
                key=lambda x: x[1], reverse=True
            )[:5],
        },
    }


def get_entity_context(db: Session, entity_id: str) -> dict[str, Any]:
    """
    Return full behavioral context for an entity — used by claws and policy
    engines to enrich their decisions with historical context.
    """
    profile = db.query(EntityProfile).filter(
        EntityProfile.entity_id == entity_id
    ).first()
    if not profile:
        return {"entity_id": entity_id, "found": False}

    # Recent anomalous events
    recent_anomalies = (
        db.query(BehaviorEvent)
        .filter(
            BehaviorEvent.entity_id  == entity_id,
            BehaviorEvent.is_anomalous == True,
        )
        .order_by(BehaviorEvent.occurred_at.desc())
        .limit(10)
        .all()
    )

    # Top actions
    top_actions = sorted(
        (profile.action_freq_json or {}).items(),
        key=lambda x: x[1], reverse=True
    )[:10]

    return {
        "entity_id":            entity_id,
        "found":                True,
        "entity_type":          profile.entity_type,
        "display_name":         profile.display_name,
        "source_claw":          profile.source_claw,
        "event_count":          profile.event_count,
        "anomalous_event_count": profile.anomalous_event_count,
        "first_seen_at":        profile.first_seen_at.isoformat() if profile.first_seen_at else None,
        "last_event_at":        profile.last_event_at.isoformat() if profile.last_event_at else None,
        "baseline_established": profile.baseline_established,
        "risk_score":           profile.risk_score,
        "anomaly_score":        profile.anomaly_score,
        "anomaly_level":        profile.anomaly_level,
        "active_anomaly_flags": profile.anomaly_flags or [],
        "typical_claws":        profile.typical_claws_json or [],
        "top_actions":          top_actions,
        "recent_anomalies": [
            {
                "id":          ev.id,
                "claw":        ev.claw,
                "action":      ev.action,
                "outcome":     ev.outcome,
                "score":       ev.anomaly_score,
                "reasons":     ev.anomaly_reasons or [],
                "occurred_at": ev.occurred_at.isoformat() if ev.occurred_at else None,
            }
            for ev in recent_anomalies
        ],
    }


def get_anomalous_entities(
    db:         Session,
    min_score:  float = 40.0,
    entity_type: str | None = None,
    limit:       int  = 50,
) -> list[dict]:
    """Return entities currently drifting from their behavioral baseline."""
    q = (
        db.query(EntityProfile)
        .filter(
            EntityProfile.anomaly_score >= min_score,
            EntityProfile.baseline_established == True,
        )
        .order_by(EntityProfile.anomaly_score.desc())
    )
    if entity_type:
        q = q.filter(EntityProfile.entity_type == entity_type)
    profiles = q.limit(limit).all()
    return [
        {
            "entity_id":     p.entity_id,
            "entity_type":   p.entity_type,
            "display_name":  p.display_name,
            "source_claw":   p.source_claw,
            "anomaly_score": p.anomaly_score,
            "anomaly_level": p.anomaly_level,
            "anomaly_flags": p.anomaly_flags or [],
            "risk_score":    p.risk_score,
            "last_event_at": p.last_event_at.isoformat() if p.last_event_at else None,
            "last_anomaly_at": p.last_anomaly_at.isoformat() if p.last_anomaly_at else None,
        }
        for p in profiles
    ]
