"""
Enkstein — Memory Cortex: Entity Behavioral Profiling Models

EntityProfile  — per-entity behavioral baseline (Honcho "Peer" equivalent)
BehaviorEvent  — individual activity log entry   (Honcho "Message" equivalent)

Entity types: user | agent | asset | connector | ip | service_account
"""
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, DateTime, JSON, Index
)
from app.database import Base


class EntityProfile(Base):
    """
    Evolving behavioral profile for any security-relevant entity.
    The baseline is recomputed from recent BehaviorEvents and stored here
    so any claw can answer "is this action unusual for this entity?" in O(1).
    """
    __tablename__ = "entity_profiles"

    # ── identity ──────────────────────────────────────────────────────────────
    entity_id    = Column(String(255), primary_key=True)  # email / hostname / IP / agent_id
    entity_type  = Column(String(64), nullable=False, index=True)
    # user | agent | asset | connector | ip | service_account
    display_name = Column(String(255), default="")
    source_claw  = Column(String(64), default="")    # primary claw that tracks this entity

    # ── event counters ────────────────────────────────────────────────────────
    event_count          = Column(Integer, default=0)
    anomalous_event_count = Column(Integer, default=0)
    last_event_at        = Column(DateTime, nullable=True)
    first_seen_at        = Column(DateTime, default=datetime.utcnow)

    # ── baseline (recomputed periodically from events) ────────────────────────
    baseline_established    = Column(Boolean, default=False)
    baseline_established_at = Column(DateTime, nullable=True)
    baseline_event_count    = Column(Integer, default=0)   # how many events used

    # Action frequency map — {action: count} e.g. {"login": 45, "scan": 12}
    action_freq_json     = Column(JSON, default=dict)
    # Hourly activity distribution — 24-element list of counts [0..23]
    hourly_dist_json     = Column(JSON, default=list)
    # Day-of-week distribution — 7-element list [Mon..Sun]
    dow_dist_json        = Column(JSON, default=list)
    # Claws this entity typically interacts with
    typical_claws_json   = Column(JSON, default=list)
    # Resources this entity typically accesses (top 50)
    typical_resources_json = Column(JSON, default=list)
    # Outcome distribution — {"allowed": N, "blocked": N, "anomalous": N}
    outcome_dist_json    = Column(JSON, default=dict)

    # ── current risk / anomaly state ──────────────────────────────────────────
    risk_score      = Column(Float, default=0.0)   # 0-100, updated on each event
    anomaly_score   = Column(Float, default=0.0)   # 0-100, rising = drift from baseline
    anomaly_level   = Column(String(16), default="none")  # none|low|medium|high|critical
    anomaly_flags   = Column(JSON, default=list)   # active anomaly descriptions
    last_anomaly_at = Column(DateTime, nullable=True)

    # ── velocity tracking (rolling 1h / 24h window counts) ───────────────────
    events_last_1h  = Column(Integer, default=0)
    events_last_24h = Column(Integer, default=0)
    # Average 1h/24h event rates from baseline
    avg_events_1h   = Column(Float, default=0.0)
    avg_events_24h  = Column(Float, default=0.0)

    # ── tags / labels ─────────────────────────────────────────────────────────
    tags            = Column(JSON, default=list)
    context_notes   = Column(Text, default="")

    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BehaviorEvent(Base):
    """
    A single security-relevant activity logged against an entity.
    These are the raw inputs for baseline computation and anomaly scoring.
    Analogous to Honcho's "Message" primitive — but security-focused.
    """
    __tablename__ = "behavior_events"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    entity_id    = Column(String(255), nullable=False, index=True)
    entity_type  = Column(String(64), nullable=False)

    # What happened
    claw         = Column(String(64), nullable=False, index=True)  # which claw logged this
    action       = Column(String(128), nullable=False)             # login, scan, api_call, policy_check, exec…
    resource     = Column(String(512), default="")                 # resource involved
    outcome      = Column(String(32), default="allowed")           # allowed|blocked|anomalous|failed

    # Anomaly assessment at log time
    is_anomalous    = Column(Boolean, default=False, index=True)
    anomaly_score   = Column(Float, default=0.0)    # 0-100
    anomaly_reasons = Column(JSON, default=list)    # list of human-readable reasons

    # Risk contribution (positive = raises risk, negative = lowers)
    risk_delta = Column(Float, default=0.0)

    # Time context
    occurred_at = Column(DateTime, default=datetime.utcnow, index=True)
    hour_of_day = Column(Integer, default=0)   # 0-23
    day_of_week = Column(Integer, default=0)   # 0=Mon … 6=Sun

    # Linked platform objects
    workflow_run_id = Column(String(128), default="")
    agent_id        = Column(String(128), default="")
    finding_id      = Column(String(128), default="")
    incident_id     = Column(String(128), default="")

    # Extra structured context
    metadata_json = Column(JSON, default=dict)


# ── Indexes ────────────────────────────────────────────────────────────────────
Index("ix_behavior_events_entity_occurred",  BehaviorEvent.entity_id, BehaviorEvent.occurred_at)
Index("ix_behavior_events_claw_action",      BehaviorEvent.claw, BehaviorEvent.action)
Index("ix_behavior_events_anomalous_recent", BehaviorEvent.is_anomalous, BehaviorEvent.occurred_at)
Index("ix_entity_profiles_type_anomaly",     EntityProfile.entity_type, EntityProfile.anomaly_level)
