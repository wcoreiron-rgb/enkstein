"""
Enkstein — Event Trigger System
Reactive triggers that watch for findings/events/webhooks and auto-launch workflows.

Trigger types:
  finding_created    — fires when a new finding is ingested (with optional claw/severity filter)
  finding_escalated  — fires when an existing finding's severity increases
  event_created      — fires when a platform Event is written (filter by source_module, action, severity)
  webhook_inbound    — fires when an external HTTP POST arrives at /triggers/webhook/{trigger_id}

Conditions are evaluated as a JSON array:
  [{"field": "severity", "op": "gte", "value": "high"},
   {"field": "claw", "op": "eq", "value": "exposureclaw"},
   {"field": "risk_score", "op": "gt", "value": 80}]

Supported operators: eq, neq, gt, gte, lt, lte, contains, not_contains, in, not_in
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text, Boolean, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class EventTrigger(Base):
    __tablename__ = "event_triggers"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Identity
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Owning tenant. Nullable only for legacy rows created before tenant
    # scoping; those cannot fire scans or swarms.
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # What kind of event activates this trigger
    # finding_created | finding_escalated | event_created | webhook_inbound
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Optional pre-filter before condition evaluation (performance optimisation)
    source_filter: Mapped[str | None] = mapped_column(String(64), nullable=True)   # claw name or source_module
    severity_min: Mapped[str | None] = mapped_column(String(16), nullable=True)    # "high" → only eval if >= high

    # JSON array of condition objects: [{field, op, value}, ...]
    conditions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # What to do when triggered
    # fire_workflow: launch a specific workflow
    # fire_scan:     trigger a claw scan
    # fire_alert:    send alert via alert_router
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, default="fire_workflow")

    # For fire_workflow
    workflow_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    # For fire_scan
    target_claw: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # For fire_alert — JSON payload override
    alert_config_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Throttling — don't fire more than once per N seconds for the same trigger
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=300)

    # State
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)

    # Ownership
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)   # "detection", "response", "compliance"

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        Index("ix_event_triggers_type_active", "trigger_type", "is_active"),
    )
