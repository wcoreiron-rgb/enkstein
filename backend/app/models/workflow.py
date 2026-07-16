"""
Enkstein — Workflow & WorkflowRun Models
Orchestration: chain agents, policy checks, conditions, and notifications
into governed multi-step workflows.
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Text, Enum as SAEnum, Integer, Boolean, Float
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class TriggerType(str, enum.Enum):
    MANUAL   = "manual"
    SCHEDULE = "schedule"
    EVENT    = "event"


class WorkflowStatus(str, enum.Enum):
    ACTIVE   = "active"
    PAUSED   = "paused"
    DRAFT    = "draft"
    ARCHIVED = "archived"


class WorkflowRunStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"
    BLOCKED   = "blocked"


class Workflow(Base):
    __tablename__ = "workflows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_type: Mapped[TriggerType] = mapped_column(SAEnum(TriggerType), default=TriggerType.MANUAL)
    status: Mapped[WorkflowStatus] = mapped_column(SAEnum(WorkflowStatus), default=WorkflowStatus.ACTIVE)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Steps stored as JSON array of step dicts
    # Each step: {id, name, type, agent_id?, config, on_failure}
    steps_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    step_count: Mapped[int] = mapped_column(Integer, default=0)

    # Tags / category for UI grouping
    category: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tags: Mapped[str | None] = mapped_column(String(255), nullable=True)  # comma-separated

    # Ownership
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Stats
    run_count: Mapped[int] = mapped_column(Integer, default=0)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class WorkflowRun(Base):
    __tablename__ = "workflow_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    status: Mapped[WorkflowRunStatus] = mapped_column(SAEnum(WorkflowRunStatus), default=WorkflowRunStatus.PENDING)
    triggered_by: Mapped[str] = mapped_column(String(255), default="manual")

    # Per-step execution log: JSON array of {step_id, name, status, output, started_at, completed_at}
    steps_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Overall result
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    steps_completed: Mapped[int] = mapped_column(Integer, default=0)
    steps_failed: Mapped[int] = mapped_column(Integer, default=0)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
