"""
Enkstein — Remediation Engine Models
DB models for autonomous remediation actions, playbooks, and audit trail.
"""
import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, DateTime, Boolean, Enum as SAEnum, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RemediationStatus(str, enum.Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED         = "approved"
    REJECTED         = "rejected"
    EXECUTING        = "executing"
    COMPLETED        = "completed"
    FAILED           = "failed"
    ROLLED_BACK      = "rolled_back"
    TIMED_OUT        = "timed_out"


class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    finding_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    workflow_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    playbook_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # What to do
    provider: Mapped[str] = mapped_column(String(64), nullable=False)         # okta, aws_iam, crowdstrike, etc.
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)      # suspend_user, quarantine_device, etc.
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)      # user, device, access_key
    target_id: Mapped[str] = mapped_column(String(512), nullable=False)       # ID of the affected entity
    target_label: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)  # human-readable name
    parameters: Mapped[Optional[str]] = mapped_column(Text, nullable=True)    # JSON blob

    # Governance
    status: Mapped[RemediationStatus] = mapped_column(
        SAEnum(RemediationStatus), default=RemediationStatus.PENDING_APPROVAL, nullable=False
    )
    risk_level: Mapped[str] = mapped_column(String(16), default="high", nullable=False)  # low/medium/high/critical
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Accountability
    triggered_by: Mapped[str] = mapped_column(String(128), default="auto", nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    rejected_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approval_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Execution tracking
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Rollback
    rollback_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)   # JSON — pre-action state

    # Output
    output: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )


class RemediationPlaybook(Base):
    __tablename__ = "remediation_playbooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, unique=True)  # stable builtin ID
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Trigger conditions
    trigger_claw: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)     # e.g. "devclaw"
    trigger_severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True) # "critical","high"
    trigger_category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    trigger_keywords: Mapped[Optional[str]] = mapped_column(Text, nullable=True)        # JSON list of strings

    # Playbook definition
    actions_json: Mapped[str] = mapped_column(Text, nullable=False)  # JSON list of action specs

    # Settings
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    auto_rollback_on_failure: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
