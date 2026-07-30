"""
Enkstein — Agent & Scheduler Models
Every agent is a governed actor. Every run goes through Trust Fabric.
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Enum as SAEnum, Integer, Boolean, Float, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
import enum

from app.core.database import Base


class ExecutionMode(str, enum.Enum):
    MONITOR    = "monitor"     # observe + log only, zero writes
    ASSIST     = "assist"      # suggest actions, human reviews before executing
    APPROVAL   = "approval"    # prepare full action plan, require explicit approval before any write
    AUTONOMOUS = "autonomous"  # auto-execute pre-approved low-risk actions; hold high-risk for approval
    EMERGENCY  = "emergency"   # only pre-approved containment actions; everything else blocked


class AgentStatus(str, enum.Enum):
    ACTIVE  = "active"
    PAUSED  = "paused"
    DRAFT   = "draft"
    RETIRED = "retired"


class ScheduleFrequency(str, enum.Enum):
    MANUAL        = "manual"
    EVERY_15_MIN  = "every_15min"
    HOURLY        = "hourly"
    EVERY_6_HOURS = "every_6h"
    DAILY         = "daily"
    WEEKLY        = "weekly"
    MONTHLY       = "monthly"


class ScheduleStatus(str, enum.Enum):
    ACTIVE   = "active"
    PAUSED   = "paused"
    DISABLED = "disabled"


class RunStatus(str, enum.Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    BLOCKED   = "blocked"    # denied by Trust Fabric
    AWAITING  = "awaiting"   # waiting for human approval (assist mode)
    CANCELLED = "cancelled"


class RiskLevel(str, enum.Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Agent(Base):
    __tablename__ = "agents"

    id:              Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Owning tenant. Nullable for built-in/seeded agents that belong to no
    # single tenant; remote agents are always owned.
    tenant_id:       Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    name:            Mapped[str]       = mapped_column(String(255), nullable=False)
    description:     Mapped[str]       = mapped_column(Text, nullable=True)
    claw:            Mapped[str]       = mapped_column(String(64), nullable=False)   # e.g. "identityclaw"
    category:        Mapped[str]       = mapped_column(String(64), nullable=True)    # e.g. "Core Security"
    icon:            Mapped[str]       = mapped_column(String(8), nullable=True)     # emoji

    # Execution governance
    execution_mode:  Mapped[ExecutionMode] = mapped_column(SAEnum(ExecutionMode), default=ExecutionMode.MONITOR)
    risk_level:      Mapped[RiskLevel]     = mapped_column(SAEnum(RiskLevel), default=RiskLevel.LOW)
    max_runtime_sec: Mapped[int]           = mapped_column(Integer, default=300)     # 5 min default
    requires_approval: Mapped[bool]        = mapped_column(Boolean, default=False)

    # Scope
    allowed_actions:  Mapped[str | None] = mapped_column(Text, nullable=True)   # JSON list
    allowed_connectors: Mapped[str | None] = mapped_column(Text, nullable=True) # JSON list of connector types
    scope_notes:      Mapped[str | None] = mapped_column(Text, nullable=True)

    # Ownership
    owner_id:   Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    status:     Mapped[AgentStatus] = mapped_column(SAEnum(AgentStatus), default=AgentStatus.ACTIVE)
    is_builtin: Mapped[bool]        = mapped_column(Boolean, default=False)  # prebuilt vs custom

    # ── External / OpenClaw agent fields ─────────────────────────────────────
    # When is_external=True the runner calls endpoint_url instead of built-in logic.
    # Every call is signed with HMAC-SHA256(signing_secret, ...).
    # Responses must carry a matching X-Agent-Signature header.
    is_external:          Mapped[bool]        = mapped_column(Boolean, default=False)
    endpoint_url:         Mapped[str | None]  = mapped_column(String(2048), nullable=True)
    signing_secret:       Mapped[str | None]  = mapped_column(String(128), nullable=True)   # HMAC secret (treat as credential)
    api_key_preview:      Mapped[str | None]  = mapped_column(String(16), nullable=True)    # first 8 chars for display only
    allowed_scopes:       Mapped[str | None]  = mapped_column(Text, nullable=True)          # JSON list e.g. ["identity:read","network:write"]
    endpoint_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    endpoint_last_error:  Mapped[str | None]  = mapped_column(Text, nullable=True)

    # Stats (denormalized for fast reads)
    total_runs:      Mapped[int]           = mapped_column(Integer, default=0)
    last_run_at:     Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str|None]      = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class Schedule(Base):
    __tablename__ = "schedules"

    id:           Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id:    Mapped[str | None]      = mapped_column(String(128), nullable=True, index=True)
    name:         Mapped[str]             = mapped_column(String(255), nullable=False)
    agent_id:     Mapped[uuid.UUID]       = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    connector_id: Mapped[uuid.UUID|None]  = mapped_column(UUID(as_uuid=True), ForeignKey("connectors.id"), nullable=True)

    frequency:       Mapped[ScheduleFrequency] = mapped_column(SAEnum(ScheduleFrequency), default=ScheduleFrequency.DAILY)
    cron_expression: Mapped[str|None]          = mapped_column(String(64), nullable=True)   # custom cron
    status:          Mapped[ScheduleStatus]    = mapped_column(SAEnum(ScheduleStatus), default=ScheduleStatus.ACTIVE)
    approval_required: Mapped[bool]            = mapped_column(Boolean, default=False)

    owner_id:   Mapped[str|None] = mapped_column(String(255), nullable=True)
    owner_name: Mapped[str|None] = mapped_column(String(255), nullable=True)
    notes:      Mapped[str|None] = mapped_column(Text, nullable=True)

    next_run_at: Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    run_count:   Mapped[int]           = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id:           Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id:    Mapped[str | None]     = mapped_column(String(128), nullable=True, index=True)
    agent_id:     Mapped[uuid.UUID]      = mapped_column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False)
    schedule_id:  Mapped[uuid.UUID|None] = mapped_column(UUID(as_uuid=True), ForeignKey("schedules.id"), nullable=True)

    status:          Mapped[RunStatus]     = mapped_column(SAEnum(RunStatus), default=RunStatus.PENDING)
    execution_mode:  Mapped[ExecutionMode] = mapped_column(SAEnum(ExecutionMode), default=ExecutionMode.MONITOR)
    triggered_by:    Mapped[str]           = mapped_column(String(255), default="scheduler")  # "scheduler" | user_id

    # Trust Fabric result
    policy_decision: Mapped[str|None]   = mapped_column(String(32), nullable=True)   # allow/deny/require_approval
    policy_name:     Mapped[str|None]   = mapped_column(String(255), nullable=True)
    risk_score:      Mapped[float|None] = mapped_column(Float, nullable=True)
    tf_blocked:      Mapped[bool]       = mapped_column(Boolean, default=False)

    # Run results
    findings_count:   Mapped[int]      = mapped_column(Integer, default=0)
    actions_taken:    Mapped[str|None] = mapped_column(Text, nullable=True)   # JSON list
    actions_blocked:  Mapped[str|None] = mapped_column(Text, nullable=True)   # JSON list
    actions_pending:  Mapped[str|None] = mapped_column(Text, nullable=True)   # JSON list (assist mode)
    summary:          Mapped[str|None] = mapped_column(Text, nullable=True)   # human-readable result
    run_log:          Mapped[str|None] = mapped_column(Text, nullable=True)   # JSON log array
    error_message:    Mapped[str|None] = mapped_column(Text, nullable=True)

    started_at:   Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime|None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_sec: Mapped[float|None]    = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


# ─── Platform-Level Autonomy Settings ────────────────────────────────────────
# Single-row configuration table for global autonomy ceiling.
# When emergency_mode is active, ALL agents are forced to EMERGENCY mode
# regardless of their individual settings.

class PlatformSettings(Base):
    __tablename__ = "platform_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)

    # The maximum autonomy mode any agent is allowed to operate in.
    # e.g. ceiling = "assist" means even agents set to autonomous will be capped at assist.
    # ceiling = "monitor" effectively read-only mode for the whole platform.
    autonomy_ceiling: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ExecutionMode.AUTONOMOUS
    )

    # Emergency mode — overrides everything, forces all agents to EMERGENCY
    emergency_mode_active: Mapped[bool] = mapped_column(Boolean, default=False)
    emergency_mode_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    emergency_mode_activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    emergency_mode_activated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Incident/change window — when active, all high/critical actions require approval
    change_window_active: Mapped[bool] = mapped_column(Boolean, default=False)
    change_window_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Global flags
    require_mfa_for_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_approve_low_risk:    Mapped[bool] = mapped_column(Boolean, default=True)
    max_concurrent_runs:      Mapped[int]  = mapped_column(Integer, default=10)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
