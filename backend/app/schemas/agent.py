"""
Enkstein — Agent & Scheduler Pydantic Schemas
"""
from __future__ import annotations
import uuid
from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

from app.models.agent import (
    ExecutionMode, AgentStatus, ScheduleFrequency,
    ScheduleStatus, RunStatus, RiskLevel,
)


# ─────────────────────────────────────────────
# Agent
# ─────────────────────────────────────────────

class AgentBase(BaseModel):
    name:            str
    description:     Optional[str] = None
    claw:            str                               # e.g. "identityclaw"
    category:        Optional[str] = None              # e.g. "Core Security"
    icon:            Optional[str] = None              # emoji
    execution_mode:  ExecutionMode   = ExecutionMode.MONITOR
    risk_level:      RiskLevel       = RiskLevel.LOW
    max_runtime_sec: int             = 300
    requires_approval: bool          = False
    allowed_actions:   Optional[str] = None            # JSON list string
    allowed_connectors: Optional[str] = None           # JSON list string
    scope_notes:     Optional[str]   = None
    owner_id:        Optional[str]   = None
    owner_name:      Optional[str]   = None
    status:          AgentStatus     = AgentStatus.ACTIVE
    is_builtin:      bool            = False


class AgentCreate(AgentBase):
    pass


class AgentUpdate(BaseModel):
    name:             Optional[str]           = None
    description:      Optional[str]           = None
    execution_mode:   Optional[ExecutionMode] = None
    risk_level:       Optional[RiskLevel]     = None
    max_runtime_sec:  Optional[int]           = None
    requires_approval: Optional[bool]         = None
    allowed_actions:  Optional[str]           = None
    allowed_connectors: Optional[str]         = None
    scope_notes:      Optional[str]           = None
    owner_id:         Optional[str]           = None
    owner_name:       Optional[str]           = None
    status:           Optional[AgentStatus]   = None


class AgentRead(AgentBase):
    id:              uuid.UUID
    total_runs:      int
    last_run_at:     Optional[datetime]
    last_run_status: Optional[str]
    created_at:      datetime
    updated_at:      datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────
# Schedule
# ─────────────────────────────────────────────

class ScheduleBase(BaseModel):
    name:               str
    agent_id:           uuid.UUID
    connector_id:       Optional[uuid.UUID] = None
    frequency:          ScheduleFrequency   = ScheduleFrequency.DAILY
    cron_expression:    Optional[str]       = None
    status:             ScheduleStatus      = ScheduleStatus.ACTIVE
    approval_required:  bool                = False
    owner_id:           Optional[str]       = None
    owner_name:         Optional[str]       = None
    notes:              Optional[str]       = None


class ScheduleCreate(ScheduleBase):
    pass


class ScheduleUpdate(BaseModel):
    name:              Optional[str]             = None
    connector_id:      Optional[uuid.UUID]       = None
    frequency:         Optional[ScheduleFrequency] = None
    cron_expression:   Optional[str]             = None
    status:            Optional[ScheduleStatus]  = None
    approval_required: Optional[bool]            = None
    owner_id:          Optional[str]             = None
    owner_name:        Optional[str]             = None
    notes:             Optional[str]             = None
    next_run_at:       Optional[datetime]        = None


class ScheduleRead(ScheduleBase):
    id:          uuid.UUID
    next_run_at: Optional[datetime]
    last_run_at: Optional[datetime]
    run_count:   int
    created_at:  datetime
    updated_at:  datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────
# AgentRun
# ─────────────────────────────────────────────

class AgentRunBase(BaseModel):
    agent_id:       uuid.UUID
    schedule_id:    Optional[uuid.UUID] = None
    execution_mode: ExecutionMode       = ExecutionMode.MONITOR
    triggered_by:   str                 = "manual"


class AgentRunCreate(AgentRunBase):
    pass


class AgentRunRead(AgentRunBase):
    id:              uuid.UUID
    status:          RunStatus
    policy_decision: Optional[str]
    policy_name:     Optional[str]
    risk_score:      Optional[float]
    tf_blocked:      bool
    findings_count:  int
    actions_taken:   Optional[str]    # JSON
    actions_blocked: Optional[str]    # JSON
    actions_pending: Optional[str]    # JSON
    summary:         Optional[str]
    run_log:         Optional[str]    # JSON
    error_message:   Optional[str]
    started_at:      Optional[datetime]
    completed_at:    Optional[datetime]
    duration_sec:    Optional[float]
    created_at:      datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────
# Manual trigger request/response
# ─────────────────────────────────────────────

class AgentTriggerRequest(BaseModel):
    connector_id:   Optional[uuid.UUID] = None
    execution_mode: Optional[ExecutionMode] = None   # override agent default for this run
    triggered_by:   str = "manual"


class AgentTriggerResponse(BaseModel):
    run_id:  uuid.UUID
    status:  RunStatus
    message: str


# ─────────────────────────────────────────────
# Approval action (assist mode)
# ─────────────────────────────────────────────

class ApprovalAction(BaseModel):
    action_index: int    # index into actions_pending list
    approved:     bool
    notes:        Optional[str] = None
