from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from app.core.marcellus.workspace_schemas import Classification


MissionCadence = Literal["manual", "hourly", "every_6h", "daily", "weekly"]
MissionMode = Literal["monitor", "assist", "approval"]
MissionStatus = Literal["active", "paused", "archived"]


class CortexMissionCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    name: str = Field(min_length=3, max_length=255)
    objective: str = Field(min_length=10, max_length=4000)
    cadence: MissionCadence = "daily"
    autonomy_mode: MissionMode = "assist"
    profile: str = Field(default="DEEP_INVESTIGATION", max_length=64)
    classification: Classification = "internal"
    participants: list[str] = Field(
        default_factory=lambda: ["identityclaw", "cloudclaw", "threatclaw", "dataclaw", "complianceclaw"],
        min_length=2,
        max_length=12,
    )
    parallelism: int = Field(default=4, ge=1, le=12)
    model_profile: str | None = Field(default="swarm_judge_profile", max_length=128)

    @field_validator("participants")
    @classmethod
    def normalize_participants(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip().lower() for value in values if value.strip()))
        if len(normalized) < 2:
            raise ValueError("A Mission requires at least two distinct Security Arms")
        return normalized


class CortexMissionUpdate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    status: MissionStatus | None = None
    cadence: MissionCadence | None = None
    autonomy_mode: MissionMode | None = None


class CortexMissionRead(BaseModel):
    id: UUID
    tenant_id: str
    owner_id: str
    name: str
    objective: str
    status: str
    cadence: str
    autonomy_mode: str
    profile: str
    classification: str
    participants: list[str]
    parallelism: int
    model_profile: str | None
    run_count: int
    latest_job_id: UUID | None
    latest_status: str | None
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime
    updated_at: datetime
    # False when the encrypted objective could not be authenticated with the
    # current runtime key. The row is still listed so it can be inspected or
    # removed, but its objective text is not trustworthy.
    readable: bool = True


class CortexMissionRunRead(BaseModel):
    mission_id: UUID
    job_id: UUID
    status: str
    message: str


class CortexMissionObservationRead(BaseModel):
    id: UUID
    mission_id: UUID
    job_id: UUID
    status: str
    severity: str
    summary: str
    evidence: dict[str, Any]
    proposed_by: str
    reviewed_by: str | None
    review_reason: str | None
    created_at: datetime
    reviewed_at: datetime | None
    readable: bool = True


class CortexMissionObservationReview(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    decision: Literal["approve", "reject"]
    reason: str = Field(default="", max_length=1000)


class CortexOvernightBriefRead(BaseModel):
    id: UUID
    generated_at: datetime
    window_start: datetime
    window_end: datetime
    headline: str
    active_missions: list[dict[str, Any]]
    material_changes: list[dict[str, Any]]
    decisions_needed: list[dict[str, Any]]
    running_arms: list[str]
    recent_reflex_actions: list[dict[str, Any]]
    blocked_actions: list[dict[str, Any]]
    security_twin_health: dict[str, Any]
