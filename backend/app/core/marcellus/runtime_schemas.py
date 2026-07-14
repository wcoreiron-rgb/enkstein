from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.marcellus.schemas import AuthorityCeiling


TenantId = str
Classification = Literal["public", "internal", "confidential", "restricted"]


class PlexusMessageCreate(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    sender_node_id: str = Field(min_length=1, max_length=128)
    recipient_node_id: str = Field(min_length=1, max_length=128)
    message_type: str = Field(default="capability.request", min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    classification: Classification = "internal"
    ttl_seconds: int = Field(default=900, ge=5, le=3600)
    correlation_id: str | None = Field(default=None, max_length=128)
    trace_id: str | None = Field(default=None, max_length=128)
    parent_message_id: str | None = Field(default=None, max_length=64)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=128)


class PlexusMessageRead(BaseModel):
    id: UUID
    tenant_id: str
    sender_node_id: str
    recipient_node_id: str
    message_type: str
    classification: str
    correlation_id: str
    trace_id: str
    parent_message_id: str | None
    idempotency_key: str | None
    payload_digest: str
    payload: dict[str, Any] | None = None
    signature: str
    signature_algorithm: str
    key_id: str
    status: str
    policy_outcome: str
    policy_name: str
    policy_reason: str
    risk_score: float
    created_by: str
    approved_by: str | None
    rejection_reason: str | None
    created_at: datetime
    expires_at: datetime
    delivered_at: datetime | None
    processed_at: datetime | None


class PlexusAcknowledge(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    recipient_node_id: str = Field(min_length=1, max_length=128)


class TenantAction(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=1000)


class ReflexCondition(BaseModel):
    field: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    operator: Literal["eq", "neq", "in", "contains", "gte", "lte"] = "eq"
    value: Any


class ReflexDefinitionCreate(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    node_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    conditions: list[ReflexCondition] = Field(default_factory=list, max_length=20)
    action_kind: Literal["record_signal", "plexus_notify"]
    action_config: dict[str, Any] = Field(default_factory=dict)
    authority: AuthorityCeiling = AuthorityCeiling.RECOMMEND
    classification: Classification = "internal"
    max_runs_per_hour: int = Field(default=10, ge=1, le=120)
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_action_config(self):
        if self.action_kind == "plexus_notify" and not self.action_config.get("recipient_node_id"):
            raise ValueError("plexus_notify requires action_config.recipient_node_id")
        return self


class ReflexDefinitionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    name: str
    node_id: str
    event_type: str
    conditions_json: str
    action_kind: str
    action_config_json: str
    authority: str
    classification: str
    owner_id: str
    is_active: bool
    max_runs_per_hour: int
    cooldown_seconds: int
    run_count: int
    last_run_at: datetime | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReflexEvent(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    event_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)
    classification: Classification = "internal"


class ReflexExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    reflex_id: UUID
    event_id: str
    event_type: str
    event_digest: str
    status: str
    requested_by: str
    approved_by: str | None
    policy_outcome: str
    policy_name: str
    policy_reason: str
    risk_score: float
    result_json: str | None
    error_message: str | None
    plexus_message_id: UUID | None
    created_at: datetime
    completed_at: datetime | None


class CheckpointManifest(BaseModel):
    skills: list[str] = Field(default_factory=list, max_length=100)
    connectors: list[str] = Field(default_factory=list, max_length=100)
    policy_pack_ids: list[str] = Field(default_factory=list, max_length=100)
    memory_refs: list[str] = Field(default_factory=list, max_length=100)
    model_profile: str | None = Field(default=None, max_length=128)
    configuration: dict[str, Any] = Field(default_factory=dict)


class NodeCheckpointCreate(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    node_id: str = Field(min_length=1, max_length=128)
    state: dict[str, Any] = Field(default_factory=dict)
    manifest: CheckpointManifest = Field(default_factory=CheckpointManifest)


class NodeCheckpointRead(BaseModel):
    id: UUID
    tenant_id: str
    node_id: str
    version: int
    state_digest: str
    manifest: dict[str, Any]
    manifest_digest: str
    signature: str
    signature_algorithm: str
    key_id: str
    status: str
    created_by: str
    created_at: datetime
    verified_at: datetime | None


class CheckpointVerification(BaseModel):
    checkpoint_id: UUID
    verified: bool
    checks: dict[str, bool]
    failures: list[str]


class RegenerationStart(BaseModel):
    tenant_id: TenantId = Field(min_length=1, max_length=128)
    checkpoint_id: UUID


class RegenerationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    node_id: str
    checkpoint_id: UUID
    requested_by: str
    approved_by: str | None
    status: str
    policy_outcome: str
    policy_name: str
    policy_reason: str
    risk_score: float
    stages_json: str
    verification_json: str | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class CapabilityNodeRuntimeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    node_id: str
    instance_id: str
    generation: int
    status: str
    state_digest: str
    manifest_json: str
    checkpoint_id: UUID
    health_json: str
    regenerated_at: datetime
    last_health_at: datetime | None
