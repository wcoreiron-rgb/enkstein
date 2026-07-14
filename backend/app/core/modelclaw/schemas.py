from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ModelProviderRead(BaseModel):
    provider: str
    enabled: bool
    default_model: str
    supports_tool_calling: bool


class ModelProfileCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    provider: str = Field(..., min_length=2, max_length=64)
    model: str = Field(..., min_length=2, max_length=256)
    allowed_claws: list[str] = Field(default_factory=list)
    allowed_data_classes: list[str] = Field(default_factory=lambda: ["public", "internal"])
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4000, ge=64, le=128000)
    tool_calling: bool = True
    requires_redaction: bool = True
    fallback_profile: str | None = None
    tenant_id: str = Field(default="global", min_length=1, max_length=128)


class ModelProfileRead(ModelProfileCreate):
    model_config = ConfigDict(from_attributes=True)
    created_at: datetime


class ModelRouteRequest(BaseModel):
    claw: str = Field(..., min_length=2, max_length=64)
    action_type: str = Field(default="MODEL_CALL", max_length=64)
    prompt: str = Field(..., min_length=1, max_length=24000)
    data_classification: str = Field(default="internal", max_length=64)
    model_profile: str | None = Field(default=None, max_length=128)
    swarm_job_id: str | None = Field(default=None, max_length=128)
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    context: dict[str, Any] = Field(default_factory=dict)


class ModelCallRead(BaseModel):
    id: str
    timestamp: datetime
    claw: str
    provider: str
    model: str
    model_profile: str | None
    tenant_id: str = "global"
    data_classification: str
    outcome: str
    policy_name: str
    reason: str
    latency_ms: int
    token_count: int


class ModelRouteResponse(BaseModel):
    allowed: bool
    outcome: str
    policy_name: str
    reason: str
    provider: str | None = None
    model: str | None = None
    model_profile: str | None = None
    response: str | None = None
    latency_ms: int | None = None
    token_count: int | None = None


class BrainStatusRead(BaseModel):
    brain: str
    kind: str
    available: bool
    authenticated: bool
    runtime: str | None = None
    account_type: str | None = None
    detail: str | None = None


class BrainInvokeRequest(BaseModel):
    brain: str = Field(..., pattern="^(codex_subscription|claude_subscription)$")
    prompt: str = Field(..., min_length=1, max_length=24000)
    model: str | None = Field(default=None, max_length=128)
    claw: str = Field(default="executive", min_length=2, max_length=64)
    data_classification: str = Field(default="internal", max_length=64)
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    context: dict[str, Any] = Field(default_factory=dict)


class BrainVoteRead(BaseModel):
    source: str
    kind: str
    available: bool
    counted: bool
    provider: str | None = None
    model: str | None = None
    response: str | None = None
    reason: str | None = None
    latency_ms: int | None = None
    token_count: int | None = None
    policy_outcome: str | None = None
    audit_id: str | None = None


class BrainInvokeResponse(BrainVoteRead):
    pass


class ConsensusRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=24000)
    sources: list[str] = Field(
        default_factory=lambda: [
            "codex_subscription",
            "claude_subscription",
            "profile:nim_fast_reasoning",
            "profile:ollama_local_fallback",
        ],
        min_length=1,
        max_length=8,
    )
    claw: str = Field(default="executive", min_length=2, max_length=64)
    data_classification: str = Field(default="internal", max_length=64)
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    minimum_votes: int = Field(default=2, ge=1, le=8)
    context: dict[str, Any] = Field(default_factory=dict)


class ConsensusResponse(BaseModel):
    status: str
    consensus: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    agreement: str
    counted_votes: int
    requested_votes: int
    votes: list[BrainVoteRead]
    policy_outcome: str
    synthesis_source: str
