from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ModelProviderRead(BaseModel):
    provider: str
    enabled: bool
    default_model: str
    supports_tool_calling: bool


class ModelProfileCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    provider: str = Field(..., min_length=2, max_length=64)
    model: str = Field(..., min_length=2, max_length=256)
    allowed_models: list[str] = Field(default_factory=list, max_length=64)
    allowed_claws: list[str] = Field(default_factory=list)
    allowed_data_classes: list[str] = Field(default_factory=lambda: ["public", "internal"])
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4000, ge=64, le=128000)
    tool_calling: bool = True
    requires_redaction: bool = True
    fallback_profile: str | None = None
    tenant_id: str = Field(default="global", min_length=1, max_length=128)

    @model_validator(mode="after")
    def include_default_model(self):
        if self.allowed_models and self.model not in self.allowed_models:
            raise ValueError("The default model must be included in allowed_models")
        return self


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


BrainReadinessStatus = Literal["ready", "needs_setup", "unavailable", "policy_blocked"]


class BrainStatusRead(BaseModel):
    brain: str
    kind: str
    available: bool
    authenticated: bool
    status: BrainReadinessStatus = "unavailable"
    runtime: str | None = None
    account_type: str | None = None
    models: list[str] = Field(default_factory=list)
    supports_custom_model: bool = False
    detail: str | None = None
    last_checked: datetime | None = None


class BrainInvokeRequest(BaseModel):
    brain: str = Field(
        ...,
        pattern="^(codex_subscription|claude_subscription|chatgpt_desktop|claude_desktop|chatgpt_browser|claude_browser|gemini_browser)$",
    )
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


RuntimeGroup = Literal["local", "hybrid", "cloud"]


class ConsensusRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=24000)
    sources: list[str] = Field(
        default_factory=lambda: [
            "codex_subscription",
            "claude_subscription",
            "profile:nim_fast_reasoning",
            "profile:gemini_general",
            "profile:ollama_local_fallback",
        ],
        min_length=1,
        max_length=8,
    )
    claw: str = Field(default="executive", min_length=2, max_length=64)
    data_classification: str = Field(default="internal", max_length=64)
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    minimum_votes: int = Field(default=2, ge=1, le=8)
    # Legacy requests omit this field entirely; the "hybrid" default keeps
    # their existing local-first-with-CLI/API-fallback behavior unchanged.
    runtime_group: RuntimeGroup = "hybrid"
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


class CortexMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=120000)


class CortexGatewayRequest(BaseModel):
    mode: Literal["chat", "cowork", "security"] = "chat"
    messages: list[CortexMessage] = Field(..., min_length=1, max_length=24)
    source: str = Field(default="auto", min_length=2, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    # Legacy requests omit this field entirely; the "hybrid" default keeps
    # their existing local-first-with-CLI/API-fallback behavior unchanged.
    runtime_group: RuntimeGroup = "hybrid"
    consensus_sources: list[str] = Field(
        default_factory=lambda: [
            "codex_subscription",
            "claude_subscription",
            "profile:nim_fast_reasoning",
            "profile:gemini_general",
            "profile:ollama_local_fallback",
        ],
        min_length=1,
        max_length=8,
    )
    minimum_votes: int = Field(default=2, ge=1, le=8)
    data_classification: str = Field(default="internal", max_length=64)
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    capability: str = Field(default="executive", min_length=2, max_length=64)
    workspace_id: str | None = Field(default=None, max_length=128)
    context: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_total_context(self):
        if sum(len(message.content) for message in self.messages) > 120000:
            raise ValueError("Conversation context exceeds 120000 characters")
        valid_source = self.source in {
            "auto",
            "consensus",
            "codex_subscription",
            "claude_subscription",
            "chatgpt_desktop",
            "claude_desktop",
            "chatgpt_browser",
            "claude_browser",
            "gemini_browser",
        }
        if not valid_source and not self.source.startswith("profile:"):
            raise ValueError("Unsupported Cortex source")
        return self


class CortexGovernanceRead(BaseModel):
    outcome: str
    policy_name: str
    reason: str
    risk_score: float = Field(ge=0.0, le=100.0)
    data_classification: str
    input_redacted: bool = False
    output_redacted: bool = False
    injection_risk: bool = False
    injection_vectors: list[str] = Field(default_factory=list)


class CortexGatewayResponse(BaseModel):
    status: str
    response: str | None = None
    source: str | None = None
    provider: str | None = None
    model: str | None = None
    mode: str
    governance: CortexGovernanceRead
    votes: list[BrainVoteRead] = Field(default_factory=list)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    agreement: str | None = None
    routing: dict[str, Any] | None = None
    latency_ms: int | None = None
