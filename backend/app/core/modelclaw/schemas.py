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
    requester_subject: str | None = None
    requester_role: str | None = None
    orchestrator_identity: str | None = None
    specialist_identity: str | None = None
    workspace_id: str | None = None
    dependency_evidence_ids: list[str] = Field(default_factory=list)


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


class CliLoginLaunchRequest(BaseModel):
    brain: str = Field(..., pattern="^(codex_subscription|claude_subscription)$")


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


SpecialistRole = Literal[
    "router",
    "context_worker",
    "planner",
    "coder",
    "researcher",
    "security_analyst",
    "security_reviewer",
    "utility_parser",
    "reviewer",
    "test_reviewer",
    "swarm_judge",
    "final_judge",
]


class CortexTaskNode(BaseModel):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")
    role: SpecialistRole
    instruction: str = Field(min_length=1, max_length=12000)
    depends_on: list[str] = Field(default_factory=list, max_length=6)
    sources: list[str] = Field(default_factory=lambda: ["auto"], min_length=1, max_length=4)
    timeout_seconds: int = Field(default=90, ge=5, le=180)


class CortexTaskGraphRequest(BaseModel):
    objective: str = Field(min_length=1, max_length=12000)
    nodes: list[CortexTaskNode] = Field(min_length=1, max_length=7)
    mode: Literal["chat", "cowork", "security"] = "cowork"
    runtime_group: RuntimeGroup = "hybrid"
    data_classification: str = Field(default="internal", max_length=64)
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    workspace_id: str | None = Field(default=None, max_length=128)
    parallelism: int = Field(default=3, ge=1, le=3)

    @model_validator(mode="after")
    def validate_graph(self):
        ids = [node.id for node in self.nodes]
        if len(ids) != len(set(ids)):
            raise ValueError("Task node ids must be unique")
        known = set(ids)
        for node in self.nodes:
            if node.id in node.depends_on or any(dep not in known for dep in node.depends_on):
                raise ValueError("Task dependencies must reference another node")
            for source in node.sources:
                valid = source in {
                    "auto", "codex_subscription", "claude_subscription",
                    "chatgpt_desktop", "claude_desktop", "chatgpt_browser",
                    "claude_browser", "gemini_browser",
                } or source.startswith("profile:")
                if not valid:
                    raise ValueError("Unsupported specialist source")
        remaining = {node.id: set(node.depends_on) for node in self.nodes}
        resolved: set[str] = set()
        while remaining:
            ready = {node_id for node_id, deps in remaining.items() if deps <= resolved}
            if not ready:
                raise ValueError("Task graph must be acyclic")
            resolved |= ready
            for node_id in ready:
                remaining.pop(node_id)
        return self


class CortexTaskResult(BaseModel):
    id: str
    role: SpecialistRole
    status: Literal["completed", "blocked", "unavailable", "timed_out", "skipped"]
    response: str | None = None
    evidence_from: list[str] = Field(default_factory=list)
    source: str | None = None
    provider: str | None = None
    model: str | None = None
    route_reason: str | None = None
    fallback_reason: str | None = None
    latency_ms: int = 0
    policy: dict[str, Any] = Field(default_factory=dict)
    attempts: list[dict[str, Any]] = Field(default_factory=list)


class CortexTaskGraphResponse(BaseModel):
    status: Literal["completed", "partial", "blocked"]
    results: list[CortexTaskResult]
    execution_order: list[str]
