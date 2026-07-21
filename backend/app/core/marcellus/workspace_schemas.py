from __future__ import annotations

import posixpath
import json
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.modelclaw.schemas import RuntimeGroup


Classification = Literal["public", "internal", "confidential", "restricted", "top_secret"]
WorkspaceMode = Literal["chat", "cowork", "security"]


class CortexProjectCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=2000)
    classification: Classification = "internal"
    default_source: str = Field(default="auto", min_length=2, max_length=128)
    kind: Literal["cowork", "chat"] = "cowork"


class CortexProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    owner_id: str
    name: str
    description: str
    kind: str
    classification: str
    default_source: str
    status: str
    created_at: datetime
    updated_at: datetime


class CortexNativeWorkspaceBind(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    token: str = Field(pattern=r"^[a-f0-9-]{36}$")
    name: str = Field(min_length=1, max_length=255)
    # A short, non-reversible display alias for the approved root (e.g. the
    # folder name plus its parent segment) so the UI can confirm which folder
    # was granted without the absolute host path ever crossing the boundary.
    path_alias: str | None = Field(default=None, max_length=255)


class CortexNativeWorkspaceRead(BaseModel):
    connected: bool
    name: str | None = None
    path_alias: str | None = None
    file_count: int = 0
    synced_files: int = 0
    removed_files: int = 0


class CortexNativePickRead(BaseModel):
    """Opaque result of a host folder-picker grant: never carries a raw path."""

    token: str = Field(pattern=r"^[a-f0-9-]{36}$")
    name: str = Field(min_length=1, max_length=255)
    path_alias: str | None = Field(default=None, max_length=255)


class CortexNativeProjectPickCreate(BaseModel):
    """Request to open the host folder picker and, only on picker success,
    create a Cowork project bound to the approved root."""

    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    classification: Classification = "internal"
    default_source: str = Field(default="auto", min_length=2, max_length=128)


class CortexNativeProjectRead(BaseModel):
    """Combined result of a picker-and-create: the new project plus the opaque
    local-folder binding state. No absolute host path is ever included."""

    project: CortexProjectRead
    workspace: CortexNativeWorkspaceRead


class CortexConversationCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    project_id: UUID | None = None
    title: str = Field(default="New conversation", min_length=1, max_length=255)
    mode: WorkspaceMode = "chat"
    classification: Classification = "internal"
    selected_source: str = Field(default="auto", min_length=2, max_length=128)


class CortexConversationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    owner_id: str
    project_id: UUID | None
    title: str
    mode: str
    classification: str
    selected_source: str
    status: str
    branch_of_id: UUID | None
    branch_message_id: UUID | None
    message_count: int
    created_at: datetime
    updated_at: datetime


class CortexConversationMove(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    project_id: UUID


class CortexConversationRename(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=255)


class CortexConversationDeleteRead(BaseModel):
    id: UUID
    status: Literal["deleted"] = "deleted"


class CortexMessageRead(BaseModel):
    id: UUID
    tenant_id: str
    conversation_id: UUID
    role: str
    content: str
    classification: str
    source: str | None
    provider: str | None
    model: str | None
    governance: dict[str, Any]
    parent_message_id: UUID | None
    created_at: datetime


class CortexConversationDetail(CortexConversationRead):
    messages: list[CortexMessageRead] = Field(default_factory=list)


class CortexTurnCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=12000)
    source: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    data_classification: Classification | None = None
    # Request-level only: there is no compatible existing storage column to
    # persist this per conversation/project without a migration, so the
    # caller must resend it on every turn. Omitted => hybrid (unchanged
    # legacy local-first-with-CLI/API-fallback behavior).
    runtime_group: RuntimeGroup | None = None
    artifact_ids: list[UUID] = Field(default_factory=list, max_length=20)
    include_project_files: bool = True
    minimum_votes: int = Field(default=2, ge=1, le=8)
    # Only used when source="consensus": lets the operator build a custom
    # swarm (any mix of browser/API/local/subscription Brains) instead of
    # the Gateway's own fixed default list. None => the Gateway's existing
    # default consensus_sources is used unchanged.
    consensus_sources: list[str] | None = Field(default=None, max_length=8)
    agent_mode: bool = False
    context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("consensus_sources")
    @classmethod
    def _dedupe_consensus_sources(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        deduped = list(dict.fromkeys(value))
        if not deduped:
            raise ValueError("consensus_sources must include at least one Brain")
        return deduped


class CortexTurnRead(BaseModel):
    conversation: CortexConversationRead
    user_message: CortexMessageRead
    assistant_message: CortexMessageRead | None = None
    gateway: dict[str, Any]


class CortexBranchCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    message_id: UUID
    title: str | None = Field(default=None, max_length=255)


class CortexArtifactItem(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=1_000_000)
    mime_type: str = Field(default="text/plain", min_length=1, max_length=128)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        raw = value.strip().replace("\\", "/")
        normalized = posixpath.normpath(raw).lstrip("/")
        if normalized in {"", "."} or normalized == ".." or normalized.startswith("../"):
            raise ValueError("Artifact path must remain within the project")
        if any(part in {".git", ".secrets", "node_modules"} for part in normalized.split("/")):
            raise ValueError("Artifact path targets a protected project directory")
        return normalized


class CortexArtifactBatchCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    project_id: UUID
    conversation_id: UUID | None = None
    classification: Classification = "internal"
    files: list[CortexArtifactItem] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_total_size(self):
        if sum(len(item.content.encode("utf-8")) for item in self.files) > 5_000_000:
            raise ValueError("Artifact batch exceeds 5 MB")
        return self


class CortexArtifactUpdate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=1_000_000)
    mime_type: str = Field(default="text/plain", min_length=1, max_length=128)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return CortexArtifactItem.normalize_path(value)


class CortexArtifactRead(BaseModel):
    id: UUID
    tenant_id: str
    project_id: UUID
    conversation_id: UUID | None
    path: str
    mime_type: str
    size_bytes: int
    content_digest: str
    classification: str
    version: int
    status: str
    created_by: str
    created_at: datetime
    content: str | None = None


class CortexChangeProposalRead(BaseModel):
    id: UUID
    project_id: UUID
    conversation_id: UUID | None
    operation: Literal["create", "update", "delete"]
    path: str
    status: str
    proposed_content: str | None = None
    current_content: str | None = None
    base_digest: str | None = None
    # Set when the approved change moves an existing file: the prior project
    # path whose approved application is a native ``rename`` rather than a
    # create-then-trash, so the host file is moved in place.
    previous_path: str | None = None
    # Review-surface metadata for a pending write: a unified diff, the files a
    # reviewer must approve, heuristic test targets, and the metadata needed to
    # undo the change after it is applied. All are derived (never persisted raw
    # host state) so an approver can judge a consequential write before it
    # reaches the approved root.
    diff: str | None = None
    affected_paths: list[str] = Field(default_factory=list)
    suggested_tests: list[str] = Field(default_factory=list)
    rollback: dict[str, Any] = Field(default_factory=dict)
    created_by: str
    created_at: datetime


class CortexChangeReview(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    decision: Literal["approve", "reject"]
    reason: str = Field(default="", max_length=1000)


class CortexResearchCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    conversation_id: UUID
    question: str = Field(min_length=3, max_length=4000)
    urls: list[str] = Field(min_length=1, max_length=8)
    source: str | None = Field(default=None, max_length=128)
    model: str | None = Field(default=None, max_length=128)
    data_classification: Classification | None = None

    @field_validator("urls")
    @classmethod
    def normalize_urls(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value.strip() for value in values if value.strip()))
        if not normalized:
            raise ValueError("At least one research URL is required")
        if any(len(value) > 2048 for value in normalized):
            raise ValueError("Research URLs cannot exceed 2048 characters")
        return normalized


class CortexCitationRead(BaseModel):
    id: int
    url: str
    title: str
    retrieved_at: datetime
    content_type: str
    content_digest: str
    excerpt: str


class CortexResearchRead(BaseModel):
    status: str
    turn: CortexTurnRead
    source_artifact: CortexArtifactRead
    report_artifact: CortexArtifactRead
    citations: list[CortexCitationRead]
    tool_trace: list[dict[str, Any]]


class CortexToolRead(BaseModel):
    name: str
    description: str
    capability: str
    input_schema: dict[str, Any]


class CortexToolInvoke(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    project_id: UUID
    conversation_id: UUID | None = None
    tool: Literal["browser.fetch", "workspace.search"]
    arguments: dict[str, Any] = Field(default_factory=dict)
    data_classification: Classification = "internal"

    @field_validator("arguments")
    @classmethod
    def limit_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(value, separators=(",", ":"))) > 20_000:
            raise ValueError("Tool arguments exceed the 20 KB limit")
        return value


class CortexToolResult(BaseModel):
    tool: str
    status: str
    policy: dict[str, Any]
    result: dict[str, Any]


class CortexSearchResult(BaseModel):
    conversation: CortexConversationRead
    matching_message_id: UUID | None = None
    excerpt: str | None = None


class CortexWorkspaceSummary(BaseModel):
    projects: int
    active_conversations: int
    artifacts: int
    messages: int


CodexSandbox = Literal["read-only", "workspace-write"]


def _reject_local_runtime(value: RuntimeGroup | None) -> RuntimeGroup | None:
    # The Codex App Server is an external subscription CLI, so a local-only
    # runtime group must never reach it. Omitted => hybrid (governed default).
    if value == "local":
        raise ValueError("Codex App Server cannot run in a local-only runtime group")
    return value


class CortexCodexStart(BaseModel):
    """Open (or resume) the root-bound Codex App Server thread for a Cowork
    conversation. The server derives the scope digest and native binding token;
    the web client never supplies a cwd, thread id, token, or scope digest."""

    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    sandbox: CodexSandbox = "read-only"
    runtime_group: RuntimeGroup | None = None

    @field_validator("runtime_group")
    @classmethod
    def reject_local(cls, value: RuntimeGroup | None) -> RuntimeGroup | None:
        return _reject_local_runtime(value)


class CortexCodexTurn(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    prompt: str = Field(min_length=1, max_length=12000)
    runtime_group: RuntimeGroup | None = None

    @field_validator("runtime_group")
    @classmethod
    def reject_local(cls, value: RuntimeGroup | None) -> RuntimeGroup | None:
        return _reject_local_runtime(value)


class CortexCodexApproval(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    decision: Literal["accept", "decline"]


class CortexCodexCancel(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)


class CortexCodexStartRead(BaseModel):
    status: str
    sandbox: str
    resumed: bool = False


class CortexCodexTurnRead(BaseModel):
    status: str
    cursor: int = 0
    turn_active: bool = False
    # Safe policy/redaction metadata only: never the prompt, command, or CLI text.
    policy: dict[str, Any] = Field(default_factory=dict)


class CortexCodexEvent(BaseModel):
    cursor: int
    channel: str
    fields: dict[str, Any] = Field(default_factory=dict)


class CortexCodexPendingApproval(BaseModel):
    approval_id: str
    method: str
    # Native bridge allowlist: bounded command/reason/cwd basename and opaque
    # item/turn identifiers only. Permissions requests remain detail-free.
    detail: dict[str, Any] = Field(default_factory=dict)
    deny_only: bool = False


class CortexCodexStatusRead(BaseModel):
    status: str
    transport: str
    session: str
    turn: str
    cursor: int = 0
    events: list[CortexCodexEvent] = Field(default_factory=list)
    pending_approvals: list[CortexCodexPendingApproval] = Field(default_factory=list)
    # Safe aggregate scan metadata for the redacted native status: counts and
    # boolean signals only — never any streamed raw command/diff/plan text.
    scan: dict[str, Any] = Field(default_factory=dict)


class CortexCodexApprovalRead(BaseModel):
    status: str
    decision: str
    governed: bool = True


class CortexCodexCancelRead(BaseModel):
    status: str


class CortexSecurityInvestigationCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    requires_approval: bool = True
    participants: list[str] = Field(
        default_factory=lambda: [
            "arcclaw",
            "threatclaw",
            "identityclaw",
            "cloudclaw",
            "dataclaw",
            "complianceclaw",
        ],
        min_length=2,
        max_length=12,
    )


class CortexSecurityInvestigationRead(BaseModel):
    job_id: UUID
    status: str
    name: str
    requires_approval: bool
    conversation_id: UUID
