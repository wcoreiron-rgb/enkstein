"""Request/response contracts for the durable Cowork job surface."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.core.marcellus.workspace_schemas import CortexTurnCreate


class CoworkJobCreate(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    conversation_id: UUID
    turn: CortexTurnCreate
    # Supplied by the client so a retried create (flaky network, reloaded tab)
    # resolves to the same job instead of starting a second provider run.
    idempotency_key: str | None = Field(default=None, max_length=128)
    inspect_workspace: bool = True
    # Which Executor performs commands/tests. Independent of the Brain: any
    # Brain composes with any Executor. "auto" prefers the local desktop
    # runtime and falls back to Codex.
    executor: Literal["auto", "enkstein_local", "codex_app_server", "unavailable"] = "auto"


class CoworkJobStepRead(BaseModel):
    id: UUID
    ordinal: int
    kind: str
    state: str
    label: str
    retryable: bool
    attempt: int
    error_detail: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class CoworkJobEventRead(BaseModel):
    sequence: int
    event_type: str
    state: str | None = None
    step_id: UUID | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class CoworkBrowserTaskRead(BaseModel):
    id: UUID
    provider: str
    state: str
    provider_tab_id: str | None = None
    provider_conversation_id: str | None = None
    heartbeat_at: datetime | None = None
    chunk_count: int = 0
    truncated: bool = False
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    failure_reason: str | None = None
    retry_token: str | None = None
    completed_at: datetime | None = None


class CoworkJobRead(BaseModel):
    id: UUID
    tenant_id: str
    owner_id: str
    project_id: UUID | None = None
    conversation_id: UUID
    state: str
    mode: str
    source: str
    runtime_group: str
    classification: str
    executor_preference: str = "auto"
    executor_used: str | None = None
    executor_label: str | None = None
    outcome: str | None = None
    root_alias: str | None = None
    workspace_branch: str | None = None
    workspace_snapshot_digest: str | None = None
    failure_reason: str | None = None
    cancel_requested: bool = False
    attempt: int = 0
    steps: list[CoworkJobStepRead] = Field(default_factory=list)
    browser_task: CoworkBrowserTaskRead | None = None
    result: dict[str, Any] | None = None
    latest_sequence: int = 0
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None


class CoworkJobResultRead(BaseModel):
    job_id: UUID
    state: str
    outcome: str | None = None
    result: dict[str, Any] | None = None
    failure_reason: str | None = None


class CoworkExecutorRead(BaseModel):
    executor: str
    label: str
    available: bool
    reason: str = ""


class CoworkExecutorStatusRead(BaseModel):
    """What the UI needs to show a real Executor field instead of guessing."""

    executors: list[CoworkExecutorRead]
    selected: str
    selected_label: str
    any_available: bool


class CoworkRetryRequest(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    step_id: UUID | None = None


class CoworkResumeRequest(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)


class CoworkBrowserAck(BaseModel):
    """Companion acknowledgement that it accepted a task into a provider tab."""

    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    submission_key: str = Field(min_length=1, max_length=128)
    provider_tab_id: str | None = Field(default=None, max_length=128)
    provider_conversation_id: str | None = Field(default=None, max_length=255)


class CoworkBrowserProgress(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    submission_key: str = Field(min_length=1, max_length=128)
    state: Literal["composing", "streaming", "waiting"] = "streaming"
    chunk: str | None = Field(default=None, max_length=200_000)


class CoworkBrowserComplete(BaseModel):
    tenant_id: str = Field(default="global", min_length=1, max_length=128)
    submission_key: str = Field(min_length=1, max_length=128)
    response: str = Field(default="", max_length=1_000_000)
    attachments: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    truncated: bool = False
    failure_reason: str | None = Field(default=None, max_length=500)
