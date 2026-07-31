"""Persistent runtime state for the Enkstein distributed architecture."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PlexusMessage(Base):
    __tablename__ = "marcellus_plexus_messages"
    __table_args__ = (
        UniqueConstraint("tenant_id", "sender_node_id", "nonce", name="uq_plexus_sender_nonce"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_plexus_idempotency"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    sender_node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    recipient_node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    message_type: Mapped[str] = mapped_column(String(128), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    parent_message_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)

    payload_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_json: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)

    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    policy_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReflexDefinition(Base):
    __tablename__ = "marcellus_reflex_definitions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_reflex_tenant_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    conditions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    action_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    action_config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    authority: Mapped[str] = mapped_column(String(32), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    max_runs_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class ReflexExecution(Base):
    __tablename__ = "marcellus_reflex_executions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "reflex_id", "event_id", name="uq_reflex_event"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    reflex_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    event_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    event_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    plexus_message_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NodeCheckpoint(Base):
    __tablename__ = "marcellus_node_checkpoints"
    __table_args__ = (
        UniqueConstraint("tenant_id", "node_id", "version", name="uq_checkpoint_node_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    state_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    state_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    envelope_json: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CapabilityNodeRuntime(Base):
    __tablename__ = "marcellus_node_runtimes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "node_id", name="uq_runtime_tenant_node"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String(64), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="quarantined", index=True)
    state_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    state_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_json: Mapped[str] = mapped_column(Text, nullable=False)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    health_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    regenerated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    last_health_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RegenerationRun(Base):
    __tablename__ = "marcellus_regeneration_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    checkpoint_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    policy_outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_name: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    stages_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    verification_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CortexProject(Base):
    __tablename__ = "marcellus_cortex_projects"
    __table_args__ = (
        UniqueConstraint("tenant_id", "owner_id", "kind", "name", name="uq_cortex_project_owner_kind_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # "cowork" projects can bind a local folder and hold artifacts/native sync
    # state; "chat" projects are a lightweight grouping folder for organizing
    # Chat conversations only and never touch native-folder/artifact state.
    # Kept on the same table (not a new model) so both share one create/list/
    # rename/archive implementation; every route filters by kind so a Chat
    # folder can never appear in Cowork's project picker or vice versa.
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="cowork", index=True)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    default_source: Mapped[str] = mapped_column(String(128), nullable=False, default="auto")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class CortexConversation(Base):
    __tablename__ = "marcellus_cortex_conversations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="New conversation")
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="chat", index=True)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    selected_source: Mapped[str] = mapped_column(String(128), nullable=False, default="auto")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    branch_of_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    branch_message_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    message_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        index=True,
    )


class CortexConversationMessage(Base):
    __tablename__ = "marcellus_cortex_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    conversation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    content_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    governance_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    parent_message_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)


class CortexArtifact(Base):
    __tablename__ = "marcellus_cortex_artifacts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "project_id", "path", "version", name="uq_cortex_artifact_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False, default="text/plain")
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    content_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class CortexMission(Base):
    __tablename__ = "marcellus_cortex_missions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "owner_id", "name", name="uq_cortex_mission_owner_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    objective_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    objective_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active", index=True)
    cadence: Mapped[str] = mapped_column(String(32), nullable=False, default="daily")
    autonomy_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="assist")
    profile: Mapped[str] = mapped_column(String(64), nullable=False, default="DEEP_INVESTIGATION")
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    participants_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    parallelism: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    model_profile: Mapped[str | None] = mapped_column(String(128), nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latest_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    latest_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)


class CortexMissionObservation(Base):
    __tablename__ = "marcellus_cortex_mission_observations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "mission_id", "job_id", name="uq_cortex_mission_job_observation"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    mission_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed", index=True)
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="low")
    summary_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    summary_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    proposed_by: Mapped[str] = mapped_column(String(255), nullable=False, default="mission-runtime")
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CortexOvernightBrief(Base):
    __tablename__ = "marcellus_cortex_overnight_briefs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)


class CoworkJob(Base):
    """Durable unit of Cowork work.

    Authoritative state for a Cowork request lives here, never in the HTTP
    request or the browser. A job therefore survives a tab refresh, an SSE
    disconnect, a desktop restart, a suspended Companion service worker, and a
    provider timeout: the client reconnects by job id and replays the durable
    event log rather than re-driving the work.

    Exactly one project and one approved local root are bound at creation
    (``project_id`` + ``root_token_digest``); the binding is never re-resolved
    later, so a job started against project A can never write into project B
    even if the operator switches projects mid-flight.
    """

    __tablename__ = "marcellus_cowork_jobs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_cowork_job_idempotency"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    conversation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    # Client-supplied de-duplication key. A retried create with the same key
    # returns the existing job instead of starting a second run against the
    # same provider (see requirement 4: never submit a duplicate prompt).
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)

    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    # Terminal jobs keep the state that ended them; ``detail`` carries an
    # operator-safe reason only (never provider text, prompts, or paths).
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="cowork")
    source: Mapped[str] = mapped_column(String(128), nullable=False, default="auto")
    runtime_group: Mapped[str] = mapped_column(String(32), nullable=False, default="hybrid")
    classification: Mapped[str] = mapped_column(String(32), nullable=False, default="internal")
    # Requested executor preference ("auto" | "enkstein_local" | "codex_app_server"
    # | "unavailable") and the executor actually used. Stored separately so the
    # UI can show what was asked for and what really ran.
    executor_preference: Mapped[str] = mapped_column(String(32), nullable=False, default="auto")
    executor_used: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Terminal outcome (completed_verified / completed_with_failures /
    # completed_unverified / blocked / failed / cancelled). Distinct from
    # ``state`` so "completed" is never mistaken for "verified".
    outcome: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    # Canonical workspace binding (requirement 2). The absolute host path is
    # never stored; only the opaque binding digest and a display alias.
    root_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    root_alias: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workspace_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    workspace_snapshot_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    request_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    result_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Heartbeat of the process currently advancing this job. A job whose lease
    # has gone stale is recoverable (resume) rather than silently abandoned.
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow, index=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CoworkJobStep(Base):
    """One addressable stage of a job so a single failure can be retried."""

    __tablename__ = "marcellus_cowork_job_steps"
    __table_args__ = (
        UniqueConstraint("job_id", "ordinal", name="uq_cowork_step_ordinal"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    retryable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class CoworkJobEvent(Base):
    """Append-only timeline; the only source of truth for stream and poll.

    Clients resume with ``after_sequence`` so a reconnect replays exactly the
    frames it missed. Payloads are encrypted and carry operator-safe summaries
    only -- never prompts, provider text, credentials, or absolute paths.
    """

    __tablename__ = "marcellus_cowork_job_events"
    __table_args__ = (
        UniqueConstraint("job_id", "sequence", name="uq_cowork_event_sequence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    step_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    payload_ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)


class CoworkBrowserTask(Base):
    """Durable Browser Companion exchange for one job."""

    """Durable Browser Companion exchange for one job.

    The Companion is an advisor, not a filesystem authority: this row records
    what was asked and what came back, and nothing here can write to disk. The
    unique submission key is what guarantees a reconnect resumes the existing
    provider conversation instead of submitting a second prompt.
    """

    __tablename__ = "marcellus_cowork_browser_tasks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "submission_key", name="uq_cowork_browser_submission"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    submission_key: Mapped[str] = mapped_column(String(128), nullable=False)
    retry_token: Mapped[str] = mapped_column(String(128), nullable=False)

    state: Mapped[str] = mapped_column(String(32), nullable=False, default="submitted", index=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    provider_tab_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    provider_conversation_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    chunk_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    response_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attachments_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CoworkExecution(Base):
    """One governed command execution.

    Durable so a command can be cancelled by id after the request that started
    it is gone, and so an operator can audit exactly what ran, where, and for
    how long. Command text is stored (it is allowlisted and argv-only, never a
    shell string); output is not stored here -- only the bounded, redacted
    summary that reaches the job timeline.
    """

    __tablename__ = "marcellus_cowork_executions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "execution_id", name="uq_cowork_execution_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    execution_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    executor: Mapped[str] = mapped_column(String(32), nullable=False)
    command_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    command: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="running", index=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    timed_out: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancelled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sandboxed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
