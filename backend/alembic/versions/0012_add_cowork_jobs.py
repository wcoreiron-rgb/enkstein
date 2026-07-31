"""Durable Cowork jobs, steps, events, and browser tasks.

Revision ID: 0012
Revises: 0011

Cowork previously kept the authoritative state of a run inside the HTTP request
that started it, so a refreshed tab, a dropped SSE stream, or a desktop restart
destroyed work that was still legitimately in flight. These tables move that
state into the database: a job is addressable by id, its timeline is an
append-only event log a client can replay from, and a browser exchange is keyed
so a reconnect resumes the provider conversation instead of prompting twice.

All four tables are tenant-scoped from the outset (there are no legacy rows to
preserve), so ownership is NOT NULL here rather than nullable as in the earlier
retro-fit revisions.

Usage:
    alembic upgrade 0012
    alembic downgrade 0011
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


revision:       str                             = "0012"
down_revision:  Union[str, None]               = "0011"
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "marcellus_cowork_jobs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False, index=True),
        sa.Column("owner_id", sa.String(255), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("conversation_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("idempotency_key", sa.String(128), nullable=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="queued", index=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("mode", sa.String(32), nullable=False, server_default="cowork"),
        sa.Column("source", sa.String(128), nullable=False, server_default="auto"),
        sa.Column("runtime_group", sa.String(32), nullable=False, server_default="hybrid"),
        sa.Column("classification", sa.String(32), nullable=False, server_default="internal"),
        sa.Column("executor_preference", sa.String(32), nullable=False, server_default="auto"),
        sa.Column("executor_used", sa.String(32), nullable=True),
        sa.Column("outcome", sa.String(32), nullable=True, index=True),
        sa.Column("root_token_digest", sa.String(64), nullable=True),
        sa.Column("root_alias", sa.String(255), nullable=True),
        sa.Column("workspace_branch", sa.String(255), nullable=True),
        sa.Column("workspace_snapshot_digest", sa.String(64), nullable=True),
        sa.Column("request_ciphertext", sa.Text(), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("result_ciphertext", sa.Text(), nullable=True),
        sa.Column("result_digest", sa.String(64), nullable=True),
        sa.Column("lease_owner", sa.String(128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_cowork_job_idempotency"),
    )

    op.create_table(
        "marcellus_cowork_job_steps",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False, index=True),
        sa.Column("job_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="queued", index=True),
        sa.Column("label", sa.String(255), nullable=False, server_default=""),
        sa.Column("retryable", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("job_id", "ordinal", name="uq_cowork_step_ordinal"),
    )

    op.create_table(
        "marcellus_cowork_job_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False, index=True),
        sa.Column("job_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("step_id", UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("state", sa.String(32), nullable=True),
        sa.Column("payload_ciphertext", sa.Text(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.UniqueConstraint("job_id", "sequence", name="uq_cowork_event_sequence"),
    )

    op.create_table(
        "marcellus_cowork_browser_tasks",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False, index=True),
        sa.Column("job_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("submission_key", sa.String(128), nullable=False),
        sa.Column("retry_token", sa.String(128), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="submitted", index=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_tab_id", sa.String(128), nullable=True),
        sa.Column("provider_conversation_id", sa.String(255), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("chunk_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("response_ciphertext", sa.Text(), nullable=True),
        sa.Column("response_digest", sa.String(64), nullable=True),
        sa.Column("attachments_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "submission_key", name="uq_cowork_browser_submission"),
    )

    op.create_table(
        "marcellus_cowork_executions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", sa.String(128), nullable=False, index=True),
        sa.Column("job_id", UUID(as_uuid=True), nullable=False, index=True),
        sa.Column("project_id", UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("conversation_id", UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("execution_id", sa.String(64), nullable=False, index=True),
        sa.Column("executor", sa.String(32), nullable=False),
        sa.Column("command_kind", sa.String(32), nullable=False),
        sa.Column("command", sa.String(300), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="running", index=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("timed_out", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cancelled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sandboxed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("tenant_id", "execution_id", name="uq_cowork_execution_id"),
    )


def downgrade() -> None:
    op.drop_table("marcellus_cowork_executions")
    op.drop_table("marcellus_cowork_browser_tasks")
    op.drop_table("marcellus_cowork_job_events")
    op.drop_table("marcellus_cowork_job_steps")
    op.drop_table("marcellus_cowork_jobs")
