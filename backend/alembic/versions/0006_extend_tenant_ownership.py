"""Extend tenant ownership to schedules, runs, and memory aggregates.

Revision ID: 0006
Revises: 0005

Rows without a tenant are legacy/system data and are deliberately visible only
to an unscoped administrator until an operator performs an audited backfill.
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ("schedules", "agent_runs", "tenant_memory", "risk_trend_snapshots"):
        op.add_column(table, sa.Column("tenant_id", sa.String(length=128), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
    op.create_unique_constraint("uq_tenant_memory_tenant_id", "tenant_memory", ["tenant_id"])


def downgrade() -> None:
    op.drop_constraint("uq_tenant_memory_tenant_id", "tenant_memory", type_="unique")
    for table in ("risk_trend_snapshots", "tenant_memory", "agent_runs", "schedules"):
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_column(table, "tenant_id")
