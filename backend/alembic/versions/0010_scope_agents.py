"""Scope agents to tenants.

Revision ID: 0010
Revises: 0009

Remote agents are dispatch targets, so an unowned agent could otherwise be
counted or dispatched from any tenant's control plane. Nullable for built-in
seeded agents that belong to no single tenant.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agents", sa.Column("tenant_id", sa.String(length=128), nullable=True))
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_agents_tenant_id", table_name="agents")
    op.drop_column("agents", "tenant_id")
