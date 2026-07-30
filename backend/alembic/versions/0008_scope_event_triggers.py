"""Scope event triggers to tenants.

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("event_triggers", sa.Column("tenant_id", sa.String(length=128), nullable=True))
    op.create_index("ix_event_triggers_tenant_id", "event_triggers", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_event_triggers_tenant_id", table_name="event_triggers")
    op.drop_column("event_triggers", "tenant_id")
