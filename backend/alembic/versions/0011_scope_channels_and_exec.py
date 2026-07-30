"""Scope channel gateway and execution channels to tenants.

Revision ID: 0011
Revises: 0010

The channel gateway and the execution channels were the last unowned
security surfaces. Without an owner, one tenant's operators could read
another tenant's inbound messages, approve their execution requests, or
enumerate their credential broker entries.

Ownership is nullable so existing rows are preserved as legacy/unowned and
remain visible only to an unscoped admin identity. There is no backfill:
guessing an owner for an existing row would create the exact cross-tenant
exposure this revision closes.

Usage:
    alembic upgrade 0011
    alembic downgrade 0010
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision:       str                             = "0011"
down_revision:  Union[str, None]               = "0010"
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


#: Tables gaining tenant ownership in this revision.
_OWNED_TABLES: tuple[str, ...] = (
    "channel_messages",
    "channel_identities",
    "channel_configs",
    "exec_requests",
    "credential_broker",
    "production_gates",
)


def _drop_single_column_uniqueness(table: str, column: str) -> None:
    """Remove single-column uniqueness on ``table.column``.

    Uniqueness may exist as a named constraint or as a unique index depending
    on how the table was created, and the generated name differs between
    deployments, so it is resolved rather than hard-coded.
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for constraint in inspector.get_unique_constraints(table):
        if constraint.get("column_names") == [column] and constraint.get("name"):
            op.drop_constraint(constraint["name"], table, type_="unique")
            return

    for index in inspector.get_indexes(table):
        if index.get("unique") and index.get("column_names") == [column] and index.get("name"):
            op.drop_index(index["name"], table_name=table)
            return


def upgrade() -> None:
    for table in _OWNED_TABLES:
        op.add_column(table, sa.Column("tenant_id", sa.String(length=128), nullable=True))
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])

    # A channel id and a credential name are unique within a tenant, not
    # globally. Global uniqueness would let the first tenant to register a
    # name lock every other tenant out of it, and would leak the existence of
    # another tenant's row through the insert conflict.
    _drop_single_column_uniqueness("channel_configs", "channel_id")
    op.create_unique_constraint(
        "uq_channel_configs_tenant_channel", "channel_configs", ["tenant_id", "channel_id"]
    )

    _drop_single_column_uniqueness("credential_broker", "name")
    op.create_unique_constraint(
        "uq_credential_broker_tenant_name", "credential_broker", ["tenant_id", "name"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_credential_broker_tenant_name", "credential_broker", type_="unique")
    op.create_index("ix_credential_broker_name", "credential_broker", ["name"], unique=True)

    op.drop_constraint("uq_channel_configs_tenant_channel", "channel_configs", type_="unique")
    op.create_index("ix_channel_configs_channel_id", "channel_configs", ["channel_id"], unique=True)

    for table in reversed(_OWNED_TABLES):
        op.drop_index(f"ix_{table}_tenant_id", table_name=table)
        op.drop_column(table, "tenant_id")
