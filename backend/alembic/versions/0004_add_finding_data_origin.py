"""Add data_origin and source_connector to findings.

Revision ID: 0004
Revises:     0003
Create Date: 2026-07-26 00:00:00.000000

A beta tenant typically has one or two live connectors configured while every
other Claw still returns realistic demonstration findings.  Without an explicit
origin marker an operator cannot tell which findings describe their own estate.
Existing rows are backfilled to 'unknown' rather than 'live' so that nothing
already in the table can be mistaken for verified customer data.

Usage:
    alembic upgrade 0004      # add the columns
    alembic downgrade 0003    # drop them
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# Revision identifiers — used by Alembic
revision:       str                             = "0004"
down_revision:  Union[str, None]               = "0003"
branch_labels:  Union[str, Sequence[str], None] = None
depends_on:     Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the provenance columns to the findings table."""
    op.add_column(
        "findings",
        sa.Column(
            "data_origin",
            sa.String(length=16),
            nullable=False,
            server_default="unknown",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("source_connector", sa.String(length=64), nullable=True),
    )
    op.create_index("ix_findings_data_origin", "findings", ["data_origin"])


def downgrade() -> None:
    """Remove the provenance columns."""
    op.drop_index("ix_findings_data_origin", table_name="findings")
    op.drop_column("findings", "source_connector")
    op.drop_column("findings", "data_origin")
