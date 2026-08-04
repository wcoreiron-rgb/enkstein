"""Record read-only connector verification separately from configuration.

Revision ID: 0013
Revises: 0012
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("connectors", sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("connectors", sa.Column("verification_level", sa.String(length=32), nullable=True))
    op.add_column("connectors", sa.Column("last_verification_error", sa.String(length=256), nullable=True))


def downgrade() -> None:
    op.drop_column("connectors", "last_verification_error")
    op.drop_column("connectors", "verification_level")
    op.drop_column("connectors", "last_verified_at")
