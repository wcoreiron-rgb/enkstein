"""Allow one tenant_memory row per tenant.

Revision ID: 0009
Revises: 0008

tenant_memory was a single-row table keyed on a hard-coded ``id=1``, so every
tenant shared one posture summary. The id column therefore has no sequence.
Give it an identity/sequence default so each tenant can own a row.
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        # SQLite assigns INTEGER PRIMARY KEY values implicitly.
        return
    op.execute("CREATE SEQUENCE IF NOT EXISTS tenant_memory_id_seq OWNED BY tenant_memory.id")
    op.execute(
        "SELECT setval('tenant_memory_id_seq', COALESCE((SELECT MAX(id) FROM tenant_memory), 0) + 1, false)"
    )
    op.execute("ALTER TABLE tenant_memory ALTER COLUMN id SET DEFAULT nextval('tenant_memory_id_seq')")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute("ALTER TABLE tenant_memory ALTER COLUMN id DROP DEFAULT")
    op.execute("DROP SEQUENCE IF EXISTS tenant_memory_id_seq")
