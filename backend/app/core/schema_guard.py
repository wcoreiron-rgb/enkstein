"""
Additive schema reconciliation for long-lived local databases.

Startup calls ``Base.metadata.create_all``, which creates missing tables but
never alters existing ones. In a packaged desktop install the database
outlives every upgrade, so a column added to a model after first run is
simply absent, and the first query that selects it fails with
``UndefinedColumnError``. That is how ``findings.data_origin`` took the
Findings page down while the Alembic revision still read as current.

This closes that gap conservatively. It only ever adds columns that the
models declare and the database lacks. It never drops, renames, retypes, or
reorders anything, so it cannot destroy operator data, and it leaves genuine
migrations (backfills, constraints, index strategy) to Alembic.
"""
from __future__ import annotations

import logging

from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateColumn

logger = logging.getLogger(__name__)


def _ddl_fragment(dialect, column) -> str | None:
    """Render ``name type [NOT NULL] [DEFAULT ...]`` for an ADD COLUMN.

    Returns None when the column cannot be added safely against rows that
    already exist — a NOT NULL column with no usable default would fail, so
    it is reported instead of attempted.
    """
    fragment = str(CreateColumn(column).compile(dialect=dialect))

    if column.nullable:
        return fragment

    if column.server_default is not None:
        return fragment

    # No server default: borrow the model-side default when it is a plain
    # scalar so existing rows get a defined value.
    default = getattr(column.default, "arg", None) if column.default is not None else None
    if default is None or callable(default):
        return None
    literal = default.value if hasattr(default, "value") else default
    if isinstance(literal, bool):
        rendered = "true" if literal else "false"
    elif isinstance(literal, (int, float)):
        rendered = str(literal)
    else:
        rendered = "'" + str(literal).replace("'", "''") + "'"
    return f"{fragment} DEFAULT {rendered}"


def reconcile_schema(sync_conn) -> list[str]:
    """Add model columns missing from existing tables. Returns what changed."""
    from app.core.database import Base

    inspector = inspect(sync_conn)
    present = set(inspector.get_table_names())
    dialect = sync_conn.dialect
    applied: list[str] = []

    for table_name, table in Base.metadata.tables.items():
        if table_name not in present:
            continue  # create_all handles brand-new tables
        existing = {col["name"] for col in inspector.get_columns(table_name)}
        for column in table.columns:
            if column.name in existing:
                continue
            fragment = _ddl_fragment(dialect, column)
            if fragment is None:
                logger.error(
                    "Schema drift needs a migration: %s.%s is NOT NULL with no "
                    "default and cannot be added to a populated table.",
                    table_name, column.name,
                )
                continue
            sync_conn.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN {fragment}'))
            applied.append(f"{table_name}.{column.name}")

    if applied:
        logger.warning("Reconciled missing columns: %s", ", ".join(applied))
    return applied
