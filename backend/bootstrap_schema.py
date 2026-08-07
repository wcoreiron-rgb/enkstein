"""Materialise the initial schema on a genuinely empty database.

Alembic's baseline revision is deliberately a no-op: it records a schema that
``Base.metadata.create_all`` had already produced at application startup. That
assumption holds on upgrade, but not on a first launch, where the database is
still empty when Alembic runs. The first revision carrying real DDL then fails
against tables that do not exist yet, Alembic aborts without ever writing
``alembic_version``, and every seed that follows runs against a schema-less
database. The API creates the tables moments later, so the install reports
success while Policies, Connectors, and Workflows stay empty until some later
launch happens to reseed them.

Creating the schema before migrations run puts the database into exactly the
state the baseline revision documents, so the caller can stamp it as current.
"""
from __future__ import annotations

import asyncio
import sys


def _register_all_models() -> None:
    """Import the application so every model attaches to the shared metadata.

    ``main`` is the one module guaranteed to import every table the running API
    depends on. Re-listing model modules here would silently drift the day a new
    one is added, which is the class of bug this script exists to prevent.
    """
    import main  # noqa: F401


async def _create_schema() -> list[str]:
    from app.core.database import Base, engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    return sorted(Base.metadata.tables)


def run() -> int:
    try:
        _register_all_models()
        created = asyncio.run(_create_schema())
    except Exception as exc:  # noqa: BLE001 - surfaced in the launcher log
        print(f"    schema bootstrap failed: {exc}", file=sys.stderr)
        return 1
    print(f"    created {len(created)} tables")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
