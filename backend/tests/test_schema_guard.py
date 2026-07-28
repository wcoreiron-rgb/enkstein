"""
A local database survives every upgrade, so a column added to a model after
first run must appear without operator intervention. This is the failure that
took the Findings page down: the model declared data_origin, create_all could
not alter the existing table, and the first query raised UndefinedColumnError.
"""
import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.database import Base
from app.core.schema_guard import reconcile_schema


@pytest.mark.asyncio
async def test_column_added_after_the_table_exists_is_reconciled():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    old = MetaData()
    Table("drift_probe", old, Column("id", Integer, primary_key=True))
    async with engine.begin() as conn:
        await conn.run_sync(old.create_all)
        await conn.execute(text("INSERT INTO drift_probe (id) VALUES (1)"))

    # The model gains two columns after the table already exists.
    Table(
        "drift_probe", Base.metadata,
        Column("id", Integer, primary_key=True),
        Column("origin", String(16), nullable=False, default="unknown"),
        Column("source", String(64), nullable=True),
        extend_existing=True,
    )
    try:
        async with engine.begin() as conn:
            applied = await conn.run_sync(reconcile_schema)

        assert "drift_probe.origin" in applied
        assert "drift_probe.source" in applied

        async with engine.begin() as conn:
            cols = await conn.run_sync(
                lambda c: {col["name"] for col in inspect(c).get_columns("drift_probe")}
            )
            # The pre-existing row must still be readable and defaulted.
            row = (await conn.execute(text("SELECT origin FROM drift_probe WHERE id=1"))).scalar_one()

        assert {"origin", "source"} <= cols
        assert row == "unknown"
    finally:
        Base.metadata.remove(Base.metadata.tables["drift_probe"])
        await engine.dispose()


@pytest.mark.asyncio
async def test_reconciler_leaves_an_aligned_schema_untouched():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    Table(
        "aligned_probe", Base.metadata,
        Column("id", Integer, primary_key=True),
        Column("label", String(32), nullable=True),
        extend_existing=True,
    )
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            applied = await conn.run_sync(reconcile_schema)
        assert applied == []
    finally:
        Base.metadata.remove(Base.metadata.tables["aligned_probe"])
        await engine.dispose()
