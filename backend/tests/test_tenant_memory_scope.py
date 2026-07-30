"""Tenant memory and risk snapshots must be per-tenant, not one shared row."""
import pytest
from sqlalchemy import select

from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.memory import TenantMemory
from app.services.memory_service import (
    capture_risk_snapshot,
    get_or_create_tenant_memory,
    get_risk_trend,
    refresh_tenant_memory,
)


def _finding(tenant_id: str, external_id: str) -> Finding:
    return Finding(
        tenant_id=tenant_id,
        claw="cloudclaw",
        provider="aws",
        external_id=external_id,
        title=f"finding-{external_id}",
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        risk_score=90.0,
    )


@pytest.mark.asyncio
async def test_each_tenant_gets_its_own_memory_row(db_session):
    a = await get_or_create_tenant_memory(db_session, "tenant-a")
    b = await get_or_create_tenant_memory(db_session, "tenant-b")
    assert a.id != b.id

    rows = (await db_session.execute(select(TenantMemory))).scalars().all()
    assert {r.tenant_id for r in rows} == {"tenant-a", "tenant-b"}


@pytest.mark.asyncio
async def test_memory_refresh_counts_only_its_own_findings(db_session):
    db_session.add_all([
        _finding("tenant-a", "a-1"),
        _finding("tenant-b", "b-1"),
        _finding("tenant-b", "b-2"),
    ])
    await db_session.commit()

    a = await refresh_tenant_memory(db_session, "tenant-a")
    b = await refresh_tenant_memory(db_session, "tenant-b")

    assert a.open_finding_count == 1
    assert b.open_finding_count == 2


@pytest.mark.asyncio
async def test_memory_requires_tenant_context(db_session):
    with pytest.raises(ValueError):
        await get_or_create_tenant_memory(db_session, "")


@pytest.mark.asyncio
async def test_risk_trend_is_scoped_to_its_tenant(db_session):
    await capture_risk_snapshot(db_session, "tenant-a", granularity="daily")

    assert len(await get_risk_trend(db_session, "tenant-a", granularity="daily")) == 1
    assert await get_risk_trend(db_session, "tenant-b", granularity="daily") == []
