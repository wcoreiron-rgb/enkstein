import pytest
from sqlalchemy import select

from app.models.finding import Finding
from app.services.finding_pipeline import ingest_findings


def _finding(external_id: str = "provider-1") -> dict:
    return {
        "provider": "github",
        "title": "Critical secret detected",
        "severity": "critical",
        "risk_score": 95,
        "external_id": external_id,
    }


@pytest.mark.asyncio
async def test_same_provider_identifier_is_isolated_per_tenant(db_session):
    await ingest_findings(db_session, "devclaw", [_finding()], tenant_id="tenant-a", run_policy_eval=False, run_alerts=False)
    await ingest_findings(db_session, "devclaw", [_finding()], tenant_id="tenant-b", run_policy_eval=False, run_alerts=False)

    rows = (await db_session.execute(select(Finding).where(Finding.external_id == "provider-1"))).scalars().all()
    assert {row.tenant_id for row in rows} == {"tenant-a", "tenant-b"}


@pytest.mark.asyncio
async def test_existing_finding_is_updated_only_inside_its_tenant(db_session):
    await ingest_findings(db_session, "devclaw", [_finding()], tenant_id="tenant-a", run_policy_eval=False, run_alerts=False)
    changed = _finding()
    changed["title"] = "Different tenant finding"
    await ingest_findings(db_session, "devclaw", [changed], tenant_id="tenant-b", run_policy_eval=False, run_alerts=False)

    tenant_a = (await db_session.execute(select(Finding).where(Finding.tenant_id == "tenant-a"))).scalar_one()
    tenant_b = (await db_session.execute(select(Finding).where(Finding.tenant_id == "tenant-b"))).scalar_one()
    assert tenant_a.title == "Critical secret detected"
    assert tenant_b.title == "Different tenant finding"


@pytest.mark.asyncio
async def test_missing_tenant_context_fails_before_writing(db_session):
    with pytest.raises(ValueError, match="tenant context"):
        await ingest_findings(db_session, "devclaw", [_finding()], tenant_id=None)
    assert (await db_session.execute(select(Finding))).scalars().all() == []
