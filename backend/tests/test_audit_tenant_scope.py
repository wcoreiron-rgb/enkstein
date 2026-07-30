"""Audit trails must not mix across tenants."""
import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.services.audit_service import log_action


async def _log(db, tenant_id, action):
    await log_action(
        db=db,
        actor="system",
        actor_type="system",
        action=action,
        outcome="executed",
        module="trust_fabric",
        tenant_id=tenant_id,
    )
    await db.commit()


@pytest.mark.asyncio
async def test_audit_entries_are_stamped_with_their_tenant(db_session):
    await _log(db_session, "tenant-a", "isolate_module")
    await _log(db_session, "tenant-b", "block_connector")

    rows = (await db_session.execute(select(AuditLog))).scalars().all()
    by_tenant = {r.tenant_id: r.action for r in rows}
    assert by_tenant["tenant-a"] == "isolate_module"
    assert by_tenant["tenant-b"] == "block_connector"


@pytest.mark.asyncio
async def test_audit_api_hides_other_tenants(client, db_session):
    """The test caller belongs to "global", so neither foreign row is visible."""
    await _log(db_session, "tenant-a", "isolate_module")
    await _log(db_session, "tenant-b", "block_connector")

    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    rows = payload if isinstance(payload, list) else payload.get("entries", payload.get("logs", []))
    actions = {r["action"] for r in rows}
    assert "isolate_module" not in actions
    assert "block_connector" not in actions


@pytest.mark.asyncio
async def test_containment_audit_inherits_connector_tenant(db_session):
    """block_connector falls back to the connector's own tenant."""
    from app.models.connector import Connector, ConnectorRisk, ConnectorStatus
    from app.trust_fabric.containment import block_connector

    connector = Connector(
        name="tenant-owned-connector",
        tenant_id="tenant-a",
        connector_type="aws_iam",
        status=ConnectorStatus.APPROVED,
        risk_level=ConnectorRisk.LOW,
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)

    assert await block_connector(db_session, connector.id, "probe", "tester") is True

    rows = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "block_connector")
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].tenant_id == "tenant-a"
