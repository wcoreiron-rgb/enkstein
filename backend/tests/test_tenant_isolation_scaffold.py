"""Tenant isolation proof scaffolding for upcoming enforcement work."""

import pytest


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason=(
        "Scaffold gap: connectors list should require tenant context and return "
        "only caller-owned rows. Endpoint currently returns unscoped connector data."
    ),
    strict=False,
)
async def test_connectors_list_requires_tenant_context(client):
    # Current auth fixture has no tenant claim. Future behavior should reject
    # unscoped calls until a tenant context is provided.
    resp = await client.get("/api/v1/connectors")
    assert resp.status_code in (401, 403), (
        "Expected tenant-context enforcement for connector list"
    )


@pytest.mark.asyncio
async def test_connectors_list_redacts_owner_identifier(client, db_session):
    from app.models.connector import Connector, ConnectorRisk, ConnectorStatus
    import uuid

    db_session.add(
        Connector(
            id=uuid.uuid4(),
            name="tenant-proof-connector",
            tenant_id="global",
            connector_type="aws_iam",
            owner_id=uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            status=ConnectorStatus.PENDING,
            risk_level=ConnectorRisk.LOW,
        )
    )
    await db_session.commit()

    resp = await client.get("/api/v1/connectors")
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert rows, "Expected at least one connector row"
    assert all("owner_id" not in row for row in rows), (
        "owner_id should be redacted from connector list payloads"
    )
