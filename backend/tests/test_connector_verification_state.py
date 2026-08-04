"""Connector configuration must not be presented as a verified connection."""
from __future__ import annotations

import pytest

from app.api.routes import connectors as connector_routes
from app.models.connector import Connector, ConnectorRisk, ConnectorStatus
from app.services.connector_tester import TestResult as ConnectorTestResult


async def _connector(db_session: object) -> Connector:
    connector = Connector(
        name="Identity source",
        tenant_id="global",
        connector_type="entra_id",
        status=ConnectorStatus.APPROVED,
        risk_level=ConnectorRisk.MEDIUM,
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


@pytest.mark.asyncio
async def test_approved_connector_without_read_only_test_is_unverified(client, db_session, monkeypatch):
    connector = await _connector(db_session)
    monkeypatch.setattr(connector_routes.secrets_manager, "list_configured", lambda: [str(connector.id)])
    monkeypatch.setattr(connector_routes.secrets_manager, "is_configured", lambda _: True)

    response = await client.get("/api/v1/connectors/health-summary")
    assert response.status_code == 200, response.text
    item = next(row for row in response.json()["connectors"] if row["id"] == str(connector.id))
    assert item["health"] == "unverified"
    assert response.json()["verified"] == 0
    assert response.json()["unverified"] == 1


@pytest.mark.asyncio
async def test_successful_read_only_test_records_verification(client, db_session, monkeypatch):
    connector = await _connector(db_session)
    monkeypatch.setattr(
        connector_routes.secrets_manager,
        "get_credential",
        lambda *_args, **_kwargs: {"tenant_id": "example"},
    )

    async def verified(**_kwargs):
        return ConnectorTestResult(True, "Microsoft Graph accepted the credentials", verification_level="credential")

    monkeypatch.setattr(connector_routes, "test_connector", verified)
    response = await client.post(f"/api/v1/connectors/{connector.id}/test")
    assert response.status_code == 200, response.text
    await db_session.refresh(connector)
    assert connector.verification_level == "credential"
    assert connector.last_verified_at is not None
    assert connector.last_verification_error is None
