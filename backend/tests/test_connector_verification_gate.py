from __future__ import annotations

import pytest

from app.api.routes import connectors as connector_routes
from app.models.connector import Connector, ConnectorRisk, ConnectorStatus
from app.services.connector_tester import TestResult as ConnectorTestResult


async def _connector(db_session, connector_type: str = "gemini") -> Connector:
    connector = Connector(
        name="Hosted Brain",
        connector_type=connector_type,
        status=ConnectorStatus.PENDING,
        risk_level=ConnectorRisk.MEDIUM,
        endpoint="https://generativelanguage.googleapis.com/v1beta",
        network_access=True,
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


@pytest.mark.asyncio
async def test_hosted_brain_fake_key_is_not_stored_or_connected(client, db_session, monkeypatch):
    connector = await _connector(db_session)

    async def rejected(**_):
        return ConnectorTestResult(False, "Gemini rejected the API key")

    monkeypatch.setattr(connector_routes, "test_connector", rejected)
    monkeypatch.setattr(
        connector_routes.secrets_manager,
        "store_credential",
        lambda *_: (_ for _ in ()).throw(AssertionError("invalid credentials must not be stored")),
    )
    response = await client.post(
        f"/api/v1/connectors/{connector.id}/configure",
        json={"credentials": {"api_key": "fake-key"}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["is_configured"] is False
    assert body["policy_decision"] == "blocked"
    assert body["policy_name"] == "Credential verification gate"
    assert "not saved" in body["message"]
    assert connector.status == ConnectorStatus.PENDING


@pytest.mark.asyncio
async def test_hosted_brain_verified_key_can_be_stored(client, db_session, monkeypatch):
    connector = await _connector(db_session, "nvidia_nim")
    stored = {}

    async def verified(**_):
        return ConnectorTestResult(True, "Provider accepted the key", verification_level="credential")

    def store(connector_id, credentials):
        stored["connector_id"] = connector_id
        stored["credentials"] = credentials
        return "key-...test"

    monkeypatch.setattr(connector_routes, "test_connector", verified)
    monkeypatch.setattr(connector_routes.secrets_manager, "store_credential", store)
    response = await client.post(
        f"/api/v1/connectors/{connector.id}/configure",
        json={"credentials": {"api_key": "verified-key"}},
    )
    assert response.status_code == 200, response.text
    assert response.json()["is_configured"] is True
    assert stored["connector_id"] == str(connector.id)
    assert stored["credentials"] == {"api_key": "verified-key"}
