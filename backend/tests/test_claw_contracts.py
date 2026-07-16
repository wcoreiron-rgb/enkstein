import pytest

from app.claws.arcclaw import routes as arc_routes


@pytest.mark.asyncio
async def test_arcclaw_contract_endpoints(client):
    stats = await client.get("/api/v1/arcclaw/stats")
    assert stats.status_code == 200, stats.text

    findings = await client.get("/api/v1/arcclaw/findings")
    assert findings.status_code == 200, findings.text
    assert isinstance(findings.json(), list)

    providers = await client.get("/api/v1/arcclaw/providers")
    assert providers.status_code == 200, providers.text
    assert isinstance(providers.json(), list)


@pytest.mark.asyncio
async def test_arcclaw_provider_status_exposes_live_ollama(client, monkeypatch):
    async def fake_available_providers(**_kwargs):
        return [
            {
                "provider": "ollama",
                "label": "Ollama (Local - Free)",
                "models": ["regent-aegis:bc"],
                "ready": True,
                "setup": "Ollama is running.",
                "cost": "free",
            }
        ]

    monkeypatch.setattr(arc_routes, "available_providers", fake_available_providers)
    response = await client.get("/api/v1/arcclaw/providers")

    assert response.status_code == 200, response.text
    assert response.json()[0]["provider"] == "ollama"
    assert response.json()[0]["ready"] is True


@pytest.mark.asyncio
async def test_identityclaw_contract_endpoints(client):
    stats = await client.get("/api/v1/identityclaw/stats")
    assert stats.status_code == 200, stats.text

    findings = await client.get("/api/v1/identityclaw/findings")
    assert findings.status_code == 200, findings.text
    assert isinstance(findings.json(), list)

    providers = await client.get("/api/v1/identityclaw/providers")
    assert providers.status_code == 200, providers.text
    assert isinstance(providers.json(), list)
