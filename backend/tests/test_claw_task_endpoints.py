import pytest
from app.claws.cloudclaw import routes as cloud_routes
from app.claws.endpointclaw import routes as endpoint_routes
from app.claws.devclaw import routes as dev_routes


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,claw",
    [
        ("/api/v1/identityclaw/task", "identityclaw"),
        ("/api/v1/cloudclaw/task", "cloudclaw"),
        ("/api/v1/threatclaw/task", "threatclaw"),
        ("/api/v1/arcclaw/task", "arcclaw"),
        ("/api/v1/accessclaw/task", "accessclaw"),
        ("/api/v1/dataclaw/task", "dataclaw"),
        ("/api/v1/devclaw/task", "devclaw"),
        ("/api/v1/endpointclaw/task", "endpointclaw"),
        ("/api/v1/appclaw/task", "appclaw"),
        ("/api/v1/logclaw/task", "logclaw"),
        ("/api/v1/netclaw/task", "netclaw"),
        ("/api/v1/complianceclaw/task", "complianceclaw"),
    ],
)
async def test_claw_task_contract_shape(client, path, claw):
    response = await client.post(
        path,
        json={
            "swarm_job_id": "job_test_123",
            "task_type": "investigate",
            "input": {"scope": "test"},
            "classification": "internal",
            "allowed_actions": ["read", "analyze", "recommend"],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["claw"] == claw
    assert body["status"] == "completed"
    for key in [
        "task_id",
        "swarm_job_id",
        "severity",
        "confidence",
        "risk_score",
        "findings",
        "evidence",
        "recommended_actions",
        "blocked_actions",
        "policy_decisions",
        "compliance_mappings",
        "execution_time_ms",
    ]:
        assert key in body


@pytest.mark.asyncio
async def test_cloud_task_uses_connector_backed_path_when_available(client, monkeypatch):
    class _Adapter:
        @staticmethod
        async def get_findings(credentials=None):
            return [{"title": "Live Cloud Exposure", "description": "connector finding", "risk_score": 91}]

    async def _creds(*args, **kwargs):
        return {"api_key": "x"}

    monkeypatch.setattr(cloud_routes, "_get_provider_credentials", _creds)
    monkeypatch.setattr(cloud_routes, "PROVIDER_CONFIG", [{"provider": "aws", "connector_type": "aws_security_hub", "adapter": _Adapter}])

    response = await client.post("/api/v1/cloudclaw/task", json={"swarm_job_id": "job_x", "task_type": "investigate"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_score"] >= 91
    assert body["findings"][0]["title"] == "Live Cloud Exposure"


@pytest.mark.asyncio
async def test_endpoint_task_uses_connector_backed_path_when_available(client, monkeypatch):
    class _Adapter:
        @staticmethod
        async def get_findings(credentials=None):
            return [{"title": "Live Endpoint Alert", "description": "connector finding", "risk_score": 88}]

    async def _creds(*args, **kwargs):
        return {"api_key": "x"}

    monkeypatch.setattr(endpoint_routes, "_get_credentials", _creds)
    monkeypatch.setattr(endpoint_routes, "PROVIDER_CONFIG", [{"provider": "defender_endpoint", "connector_type": "defender_endpoint", "adapter": _Adapter}])

    response = await client.post("/api/v1/endpointclaw/task", json={"swarm_job_id": "job_x", "task_type": "investigate"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_score"] >= 88
    assert body["findings"][0]["title"] == "Live Endpoint Alert"


@pytest.mark.asyncio
async def test_dev_task_uses_github_connector_backed_path_when_available(client, monkeypatch):
    async def _configured(*args, **kwargs):
        return True

    async def _fetch(*args, **kwargs):
        return [{"title": "Live GitHub Secret", "description": "connector finding", "risk_score": 96}]

    monkeypatch.setattr("app.services.connector_check.is_connector_configured", _configured)
    monkeypatch.setattr("app.claws.devclaw.github_scanner.fetch_github_findings", _fetch)

    response = await client.post("/api/v1/devclaw/task", json={"swarm_job_id": "job_x", "task_type": "investigate"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["risk_score"] >= 96
    assert body["findings"][0]["title"] == "Live GitHub Secret"
