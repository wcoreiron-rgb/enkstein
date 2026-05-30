import pytest


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
