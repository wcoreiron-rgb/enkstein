import pytest
from app.fabric.providers.agt import adapter as agt_adapter_module
from app.core.config import settings
import json


BASE = "/api/v1/swarm/jobs"


def _payload(**overrides):
    body = {
        "name": "Test Incident Swarm",
        "profile": "INCIDENT_RESPONSE",
        "participants": ["identityclaw", "cloudclaw", "threatclaw"],
        "task_type": "investigate",
        "input": {"entity": "redacted_user", "time_range": "24h"},
        "classification": "confidential",
        "parallelism": 3,
    }
    body.update(overrides)
    return body


@pytest.mark.asyncio
async def test_create_swarm_job(client):
    response = await client.post(BASE, json=_payload())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["name"] == "Test Incident Swarm"
    assert body["status"] in {"pending", "running", "requires_approval", "completed"}
    assert "id" in body


@pytest.mark.asyncio
async def test_get_swarm_job_and_tasks(client):
    create = await client.post(BASE, json=_payload())
    assert create.status_code == 201, create.text
    job_id = create.json()["id"]

    get_job = await client.get(f"{BASE}/{job_id}")
    assert get_job.status_code == 200
    assert get_job.json()["id"] == job_id

    get_tasks = await client.get(f"{BASE}/{job_id}/tasks")
    assert get_tasks.status_code == 200
    tasks = get_tasks.json()
    assert isinstance(tasks, list)
    assert len(tasks) == 3
    assert set(t["claw"] for t in tasks) == {"identityclaw", "cloudclaw", "threatclaw"}


@pytest.mark.asyncio
async def test_cancel_swarm_job(client):
    create = await client.post(BASE, json=_payload())
    job_id = create.json()["id"]
    response = await client.post(f"{BASE}/{job_id}/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["job_id"] == job_id
    assert body["status"] in {"cancelled", "completed", "requires_approval"}


@pytest.mark.asyncio
async def test_list_swarm_jobs(client):
    await client.post(BASE, json=_payload(name="Swarm A"))
    await client.post(BASE, json=_payload(name="Swarm B"))
    response = await client.get(BASE)
    assert response.status_code == 200
    jobs = response.json()
    assert isinstance(jobs, list)
    assert len(jobs) >= 2


@pytest.mark.asyncio
async def test_swarm_task_secure_channel_disabled_by_default(client):
    settings.AGT_ENABLE_E2E_MESSAGING = False
    agt_adapter_module._adapter = None
    try:
        create = await client.post(BASE, json=_payload(name="Swarm E2E Off"))
        assert create.status_code == 201, create.text
        job_id = create.json()["id"]

        tasks_res = await client.get(f"{BASE}/{job_id}/tasks")
        assert tasks_res.status_code == 200
        tasks = tasks_res.json()
        assert tasks
        sample_output = json.loads(tasks[0]["output_json"])
        assert "secure_channel" not in sample_output
    finally:
        settings.AGT_ENABLE_E2E_MESSAGING = False
        agt_adapter_module._adapter = None


@pytest.mark.asyncio
async def test_swarm_task_secure_channel_enabled(client):
    settings.AGT_ENABLE_E2E_MESSAGING = True
    agt_adapter_module._adapter = None
    try:
        create = await client.post(BASE, json=_payload(name="Swarm E2E On"))
        assert create.status_code == 201, create.text
        job_id = create.json()["id"]

        tasks_res = await client.get(f"{BASE}/{job_id}/tasks")
        assert tasks_res.status_code == 200
        tasks = tasks_res.json()
        assert tasks
        sample_output = json.loads(tasks[0]["output_json"])
        assert sample_output["secure_channel"]["enabled"] is True
        assert sample_output["policy_decisions"][-1]["action"] == "E2E_MESSAGE"
        assert sample_output["secure_channel"]["signature_algorithm"] == "ed25519"
        assert sample_output["secure_channel"]["key_id"]
        assert sample_output["secure_channel"]["signature"]
    finally:
        # Restore default toggle for test isolation across modules.
        settings.AGT_ENABLE_E2E_MESSAGING = False
        agt_adapter_module._adapter = None


@pytest.mark.asyncio
async def test_swarm_job_stream_emits_events(client):
    create = await client.post(BASE, json=_payload(name="Swarm Stream Test"))
    assert create.status_code == 201, create.text
    job_id = create.json()["id"]

    seen_event_headers = []
    async with client.stream("GET", f"{BASE}/{job_id}/stream?timeout_seconds=2&poll_interval_ms=200") as response:
        assert response.status_code == 200
        async for line in response.aiter_lines():
            if line.startswith("event: "):
                seen_event_headers.append(line.replace("event: ", "").strip())
            if "job_completed" in seen_event_headers:
                break

    assert "job_snapshot" in seen_event_headers
    assert "job_completed" in seen_event_headers


@pytest.mark.asyncio
async def test_swarm_job_stream_includes_execution_mode_for_real_task(client):
    create = await client.post(BASE, json=_payload(name="Swarm Stream Execution Mode"))
    assert create.status_code == 201, create.text
    job_id = create.json()["id"]

    current_event = None
    task_completed_payload = None
    async with client.stream("GET", f"{BASE}/{job_id}/stream?timeout_seconds=3&poll_interval_ms=200") as response:
        assert response.status_code == 200
        async for line in response.aiter_lines():
            if line.startswith("event: "):
                current_event = line.replace("event: ", "").strip()
                continue
            if line.startswith("data: ") and current_event == "task_completed":
                task_completed_payload = json.loads(line.replace("data: ", "").strip())
                break

    assert task_completed_payload is not None
    assert task_completed_payload.get("execution_mode") == "real_task_handler"


@pytest.mark.asyncio
async def test_swarm_job_stream_includes_execution_provenance_for_fallback_task(client):
    create = await client.post(
        BASE,
        json=_payload(
            name="Swarm Stream Provenance",
            participants=["unknownclaw"],
            parallelism=1,
        ),
    )
    assert create.status_code == 201, create.text
    job_id = create.json()["id"]

    current_event = None
    task_completed_payload = None
    async with client.stream("GET", f"{BASE}/{job_id}/stream?timeout_seconds=3&poll_interval_ms=200") as response:
        assert response.status_code == 200
        async for line in response.aiter_lines():
            if line.startswith("event: "):
                current_event = line.replace("event: ", "").strip()
                continue
            if line.startswith("data: ") and current_event == "task_completed":
                task_completed_payload = json.loads(line.replace("data: ", "").strip())
                break

    assert task_completed_payload is not None
    assert task_completed_payload["execution_mode"] == "simulated_fallback"
    assert "Unsupported claw" in task_completed_payload.get("fallback_reason", "")


@pytest.mark.asyncio
async def test_sprint6_suspicious_identity_preset_creates_approval_gated_job(client):
    response = await client.post(
        f"{BASE}/presets/suspicious-identity",
        json={
            "identity": "user@company.com",
            "time_range": "24h",
            "requested_by": "sprint6-test",
            "requires_approval_for_actions": True,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "requires_approval"
    assert "Suspicious Identity Investigation" in body["name"]

    job_id = body["id"]
    tasks_res = await client.get(f"{BASE}/{job_id}/tasks")
    assert tasks_res.status_code == 200, tasks_res.text
    claws = {t["claw"] for t in tasks_res.json()}
    assert claws == {
        "identityclaw",
        "threatclaw",
        "cloudclaw",
        "dataclaw",
        "complianceclaw",
        "automationclaw",
    }


@pytest.mark.asyncio
async def test_microsoft_identity_incident_preset_creates_connector_oriented_job(client):
    response = await client.post(
        f"{BASE}/presets/microsoft-identity-incident",
        json={
            "identity": "user@company.com",
            "time_range": "24h",
            "requested_by": "microsoft-demo-test",
            "requires_approval_for_actions": True,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "requires_approval"
    assert "Microsoft Identity Incident" in body["name"]

    job_id = body["id"]
    tasks_res = await client.get(f"{BASE}/{job_id}/tasks")
    assert tasks_res.status_code == 200, tasks_res.text
    claws = {t["claw"] for t in tasks_res.json()}
    assert claws == {
        "identityclaw",
        "cloudclaw",
        "endpointclaw",
        "logclaw",
        "threatclaw",
        "complianceclaw",
        "automationclaw",
    }

    approve_res = await client.post(f"{BASE}/{job_id}/approve")
    assert approve_res.status_code == 200, approve_res.text
    assert approve_res.json()["status"] in {"completed", "requires_approval"}
