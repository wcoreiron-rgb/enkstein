import pytest


BASE = "/api/v1/modelclaw"


@pytest.mark.asyncio
async def test_modelclaw_providers_and_profiles(client):
    providers = await client.get(f"{BASE}/providers")
    assert providers.status_code == 200, providers.text
    assert isinstance(providers.json(), list)
    assert any(p["provider"] == "nvidia_nim" for p in providers.json())

    profiles = await client.get(f"{BASE}/profiles")
    assert profiles.status_code == 200, profiles.text
    assert isinstance(profiles.json(), list)
    assert any(p["name"] == "nim_fast_reasoning" for p in profiles.json())


@pytest.mark.asyncio
async def test_modelclaw_route_and_calls_audit(client):
    routed = await client.post(
        f"{BASE}/route",
        json={
            "claw": "threatclaw",
            "prompt": "Summarize this IOC campaign in 5 bullets.",
            "data_classification": "internal",
            "model_profile": "nim_fast_reasoning",
            "swarm_job_id": "job_001",
        },
    )
    assert routed.status_code == 200, routed.text
    body = routed.json()
    assert body["allowed"] is True
    assert body["provider"] == "nvidia_nim"
    assert body["model_profile"] == "nim_fast_reasoning"
    assert body["response"]

    calls = await client.get(f"{BASE}/calls")
    assert calls.status_code == 200, calls.text
    rows = calls.json()
    assert isinstance(rows, list)
    assert rows
    assert rows[0]["provider"] == "nvidia_nim"


@pytest.mark.asyncio
async def test_modelclaw_denies_disallowed_classification(client):
    denied = await client.post(
        f"{BASE}/route",
        json={
            "claw": "threatclaw",
            "prompt": "Top secret prompt",
            "data_classification": "top_secret",
            "model_profile": "nim_fast_reasoning",
        },
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_modelclaw_tenant_scoped_profiles_and_calls(client):
    created = await client.post(
        f"{BASE}/profiles",
        json={
            "name": "tenant_a_profile",
            "provider": "ollama",
            "model": "qwen2.5:14b-instruct",
            "allowed_claws": ["threatclaw"],
            "allowed_data_classes": ["internal"],
            "tenant_id": "tenant-a",
        },
    )
    assert created.status_code == 200, created.text

    tenant_a_profiles = await client.get(f"{BASE}/profiles?tenant_id=tenant-a")
    assert tenant_a_profiles.status_code == 200
    assert any(p["name"] == "tenant_a_profile" for p in tenant_a_profiles.json())

    global_profiles = await client.get(f"{BASE}/profiles?tenant_id=global")
    assert global_profiles.status_code == 200
    assert not any(p["name"] == "tenant_a_profile" for p in global_profiles.json())

    denied = await client.post(
        f"{BASE}/route",
        json={
            "claw": "threatclaw",
            "prompt": "test",
            "data_classification": "internal",
            "model_profile": "tenant_a_profile",
            "tenant_id": "global",
        },
    )
    assert denied.status_code == 404

    allowed = await client.post(
        f"{BASE}/route",
        json={
            "claw": "threatclaw",
            "prompt": "test",
            "data_classification": "internal",
            "model_profile": "tenant_a_profile",
            "tenant_id": "tenant-a",
        },
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["allowed"] is True

    tenant_a_calls = await client.get(f"{BASE}/calls?tenant_id=tenant-a")
    assert tenant_a_calls.status_code == 200
    assert tenant_a_calls.json()
    assert all(c.get("tenant_id") == "tenant-a" for c in tenant_a_calls.json())
