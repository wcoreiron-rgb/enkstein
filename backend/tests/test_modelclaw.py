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


@pytest.mark.asyncio
async def test_runtime_pinned_profiles_are_flagged_internal(client):
    """Cowork authoring and workspace scanning are pinned by the runtime.

    Three Ollama profiles rendered as indistinguishable "Ollama" rows in the
    Brain picker even though two of them are internal steps the runtime pins
    by name. They stay routable and policy-governed; the flag only keeps them
    out of the operator's choice list.
    """
    response = await client.get(f"{BASE}/profiles")
    assert response.status_code == 200, response.text
    rows = response.json()
    by_name = {row["name"]: row for row in rows}

    assert by_name["ollama_cowork_author"]["internal_role"] is True
    assert by_name["gemma_scanner"]["internal_role"] is True
    # The general local Brain remains an operator choice.
    assert by_name["ollama_local_fallback"]["internal_role"] is False

    # Exactly one selectable Ollama profile remains, so the picker cannot
    # render duplicate rows that behave differently.
    selectable_ollama = [
        row for row in rows
        if row["provider"] == "ollama"
        and not row["internal_role"]
        and "executive" in (row.get("allowed_claws") or [])
    ]
    assert len(selectable_ollama) == 1

    # Flagging is presentation-only: the pinned profiles keep their routing.
    assert by_name["gemma_scanner"]["provider"] == "ollama"
    assert "executive" in by_name["ollama_cowork_author"]["allowed_claws"]
