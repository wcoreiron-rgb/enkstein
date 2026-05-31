import pytest


@pytest.mark.asyncio
async def test_remote_agent_register_list_and_heartbeat(client):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "edge-worker-1",
            "tenant_id": "tenant_a",
            "owner": "secops@company.com",
            "host": "edge-01",
            "device": "linux",
            "allowed_claws": ["cloudclaw", "identityclaw"],
            "allowed_connectors": ["aws", "okta"],
            "allowed_actions": ["run_swarm", "create_ticket"],
            "trust_score": 77,
            "version": "1.0.0",
            "public_key": "pk_test",
        },
    )
    assert reg.status_code == 200, reg.text
    agent = reg.json()
    agent_id = agent["id"]
    assert agent["tenant_id"] == "tenant_a"
    assert agent["status"] == "active"

    hb = await client.post(
        f"/api/v1/remote-agents/{agent_id}/heartbeat",
        json={"status": "online", "trust_score": 81, "current_jobs": ["job_1"]},
    )
    assert hb.status_code == 200, hb.text
    heartbeat = hb.json()
    assert heartbeat["trust_score"] == 81
    assert heartbeat["current_jobs"] == ["job_1"]

    listing = await client.get("/api/v1/remote-agents")
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["count"] >= 1
    assert any(a["id"] == agent_id for a in body["agents"])


@pytest.mark.asyncio
async def test_remote_agent_dispatch_and_recent_commands(client):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "edge-worker-2",
            "tenant_id": "tenant_b",
            "owner": "soc@company.com",
            "allowed_actions": ["run_swarm"],
        },
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["id"]

    dispatch = await client.post(
        f"/api/v1/remote-agents/{agent_id}/dispatch",
        json={
            "command_id": "cmd_001",
            "source": "teams",
            "requester": "soc@company.com",
            "tenant_id": "tenant_b",
            "intent": "run_swarm",
            "target": "cloud_exposure",
            "scope": "prod",
            "mode": "approval",
            "classification": "confidential",
            "payload": {"profile": "INCIDENT_RESPONSE"},
        },
    )
    assert dispatch.status_code == 200, dispatch.text
    out = dispatch.json()
    assert out["command_id"] == "cmd_001"
    assert "outcome" in out
    assert "policy_name" in out

    recent = await client.get("/api/v1/commands/recent")
    assert recent.status_code == 200, recent.text
    recent_body = recent.json()
    assert recent_body["count"] >= 1
    assert any(c["action"] == "run_swarm" for c in recent_body["commands"])


@pytest.mark.asyncio
async def test_remote_agent_revoke_and_kill(client):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={"name": "edge-worker-3", "tenant_id": "tenant_c", "owner": "owner@company.com"},
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["id"]

    revoke = await client.post(f"/api/v1/remote-agents/{agent_id}/revoke")
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["status"] == "paused"

    kill = await client.post(f"/api/v1/remote-agents/{agent_id}/kill")
    assert kill.status_code == 200, kill.text
    killed = kill.json()
    assert killed["status"] == "retired"
    assert killed["kill_switch_status"] == "active"

