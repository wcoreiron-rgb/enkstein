import pytest


@pytest.mark.asyncio
async def test_channel_gateway_message_executes_commandclaw_and_returns_command_result(client):
    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "teams",
            "platform_user_id": "u-1",
            "platform_email": "analyst@company.com",
            "platform_name": "Analyst",
            "regentclaw_role": "engineer",
            "is_trusted": True,
            "trust_score": 85,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/message",
        json={
            "channel_type": "teams",
            "channel_id": "secops",
            "sender_id": "u-1",
            "sender_email": "analyst@company.com",
            "sender_name": "Analyst",
            "message_text": "run cloud scan in prod",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["detected_intent"]
    assert "command_result" in body
    assert body["command_result"]["command_id"].startswith("chan_")
    assert body["command_result"]["source"] == "teams"
    assert body["command_result"]["intent"] == "run_scan"
    assert body["command_result"]["outcome"] in {"allowed", "requires_approval", "blocked", "unavailable"}


@pytest.mark.asyncio
async def test_channel_gateway_blocked_message_skips_command_execution(client):
    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "slack",
            "platform_user_id": "readonly-1",
            "platform_email": "readonly@company.com",
            "platform_name": "Readonly User",
            "regentclaw_role": "readonly",
            "is_trusted": True,
            "trust_score": 80,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/message",
        json={
            "channel_type": "slack",
            "channel_id": "soc-room",
            "sender_id": "readonly-1",
            "sender_email": "readonly@company.com",
            "sender_name": "Readonly User",
            "message_text": "block this account now",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["policy_decision"] == "blocked"
    assert body["command_result"] is None


@pytest.mark.asyncio
async def test_channel_gateway_simulate_includes_command_result(client):
    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "teams",
            "platform_user_id": "sim-u1",
            "platform_email": "sim@company.com",
            "platform_name": "Sim User",
            "regentclaw_role": "engineer",
            "is_trusted": True,
            "trust_score": 88,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/simulate",
        json={
            "channel_type": "teams",
            "channel_id": "sim-room",
            "sender_id": "sim-u1",
            "sender_email": "sim@company.com",
            "sender_name": "Sim User",
            "message_text": "run cloud scan now",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "command_result" in body
    assert body["command_result"]["command_id"].startswith("chan_sim-")


@pytest.mark.asyncio
async def test_channel_gateway_webhook_ingest_routes_to_command_contract(client):
    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "webhook",
            "platform_user_id": "webhook@company.com",
            "platform_email": "webhook@company.com",
            "platform_name": "Webhook Bot",
            "regentclaw_role": "engineer",
            "is_trusted": True,
            "trust_score": 82,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/webhook",
        json={
            "channel_id": "webhook-alerts",
            "sender_email": "webhook@company.com",
            "sender_name": "Webhook Bot",
            "message_text": "investigate threat indicator in prod",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["channel_type"] == "webhook"
    assert body["command_result"]["source"] == "webhook"
    assert body["command_result"]["command_id"].startswith("chan_webhook-")


@pytest.mark.asyncio
async def test_channel_gateway_email_inbound_routes_to_command_contract(client):
    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "email",
            "platform_user_id": "analyst@company.com",
            "platform_email": "analyst@company.com",
            "platform_name": "SOC Analyst",
            "regentclaw_role": "engineer",
            "is_trusted": True,
            "trust_score": 84,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/email/inbound",
        json={
            "inbox": "soc-inbox",
            "from_email": "analyst@company.com",
            "from_name": "SOC Analyst",
            "subject": "Cloud alert",
            "body_text": "run cloud scan for tenant prod",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["channel_type"] == "email"
    assert body["command_result"]["source"] == "email"
    assert body["command_result"]["command_id"].startswith("chan_email-")
