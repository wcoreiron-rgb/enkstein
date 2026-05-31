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
