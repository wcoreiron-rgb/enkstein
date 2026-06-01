import pytest


@pytest.mark.asyncio
async def test_control_center_summary_endpoint_returns_expected_shape(client):
    res = await client.get("/api/v1/dashboard/control-center-summary")
    assert res.status_code == 200, res.text
    body = res.json()
    expected_keys = {
        "pending_commands",
        "running_swarms",
        "blocked_swarms",
        "remote_agents_total",
        "remote_agents_online",
        "schedules_active",
        "schedules_total",
        "channel_messages_24h",
        "channel_blocked_24h",
        "channel_replies_sent_24h",
        "channel_replies_pending_24h",
        "execution_pending_approval",
        "execution_blocked_24h",
        "blocked_actions_24h",
    }
    assert expected_keys.issubset(set(body.keys()))
    for key in expected_keys:
        assert isinstance(body[key], int)
