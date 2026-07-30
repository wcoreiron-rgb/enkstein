import pytest
from app.models.channel_gateway import ChannelMessage


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


@pytest.mark.asyncio
async def test_control_center_summary_counts_recent_channel_messages(client, db_session):
    db_session.add(
        ChannelMessage(
            id="control-center-channel-message-1",
            tenant_id="global",
            channel_type="slack",
            channel_id="C123",
            sender_id="U123",
            message_text="run devclaw scan",
            policy_decision="allowed",
            response_sent=True,
        )
    )
    await db_session.commit()

    res = await client.get("/api/v1/dashboard/control-center-summary")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["channel_messages_24h"] == 1
    assert body["channel_replies_sent_24h"] == 1


@pytest.mark.asyncio
async def test_control_center_summary_excludes_other_tenant_channel_messages(
    client, db_session
):
    """A message owned elsewhere must not inflate this tenant's counters."""
    db_session.add(
        ChannelMessage(
            id="control-center-channel-message-2",
            tenant_id="tenant-intruder",
            channel_type="slack",
            channel_id="C999",
            sender_id="U999",
            message_text="intruder traffic",
            policy_decision="blocked",
            response_sent=True,
        )
    )
    await db_session.commit()

    body = (await client.get("/api/v1/dashboard/control-center-summary")).json()
    assert body["channel_messages_24h"] == 0
    assert body["channel_blocked_24h"] == 0
    assert body["channel_replies_sent_24h"] == 0
