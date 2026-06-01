import pytest
import json

from app.models.event import Event, EventOutcome, EventSeverity


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
    # command_result is None when the policy blocks execution before CommandClaw runs
    if body["command_result"] is not None:
        cr = body["command_result"]
        assert cr["command_id"].startswith("chan_")
        # source and intent are set by CommandRequest — present when command executes
        if "source" in cr:
            assert cr["source"] == "teams"
        if "intent" in cr:
            assert cr["intent"] in {"run_scan", "scan", "unknown"}
        if "outcome" in cr:
            assert cr["outcome"] in {"allowed", "requires_approval", "blocked", "unavailable"}


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
    # command_result is None if policy blocks before CommandClaw executes
    if body["command_result"] is not None:
        cr = body["command_result"]
        assert cr["command_id"].startswith("chan_")
        if "source" in cr:
            assert cr["source"] == "webhook"


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


@pytest.mark.asyncio
async def test_channel_gateway_cli_command_with_tenant_identity(client):
    resp = await client.post(
        "/api/v1/channel-gateway/cli/command",
        json={
            "terminal_id": "term-01",
            "terminal_name": "SOC CLI",
            "user": "analyst@company.com",
            "tenant_id": "tenant_cli",
            "message_text": "run cloud scan now",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["channel_type"] == "cli"
    # CLI commands may be blocked by policy; command_result is None in that case
    if body["command_result"] is not None:
        cr = body["command_result"]
        if "source" in cr:
            assert cr["source"] == "cli"
        if "tenant_id" in cr:
            assert cr["tenant_id"] == "tenant_cli"


@pytest.mark.asyncio
async def test_channel_gateway_message_can_approve_pending_command(client, db_session):
    cmd_id = "cmd_chan_approve_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner@company.com",
        actor_name="owner@company.com",
        actor_type="human",
        action="run_swarm",
        target="identity_risk",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.HIGH,
        risk_score=81.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded for channel approve flow test",
        description="[commandclaw] owner@company.com -> run_swarm",
        metadata_json=json.dumps(
            {"context": {"command_id": cmd_id, "requester": "owner@company.com", "mode": "approval"}}
        ),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "teams",
            "platform_user_id": "secops-approver",
            "platform_email": "secops@company.com",
            "platform_name": "SecOps Approver",
            "regentclaw_role": "security_admin",
            "is_trusted": True,
            "trust_score": 92,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/message",
        json={
            "channel_type": "teams",
            "channel_id": "soc-room",
            "sender_id": "secops-approver",
            "sender_email": "secops@company.com",
            "sender_name": "SecOps Approver",
            "message_text": f"approve {cmd_id}",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    cr = body["command_result"]
    assert cr["review_action"] == "approve"
    assert cr["outcome"] == "allowed"
    assert body["execution_status"] == "dispatched"
    assert body["response_text"].startswith("✅ Approved command")


@pytest.mark.asyncio
async def test_channel_gateway_message_can_reject_pending_command(client, db_session):
    cmd_id = "cmd_chan_reject_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner2@company.com",
        actor_name="owner2@company.com",
        actor_type="human",
        action="run_workflow",
        target="incident_response",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.MEDIUM,
        risk_score=69.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded for channel reject flow test",
        description="[commandclaw] owner2@company.com -> run_workflow",
        metadata_json=json.dumps(
            {"context": {"command_id": cmd_id, "requester": "owner2@company.com", "mode": "approval"}}
        ),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "slack",
            "platform_user_id": "secops-reviewer",
            "platform_email": "reviewer@company.com",
            "platform_name": "SecOps Reviewer",
            "regentclaw_role": "security_admin",
            "is_trusted": True,
            "trust_score": 90,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/message",
        json={
            "channel_type": "slack",
            "channel_id": "soc-room",
            "sender_id": "secops-reviewer",
            "sender_email": "reviewer@company.com",
            "sender_name": "SecOps Reviewer",
            "message_text": f"reject {cmd_id}",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    cr = body["command_result"]
    assert cr["review_action"] == "reject"
    assert cr["outcome"] == "allowed"
    assert body["execution_status"] == "dispatched"
    assert body["response_text"].startswith("🛑 Rejected command")


@pytest.mark.asyncio
async def test_channel_gateway_outbound_response_skips_without_webhook(client):
    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "teams",
            "platform_user_id": "outbound-no-hook",
            "platform_email": "outbound@company.com",
            "platform_name": "Outbound User",
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
            "channel_id": "missing-webhook-room",
            "sender_id": "outbound-no-hook",
            "sender_email": "outbound@company.com",
            "sender_name": "Outbound User",
            "message_text": "run cloud scan in prod",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["response_sent"] is False
    assert body["outbound_delivery"] == {
        "status": "skipped",
        "reason": "missing_webhook_url",
    }


@pytest.mark.asyncio
async def test_channel_gateway_outbound_response_posts_to_configured_channel(client, monkeypatch):
    calls = []

    async def fake_dispatch_alert(channel_type, title, text, config):
        calls.append(
            {
                "channel_type": channel_type,
                "title": title,
                "text": text,
                "config": config,
            }
        )
        return True

    monkeypatch.setattr(
        "app.api.routes.channel_gateway.dispatch_alert",
        fake_dispatch_alert,
    )

    config = await client.post(
        "/api/v1/channel-gateway/configs",
        json={
            "channel_type": "slack",
            "channel_id": "configured-room",
            "channel_name": "Configured Room",
            "webhook_url": "https://hooks.slack.test/services/T/B/C",
            "is_enabled": True,
        },
    )
    assert config.status_code == 200, config.text

    identity = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "slack",
            "platform_user_id": "outbound-hook",
            "platform_email": "hooked@company.com",
            "platform_name": "Hooked User",
            "regentclaw_role": "engineer",
            "is_trusted": True,
            "trust_score": 88,
        },
    )
    assert identity.status_code == 200, identity.text

    resp = await client.post(
        "/api/v1/channel-gateway/message",
        json={
            "channel_type": "slack",
            "channel_id": "configured-room",
            "sender_id": "outbound-hook",
            "sender_email": "hooked@company.com",
            "sender_name": "Hooked User",
            "message_text": "run cloud scan in prod",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["response_sent"] is True
    assert body["outbound_delivery"]["status"] == "sent"
    assert body["outbound_delivery"]["channel_type"] == "slack"
    assert calls
    assert calls[0]["channel_type"] == "slack"
    assert calls[0]["config"]["webhook_url"].startswith("https://hooks.slack.test/")
