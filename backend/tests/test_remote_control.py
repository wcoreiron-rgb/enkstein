import pytest
import json
from app.models.event import Event, EventOutcome, EventSeverity


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


@pytest.mark.asyncio
async def test_remote_agent_dispatch_blocks_tenant_mismatch(client):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "edge-worker-tenant-1",
            "tenant_id": "tenant_1",
            "owner": "owner@company.com",
            "allowed_actions": ["run_swarm"],
        },
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["id"]

    dispatch = await client.post(
        f"/api/v1/remote-agents/{agent_id}/dispatch",
        json={
            "command_id": "cmd_tenant_mismatch",
            "source": "portal",
            "requester": "owner@company.com",
            "tenant_id": "tenant_2",
            "intent": "run_swarm",
            "target": "identity_risk",
            "scope": "prod",
            "mode": "approval",
            "classification": "internal",
            "payload": {},
        },
    )
    assert dispatch.status_code == 403, dispatch.text
    assert "Tenant mismatch" in dispatch.text


@pytest.mark.asyncio
async def test_remote_agent_dispatch_blocks_disallowed_intent(client):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "edge-worker-limited",
            "tenant_id": "tenant_limit",
            "owner": "owner@company.com",
            "allowed_actions": ["run_scan"],
        },
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["id"]

    dispatch = await client.post(
        f"/api/v1/remote-agents/{agent_id}/dispatch",
        json={
            "command_id": "cmd_disallowed_intent",
            "source": "portal",
            "requester": "owner@company.com",
            "tenant_id": "tenant_limit",
            "intent": "run_swarm",
            "target": "identity_risk",
            "scope": "prod",
            "mode": "approval",
            "classification": "internal",
            "payload": {},
        },
    )
    assert dispatch.status_code == 403, dispatch.text
    assert "not allowed" in dispatch.text


@pytest.mark.asyncio
async def test_remote_agent_dispatch_remote_agent_id_must_match_path(client):
    reg_a = await client.post(
        "/api/v1/remote-agents/register",
        json={"name": "edge-worker-a", "tenant_id": "tenant_a1", "owner": "owner@company.com"},
    )
    reg_b = await client.post(
        "/api/v1/remote-agents/register",
        json={"name": "edge-worker-b", "tenant_id": "tenant_a1", "owner": "owner@company.com"},
    )
    assert reg_a.status_code == 200 and reg_b.status_code == 200
    agent_a = reg_a.json()["id"]
    agent_b = reg_b.json()["id"]

    dispatch = await client.post(
        f"/api/v1/remote-agents/{agent_a}/dispatch",
        json={
            "command_id": "cmd_id_mismatch",
            "source": "portal",
            "requester": "owner@company.com",
            "tenant_id": "tenant_a1",
            "intent": "run_scan",
            "target": "cloud",
            "scope": "prod",
            "mode": "assist",
            "classification": "internal",
            "remote_agent_id": agent_b,
            "payload": {},
        },
    )
    assert dispatch.status_code == 400, dispatch.text


@pytest.mark.asyncio
async def test_commands_pending_and_approve_flow(client, db_session):
    cmd_id = "cmd_pending_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner@company.com",
        actor_name="owner@company.com",
        actor_type="human",
        action="run_swarm",
        target="cloud_exposure",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.HIGH,
        risk_score=82.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded for approval workflow test",
        description="[commandclaw] owner@company.com -> run_swarm",
        metadata_json=json.dumps(
            {
                "context": {
                    "command_id": cmd_id,
                    "requester": "owner@company.com",
                    "mode": "approval",
                }
            }
        ),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    pending = await client.get("/api/v1/commands/pending")
    assert pending.status_code == 200, pending.text
    commands = pending.json()["commands"]
    match = next((c for c in commands if c["command_id"] == cmd_id), None)
    assert match is not None
    assert match["required_approvals"] == 2
    assert match["approvals_received"] == 0

    # self-approval blocked
    self_approve = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "owner@company.com", "reason": "self approve"},
    )
    assert self_approve.status_code == 403, self_approve.text

    # first distinct approval records step but keeps pending
    first = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-admin", "reason": "first approval"},
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["status"] == "pending_more_approvals"
    assert first_body["approvals_received"] == 1
    assert first_body["approvals_required"] == 2

    # duplicate approver blocked
    dup = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-admin", "reason": "duplicate approval"},
    )
    assert dup.status_code == 409, dup.text

    # second distinct approval finalizes
    second = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-lead", "reason": "second approval"},
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["status"] == "approved"
    assert second_body["approvals_received"] == 2
    assert second_body["approvals_required"] == 2


@pytest.mark.asyncio
async def test_commands_pending_reject_flow(client, db_session):
    cmd_id = "cmd_pending_reject_001"
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
        risk_score=68.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded for rejection workflow test",
        description="[commandclaw] owner2@company.com -> run_workflow",
        metadata_json=json.dumps(
            {
                "context": {
                    "command_id": cmd_id,
                    "requester": "owner2@company.com",
                    "mode": "approval",
                }
            }
        ),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    reject = await client.post(
        f"/api/v1/commands/{cmd_id}/reject",
        json={"reviewer": "secops-manager", "reason": "insufficient evidence"},
    )
    assert reject.status_code == 200, reject.text
    assert reject.json()["status"] == "rejected"

    pending_after = await client.get("/api/v1/commands/pending")
    assert pending_after.status_code == 200, pending_after.text
    commands = pending_after.json()["commands"]
    assert not any(c["command_id"] == cmd_id for c in commands)


@pytest.mark.asyncio
async def test_command_timeline_endpoint(client, db_session):
    cmd_id = "cmd_timeline_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner3@company.com",
        actor_name="owner3@company.com",
        actor_type="human",
        action="run_scan",
        target="cloud",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.MEDIUM,
        risk_score=55.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded for timeline test",
        description="[commandclaw] owner3@company.com -> run_scan",
        metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner3@company.com"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    approve = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-a", "reason": "step one"},
    )
    assert approve.status_code == 200, approve.text

    timeline = await client.get(f"/api/v1/commands/{cmd_id}/timeline")
    assert timeline.status_code == 200, timeline.text
    body = timeline.json()
    assert body["command_id"] == cmd_id
    assert body["count"] >= 2
    actions = {item["action"] for item in body["timeline"]}
    assert "run_scan" in actions
    assert "approve_command_step" in actions or "approve_command" in actions
