import pytest
import json
import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from app.models.event import Event, EventOutcome, EventSeverity
from app.models.agent import Agent


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
async def test_remote_agent_signed_enrollment_and_key_rotation(client):
    token_res = await client.post(
        "/api/v1/remote-agents/enrollment-token",
        json={
            "tenant_id": "tenant_signed",
            "owner": "signed-owner@company.com",
            "allowed_claws": ["identityclaw"],
            "allowed_connectors": ["entra_id"],
            "allowed_actions": ["run_swarm"],
            "ttl_minutes": 30,
        },
    )
    assert token_res.status_code == 200, token_res.text
    token = token_res.json()["token"]

    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "signed-edge-worker",
            "tenant_id": "tenant_signed",
            "owner": "signed-owner@company.com",
            "allowed_claws": ["identityclaw"],
            "allowed_connectors": ["entra_id"],
            "allowed_actions": ["run_swarm"],
            "version": "2.0.0",
            "public_key": "-----BEGIN PUBLIC KEY-----signed-key-v1-----END PUBLIC KEY-----",
            "capabilities": ["swarm_task", "connector_read"],
            "enrollment_token": token,
        },
    )
    assert reg.status_code == 200, reg.text
    body = reg.json()
    agent_id = body["id"]
    assert body["key_fingerprint"]
    assert body["capabilities"] == ["swarm_task", "connector_read"]

    rotate = await client.post(
        f"/api/v1/remote-agents/{agent_id}/rotate-key",
        json={
            "public_key": "-----BEGIN PUBLIC KEY-----signed-key-v2-----END PUBLIC KEY-----",
            "reason": "scheduled rotation",
        },
    )
    assert rotate.status_code == 200, rotate.text
    rotated = rotate.json()
    assert rotated["key_fingerprint"] != body["key_fingerprint"]

    duplicate = await client.post(
        f"/api/v1/remote-agents/{agent_id}/rotate-key",
        json={
            "public_key": "-----BEGIN PUBLIC KEY-----signed-key-v2-----END PUBLIC KEY-----",
            "reason": "duplicate rotation",
        },
    )
    assert duplicate.status_code == 409, duplicate.text


@pytest.mark.asyncio
async def test_remote_agent_signed_enrollment_blocks_scope_expansion(client):
    token_res = await client.post(
        "/api/v1/remote-agents/enrollment-token",
        json={
            "tenant_id": "tenant_scope",
            "owner": "scope-owner@company.com",
            "allowed_claws": ["identityclaw"],
            "allowed_connectors": ["entra_id"],
            "allowed_actions": ["run_swarm"],
        },
    )
    assert token_res.status_code == 200, token_res.text

    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "scope-expansion-worker",
            "tenant_id": "tenant_scope",
            "owner": "scope-owner@company.com",
            "allowed_claws": ["identityclaw", "cloudclaw"],
            "allowed_connectors": ["entra_id"],
            "allowed_actions": ["run_swarm", "create_ticket"],
            "enrollment_token": token_res.json()["token"],
        },
    )
    assert reg.status_code == 403, reg.text
    assert "exceed enrollment token scope" in reg.text


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
async def test_remote_agent_dispatch_blocks_stale_heartbeat(client, db_session):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "edge-worker-stale",
            "tenant_id": "tenant_stale",
            "owner": "owner@company.com",
            "allowed_actions": ["run_swarm"],
        },
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["id"]

    result = await db_session.execute(select(Agent).where(Agent.id == uuid.UUID(agent_id)))
    agent = result.scalar_one()
    meta = json.loads(agent.scope_notes or "{}")
    meta["last_seen"] = (datetime.now(timezone.utc) - timedelta(minutes=45)).isoformat()
    agent.scope_notes = json.dumps(meta)
    db_session.add(agent)
    await db_session.commit()

    dispatch = await client.post(
        f"/api/v1/remote-agents/{agent_id}/dispatch",
        json={
            "command_id": "cmd_stale_dispatch",
            "source": "portal",
            "requester": "owner@company.com",
            "tenant_id": "tenant_stale",
            "intent": "run_swarm",
            "target": "identity_risk",
            "scope": "prod",
            "mode": "approval",
            "classification": "internal",
            "payload": {},
        },
    )
    assert dispatch.status_code == 409, dispatch.text
    assert "heartbeat is stale" in dispatch.text


@pytest.mark.asyncio
async def test_remote_agent_dispatch_blocks_low_trust_score(client):
    reg = await client.post(
        "/api/v1/remote-agents/register",
        json={
            "name": "edge-worker-low-trust",
            "tenant_id": "tenant_trust",
            "owner": "owner@company.com",
            "allowed_actions": ["run_swarm"],
            "trust_score": 20,
        },
    )
    assert reg.status_code == 200, reg.text
    agent_id = reg.json()["id"]

    dispatch = await client.post(
        f"/api/v1/remote-agents/{agent_id}/dispatch",
        json={
            "command_id": "cmd_low_trust",
            "source": "portal",
            "requester": "owner@company.com",
            "tenant_id": "tenant_trust",
            "intent": "run_swarm",
            "target": "identity_risk",
            "scope": "prod",
            "mode": "approval",
            "classification": "internal",
            "payload": {},
        },
    )
    assert dispatch.status_code == 403, dispatch.text
    assert "trust score below minimum dispatch threshold" in dispatch.text


@pytest.mark.asyncio
async def test_remote_agent_health_endpoint(client):
    reg_fresh = await client.post(
        "/api/v1/remote-agents/register",
        json={"name": "edge-worker-health-a", "tenant_id": "tenant_health", "owner": "owner@company.com"},
    )
    reg_stale = await client.post(
        "/api/v1/remote-agents/register",
        json={"name": "edge-worker-health-b", "tenant_id": "tenant_health", "owner": "owner@company.com"},
    )
    assert reg_fresh.status_code == 200 and reg_stale.status_code == 200

    health = await client.get("/api/v1/remote-agents/health")
    assert health.status_code == 200, health.text
    body = health.json()
    assert "heartbeat_ttl_minutes" in body
    assert "min_trust_score" in body
    assert body["total"] >= 2
    assert isinstance(body["agents"], list)


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

    # duplicate principal remains blocked even if display name changes
    dup_spoof = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "different-display-name", "reason": "attempt display spoof"},
    )
    assert dup_spoof.status_code == 409, dup_spoof.text

    # Same JWT principal cannot add a second approval even with a different display value.
    second = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-lead", "reason": "second approval"},
    )
    assert second.status_code == 409, second.text


@pytest.mark.asyncio
async def test_commands_self_approval_blocked_by_jwt_principal(client, db_session):
    cmd_id = "cmd_self_block_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="test-user",
        actor_name="test-user",
        actor_type="human",
        action="run_scan",
        target="cloud",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.HIGH,
        risk_score=80.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded self approval principal test",
        description="[commandclaw] test-user -> run_scan",
        metadata_json=json.dumps(
            {"context": {"command_id": cmd_id, "requester": "test-user", "mode": "approval"}}
        ),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    self_approve = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "spoofed-display", "reason": "self approve attempt"},
    )
    assert self_approve.status_code == 403, self_approve.text


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

    approvals_only = await client.get(f"/api/v1/commands/{cmd_id}/timeline?action_contains=approve")
    assert approvals_only.status_code == 200, approvals_only.text
    approvals_actions = {item["action"] for item in approvals_only.json()["timeline"]}
    assert all("approve" in a for a in approvals_actions)

    allowed_approvals = await client.get(
        f"/api/v1/commands/{cmd_id}/timeline?action_contains=approve&outcome=allowed"
    )
    assert allowed_approvals.status_code == 200, allowed_approvals.text
    rows = allowed_approvals.json()["timeline"]
    assert rows
    assert all("approve" in (item.get("action") or "") for item in rows)
    assert all((item.get("outcome") or "").lower() == "allowed" for item in rows)


@pytest.mark.asyncio
async def test_commands_pending_filters_and_status_endpoint(client, db_session):
    seeded_a = Event(
        source_module="commandclaw",
        actor_id="req-a@company.com",
        actor_name="req-a@company.com",
        actor_type="human",
        action="run_scan",
        target="cloud",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.MEDIUM,
        risk_score=42.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded A",
        description="[commandclaw] req-a@company.com -> run_scan",
        metadata_json=json.dumps({"context": {"command_id": "cmd_filter_a", "requester": "req-a@company.com", "source": "cli"}}),
        is_anomaly=False,
        requires_review=True,
    )
    seeded_b = Event(
        source_module="commandclaw",
        actor_id="req-b@company.com",
        actor_name="req-b@company.com",
        actor_type="human",
        action="run_swarm",
        target="identity",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.HIGH,
        risk_score=86.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded B",
        description="[commandclaw] req-b@company.com -> run_swarm",
        metadata_json=json.dumps({"context": {"command_id": "cmd_filter_b", "requester": "req-b@company.com", "source": "teams"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add_all([seeded_a, seeded_b])
    await db_session.commit()

    filtered = await client.get("/api/v1/commands/pending?source=teams&min_risk=80")
    assert filtered.status_code == 200, filtered.text
    body = filtered.json()
    ids = {c["command_id"] for c in body["commands"]}
    assert "cmd_filter_b" in ids
    assert "cmd_filter_a" not in ids

    status = await client.get("/api/v1/commands/cmd_filter_b/status")
    assert status.status_code == 200, status.text
    status_body = status.json()
    assert status_body["command_id"] == "cmd_filter_b"
    assert status_body["source"] == "teams"
    assert status_body["requester"] == "req-b@company.com"
    assert "approval_audit" in status_body
    assert status_body["approval_audit"]["approvals_count"] == 0


@pytest.mark.asyncio
async def test_update_command_approval_policy_flow(client, db_session):
    cmd_id = "cmd_policy_update_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner4@company.com",
        actor_name="owner4@company.com",
        actor_type="human",
        action="run_workflow",
        target="incident-response",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.HIGH,
        risk_score=74.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded policy update test",
        description="[commandclaw] owner4@company.com -> run_workflow",
        metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner4@company.com", "mode": "approval"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    update = await client.post(
        f"/api/v1/commands/{cmd_id}/approval-policy",
        json={"required_approvals": 3, "reason": "high impact action"},
    )
    assert update.status_code == 200, update.text
    body = update.json()
    assert body["required_approvals"] == 3
    assert body["approvals_received"] == 0
    assert body["approval_status"] == "pending"


@pytest.mark.asyncio
async def test_update_command_approval_policy_rejects_below_recorded_approvals(client, db_session):
    cmd_id = "cmd_policy_update_002"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner5@company.com",
        actor_name="owner5@company.com",
        actor_type="human",
        action="run_workflow",
        target="incident-response",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.HIGH,
        risk_score=74.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded policy update test",
        description="[commandclaw] owner5@company.com -> run_workflow",
        metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner5@company.com", "mode": "approval"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    set_three = await client.post(
        f"/api/v1/commands/{cmd_id}/approval-policy",
        json={"required_approvals": 3, "reason": "raise threshold"},
    )
    assert set_three.status_code == 200, set_three.text

    first = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-a", "reason": "step one"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["approvals_received"] == 1

    bad_update = await client.post(
        f"/api/v1/commands/{cmd_id}/approval-policy",
        json={"required_approvals": 0, "reason": "invalid lower bound"},
    )
    assert bad_update.status_code == 422, bad_update.text

    second = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "secops-b", "reason": "step two"},
    )
    assert second.status_code == 409, second.text

    # Simulate a second distinct operator approval for guardrail coverage.
    result = await db_session.execute(
        select(Event).where(Event.source_module == "commandclaw", Event.outcome == EventOutcome.REQUIRES_APPROVAL)
    )
    pending_events = result.scalars().all()
    pending = next((e for e in pending_events if cmd_id in (e.metadata_json or "")), None)
    assert pending is not None
    metadata = json.loads(pending.metadata_json or "{}")
    approval_state = metadata.get("approval_state") or {}
    approvals = approval_state.get("approvals") or []
    approvals.append(
        {
            "approved_at": "2026-05-31T00:00:00Z",
            "approved_by": "secops-other-user",
            "approver_display": "secops-other-user",
            "reason": "seeded second principal",
        }
    )
    approval_state["approvals"] = approvals
    approval_state["required_approvals"] = 3
    approval_state["status"] = "pending"
    metadata["approval_state"] = approval_state
    pending.metadata_json = json.dumps(metadata)
    db_session.add(pending)
    await db_session.commit()

    deny_lower = await client.post(
        f"/api/v1/commands/{cmd_id}/approval-policy",
        json={"required_approvals": 1, "reason": "now below recorded approvals"},
    )
    assert deny_lower.status_code == 400, deny_lower.text


@pytest.mark.asyncio
async def test_bulk_review_pending_commands_approve_flow(client, db_session):
    cmd_ids = ["cmd_bulk_approve_1", "cmd_bulk_approve_2"]
    seeded_events = []
    for cmd_id in cmd_ids:
        seeded_events.append(
            Event(
                source_module="commandclaw",
                actor_id="owner-bulk@company.com",
                actor_name="owner-bulk@company.com",
                actor_type="human",
                action="run_swarm",
                target="cloud_exposure",
                target_type="command_target",
                outcome=EventOutcome.REQUIRES_APPROVAL,
                severity=EventSeverity.HIGH,
                risk_score=81.0,
                policy_name="seeded_requires_approval",
                policy_reason="seeded bulk approve test",
                description="[commandclaw] owner-bulk@company.com -> run_swarm",
                metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner-bulk@company.com", "mode": "approval"}}),
                is_anomaly=False,
                requires_review=True,
            )
        )
    db_session.add_all(seeded_events)
    await db_session.commit()

    bulk = await client.post(
        "/api/v1/commands/bulk-review",
        json={
            "command_ids": cmd_ids,
            "decision": "approve",
            "actor": "secops-bulk",
            "reason": "bulk approval step one",
        },
    )
    assert bulk.status_code == 200, bulk.text
    body = bulk.json()
    assert body["processed"] == 2
    assert body["approved"] == 0
    assert body["rejected"] == 0
    assert body["errors"] == []


@pytest.mark.asyncio
async def test_bulk_review_pending_commands_reject_flow(client, db_session):
    cmd_ids = ["cmd_bulk_reject_1", "cmd_bulk_reject_2"]
    seeded_events = []
    for cmd_id in cmd_ids:
        seeded_events.append(
            Event(
                source_module="commandclaw",
                actor_id="owner-reject@company.com",
                actor_name="owner-reject@company.com",
                actor_type="human",
                action="run_workflow",
                target="incident_response",
                target_type="command_target",
                outcome=EventOutcome.REQUIRES_APPROVAL,
                severity=EventSeverity.MEDIUM,
                risk_score=66.0,
                policy_name="seeded_requires_approval",
                policy_reason="seeded bulk reject test",
                description="[commandclaw] owner-reject@company.com -> run_workflow",
                metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner-reject@company.com", "mode": "approval"}}),
                is_anomaly=False,
                requires_review=True,
            )
        )
    db_session.add_all(seeded_events)
    await db_session.commit()

    bulk = await client.post(
        "/api/v1/commands/bulk-review",
        json={
            "command_ids": cmd_ids,
            "decision": "reject",
            "actor": "secops-bulk",
            "reason": "bulk rejection",
        },
    )
    assert bulk.status_code == 200, bulk.text
    body = bulk.json()
    assert body["processed"] == 2
    assert body["approved"] == 0
    assert body["rejected"] == 2
    assert body["errors"] == []


@pytest.mark.asyncio
async def test_bulk_review_pending_commands_rejects_duplicate_ids(client):
    dup = await client.post(
        "/api/v1/commands/bulk-review",
        json={
            "command_ids": ["cmd_dup_1", "cmd_dup_1"],
            "decision": "approve",
            "actor": "secops-bulk",
            "reason": "duplicate payload test",
        },
    )
    assert dup.status_code == 400, dup.text
    assert "must not contain duplicates" in dup.json().get("detail", "")


@pytest.mark.asyncio
async def test_bulk_review_pending_commands_partial_errors_reported(client, db_session):
    cmd_id = "cmd_bulk_partial_1"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner-partial@company.com",
        actor_name="owner-partial@company.com",
        actor_type="human",
        action="run_scan",
        target="cloud",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.MEDIUM,
        risk_score=60.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded partial error test",
        description="[commandclaw] owner-partial@company.com -> run_scan",
        metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner-partial@company.com", "mode": "approval"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    bulk = await client.post(
        "/api/v1/commands/bulk-review",
        json={
            "command_ids": [cmd_id, "cmd_missing_partial"],
            "decision": "approve",
            "actor": "secops-bulk",
            "reason": "partial bulk approve",
        },
    )
    assert bulk.status_code == 200, bulk.text
    body = bulk.json()
    assert body["requested"] == 2
    assert body["processed"] == 1
    assert body["approved"] == 0
    assert body["rejected"] == 0
    assert len(body["errors"]) == 1
    assert body["errors"][0]["command_id"] == "cmd_missing_partial"


@pytest.mark.asyncio
async def test_command_status_includes_approval_audit_details(client, db_session):
    cmd_id = "cmd_status_audit_001"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner-audit@company.com",
        actor_name="owner-audit@company.com",
        actor_type="human",
        action="run_scan",
        target="cloud",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.MEDIUM,
        risk_score=61.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded status audit test",
        description="[commandclaw] owner-audit@company.com -> run_scan",
        metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner-audit@company.com", "mode": "approval"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    first = await client.post(
        f"/api/v1/commands/{cmd_id}/approve",
        json={"approver": "audit-display", "reason": "first"},
    )
    assert first.status_code == 200, first.text

    status = await client.get(f"/api/v1/commands/{cmd_id}/status")
    assert status.status_code == 200, status.text
    body = status.json()
    audit = body.get("approval_audit") or {}
    assert audit.get("approvals_count") == 1
    assert audit.get("last_approved_by") == "test-user"
    assert audit.get("last_approver_display") == "audit-display"


@pytest.mark.asyncio
async def test_bulk_review_pending_commands_duplicate_principal_blocked_even_with_display_change(client, db_session):
    cmd_id = "cmd_bulk_principal_dup_1"
    seeded = Event(
        source_module="commandclaw",
        actor_id="owner-principal@company.com",
        actor_name="owner-principal@company.com",
        actor_type="human",
        action="run_scan",
        target="cloud",
        target_type="command_target",
        outcome=EventOutcome.REQUIRES_APPROVAL,
        severity=EventSeverity.MEDIUM,
        risk_score=60.0,
        policy_name="seeded_requires_approval",
        policy_reason="seeded principal duplication test",
        description="[commandclaw] owner-principal@company.com -> run_scan",
        metadata_json=json.dumps({"context": {"command_id": cmd_id, "requester": "owner-principal@company.com", "mode": "approval"}}),
        is_anomaly=False,
        requires_review=True,
    )
    db_session.add(seeded)
    await db_session.commit()

    first = await client.post(
        "/api/v1/commands/bulk-review",
        json={
            "command_ids": [cmd_id],
            "decision": "approve",
            "actor": "display-one",
            "reason": "first principal approval",
        },
    )
    assert first.status_code == 200, first.text
    first_body = first.json()
    assert first_body["processed"] == 1
    assert first_body["errors"] == []

    second = await client.post(
        "/api/v1/commands/bulk-review",
        json={
            "command_ids": [cmd_id],
            "decision": "approve",
            "actor": "display-two",
            "reason": "same principal, different display",
        },
    )
    assert second.status_code == 200, second.text
    second_body = second.json()
    assert second_body["processed"] == 0
    assert len(second_body["errors"]) == 1
    assert "Approver already recorded" in second_body["errors"][0]["detail"]
