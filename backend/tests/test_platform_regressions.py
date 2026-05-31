import json

import pytest


@pytest.mark.asyncio
async def test_policy_packs_stats_route_not_shadowed(client):
    resp = await client.get("/api/v1/policy-packs/stats")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "total_packs" in body
    assert "applied_packs" in body
    assert "total_policies" in body


@pytest.mark.asyncio
async def test_schedule_delete_with_linked_runs(client):
    agent_resp = await client.post(
        "/api/v1/agents",
        json={
            "name": "Schedule Test Agent",
            "description": "Regression test agent",
            "claw": "identityclaw",
            "execution_mode": "monitor",
            "risk_level": "low",
            "status": "active",
        },
    )
    assert agent_resp.status_code == 201, agent_resp.text
    agent_id = agent_resp.json()["id"]

    sched_resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Regression Schedule",
            "agent_id": agent_id,
            "frequency": "hourly",
            "status": "active",
            "approval_required": False,
        },
    )
    assert sched_resp.status_code == 201, sched_resp.text
    schedule_id = sched_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/schedules/{schedule_id}/run")
    assert run_resp.status_code == 202, run_resp.text

    delete_resp = await client.delete(f"/api/v1/schedules/{schedule_id}")
    assert delete_resp.status_code == 204, delete_resp.text


@pytest.mark.asyncio
async def test_autonomy_emergency_json_payload_shape(client):
    on_resp = await client.post(
        "/api/v1/autonomy/emergency/activate",
        json={"reason": "regression test", "activated_by": "tester"},
    )
    assert on_resp.status_code == 200, on_resp.text
    assert on_resp.json()["status"] == "emergency_mode_activated"

    off_resp = await client.post(
        "/api/v1/autonomy/emergency/deactivate",
        json={"deactivated_by": "tester"},
    )
    assert off_resp.status_code == 200, off_resp.text
    assert off_resp.json()["status"] == "emergency_mode_deactivated"


@pytest.mark.asyncio
async def test_orchestration_replay_alias_by_run_id(client):
    create_resp = await client.post(
        "/api/v1/orchestrations",
        json={
            "name": "Replay Alias Workflow",
            "description": "Regression workflow",
            "trigger_type": "manual",
            "is_active": True,
            "steps_json": json.dumps(
                [
                    {"id": "s1", "name": "notify", "type": "notify", "config": {"message": "hi"}, "on_failure": "continue"},
                    {"id": "s2", "name": "wait", "type": "wait", "config": {"seconds": 1}, "on_failure": "stop"},
                ]
            ),
        },
    )
    assert create_resp.status_code == 201, create_resp.text
    workflow_id = create_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/orchestrations/{workflow_id}/run")
    assert run_resp.status_code == 200, run_resp.text
    run_id = run_resp.json()["run_id"]

    replay_resp = await client.get(f"/api/v1/orchestrations/run-replay/{run_id}")
    assert replay_resp.status_code == 200, replay_resp.text
    replay = replay_resp.json()
    assert replay["run"]["id"] == run_id
    assert "timeline" in replay


@pytest.mark.asyncio
async def test_trust_fabric_multi_agent_status(client):
    resp = await client.get("/api/v1/trust-fabric/multi-agent/status")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["provider"] == "agt"
    assert "agent_mesh_enabled" in body
    assert "encrypted_messaging_enabled" in body
    assert "cryptographic_identity_enabled" in body
    assert "signature_algorithm" in body
    assert "compatibility_mode" in body


@pytest.mark.asyncio
async def test_trust_fabric_mcp_scan_route(client):
    resp = await client.post(
        "/api/v1/trust-fabric/mcp/scan",
        json={"target_type": "skill", "path": "/app/app"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["target_type"] == "skill"
    assert "mcp_gateway_enabled" in body
    assert "risk_score" in body


@pytest.mark.asyncio
async def test_trust_fabric_mcp_scan_blocks_parent_traversal_path(client):
    resp = await client.post(
        "/api/v1/trust-fabric/mcp/scan",
        json={"target_type": "skill", "path": "../../etc"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_safe"] is False
    assert body["risk_score"] >= 90
    assert "error" in body


@pytest.mark.asyncio
async def test_trust_fabric_mcp_scan_blocks_absolute_outside_repo_path(client):
    resp = await client.post(
        "/api/v1/trust-fabric/mcp/scan",
        json={"target_type": "skill", "path": "/etc"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_safe"] is False
    assert body["risk_score"] >= 90
    assert "error" in body


@pytest.mark.asyncio
async def test_trust_fabric_multi_agent_verify_route(client):
    from app.core.config import settings
    from app.fabric.providers.agt import adapter as agt_adapter_module
    from app.fabric.providers.agt import get_agt_adapter

    settings.AGT_ENABLE_E2E_MESSAGING = True
    agt_adapter_module._adapter = None
    try:
        adapter = get_agt_adapter()
        secure = adapter.send_secure_message(
            sender="identityclaw",
            recipient="swarm_judge",
            message_type="TASK_RESULT",
            payload={"task_id": "t-1", "risk_score": 55},
        )

        resp = await client.post(
            "/api/v1/trust-fabric/multi-agent/verify",
            json={
                "envelope": secure["envelope"],
                "signature": secure["signature"],
                "key_id": secure["key_id"],
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["verified"] is True
        assert body["algorithm"] == "ed25519"
    finally:
        settings.AGT_ENABLE_E2E_MESSAGING = False
        agt_adapter_module._adapter = None


@pytest.mark.asyncio
async def test_trust_fabric_sre_status_and_reset(client):
    status = await client.get("/api/v1/trust-fabric/sre/status")
    assert status.status_code == 200, status.text
    body = status.json()
    assert "enabled" in body
    assert "modules" in body

    reset = await client.post("/api/v1/trust-fabric/sre/reset", json={"module": None})
    assert reset.status_code == 200, reset.text
    assert reset.json()["reset"] is True


@pytest.mark.asyncio
async def test_trust_fabric_sre_circuit_breaker_blocks_evaluate(client):
    from app.core.config import settings
    from app.services.sre_policy import get_sre_engine

    old_min = settings.SRE_MIN_SAMPLES
    old_threshold = settings.SRE_CIRCUIT_BREAKER_THRESHOLD
    old_open = settings.SRE_CIRCUIT_BREAKER_OPEN_SECONDS
    old_enabled = settings.SRE_POLICY_ENABLED

    settings.SRE_POLICY_ENABLED = True
    settings.SRE_MIN_SAMPLES = 2
    settings.SRE_CIRCUIT_BREAKER_THRESHOLD = 0.5
    settings.SRE_CIRCUIT_BREAKER_OPEN_SECONDS = 60

    engine = get_sre_engine()
    engine.reset("sre_test_module")

    # Prime two failures to open the circuit.
    engine.record_outcome("sre_test_module", success=False)
    engine.record_outcome("sre_test_module", success=False)

    try:
        resp = await client.post(
            "/api/v1/trust-fabric/evaluate",
            json={
                "module": "sre_test_module",
                "actor_id": "tester",
                "actor_name": "Tester",
                "actor_type": "human",
                "action": "read_status",
                "target": "trust-fabric",
                "target_type": "module",
                "context": {},
            },
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["allowed"] is False
        assert body["policy_name"] == "sre_circuit_breaker"
    finally:
        settings.SRE_MIN_SAMPLES = old_min
        settings.SRE_CIRCUIT_BREAKER_THRESHOLD = old_threshold
        settings.SRE_CIRCUIT_BREAKER_OPEN_SECONDS = old_open
        settings.SRE_POLICY_ENABLED = old_enabled
        engine.reset("sre_test_module")


@pytest.mark.asyncio
async def test_trust_fabric_ring_policy_blocks_ring0_action(client):
    resp = await client.post(
        "/api/v1/trust-fabric/evaluate",
        json={
            "module": "exec_channels",
            "actor_id": "agent-1",
            "actor_name": "Agent One",
            "actor_type": "agent",
            "action": "kernel_exec",
            "target": "node-1",
            "target_type": "host",
            "context": {
                "channel": "kernel",
                "enforce_ring_policy": True,
                "caller_role": "super_admin",
                "trust_score": 99.0,
            },
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["allowed"] is False
    assert body["policy_name"] == "execution_ring_violation"


@pytest.mark.asyncio
async def test_trust_fabric_ring_policy_requires_approval(client):
    resp = await client.post(
        "/api/v1/trust-fabric/evaluate",
        json={
            "module": "remediation",
            "actor_id": "analyst-1",
            "actor_name": "Analyst One",
            "actor_type": "human",
            "action": "create_ticket",
            "target": "finding-123",
            "target_type": "finding",
            "context": {
                "enforce_ring_policy": True,
                "caller_role": "analyst",
                "trust_score": 20.0,
            },
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["allowed"] is False
    assert body["outcome"] == "requires_approval"
    assert body["policy_name"] == "execution_ring_policy"


@pytest.mark.asyncio
async def test_exec_shell_request_fails_closed_when_trust_fabric_unavailable_by_default(client):
    resp = await client.post(
        "/api/v1/exec/shell",
        json={
            "command": "ls -la",
            "requested_by": "tester",
            "environment": "dev",
            "agent_id": "agent-1",
            "caller_role": "admin",
        },
    )
    assert resp.status_code == 503, resp.text
    detail = resp.json().get("detail", {})
    assert detail.get("policy_name") == "trust_fabric_unavailable"


@pytest.mark.asyncio
async def test_exec_shell_request_fails_closed_when_trust_fabric_unavailable(client, monkeypatch):
    import app.api.routes.exec_channels as exec_routes

    async def _raise_enforce(*args, **kwargs):
        raise RuntimeError("tf down")

    monkeypatch.setattr(exec_routes, "enforce", _raise_enforce)

    resp = await client.post(
        "/api/v1/exec/shell",
        json={
            "command": "ls -la",
            "requested_by": "tester",
            "environment": "dev",
            "agent_id": "agent-1",
            "caller_role": "admin",
        },
    )
    assert resp.status_code == 503, resp.text
    detail = resp.json().get("detail", {})
    assert detail.get("policy_name") == "trust_fabric_unavailable"


@pytest.mark.asyncio
async def test_exec_execute_fails_closed_when_trust_fabric_unavailable(client, monkeypatch):
    import app.api.routes.exec_channels as exec_routes
    monkeypatch.setattr(exec_routes, "PRODUCTION_APPROVALS_REQUIRED", 1)
    
    class _Val:
        def __init__(self, value):
            self.value = value
    
    class _Decision:
        allowed = True
        outcome = _Val("requires_approval")
        severity = _Val("medium")
        policy_name = "execution_ring_policy"
        reason = "approval required"

    async def _allow_enforce(*args, **kwargs):
        return _Decision()

    # Allow create path so request can be persisted, then fail closed on execute.
    monkeypatch.setattr(exec_routes, "enforce", _allow_enforce)

    create = await client.post(
        "/api/v1/exec/shell",
        json={
            "command": "echo hello",
            "requested_by": "tester",
            "environment": "dev",
            "agent_id": "agent-1",
            "caller_role": "admin",
        },
    )
    assert create.status_code == 200, create.text
    req_id = create.json()["id"]

    # single approval after test-local override above
    a1 = await client.post(f"/api/v1/exec/requests/{req_id}/approve", json={"note": "ok1"})
    assert a1.status_code == 200, a1.text
    assert a1.json()["status"] == "approved"

    async def _raise_enforce(*args, **kwargs):
        raise RuntimeError("tf down")

    monkeypatch.setattr(exec_routes, "enforce", _raise_enforce)

    run = await client.post(f"/api/v1/exec/requests/{req_id}/execute")
    assert run.status_code == 503, run.text
    detail = run.json().get("detail", {})
    assert detail.get("policy_name") == "trust_fabric_unavailable"


@pytest.mark.asyncio
async def test_production_gate_approve_uses_authenticated_identity(client, monkeypatch):
    import app.api.routes.exec_channels as exec_routes

    monkeypatch.setattr(exec_routes, "PRODUCTION_APPROVALS_REQUIRED", 1)
    created = await client.post(
        "/api/v1/exec/production",
        json={
            "title": "Apply prod change",
            "requested_by": "operator-a",
            "change_type": "config_update",
            "target_system": "prod-api",
        },
    )
    assert created.status_code == 200, created.text
    gate_id = created.json()["id"]

    approve = await client.post(
        f"/api/v1/exec/production-gates/{gate_id}/approve",
        json={"approved_by": "spoofed-user", "note": "approve"},
    )
    assert approve.status_code == 200, approve.text

    detail = await client.get(f"/api/v1/exec/production-gates/{gate_id}")
    assert detail.status_code == 200, detail.text
    approvals = detail.json().get("approvals_received") or []
    assert approvals
    assert approvals[0]["approver"] == "test-user"


@pytest.mark.asyncio
async def test_production_gate_execute_fails_closed_when_trust_fabric_unavailable(client, monkeypatch):
    import app.api.routes.exec_channels as exec_routes

    monkeypatch.setattr(exec_routes, "PRODUCTION_APPROVALS_REQUIRED", 1)
    created = await client.post(
        "/api/v1/exec/production",
        json={
            "title": "Apply prod change",
            "requested_by": "operator-a",
            "change_type": "config_update",
            "target_system": "prod-api",
        },
    )
    assert created.status_code == 200, created.text
    gate_id = created.json()["id"]

    approve = await client.post(
        f"/api/v1/exec/production-gates/{gate_id}/approve",
        json={"approved_by": "admin-user"},
    )
    assert approve.status_code == 200, approve.text
    assert approve.json()["status"] == "approved"

    async def _raise_enforce(*args, **kwargs):
        raise RuntimeError("tf down")

    monkeypatch.setattr(exec_routes, "enforce", _raise_enforce)

    execute = await client.post(f"/api/v1/exec/production-gates/{gate_id}/execute")
    assert execute.status_code == 503, execute.text
    detail = execute.json().get("detail", {})
    assert detail.get("policy_name") == "trust_fabric_unavailable"


@pytest.mark.asyncio
async def test_production_gate_self_approval_blocked(client):
    created = await client.post(
        "/api/v1/exec/production",
        json={
            "title": "Apply prod change",
            "requested_by": "test-user",
            "change_type": "config_update",
            "target_system": "prod-api",
        },
    )
    assert created.status_code == 200, created.text
    gate_id = created.json()["id"]

    approve = await client.post(
        f"/api/v1/exec/production-gates/{gate_id}/approve",
        json={"approved_by": "spoofed-user"},
    )
    assert approve.status_code == 403, approve.text
    assert "Self-approval not permitted" in approve.text


@pytest.mark.asyncio
async def test_production_gate_reject_uses_authenticated_identity(client):
    created = await client.post(
        "/api/v1/exec/production",
        json={
            "title": "Apply prod change",
            "requested_by": "operator-a",
            "change_type": "config_update",
            "target_system": "prod-api",
        },
    )
    assert created.status_code == 200, created.text
    gate_id = created.json()["id"]

    reject = await client.post(
        f"/api/v1/exec/production-gates/{gate_id}/reject",
        json={"rejected_by": "spoofed-user", "reason": "not safe"},
    )
    assert reject.status_code == 200, reject.text

    detail = await client.get(f"/api/v1/exec/production-gates/{gate_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["rejected_by"] == "test-user"


@pytest.mark.asyncio
async def test_remediation_approve_blocked_by_ring0_trust_fabric(client):
    # Create a manual remediation action with ring0 action_type.
    trig = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "generic",
                "action_type": "kernel_exec",
                "target_id": "host-1",
                "target_type": "host",
                "target_label": "host-1",
                "parameters": {},
            },
            "triggered_by": "manual",
        },
    )
    assert trig.status_code == 200, trig.text
    actions = trig.json().get("actions") or []
    assert actions
    action_id = actions[0]["id"]

    approve = await client.post(
        f"/api/v1/remediation/actions/{action_id}/approve",
        json={"approved_by": "admin"},
    )
    assert approve.status_code == 403, approve.text
    detail = approve.json().get("detail", {})
    assert detail.get("policy_name") == "execution_ring_violation"


@pytest.mark.asyncio
async def test_remediation_approve_fails_closed_when_trust_fabric_unavailable(client, monkeypatch):
    trig = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "generic",
                "action_type": "disable_user",
                "target_id": "user-1",
                "target_type": "identity",
                "target_label": "user-1",
                "parameters": {},
            },
            "triggered_by": "manual",
        },
    )
    assert trig.status_code == 200, trig.text
    actions = trig.json().get("actions") or []
    assert actions
    action_id = actions[0]["id"]

    import app.api.routes.remediation as remediation_routes

    async def _raise_enforce(*args, **kwargs):
        raise RuntimeError("tf down")

    monkeypatch.setattr(remediation_routes, "enforce", _raise_enforce)

    approve = await client.post(
        f"/api/v1/remediation/actions/{action_id}/approve",
        json={"approved_by": "admin"},
    )
    assert approve.status_code == 503, approve.text
    detail = approve.json().get("detail", {})
    assert detail.get("policy_name") == "trust_fabric_unavailable"


@pytest.mark.asyncio
async def test_swarm_ticket_handoff_payload_shape_validation(client):
    missing_required = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "jira",
                "action_type": "create_jira_ticket",
                "target_type": "ticket",
                "target_id": "swarm_job_123",
                "parameters": {"project_key": "SEC", "summary": "x"},
            },
            "triggered_by": "swarm:test",
        },
    )
    assert missing_required.status_code == 400, missing_required.text
    assert "missing required parameters" in missing_required.json().get("detail", "")


@pytest.mark.asyncio
async def test_swarm_ticket_handoff_policy_outcome_low_risk_auto_approved(client):
    resp = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "jira",
                "action_type": "create_jira_ticket",
                "target_type": "ticket",
                "target_id": "swarm_job_123",
                "target_label": "Swarm Job 123",
                "parameters": {
                    "project_key": "SEC",
                    "summary": "[RegentClaw] Incident",
                    "description": "ticket draft body",
                },
            },
            "triggered_by": "swarm:test",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["triggered"] == 1
    action = body["actions"][0]
    assert action["action_type"] == "create_jira_ticket"
    assert action["provider"] == "jira"
    assert action["target_type"] == "ticket"
    assert action["target_id"] == "swarm_job_123"
    assert action["risk_level"] == "low"
    assert action["requires_approval"] is False
    assert action["status"] == "completed"
    assert action["triggered_by"] == "swarm:test"
    assert isinstance(action.get("parameters"), dict)
    assert action["parameters"]["project_key"] == "SEC"
    # Low-risk ticket handoff should never queue for approval.
    assert action["status"] != "pending_approval"


@pytest.mark.asyncio
async def test_swarm_ticket_handoff_rejects_invalid_project_key(client):
    invalid = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "jira",
                "action_type": "create_jira_ticket",
                "target_type": "ticket",
                "target_id": "swarm_job_123",
                "target_label": "Swarm Job 123",
                "parameters": {
                    "project_key": "sec",
                    "summary": "[RegentClaw] Incident",
                    "description": "ticket draft body with enough characters",
                },
            },
            "triggered_by": "swarm:test",
        },
    )
    assert invalid.status_code == 400, invalid.text
    assert "project_key must be uppercase" in invalid.json().get("detail", "")


@pytest.mark.asyncio
async def test_swarm_ticket_handoff_rejects_non_jira_provider(client):
    invalid = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "generic",
                "action_type": "create_jira_ticket",
                "target_type": "ticket",
                "target_id": "swarm_job_123",
                "parameters": {
                    "project_key": "SEC",
                    "summary": "[RegentClaw] Incident",
                    "description": "ticket draft body with enough characters",
                },
            },
            "triggered_by": "swarm:test",
        },
    )
    assert invalid.status_code == 400, invalid.text
    assert "requires provider='jira'" in invalid.json().get("detail", "")


@pytest.mark.asyncio
async def test_swarm_ticket_handoff_rejects_non_ticket_target_type(client):
    invalid = await client.post(
        "/api/v1/remediation/trigger",
        json={
            "action_spec": {
                "provider": "jira",
                "action_type": "create_jira_ticket",
                "target_type": "incident",
                "target_id": "swarm_job_123",
                "parameters": {
                    "project_key": "SEC",
                    "summary": "[RegentClaw] Incident",
                    "description": "ticket draft body with enough characters",
                },
            },
            "triggered_by": "swarm:test",
        },
    )
    assert invalid.status_code == 400, invalid.text
    assert "requires target_type='ticket'" in invalid.json().get("detail", "")


@pytest.mark.asyncio
async def test_trigger_start_swarm_action_creates_swarm_job(client):
    create = await client.post(
        "/api/v1/triggers",
        json={
            "name": "Trigger -> Swarm",
            "trigger_type": "webhook_inbound",
            "action_type": "start_swarm",
            "target_claw": "identityclaw,threatclaw",
            "alert_config_json": json.dumps(
                {
                    "name": "Webhook Incident Swarm",
                    "profile": "INCIDENT_RESPONSE",
                    "task_type": "investigate",
                    "parallelism": 2,
                    "classification": "internal",
                }
            ),
            "is_active": True,
        },
    )
    assert create.status_code == 201, create.text
    trigger_id = create.json()["id"]

    fired = await client.post(f"/api/v1/triggers/webhook/{trigger_id}", json={"severity": "high", "source": "test"})
    assert fired.status_code == 200, fired.text
    body = fired.json()
    assert body["status"] == "fired"
    assert body["action_type"] == "start_swarm"

    jobs = await client.get("/api/v1/swarm/jobs")
    assert jobs.status_code == 200, jobs.text
    assert any(j["name"] == "Webhook Incident Swarm" for j in jobs.json())


@pytest.mark.asyncio
async def test_schedule_run_swarm_uses_notes_config(client):
    agent_resp = await client.post(
        "/api/v1/agents",
        json={
            "name": "Schedule Swarm Agent",
            "description": "Regression schedule swarm",
            "claw": "identityclaw",
            "execution_mode": "monitor",
            "risk_level": "low",
            "status": "active",
        },
    )
    assert agent_resp.status_code == 201, agent_resp.text
    agent_id = agent_resp.json()["id"]

    sched_resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Swarm Schedule",
            "agent_id": agent_id,
            "frequency": "hourly",
            "status": "active",
            "approval_required": False,
            "notes": json.dumps(
                {
                    "type": "SWARM_JOB",
                    "action": {
                        "name": "Hourly Swarm Check",
                        "profile": "FAST_TRIAGE",
                        "participants": ["identityclaw", "cloudclaw"],
                        "task_type": "analyze",
                        "parallelism": 2,
                        "input": {"scenario": "scheduled_check"},
                    },
                }
            ),
        },
    )
    assert sched_resp.status_code == 201, sched_resp.text
    schedule_id = sched_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/schedules/{schedule_id}/run-swarm")
    assert run_resp.status_code == 202, run_resp.text
    body = run_resp.json()
    assert body["message"].startswith("Schedule 'Swarm Schedule' triggered swarm job")

    jobs = await client.get("/api/v1/swarm/jobs")
    assert jobs.status_code == 200, jobs.text
    assert any(j["name"] == "Hourly Swarm Check" for j in jobs.json())


@pytest.mark.asyncio
async def test_schedule_run_swarm_requires_pre_execution_approval(client):
    agent_resp = await client.post(
        "/api/v1/agents",
        json={
            "name": "Schedule Swarm Approval Agent",
            "description": "approval schedule swarm",
            "claw": "identityclaw",
            "execution_mode": "monitor",
            "risk_level": "low",
            "status": "active",
        },
    )
    assert agent_resp.status_code == 201, agent_resp.text
    agent_id = agent_resp.json()["id"]

    sched_resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Approval Swarm Schedule",
            "agent_id": agent_id,
            "frequency": "hourly",
            "status": "active",
            "approval_required": False,
            "notes": json.dumps(
                {
                    "type": "SWARM_JOB",
                    "action": {
                        "name": "Approval-Gated Swarm",
                        "profile": "FAST_TRIAGE",
                        "participants": ["identityclaw", "cloudclaw"],
                        "task_type": "analyze",
                        "parallelism": 2,
                        "requires_approval_for_actions": True,
                    },
                }
            ),
        },
    )
    assert sched_resp.status_code == 201, sched_resp.text
    schedule_id = sched_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/schedules/{schedule_id}/run-swarm")
    assert run_resp.status_code == 202, run_resp.text
    run_body = run_resp.json()
    assert run_body["status"] == "requires_approval"
    job_id = run_body["job_id"]

    job_resp = await client.get(f"/api/v1/swarm/jobs/{job_id}")
    assert job_resp.status_code == 200, job_resp.text
    assert job_resp.json()["started_at"] is None

    approve_resp = await client.post(f"/api/v1/swarm/jobs/{job_id}/approve")
    assert approve_resp.status_code == 200, approve_resp.text
    assert approve_resp.json()["status"] in {"completed", "requires_approval"}

    job_after = await client.get(f"/api/v1/swarm/jobs/{job_id}")
    assert job_after.status_code == 200, job_after.text
    assert job_after.json()["started_at"] is not None


@pytest.mark.asyncio
async def test_trigger_start_swarm_can_require_pre_execution_approval(client):
    create = await client.post(
        "/api/v1/triggers",
        json={
            "name": "Trigger -> Approval Swarm",
            "trigger_type": "webhook_inbound",
            "action_type": "start_swarm",
            "target_claw": "identityclaw,threatclaw",
            "alert_config_json": json.dumps(
                {
                    "name": "Webhook Approval Swarm",
                    "profile": "INCIDENT_RESPONSE",
                    "task_type": "investigate",
                    "parallelism": 2,
                    "requires_approval_for_actions": True,
                }
            ),
            "is_active": True,
        },
    )
    assert create.status_code == 201, create.text
    trigger_id = create.json()["id"]

    fire = await client.post(f"/api/v1/triggers/webhook/{trigger_id}", json={"incident": "approval-case"})
    assert fire.status_code == 200, fire.text

    jobs_resp = await client.get("/api/v1/swarm/jobs?limit=5")
    assert jobs_resp.status_code == 200, jobs_resp.text
    jobs = jobs_resp.json()
    assert jobs
    assert jobs[0]["name"] == "Webhook Approval Swarm"
    assert jobs[0]["status"] == "requires_approval"
    assert jobs[0]["started_at"] is None


@pytest.mark.asyncio
async def test_schedule_run_swarm_applies_profile_defaults(client):
    agent_resp = await client.post(
        "/api/v1/agents",
        json={
            "name": "Schedule Swarm Profile Agent",
            "description": "profile defaults",
            "claw": "identityclaw",
            "execution_mode": "monitor",
            "risk_level": "low",
            "status": "active",
        },
    )
    assert agent_resp.status_code == 201, agent_resp.text
    agent_id = agent_resp.json()["id"]

    sched_resp = await client.post(
        "/api/v1/schedules",
        json={
            "name": "Profile Default Swarm Schedule",
            "agent_id": agent_id,
            "frequency": "hourly",
            "status": "active",
            "approval_required": False,
            "notes": json.dumps(
                {
                    "type": "START_SWARM",
                    "action": {
                        "name": "Profile Defaults Swarm",
                        "profile": "INCIDENT_RESPONSE",
                        "participants": ["identityclaw", "cloudclaw"],
                    },
                }
            ),
        },
    )
    assert sched_resp.status_code == 201, sched_resp.text
    schedule_id = sched_resp.json()["id"]

    run_resp = await client.post(f"/api/v1/schedules/{schedule_id}/run-swarm")
    assert run_resp.status_code == 202, run_resp.text
    body = run_resp.json()
    # INCIDENT_RESPONSE defaults to approval-gated launch.
    assert body["status"] == "requires_approval"
    job_id = body["job_id"]

    job_resp = await client.get(f"/api/v1/swarm/jobs/{job_id}")
    assert job_resp.status_code == 200, job_resp.text
    job = job_resp.json()
    assert job["parallelism"] == 8
