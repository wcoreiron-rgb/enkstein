"""Adversarial cross-tenant access checks for the platform routes.

The shared ``client`` fixture authenticates as tenant "global". Every record
below belongs to "tenant-intruder", so a correct implementation must hide it,
refuse the write, or 404 the lookup.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.agent import AgentRun, RunStatus, Schedule, ScheduleStatus
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.swarm import SwarmJob, SwarmJobStatus
from app.models.trigger import EventTrigger

OTHER = "tenant-intruder"


def _finding(tenant_id: str, title: str) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        claw="cloudclaw",
        provider="aws",
        external_id=f"ext-{title}",
        title=title,
        severity=FindingSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        risk_score=95.0,
    )


def _swarm_job(tenant_id: str, name: str) -> SwarmJob:
    return SwarmJob(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        name=name,
        profile="INCIDENT_RESPONSE",
        status=SwarmJobStatus.REQUIRES_APPROVAL,
        requested_by="intruder",
        trigger_type="manual",
        input_json="{}",
        classification="internal",
        participants_json=json.dumps(["identityclaw"]),
        parallelism=1,
    )


@pytest.mark.asyncio
async def test_findings_list_excludes_other_tenants(client, db_session):
    db_session.add(_finding(OTHER, "intruder-finding"))
    await db_session.commit()

    resp = await client.get("/api/v1/findings")
    assert resp.status_code == 200
    assert all(f["title"] != "intruder-finding" for f in resp.json())


@pytest.mark.asyncio
async def test_swarm_job_from_another_tenant_is_not_found(client, db_session):
    job = _swarm_job(OTHER, "intruder-swarm")
    db_session.add(job)
    await db_session.commit()

    assert (await client.get(f"/api/v1/swarm/jobs/{job.id}")).status_code == 404
    assert (await client.get(f"/api/v1/swarm/jobs/{job.id}/tasks")).status_code == 404
    assert (await client.post(f"/api/v1/swarm/jobs/{job.id}/cancel")).status_code == 404
    assert (await client.post(f"/api/v1/swarm/jobs/{job.id}/approve")).status_code == 404

    listing = await client.get("/api/v1/swarm/jobs")
    assert listing.status_code == 200
    assert all(j["id"] != str(job.id) for j in listing.json())


@pytest.mark.asyncio
async def test_schedule_from_another_tenant_is_not_found(client, db_session):
    from app.models.agent import Agent, ExecutionMode, RiskLevel

    agent = Agent(
        id=uuid.uuid4(),
        tenant_id=OTHER,
        name="intruder-agent",
        claw="cloudclaw",
        execution_mode=ExecutionMode.MONITOR,
        risk_level=RiskLevel.LOW,
    )
    schedule = Schedule(
        id=uuid.uuid4(),
        tenant_id=OTHER,
        name="intruder-schedule",
        agent_id=agent.id,
        status=ScheduleStatus.ACTIVE,
    )
    db_session.add_all([agent, schedule])
    await db_session.commit()

    assert (await client.get(f"/api/v1/schedules/{schedule.id}")).status_code == 404
    assert (await client.delete(f"/api/v1/schedules/{schedule.id}")).status_code == 404
    assert (await client.post(f"/api/v1/schedules/{schedule.id}/run")).status_code == 404

    listing = await client.get("/api/v1/schedules")
    assert listing.status_code == 200
    assert all(s["id"] != str(schedule.id) for s in listing.json())


@pytest.mark.asyncio
async def test_trigger_from_another_tenant_is_not_found(client, db_session):
    trigger = EventTrigger(
        id=uuid.uuid4(),
        tenant_id=OTHER,
        name="intruder-trigger",
        trigger_type="finding_created",
        conditions_json="[]",
        action_type="fire_scan",
        target_claw="cloudclaw",
        is_active=True,
    )
    db_session.add(trigger)
    await db_session.commit()

    assert (await client.get(f"/api/v1/triggers/{trigger.id}")).status_code == 404
    assert (await client.delete(f"/api/v1/triggers/{trigger.id}")).status_code == 404

    listing = await client.get("/api/v1/triggers")
    assert listing.status_code == 200
    assert all(t["id"] != str(trigger.id) for t in listing.json())


@pytest.mark.asyncio
async def test_dashboard_counts_exclude_other_tenants(client, db_session):
    db_session.add_all([
        _finding(OTHER, "intruder-critical-1"),
        _finding(OTHER, "intruder-critical-2"),
        _swarm_job(OTHER, "intruder-running"),
    ])
    await db_session.commit()

    summary = await client.get("/api/v1/dashboard/control-center-summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["running_swarms"] == 0
    assert body["blocked_swarms"] == 0


@pytest.mark.asyncio
async def test_control_investigation_ignores_other_tenants_findings(client, db_session):
    db_session.add(_finding(OTHER, "intruder-control-finding"))
    await db_session.commit()

    resp = await client.post("/api/v1/controls/does-not-exist/investigate/swarm")
    # Whatever the outcome, it must never surface the other tenant's finding.
    assert resp.status_code in (400, 404, 409, 422)
    assert "intruder-control-finding" not in resp.text


@pytest.mark.asyncio
async def test_unscoped_non_admin_is_refused(client, db_session):
    """A viewer whose token carries no tenant claim must not see everything."""
    from app.core.deps import get_current_user
    from main import app

    db_session.add(_finding(OTHER, "intruder-viewer-check"))
    await db_session.commit()

    previous = app.dependency_overrides.get(get_current_user)
    app.dependency_overrides[get_current_user] = lambda: {
        "id": "viewer",
        "sub": "viewer",
        "role": "viewer",
    }
    try:
        resp = await client.get("/api/v1/findings")
        assert resp.status_code == 403, resp.text
    finally:
        if previous is not None:
            app.dependency_overrides[get_current_user] = previous


@pytest.mark.asyncio
async def test_agent_run_history_is_tenant_scoped(client, db_session):
    from app.models.agent import Agent, ExecutionMode, RiskLevel

    agent = Agent(
        id=uuid.uuid4(),
        tenant_id=OTHER,
        name="intruder-run-agent",
        claw="cloudclaw",
        execution_mode=ExecutionMode.MONITOR,
        risk_level=RiskLevel.LOW,
    )
    schedule = Schedule(
        id=uuid.uuid4(),
        tenant_id=OTHER,
        name="intruder-run-schedule",
        agent_id=agent.id,
        status=ScheduleStatus.ACTIVE,
    )
    run = AgentRun(
        id=uuid.uuid4(),
        tenant_id=OTHER,
        agent_id=agent.id,
        schedule_id=schedule.id,
        status=RunStatus.COMPLETED,
        started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    db_session.add_all([agent, schedule, run])
    await db_session.commit()

    resp = await client.get(f"/api/v1/schedules/{schedule.id}/runs")
    assert resp.status_code == 404, resp.text
