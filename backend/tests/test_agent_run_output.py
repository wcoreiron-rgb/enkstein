"""
An agent run must report what it actually executed.

Runs used to return a hardcoded scenario per Capability Node, so an agent
"found" the same two issues forever whether or not a connector existed, and
parked actions for targets that were never real. A run now executes the node's
governed scan and reports its result, including nothing when nothing is wired.
"""
import json
import uuid

import pytest

from app.models.agent import (
    Agent,
    AgentRun,
    AgentStatus,
    ExecutionMode,
    RiskLevel,
    RunStatus,
)
from app.models.finding import Finding
from app.services.agent_runner import AgentRunner, _actions_for


def _scan_phase(run: AgentRun) -> dict:
    entries = json.loads(run.run_log or "[]")
    scan = [e for e in entries if e.get("phase") == "scan"]
    assert scan, f"run log has no scan phase: {entries}"
    return scan[0]


async def _seed(db, mode: ExecutionMode, claw: str = "arcclaw") -> AgentRun:
    agent = Agent(
        id=uuid.uuid4(),
        name="AI/LLM Traffic Sentinel",
        claw=claw,
        category="AI Security",
        execution_mode=mode,
        risk_level=RiskLevel.LOW,
        status=AgentStatus.ACTIVE,
        is_builtin=True,
    )
    db.add(agent)
    await db.flush()
    run = AgentRun(
        id=uuid.uuid4(),
        agent_id=agent.id,
        status=RunStatus.PENDING,
        execution_mode=mode,
        triggered_by="portal-user",
    )
    db.add(run)
    await db.commit()
    return run


@pytest.mark.asyncio
async def test_a_run_records_the_findings_its_scan_produced(db_session):
    run = await _seed(db_session, ExecutionMode.MONITOR)

    await AgentRunner(db_session).execute(run.id)
    await db_session.refresh(run)

    phase = _scan_phase(run)
    detail = phase.get("findings_detail")
    assert detail is not None, "scan phase recorded a tally but not the findings"
    assert len(detail) == run.findings_count
    # Whatever the scan produced must be traceable back to a real record.
    for finding in detail:
        assert finding.get("title")
        assert finding.get("data_origin") in {"live", "simulated", "unknown"}


@pytest.mark.asyncio
async def test_a_run_with_no_connector_invents_nothing(db_session):
    run = await _seed(db_session, ExecutionMode.ASSIST)

    await AgentRunner(db_session).execute(run.id)
    await db_session.refresh(run)

    # Nothing is configured in this tenant, so nothing may be proposed for
    # approval. Parking an action here would ask an operator to authorise a
    # change against a target that does not exist.
    assert json.loads(run.actions_pending or "[]") == []
    assert run.status == RunStatus.COMPLETED
    assert "scan" in _scan_phase(run)


def test_only_connector_backed_findings_become_proposed_actions():
    findings = [
        {"id": "1", "severity": "critical", "title": "Public bucket", "resource": "logs-prod"},
        {"id": "2", "severity": "low", "title": "Cosmetic", "resource": "x"},
    ]
    assert _actions_for(findings, live=False) == [], "demo findings must not be actionable"

    actions = _actions_for(findings, live=True)
    assert [a["target"] for a in actions] == ["logs-prod"]
    assert actions[0]["finding_id"] == "1"


@pytest.mark.asyncio
async def test_findings_are_read_back_from_the_scan_not_fabricated(db_session):
    # A finding the node's scan would have persisted.
    db_session.add(Finding(
        id=uuid.uuid4(),
        claw="arcclaw",
        provider="openai",
        title="Prompt injection attempt blocked",
        severity="high",
        risk_score=75.0,
        status="open",
        data_origin="live",
        source_connector="openai",
    ))
    await db_session.commit()

    run = await _seed(db_session, ExecutionMode.MONITOR)
    await AgentRunner(db_session).execute(run.id)
    await db_session.refresh(run)

    titles = [f["title"] for f in _scan_phase(run)["findings_detail"]]
    assert "Prompt injection attempt blocked" in titles
