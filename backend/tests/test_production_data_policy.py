"""
Nothing may present itself as a real result when it did not execute.

Three paths used to do exactly that: a remediation with no credentials recorded
COMPLETED, a workflow policy gate returned PASS unconditionally, and every
Capability Node manufactured findings when no connector existed.
"""
import pytest

from app.core.config import settings
from app.services.claw_scan import run_claw_scan
from app.services.remediation.actions.base import not_configured
from app.services.workflow_runner import _exec_condition, _exec_policy_check


DEMO = [{"title": "Sample exposure", "severity": "high", "provider": "demo"}]


def test_an_action_that_cannot_run_is_not_a_success():
    result = not_configured("disable_account", "svc-deploy")
    # Recording this as success made the engine mark the action COMPLETED, so
    # an operator believed an account was disabled when nothing happened.
    assert result.success is False
    assert result.error == "provider_not_configured"
    assert result.output["executed"] is False


@pytest.mark.asyncio
async def test_a_policy_gate_that_cannot_be_evaluated_does_not_pass():
    step = {"config": {"field": "risk_score", "op": "gt", "value": 90, "label": "high risk"}}

    missing = await _exec_policy_check(step, None, {})
    assert missing["status"] == "failed"
    assert missing["result"] == "error"

    passing = await _exec_policy_check(step, None, {"risk_score": 95})
    assert passing["status"] == "completed"
    assert passing["result"] == "pass"

    failing = await _exec_policy_check(step, None, {"risk_score": 10})
    assert failing["status"] == "failed"
    assert failing["result"] == "fail"


@pytest.mark.asyncio
async def test_a_free_form_condition_does_not_silently_continue():
    result = await _exec_condition({"config": {"expression": "anything"}}, None, {})
    assert result["status"] == "failed"


@pytest.mark.asyncio
async def test_production_mode_returns_nothing_rather_than_demonstration_data(db_session, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_LIVE_DATA", True)
    result = await run_claw_scan(
        db_session, claw="cloudclaw", provider_config=[], demo_findings=DEMO, tenant_id="tenant-test",
    )
    assert result["mode"] == "empty"
    assert result["findings_created"] == 0
    assert "Connect and verify a provider" in result["message"]


@pytest.mark.asyncio
async def test_demonstration_data_is_labelled_when_the_policy_is_off(db_session, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_LIVE_DATA", False)
    result = await run_claw_scan(
        db_session, claw="cloudclaw", provider_config=[], demo_findings=DEMO, tenant_id="tenant-test",
    )
    # Still available for evaluation, but it must never claim to be live.
    assert result["mode"] == "simulated"


@pytest.mark.asyncio
async def test_every_capability_node_reports_where_its_data_came_from(db_session):
    """
    Callers branch on ``mode`` to decide whether a scan may be treated as the
    tenant's real estate. Two nodes with bespoke scan paths omitted it, so an
    agent run could not tell demonstration data from a connector result.
    """
    import glob
    import os

    from app.services.claw_scan_dispatch import resolve_scan

    nodes = sorted(
        os.path.basename(os.path.dirname(p))
        for p in glob.glob(
            os.path.join(os.path.dirname(__file__), "..", "app", "claws", "*", "routes.py")
        )
    )
    assert nodes, "no Capability Nodes were discovered"

    unresolved = [n for n in nodes if resolve_scan(n) is None]
    assert unresolved == [], f"nodes with no scan entrypoint: {unresolved}"
