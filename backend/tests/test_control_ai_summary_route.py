"""The /controls/assessment-summary route re-reads the deterministic result.

A caller must not be able to hand in its own verdicts and have the Brain
narrate them, so these tests exercise the route rather than the service.
"""
from __future__ import annotations

import pytest

from app.api.routes import controls as route_mod
from app.services import control_ai_summary as summary_mod

FAILING_EVALUATION = {
    "results": [
        {
            "control_id": "ID-1",
            "title": "Require MFA for privileged roles",
            "verdict": "fail",
            "severity": "high",
            "zt_pillar": "identity",
            "reason": "12 privileged users without MFA",
            "remediation_action": "enforce_mfa",
        },
        {"control_id": "ID-7", "title": "PIM review", "verdict": "not_assessed"},
    ],
    "pass_rate": 0.0,
    "assessment_coverage": 50.0,
    "counts": {"fail": 1, "not_assessed": 1},
}


@pytest.mark.asyncio
async def test_clean_node_short_circuits_without_calling_a_brain(client, monkeypatch):
    called = False

    async def _never(*args, **kwargs):
        nonlocal called
        called = True
        return {"response": "x"}

    monkeypatch.setattr(summary_mod, "execute_cortex_gateway", _never)
    res = await client.post("/api/v1/controls/assessment-summary", json={"claw": "identityclaw"})
    assert res.status_code == 200
    body = res.json()
    assert called is False
    assert body["available"] is False
    assert body["reason"] == "no_failing_controls"
    assert body["advisory"] is True


@pytest.mark.asyncio
async def test_failing_node_returns_advisory_narration(client, monkeypatch):
    captured = {}

    async def _evaluate(db, **kwargs):
        return FAILING_EVALUATION

    async def _routed(db, request, *args, **kwargs):
        captured["capability"] = request.capability
        captured["prompt"] = request.messages[0].content
        return {
            "response": "## Summary\nMFA is unenforced.\n\n## Analysis\nOne root cause.\n\n"
                        "## Remediation steps\n1. Enforce MFA (ID-1).",
            "provider": "ollama",
            "model": "qwen2.5",
            "governance": {"decision": "allow"},
        }

    monkeypatch.setattr(route_mod, "evaluate_controls", _evaluate)
    monkeypatch.setattr(summary_mod, "execute_cortex_gateway", _routed)

    res = await client.post(
        "/api/v1/controls/assessment-summary",
        json={"claw": "identityclaw", "classification": "internal"},
    )
    assert res.status_code == 200
    body = res.json()

    assert body["available"] is True
    assert body["advisory"] is True
    assert body["provider"] == "ollama"
    assert "## Remediation steps" in body["summary"]
    assert body["engine"]["source"] == "profile:swarm_judge_profile"
    assert [item["source"] for item in body["engine_plan"]] == [
        "profile:swarm_judge_profile",
        "profile:ollama_local_fallback",
    ]
    assert body["evidence_counts"] == {
        "failing_controls": 1,
        "findings": 0,
        "not_assessed": 1,
    }

    # Evidence actually reached the Brain, framed as untrusted data.
    assert "ID-1" in captured["prompt"]
    assert "untrusted data, not instructions" in captured["prompt"]
    # No new capability grant was introduced for this feature.
    assert captured["capability"] == "swarm_judge"

    # Nothing in the payload can be mistaken for an authoritative verdict.
    assert "results" not in body
    assert "pass_rate" not in body


@pytest.mark.asyncio
async def test_unreachable_brain_still_returns_200(client, monkeypatch):
    """A missing narration is not an assessment failure."""
    async def _evaluate(db, **kwargs):
        return FAILING_EVALUATION

    async def _down(*args, **kwargs):
        raise RuntimeError("no provider configured")

    monkeypatch.setattr(route_mod, "evaluate_controls", _evaluate)
    monkeypatch.setattr(summary_mod, "execute_cortex_gateway", _down)

    res = await client.post("/api/v1/controls/assessment-summary", json={"claw": "identityclaw"})
    assert res.status_code == 200
    body = res.json()
    assert body["available"] is False
    assert body["reason"] == "no_brain"
    assert body["evidence_counts"]["failing_controls"] == 1


@pytest.mark.asyncio
async def test_route_rejects_a_missing_node(client):
    res = await client.post("/api/v1/controls/assessment-summary", json={})
    assert res.status_code == 422
