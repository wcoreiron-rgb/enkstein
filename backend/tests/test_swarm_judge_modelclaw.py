import pytest

from app.core.swarm import judge as judge_module
from app.core.swarm.judge import judge_swarm_result_with_modelclaw


@pytest.mark.asyncio
async def test_swarm_judge_uses_modelclaw_summary_when_allowed(db_session, monkeypatch):
    async def fake_gateway(db, payload):
        return {
            "status": "completed",
            "response": "Governed Cortex synthesis",
            "source": "profile:swarm_judge_profile",
            "provider": "nvidia_nim",
            "model": "meta/llama-3.3-70b-instruct",
            "governance": {"outcome": "allowed", "policy_name": "Swarm policy", "reason": "Allowed"},
        }

    monkeypatch.setattr(judge_module, "execute_cortex_gateway", fake_gateway)
    aggregate = {
        "overall_severity": "high",
        "confidence": 0.84,
        "risk_score": 71.0,
        "top_findings": [{"title": "test finding"}],
        "recommended_actions": ["action1"],
    }
    judged = await judge_swarm_result_with_modelclaw(
        db_session,
        "ModelClaw Judge Allow",
        aggregate,
        task_count=4,
        classification="internal",
        swarm_job_id="job_allow_1",
    )
    assert "judge_model" in judged
    assert judged["judge_model"]["profile"] == "swarm_judge_profile"
    assert judged["executive_summary"] == "Governed Cortex synthesis"


@pytest.mark.asyncio
async def test_swarm_judge_falls_back_when_modelclaw_profile_denies(db_session):
    aggregate = {
        "overall_severity": "medium",
        "confidence": 0.7,
        "risk_score": 45.0,
        "top_findings": [],
        "recommended_actions": [],
    }
    judged = await judge_swarm_result_with_modelclaw(
        db_session,
        "ModelClaw Judge Deny",
        aggregate,
        task_count=2,
        classification="top_secret",  # not allowed by swarm_judge_profile
        swarm_job_id="job_deny_1",
    )
    assert "judge_model" in judged
    assert judged["judge_model"]["blocked"] is True
    assert judged["executive_summary"].startswith("Swarm job 'ModelClaw Judge Deny' completed")
