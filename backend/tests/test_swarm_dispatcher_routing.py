import json
import uuid

import pytest

from app.core.swarm.dispatcher import execute_task
from app.models.swarm import SwarmTask, SwarmTaskStatus


def _mk_task(claw: str, task_type: str = "investigate", task_input: dict | None = None) -> SwarmTask:
    return SwarmTask(
        id=uuid.uuid4(),
        swarm_job_id=uuid.uuid4(),
        claw=claw,
        task_type=task_type,
        status=SwarmTaskStatus.PENDING,
        model_profile=None,
        input_json=json.dumps(task_input or {"scope": "test"}),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claw",
    [
        "identityclaw",
        "accessclaw",
        "dataclaw",
        "devclaw",
        "endpointclaw",
        "appclaw",
        "logclaw",
        "netclaw",
        "complianceclaw",
        "intelclaw",
        "recoveryclaw",
        "terraclaw",
        "saasclaw",
        "privacyclaw",
        "userclaw",
        "insiderclaw",
        "vendorclaw",
        "attackpathclaw",
        "automationclaw",
        "configclaw",
        "exposureclaw",
        "customclaw",
    ],
)
async def test_dispatcher_routes_to_real_task(db_session, claw):
    task = _mk_task(claw)
    db_session.add(task)
    await db_session.commit()

    out = await execute_task(db_session, task)
    assert out["claw"] == claw
    assert out["status"] == "completed"
    assert isinstance(out["recommended_actions"], list)
    assert out["execution_mode"] == "real_task_handler"
    # Real /task path has specific recommendations, not simulated fallback title.
    if out["findings"]:
        assert not out["findings"][0]["title"].endswith("simulated analysis")
    else:
        assert out.get("data_source") == "no_data_source"


@pytest.mark.asyncio
async def test_dispatcher_falls_back_for_unsupported_claw(db_session):
    task = _mk_task("unknownclaw")
    db_session.add(task)
    await db_session.commit()

    out = await execute_task(db_session, task)
    assert out["claw"] == "unknownclaw"
    assert out["status"] == "completed"
    assert out["execution_mode"] == "simulated_fallback"
    assert "Unsupported claw" in out["fallback_reason"]
    assert out["findings"][0]["title"] == "unknownclaw simulated analysis"


@pytest.mark.asyncio
async def test_live_or_recorded_mission_never_scores_simulated_fallback(db_session):
    task = _mk_task(
        "unknownclaw",
        task_input={"scope": "test", "evidence_mode": "live_or_recorded", "allow_demo_evidence": False},
    )
    db_session.add(task)
    await db_session.commit()

    out = await execute_task(db_session, task)
    assert out["status"] == "blocked"
    assert out["evidence_status"] == "unavailable"
    assert out["risk_score"] == 0.0
    assert out["findings"] == []
    assert "Seeded or simulated evidence is disabled" in out["evidence_reason"]
    assert task.status == SwarmTaskStatus.BLOCKED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "claw",
    [
        "cloudclaw",
        "endpointclaw",
        "devclaw",
        "identityclaw",
        "threatclaw",
        "exposureclaw",
        "accessclaw",
        "dataclaw",
        "netclaw",
        "logclaw",
        "configclaw",
        "attackpathclaw",
        "appclaw",
        "complianceclaw",
        "recoveryclaw",
        "terraclaw",
        "automationclaw",
        "intelclaw",
        "privacyclaw",
        "vendorclaw",
        "insiderclaw",
        "userclaw",
        "saasclaw",
        "customclaw",
    ],
)
async def test_dispatcher_task_provenance_fields_present(db_session, claw):
    task = _mk_task(claw)
    db_session.add(task)
    await db_session.commit()

    out = await execute_task(db_session, task)
    assert out["claw"] == claw
    assert out.get("execution_mode") == "real_task_handler"
    assert out.get("data_source") in {"live_connector", "persisted_db", "seeded_fallback", "no_data_source"}
    assert out.get("connector_state") in {"configured", "unconfigured"}
