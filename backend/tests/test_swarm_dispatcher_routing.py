import json
import uuid

import pytest

from app.core.swarm.dispatcher import execute_task
from app.models.swarm import SwarmTask, SwarmTaskStatus


def _mk_task(claw: str, task_type: str = "investigate") -> SwarmTask:
    return SwarmTask(
        id=uuid.uuid4(),
        swarm_job_id=uuid.uuid4(),
        claw=claw,
        task_type=task_type,
        status=SwarmTaskStatus.PENDING,
        model_profile=None,
        input_json=json.dumps({"scope": "test"}),
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
    # Real /task path has specific recommendations, not simulated fallback title.
    assert not out["findings"][0]["title"].endswith("simulated analysis")


@pytest.mark.asyncio
async def test_dispatcher_falls_back_for_unsupported_claw(db_session):
    task = _mk_task("unknownclaw")
    db_session.add(task)
    await db_session.commit()

    out = await execute_task(db_session, task)
    assert out["claw"] == "unknownclaw"
    assert out["status"] == "completed"
    assert out["findings"][0]["title"] == "unknownclaw simulated analysis"
