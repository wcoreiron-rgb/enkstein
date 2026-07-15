from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from app.core.deps import get_current_user
from app.core.marcellus import mission_routes, missions
from app.core.marcellus.crypto import encrypt_json
from app.models.marcellus import CortexMission, CortexMissionObservation, CortexOvernightBrief
from app.core.swarm.dispatcher import _hydrate_mission_context
from app.models.swarm import SwarmJob, SwarmTask
from app.services.memory_runtime import build_swarm_memory_context
from main import app


BASE = "/api/v1/marcellus/missions"


def _identity(sub: str = "mission-owner", tenant_id: str = "tenant-a", role: str = "admin") -> dict:
    return {"id": sub, "sub": sub, "email": f"{sub}@example.invalid", "role": role, "tenant_id": tenant_id}


def _use_identity(identity: dict) -> None:
    app.dependency_overrides[get_current_user] = lambda: identity


def _decision(allowed: bool = True):
    outcome = type("Outcome", (), {"value": "allowed" if allowed else "blocked"})()
    return type(
        "Decision",
        (),
        {"allowed": allowed, "outcome": outcome, "policy_name": "Mission test policy", "risk_score": 0, "reason": "test"},
    )()


async def _allow(*args, **kwargs):
    return _decision()


async def _create_mission(client, name: str = "Reduce identity risk") -> dict:
    response = await client.post(
        BASE,
        json={
            "tenant_id": "tenant-a",
            "name": name,
            "objective": "Continuously investigate material identity and cloud risk changes.",
            "cadence": "daily",
            "autonomy_mode": "assist",
            "participants": ["identityclaw", "cloudclaw", "threatclaw"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_mission_create_run_and_pause_are_policy_governed(client, db_session, monkeypatch):
    _use_identity(_identity())
    actions: list[str] = []

    async def allow(db, request, ip_address=None):
        actions.append(request.action)
        return _decision()

    async def no_background_run(*args, **kwargs):
        return None

    monkeypatch.setattr(missions, "enforce", allow)
    monkeypatch.setattr(mission_routes, "run_mission_job", no_background_run)
    mission = await _create_mission(client)
    assert mission["status"] == "active"
    assert mission["next_run_at"] is not None
    assert actions[-1] == "mission_create"
    stored_mission = await db_session.get(CortexMission, uuid.UUID(mission["id"]))
    assert "material identity" not in stored_mission.objective_ciphertext

    launched = await client.post(f"{BASE}/{mission['id']}/run", params={"tenant_id": "tenant-a"})
    assert launched.status_code == 200, launched.text
    assert actions[-1] == "mission_run"
    job = await db_session.get(SwarmJob, uuid.UUID(launched.json()["job_id"]))
    job_input = json.loads(job.input_json)
    assert job_input["tenant_id"] == "tenant-a"
    assert job_input["mission_id"] == mission["id"]
    assert job_input["allowed_actions"] == ["read", "analyze", "recommend"]
    assert job_input["source"] == "marcellus_mission"
    assert "objective" not in job_input
    assert job_input["objective_digest"] == stored_mission.objective_digest
    task = (
        await db_session.execute(select(SwarmTask).where(SwarmTask.swarm_job_id == job.id))
    ).scalars().first()
    hydrated = await _hydrate_mission_context(db_session, json.loads(task.input_json))
    assert hydrated["mission_context_status"] == "loaded"
    assert "material identity" in hydrated["objective"]

    paused = await client.patch(
        f"{BASE}/{mission['id']}",
        json={"tenant_id": "tenant-a", "status": "paused"},
    )
    assert paused.status_code == 200, paused.text
    assert paused.json()["next_run_at"] is None
    assert actions[-1] == "mission_update"


@pytest.mark.asyncio
async def test_mission_policy_denial_prevents_persistence(client, db_session, monkeypatch):
    _use_identity(_identity())

    async def deny(*args, **kwargs):
        return _decision(False)

    monkeypatch.setattr(missions, "enforce", deny)
    response = await client.post(
        BASE,
        json={
            "tenant_id": "tenant-a",
            "name": "Denied mission",
            "objective": "This objective should never be persisted after policy denial.",
            "participants": ["identityclaw", "cloudclaw"],
        },
    )
    assert response.status_code == 403
    assert (await db_session.execute(select(CortexMission))).scalars().all() == []


@pytest.mark.asyncio
async def test_mission_memory_review_is_owner_and_tenant_scoped(client, db_session, monkeypatch):
    _use_identity(_identity())
    monkeypatch.setattr(missions, "enforce", _allow)
    mission = await _create_mission(client)
    ciphertext, digest = encrypt_json({"summary": "Approved evidence from the previous Mission run."})
    observation = CortexMissionObservation(
        tenant_id="tenant-a",
        mission_id=uuid.UUID(mission["id"]),
        job_id=uuid.uuid4(),
        status="proposed",
        severity="high",
        summary_ciphertext=ciphertext,
        summary_digest=digest,
        evidence_json=json.dumps({"job_status": "completed"}),
    )
    db_session.add(observation)
    await db_session.commit()
    await db_session.refresh(observation)

    approved = await client.post(
        f"{BASE}/memory/observations/{observation.id}/review",
        json={"tenant_id": "tenant-a", "decision": "approve", "reason": "Evidence verified"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"

    _use_identity(_identity(sub="other-user", role="analyst"))
    listed = await client.get(f"{BASE}/memory/observations", params={"tenant_id": "tenant-a"})
    assert listed.status_code == 200
    assert listed.json() == []


@pytest.mark.asyncio
async def test_approved_mission_memory_is_loaded_without_cross_tenant_context(client, db_session, monkeypatch):
    _use_identity(_identity())
    monkeypatch.setattr(missions, "enforce", _allow)
    mission = await _create_mission(client)
    mission_id = uuid.UUID(mission["id"])
    for tenant, summary in (("tenant-a", "Known identity exception is approved."), ("tenant-b", "Other tenant private memory.")):
        ciphertext, digest = encrypt_json({"summary": summary})
        db_session.add(
            CortexMissionObservation(
                tenant_id=tenant,
                mission_id=mission_id,
                job_id=uuid.uuid4(),
                status="approved",
                severity="medium",
                summary_ciphertext=ciphertext,
                summary_digest=digest,
                evidence_json="{}",
            )
        )
    await db_session.commit()
    context = await build_swarm_memory_context(
        db_session,
        {"tenant_id": "tenant-a", "mission_id": str(mission_id)},
        "identityclaw",
    )
    assert context["loaded"] is True
    rendered = json.dumps(context)
    assert "Known identity exception" in rendered
    assert "Other tenant private memory" not in rendered


@pytest.mark.asyncio
async def test_overnight_brief_persists_encrypted_evidence_and_review_queue(client, db_session, monkeypatch):
    _use_identity(_identity())
    monkeypatch.setattr(missions, "enforce", _allow)
    mission = await _create_mission(client)
    ciphertext, digest = encrypt_json({"summary": "A material access-policy change needs review."})
    observation = CortexMissionObservation(
        tenant_id="tenant-a",
        mission_id=uuid.UUID(mission["id"]),
        job_id=uuid.uuid4(),
        status="proposed",
        severity="high",
        summary_ciphertext=ciphertext,
        summary_digest=digest,
        evidence_json=json.dumps({"job_status": "completed"}),
    )
    db_session.add(observation)
    await db_session.commit()

    response = await client.post(f"{BASE}/overnight-brief", params={"tenant_id": "tenant-a", "hours": 12})
    assert response.status_code == 200, response.text
    brief = response.json()
    assert brief["decisions_needed"][0]["observation_id"] == str(observation.id)
    assert brief["security_twin_health"]["pending_memory_reviews"] == 1
    stored = (await db_session.execute(select(CortexOvernightBrief))).scalar_one()
    assert "material access-policy" not in stored.payload_ciphertext
