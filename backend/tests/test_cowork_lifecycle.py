"""Durable Cowork job lifecycle, recovery, and isolation tests.

These drive the real HTTP surface and the real durable store: a job is created
through the API, advanced by the real runner, and then inspected in the
database. Nothing asserts on in-memory task state, because in-memory state is
precisely what these tests exist to prove is *not* authoritative.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.deps import get_current_user
from app.core.marcellus import cowork_executors as executors
from app.core.marcellus import cowork_jobs as jobs
from app.core.marcellus import cowork_states as states
from app.core.marcellus import workspace
from app.models.marcellus import CoworkExecution, CoworkJob, CoworkJobEvent
from main import app


BASE = "/api/v1/marcellus/workspace"
COWORK = "/api/v1/marcellus/cowork"


def _identity(sub="cowork-owner", tenant_id="global", role="admin") -> dict:
    return {"id": sub, "sub": sub, "email": f"{sub}@example.invalid", "role": role, "tenant_id": tenant_id}


def _use_identity(identity: dict) -> None:
    app.dependency_overrides[get_current_user] = lambda: identity


def _gateway(text="Done", changes: str = "") -> dict:
    return {
        "status": "completed",
        "response": f"{text}{changes}",
        "source": "profile:ollama_local_fallback",
        "provider": "ollama",
        "model": "qwen2.5:7b",
        "mode": "cowork",
        "governance": {
            "outcome": "allowed", "policy_name": "Test", "reason": "Allowed", "risk_score": 0,
            "data_classification": "internal", "input_redacted": False, "output_redacted": False,
            "injection_risk": False, "injection_vectors": [],
        },
        "votes": [], "confidence": 0.9, "agreement": "high", "latency_ms": 2,
    }


@pytest.fixture
def inline_runner(db_session):
    class _Factory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return db_session

        async def __aexit__(self, *_exc):
            return False

    jobs.configure_runner(_Factory(), inline=True)
    yield _Factory()
    jobs.reset_runner()


async def _project(client, name="Project A") -> dict:
    response = await client.post(
        f"{BASE}/projects", json={"tenant_id": "global", "name": name, "classification": "internal"}
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _conversation(client, project_id=None) -> dict:
    response = await client.post(
        f"{BASE}/conversations",
        json={
            "tenant_id": "global", "project_id": project_id, "title": "Cowork",
            "mode": "cowork", "classification": "internal",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _create_job(client, conversation_id, **extra) -> dict:
    body = {
        "tenant_id": "global",
        "conversation_id": conversation_id,
        "turn": {"tenant_id": "global", "content": "Add a health endpoint"},
    }
    body.update(extra)
    response = await client.post(f"{COWORK}/jobs", json=body)
    assert response.status_code == 200, response.text
    return response.json()


# --------------------------------------------------------------------------
# Durability
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_job_state_is_durable_not_request_scoped(client, db_session, monkeypatch, inline_runner):
    _use_identity(_identity())
    monkeypatch.setattr(workspace, "execute_cortex_gateway", lambda *a, **k: _gateway())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    # The authoritative record exists in the database, independent of any request.
    stored = await db_session.execute(select(CoworkJob).where(CoworkJob.id == uuid.UUID(job["id"])))
    row = stored.scalar_one()
    assert row.state in states.ALL_STATES
    assert row.request_ciphertext
    # The prompt is encrypted at rest.
    assert "health endpoint" not in row.request_ciphertext


@pytest.mark.asyncio
async def test_events_are_replayable_from_a_cursor(client, monkeypatch, inline_runner):
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    first = await client.get(f"{COWORK}/jobs/{job['id']}/events", params={"tenant_id": "global"})
    assert first.status_code == 200
    events = first.json()
    assert events, "a durable timeline should exist"
    sequences = [item["sequence"] for item in events]
    assert sequences == sorted(sequences)

    # Reconnecting from a cursor replays only what was missed -- the property a
    # disconnected client relies on.
    midpoint = sequences[len(sequences) // 2]
    resumed = await client.get(
        f"{COWORK}/jobs/{job['id']}/events",
        params={"tenant_id": "global", "after_sequence": midpoint},
    )
    assert all(item["sequence"] > midpoint for item in resumed.json())


@pytest.mark.asyncio
async def test_idempotent_create_does_not_start_a_second_run(client, monkeypatch, inline_runner):
    _use_identity(_identity())
    calls = {"count": 0}

    async def fake_gateway(db, payload, **_kw):
        calls["count"] += 1
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    first = await _create_job(client, conversation["id"], idempotency_key="key-1")
    after_first = calls["count"]
    second = await _create_job(client, conversation["id"], idempotency_key="key-1")
    assert first["id"] == second["id"]
    assert calls["count"] == after_first, "a duplicate create must not re-invoke the Brain"


@pytest.mark.asyncio
async def test_orphaned_job_is_recovered_after_restart(client, db_session, monkeypatch, inline_runner):
    """Simulates a desktop restart: the in-process task is gone, the row is not."""
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    # Force the job back into a non-terminal state with an expired lease, which
    # is exactly what a crash mid-run leaves behind.
    row = await db_session.get(CoworkJob, uuid.UUID(job["id"]))
    row.state = states.WAITING_FOR_BRAIN
    row.completed_at = None
    row.lease_owner = "dead-process"
    row.lease_expires_at = None
    await db_session.commit()

    recovered = await jobs.recover_orphaned_jobs(inline_runner)
    assert recovered >= 1

    events = await db_session.execute(
        select(CoworkJobEvent).where(
            CoworkJobEvent.job_id == row.id, CoworkJobEvent.event_type == "job_recovered"
        )
    )
    assert events.scalars().first() is not None


@pytest.mark.asyncio
async def test_resume_is_a_noop_while_a_lease_is_active(client, db_session, monkeypatch, inline_runner):
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    row = await db_session.get(CoworkJob, uuid.UUID(job["id"]))
    row.state = states.WAITING_FOR_BRAIN
    row.completed_at = None
    from datetime import datetime, timedelta

    row.lease_expires_at = datetime.utcnow() + timedelta(minutes=10)
    await db_session.commit()

    response = await client.post(f"{COWORK}/jobs/{job['id']}/resume", json={"tenant_id": "global"})
    assert response.status_code == 200
    events = await db_session.execute(
        select(CoworkJobEvent).where(
            CoworkJobEvent.job_id == row.id, CoworkJobEvent.event_type == "resume_noop"
        )
    )
    assert events.scalars().first() is not None, "an active lease must not be double-driven"


@pytest.mark.asyncio
async def test_cancel_is_durable_and_terminal(client, monkeypatch, inline_runner):
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    response = await client.post(f"{COWORK}/jobs/{job['id']}/cancel", json={"tenant_id": "global"})
    assert response.status_code == 200
    # A completed job stays completed; a live one becomes cancelled. Either way
    # the result is terminal and recorded durably.
    assert response.json()["state"] in states.TERMINAL_STATES


@pytest.mark.asyncio
async def test_result_and_outcome_remain_recoverable(client, monkeypatch, inline_runner):
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    result = await client.get(f"{COWORK}/jobs/{job['id']}/result", params={"tenant_id": "global"})
    assert result.status_code == 200
    body = result.json()
    assert body["job_id"] == job["id"]
    if body["state"] == states.COMPLETED:
        # Completion must carry an explicit outcome, never a bare "completed".
        assert body["outcome"] in states.FINAL_OUTCOMES


# --------------------------------------------------------------------------
# Executor reporting
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_executor_status_endpoint_reports_both_executors(client, monkeypatch):
    _use_identity(_identity())
    monkeypatch.setattr(executors, "bridge_configured", lambda: False)
    response = await client.get(f"{COWORK}/executors", params={"tenant_id": "global"})
    assert response.status_code == 200
    body = response.json()
    names = {item["executor"] for item in body["executors"]}
    assert names == {"enkstein_local", "codex_app_server"}
    assert body["any_available"] is False
    assert body["selected"] == "unavailable"


@pytest.mark.asyncio
async def test_executor_preference_is_persisted_on_the_job(client, db_session, monkeypatch, inline_runner):
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"], executor="enkstein_local")
    assert job["executor_preference"] == "enkstein_local"


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_tenant_job_access_is_denied(client, db_session, monkeypatch, inline_runner):
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project = await _project(client)
    conversation = await _conversation(client, project["id"])
    job = await _create_job(client, conversation["id"])

    # A different tenant must not be able to read, cancel, retry, or resume it.
    _use_identity(_identity(sub="other-owner", tenant_id="tenant-b"))
    for path, method in (
        (f"{COWORK}/jobs/{job['id']}", "get"),
        (f"{COWORK}/jobs/{job['id']}/events", "get"),
        (f"{COWORK}/jobs/{job['id']}/result", "get"),
    ):
        response = await client.get(path, params={"tenant_id": "tenant-b"})
        assert response.status_code == 404, f"{path} leaked across tenants"

    for path in (f"{COWORK}/jobs/{job['id']}/cancel", f"{COWORK}/jobs/{job['id']}/resume"):
        response = await client.post(path, json={"tenant_id": "tenant-b"})
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_tenant_claim_mismatch_is_rejected(client, monkeypatch, inline_runner):
    _use_identity(_identity(tenant_id="tenant-a"))
    response = await client.get(f"{COWORK}/jobs", params={"tenant_id": "tenant-b"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_job_binds_one_project_and_switching_cannot_mix(client, db_session, monkeypatch, inline_runner):
    """A job created against project A stays bound to A."""
    _use_identity(_identity())

    async def fake_gateway(db, payload, **_kw):
        return _gateway()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    project_a = await _project(client, "Project A")
    project_b = await _project(client, "Project B")
    conversation_a = await _conversation(client, project_a["id"])
    conversation_b = await _conversation(client, project_b["id"])

    job_a = await _create_job(client, conversation_a["id"])
    job_b = await _create_job(client, conversation_b["id"])

    assert job_a["project_id"] == project_a["id"]
    assert job_b["project_id"] == project_b["id"]
    assert job_a["project_id"] != job_b["project_id"]

    # Listing by conversation must never return the other project's job -- the
    # stale-response case a project switch would otherwise expose.
    listed = await client.get(
        f"{COWORK}/jobs", params={"tenant_id": "global", "conversation_id": conversation_b["id"]}
    )
    ids = {item["id"] for item in listed.json()}
    assert job_b["id"] in ids
    assert job_a["id"] not in ids


@pytest.mark.asyncio
async def test_unknown_job_is_404_not_403(client, inline_runner):
    _use_identity(_identity())
    response = await client.get(
        f"{COWORK}/jobs/{uuid.uuid4()}", params={"tenant_id": "global"}
    )
    assert response.status_code == 404
