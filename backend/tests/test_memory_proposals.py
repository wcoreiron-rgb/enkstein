import json

import pytest


async def _create_memory_proposal(client):
    created = await client.post(
        "/api/v1/memory/incidents",
        json={
            "title": "Swarm review proposed: suspicious identity",
            "description": "High-risk identity behavior requires analyst review.",
            "severity": "high",
            "source_claw": "swarmclaw",
            "affected_users": ["vip@company.com"],
            "created_by": "swarm_memory_runtime",
        },
    )
    assert created.status_code == 200, created.text
    incident = created.json()
    patch = await client.patch(
        f"/api/v1/memory/incidents/{incident['id']}",
        json={"status": "investigating"},
    )
    assert patch.status_code == 200, patch.text
    return patch.json()


@pytest.mark.asyncio
async def test_memory_proposal_approve_and_reject_paths(client):
    proposal = await _create_memory_proposal(client)

    listed = await client.get("/api/v1/memory/proposals")
    assert listed.status_code == 200, listed.text
    assert any(item["id"] == proposal["id"] for item in listed.json())

    approved = await client.post(
        f"/api/v1/memory/proposals/{proposal['id']}/approve",
        json={"reviewer": "memory-reviewer", "reason": "valid recurring incident pattern"},
    )
    assert approved.status_code == 200, approved.text
    approved_body = approved.json()
    assert approved_body["status"] == "open"
    assert any(e["type"] == "memory_approved" for e in approved_body["timeline"])

    second = await _create_memory_proposal(client)
    rejected = await client.post(
        f"/api/v1/memory/proposals/{second['id']}/reject",
        json={"reviewer": "memory-reviewer", "reason": "insufficient evidence"},
    )
    assert rejected.status_code == 200, rejected.text
    rejected_body = rejected.json()
    assert rejected_body["status"] == "false_positive"
    assert any(e["type"] == "memory_rejected" for e in rejected_body["timeline"])


@pytest.mark.asyncio
async def test_memory_incident_rollback_marks_false_positive_and_preserves_audit(client):
    proposal = await _create_memory_proposal(client)
    approve = await client.post(
        f"/api/v1/memory/proposals/{proposal['id']}/approve",
        json={"reviewer": "memory-reviewer"},
    )
    assert approve.status_code == 200, approve.text

    rolled = await client.post(
        f"/api/v1/memory/incidents/{proposal['id']}/rollback",
        json={"reviewer": "memory-reviewer", "reason": "tenant exception expired"},
    )
    assert rolled.status_code == 200, rolled.text
    body = rolled.json()
    assert body["status"] == "false_positive"
    assert any(e["type"] == "memory_rollback" for e in body["timeline"])
    assert json.loads(json.dumps(body["timeline"]))
