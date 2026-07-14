import json

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from uuid import UUID

from app.core.deps import get_current_user
from app.models.marcellus import CapabilityNodeRuntime, PlexusMessage
from app.models.policy import Policy, PolicyAction, PolicyScope
from main import app


def _identity(
    sub: str,
    tenant_id: str = "tenant-a",
    *,
    role: str = "admin",
    node_id: str | None = None,
) -> dict:
    identity = {
        "id": sub,
        "sub": sub,
        "email": f"{sub}@example.invalid",
        "role": role,
        "tenant_id": tenant_id,
    }
    if node_id:
        identity["node_id"] = node_id
    return identity


def _use_identity(identity: dict) -> None:
    app.dependency_overrides[get_current_user] = lambda: identity


@pytest.mark.asyncio
async def test_plexus_message_is_signed_encrypted_idempotent_and_acknowledged(client: AsyncClient, db_session):
    _use_identity(_identity("operator-a"))
    body = {
        "tenant_id": "tenant-a",
        "sender_node_id": "threat-intelligence",
        "recipient_node_id": "threat-analysis",
        "message_type": "indicator.enrichment",
        "payload": {"indicator": "203.0.113.10", "confidence": 0.92},
        "classification": "internal",
        "idempotency_key": "indicator-event-0001",
    }

    first = await client.post("/api/v1/marcellus/plexus/messages", json=body)
    second = await client.post("/api/v1/marcellus/plexus/messages", json=body)

    assert first.status_code == 200
    assert first.json()["status"] == "delivered"
    assert first.json()["signature_algorithm"] == "ed25519"
    assert first.json()["payload"]["indicator"] == "203.0.113.10"
    assert second.json()["id"] == first.json()["id"]

    stored_result = await db_session.execute(
        select(PlexusMessage).where(PlexusMessage.id == UUID(first.json()["id"]))
    )
    stored = stored_result.scalar_one()
    assert "203.0.113.10" not in stored.payload_ciphertext
    assert stored.signature
    assert stored.nonce

    inbox = await client.get(
        "/api/v1/marcellus/plexus/inbox/threat-analysis",
        params={"tenant_id": "tenant-a"},
    )
    assert inbox.status_code == 200
    assert [item["id"] for item in inbox.json()] == [first.json()["id"]]

    ack = await client.post(
        f"/api/v1/marcellus/plexus/messages/{first.json()['id']}/ack",
        json={"tenant_id": "tenant-a", "recipient_node_id": "threat-analysis"},
    )
    assert ack.status_code == 200
    assert ack.json()["status"] == "processed"
    assert ack.json()["payload"]["confidence"] == 0.92


@pytest.mark.asyncio
async def test_plexus_denial_is_persisted_without_delivery(client: AsyncClient, db_session):
    db_session.add(
        Policy(
            name="Deny Plexus send",
            scope=PolicyScope.GLOBAL,
            condition_json=json.dumps({"field": "action", "op": "eq", "value": "plexus_send"}),
            action=PolicyAction.DENY,
            priority=1,
            created_by="test",
        )
    )
    await db_session.commit()
    _use_identity(_identity("operator-a"))

    response = await client.post(
        "/api/v1/marcellus/plexus/messages",
        json={
            "tenant_id": "tenant-a",
            "sender_node_id": "cloud-security",
            "recipient_node_id": "configuration-security",
            "message_type": "posture.signal",
            "payload": {"resource_id": "resource-1"},
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    inbox = await client.get(
        "/api/v1/marcellus/plexus/inbox/configuration-security",
        params={"tenant_id": "tenant-a"},
    )
    assert inbox.json() == []


@pytest.mark.asyncio
async def test_tenant_bound_identity_cannot_read_another_plexus_tenant(client: AsyncClient):
    _use_identity(_identity("tenant-user", tenant_id="tenant-a"))
    response = await client.get(
        "/api/v1/marcellus/plexus/messages",
        params={"tenant_id": "tenant-b"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-tenant access denied"


@pytest.mark.asyncio
async def test_plexus_payload_requires_participant_or_security_admin(client: AsyncClient):
    _use_identity(_identity("operator-a"))
    created = await client.post(
        "/api/v1/marcellus/plexus/messages",
        json={
            "tenant_id": "tenant-a",
            "sender_node_id": "threat-analysis",
            "recipient_node_id": "threat-intelligence",
            "message_type": "indicator.enrichment",
            "payload": {"indicator": "198.51.100.4"},
        },
    )
    message_id = created.json()["id"]

    _use_identity(_identity("tenant-viewer", role="viewer"))
    metadata = await client.get(
        "/api/v1/marcellus/plexus/messages",
        params={"tenant_id": "tenant-a"},
    )
    payload_read = await client.get(
        f"/api/v1/marcellus/plexus/messages/{message_id}",
        params={"tenant_id": "tenant-a"},
    )
    assert metadata.status_code == 200
    assert metadata.json()[0]["payload"] is None
    assert payload_read.status_code == 403

    _use_identity(
        _identity(
            "threat-intelligence-runtime",
            role="agent",
            node_id="threat-intelligence",
        )
    )
    participant_read = await client.get(
        f"/api/v1/marcellus/plexus/messages/{message_id}",
        params={"tenant_id": "tenant-a"},
    )
    assert participant_read.status_code == 200
    assert participant_read.json()["payload"]["indicator"] == "198.51.100.4"


@pytest.mark.asyncio
async def test_viewer_cannot_inject_reflex_events(client: AsyncClient):
    _use_identity(_identity("tenant-viewer", role="viewer"))
    response = await client.post(
        "/api/v1/marcellus/reflexes/evaluate",
        json={
            "tenant_id": "tenant-a",
            "event_id": "untrusted-event-1",
            "event_type": "finding.created",
            "payload": {"severity": "critical"},
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "Runtime operator or Capability Node required"


@pytest.mark.asyncio
async def test_reflex_evaluates_conditions_and_deduplicates_event(client: AsyncClient):
    _use_identity(_identity("operator-a"))
    definition = await client.post(
        "/api/v1/marcellus/reflexes",
        json={
            "tenant_id": "tenant-a",
            "name": "Record critical threat signal",
            "node_id": "threat-analysis",
            "event_type": "finding.created",
            "conditions": [{"field": "severity", "operator": "eq", "value": "critical"}],
            "action_kind": "record_signal",
            "action_config": {},
            "authority": "observe",
        },
    )
    assert definition.status_code == 200

    event = {
        "tenant_id": "tenant-a",
        "event_id": "finding-100",
        "event_type": "finding.created",
        "payload": {"severity": "critical", "finding_id": "finding-100"},
    }
    first = await client.post("/api/v1/marcellus/reflexes/evaluate", json=event)
    second = await client.post("/api/v1/marcellus/reflexes/evaluate", json=event)

    assert first.status_code == 200
    assert first.json()[0]["status"] == "completed"
    assert json.loads(first.json()[0]["result_json"])["recorded"] is True
    assert second.json()[0]["id"] == first.json()[0]["id"]


@pytest.mark.asyncio
async def test_action_reflex_requires_independent_approval_before_plexus_effect(client: AsyncClient):
    _use_identity(_identity("operator-a"))
    definition = await client.post(
        "/api/v1/marcellus/reflexes",
        json={
            "tenant_id": "tenant-a",
            "name": "Escalate critical automation signal",
            "node_id": "security-automation",
            "event_type": "containment.requested",
            "conditions": [],
            "action_kind": "plexus_notify",
            "action_config": {"recipient_node_id": "endpoint-security", "message_type": "containment.review"},
            "authority": "approval_gated_action",
        },
    )
    assert definition.status_code == 200

    evaluated = await client.post(
        "/api/v1/marcellus/reflexes/evaluate",
        json={
            "tenant_id": "tenant-a",
            "event_id": "containment-1",
            "event_type": "containment.requested",
            "payload": {"asset_id": "endpoint-1"},
        },
    )
    assert evaluated.status_code == 200
    execution = evaluated.json()[0]
    assert execution["status"] == "requires_approval"

    self_approval = await client.post(
        f"/api/v1/marcellus/reflexes/executions/{execution['id']}/approve",
        json={"tenant_id": "tenant-a"},
    )
    assert self_approval.status_code == 409

    _use_identity(_identity("operator-b"))
    approval = await client.post(
        f"/api/v1/marcellus/reflexes/executions/{execution['id']}/approve",
        json={"tenant_id": "tenant-a"},
    )
    assert approval.status_code == 200
    assert approval.json()["status"] == "completed"
    assert approval.json()["plexus_message_id"]

    _use_identity(_identity("operator-c"))
    duplicate_approval = await client.post(
        f"/api/v1/marcellus/reflexes/executions/{execution['id']}/approve",
        json={"tenant_id": "tenant-a"},
    )
    assert duplicate_approval.status_code == 409


@pytest.mark.asyncio
async def test_checkpoint_rejects_secrets_and_regeneration_restores_new_generation(client: AsyncClient, db_session):
    _use_identity(_identity("operator-a"))
    rejected = await client.post(
        "/api/v1/marcellus/regeneration/checkpoints",
        json={
            "tenant_id": "tenant-a",
            "node_id": "cloud-security",
            "state": {"api_token": "must-not-be-checkpointed"},
            "manifest": {},
        },
    )
    assert rejected.status_code == 422

    checkpoint_response = await client.post(
        "/api/v1/marcellus/regeneration/checkpoints",
        json={
            "tenant_id": "tenant-a",
            "node_id": "cloud-security",
            "state": {"cursor": "finding-200", "risk_threshold": 80, "mode": "observe"},
            "manifest": {
                "skills": ["cloud-posture"],
                "connectors": ["aws-security-hub"],
                "policy_pack_ids": ["zero-trust-baseline"],
            },
        },
    )
    assert checkpoint_response.status_code == 200
    checkpoint = checkpoint_response.json()

    verification = await client.post(
        f"/api/v1/marcellus/regeneration/checkpoints/{checkpoint['id']}/verify",
        json={"tenant_id": "tenant-a"},
    )
    assert verification.status_code == 200
    assert verification.json()["verified"] is True

    started = await client.post(
        "/api/v1/marcellus/regeneration/runs",
        json={"tenant_id": "tenant-a", "checkpoint_id": checkpoint["id"]},
    )
    assert started.status_code == 200
    run = started.json()
    assert run["status"] == "requires_approval"

    self_approval = await client.post(
        f"/api/v1/marcellus/regeneration/runs/{run['id']}/approve",
        json={"tenant_id": "tenant-a"},
    )
    assert self_approval.status_code == 409

    _use_identity(_identity("operator-b"))
    approved = await client.post(
        f"/api/v1/marcellus/regeneration/runs/{run['id']}/approve",
        json={"tenant_id": "tenant-a"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "completed"
    stages = json.loads(approved.json()["stages_json"])
    assert [stage["stage"] for stage in stages] == [
        "contain",
        "checkpoint",
        "recreate",
        "rehydrate",
        "verify",
        "rejoin",
    ]

    runtime_result = await db_session.execute(
        select(CapabilityNodeRuntime).where(
            CapabilityNodeRuntime.tenant_id == "tenant-a",
            CapabilityNodeRuntime.node_id == "cloud-security",
        )
    )
    runtime = runtime_result.scalar_one()
    assert runtime.status == "active"
    assert runtime.generation == 1
    assert json.loads(runtime.health_json)["credentials_restored"] is False

    _use_identity(_identity("operator-c"))
    duplicate_approval = await client.post(
        f"/api/v1/marcellus/regeneration/runs/{run['id']}/approve",
        json={"tenant_id": "tenant-a"},
    )
    assert duplicate_approval.status_code == 409
