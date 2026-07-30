"""Cross-tenant checks for the channel gateway and the execution channels.

These two surfaces carry the highest consequence in the product: the exec
channels run commands and hand out credentials, and the gateway is the
unauthenticated ingress that feeds them. The shared ``client`` fixture
authenticates as tenant "global", so every record below belongs to
"tenant-intruder" and must be invisible, unapprovable, and unexecutable.
"""
import uuid
from datetime import datetime

import pytest

from app.models.channel_gateway import ChannelConfig, ChannelIdentity, ChannelMessage
from app.models.exec_channels import CredentialBrokerEntry, ExecRequest, ProductionGate

OTHER = "tenant-intruder"


def _exec_request(tenant_id: str | None, command: str, status: str = "pending_approval"):
    return ExecRequest(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        channel="shell",
        requested_by="intruder@example.com",
        command=command,
        environment="prod",
        status=status,
        policy_decision="requires_approval",
        requires_approval=True,
    )


def _channel_message(tenant_id: str | None, text: str) -> ChannelMessage:
    return ChannelMessage(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        channel_type="slack",
        channel_id="C-INTRUDER",
        sender_id="U-INTRUDER",
        sender_email="intruder@example.com",
        message_text=text,
        policy_decision="allowed",
        created_at=datetime.utcnow(),
    )


@pytest.mark.asyncio
async def test_exec_requests_list_excludes_other_tenants(client, db_session):
    db_session.add(_exec_request(OTHER, "cat /etc/shadow"))
    await db_session.commit()

    resp = await client.get("/api/v1/exec/requests")
    assert resp.status_code == 200
    assert all(r["command"] != "cat /etc/shadow" for r in resp.json()["requests"])


@pytest.mark.asyncio
async def test_exec_request_from_another_tenant_is_not_found(client, db_session):
    req = _exec_request(OTHER, "rm -rf /")
    db_session.add(req)
    await db_session.commit()

    assert (await client.get(f"/api/v1/exec/requests/{req.id}")).status_code == 404
    assert (
        await client.post(f"/api/v1/exec/requests/{req.id}/approve", json={})
    ).status_code == 404
    assert (
        await client.post(f"/api/v1/exec/requests/{req.id}/reject", json={})
    ).status_code == 404


@pytest.mark.asyncio
async def test_approved_request_of_another_tenant_cannot_be_executed(client, db_session):
    req = _exec_request(OTHER, "deploy --prod", status="approved")
    db_session.add(req)
    await db_session.commit()

    resp = await client.post(f"/api/v1/exec/requests/{req.id}/execute")
    assert resp.status_code == 404

    await db_session.refresh(req)
    assert req.status == "approved", "a foreign execute attempt must not run the command"


@pytest.mark.asyncio
async def test_credential_broker_entries_are_tenant_scoped(client, db_session):
    cred = CredentialBrokerEntry(
        id=str(uuid.uuid4()),
        tenant_id=OTHER,
        name="intruder_api_key",
        secret_path="secrets/intruder/api_key",
        is_active=True,
    )
    db_session.add(cred)
    await db_session.commit()

    listed = await client.get("/api/v1/exec/credentials")
    assert listed.status_code == 200
    assert all(c["name"] != "intruder_api_key" for c in listed.json())

    # The secret path must not be reachable by id either.
    assert (
        await client.patch(f"/api/v1/exec/credentials/{cred.id}", json={"description": "x"})
    ).status_code == 404
    assert (await client.delete(f"/api/v1/exec/credentials/{cred.id}")).status_code == 404
    assert (
        await client.post(f"/api/v1/exec/credentials/{cred.id}/rotate")
    ).status_code == 404


@pytest.mark.asyncio
async def test_credential_name_may_repeat_across_tenants(client, db_session):
    """Global uniqueness would let one tenant reserve a name for everyone."""
    db_session.add(
        CredentialBrokerEntry(
            id=str(uuid.uuid4()),
            tenant_id=OTHER,
            name="shared_name",
            secret_path="secrets/intruder/shared",
            is_active=True,
        )
    )
    await db_session.commit()

    resp = await client.post(
        "/api/v1/exec/credentials",
        json={"name": "shared_name", "secret_path": "secrets/global/shared"},
    )
    assert resp.status_code == 200, resp.text[:300]


@pytest.mark.asyncio
async def test_production_gate_of_another_tenant_is_not_found(client, db_session):
    gate = ProductionGate(
        id=str(uuid.uuid4()),
        tenant_id=OTHER,
        title="intruder-gate",
        requested_by="intruder@example.com",
        status="pending_approval",
        approvals_required=2,
        approvals_received=[],
    )
    db_session.add(gate)
    await db_session.commit()

    listed = await client.get("/api/v1/exec/production-gates")
    assert listed.status_code == 200
    assert all(g["title"] != "intruder-gate" for g in listed.json())

    assert (await client.get(f"/api/v1/exec/production-gates/{gate.id}")).status_code == 404
    assert (
        await client.post(f"/api/v1/exec/production-gates/{gate.id}/approve", json={})
    ).status_code == 404
    assert (
        await client.post(f"/api/v1/exec/production-gates/{gate.id}/execute")
    ).status_code == 404


@pytest.mark.asyncio
async def test_exec_stats_do_not_count_other_tenants(client, db_session):
    db_session.add(_exec_request(OTHER, "whoami"))
    await db_session.commit()

    resp = await client.get("/api/v1/exec/stats")
    assert resp.status_code == 200
    assert resp.json()["total_requests"] == 0


@pytest.mark.asyncio
async def test_channel_messages_are_tenant_scoped(client, db_session):
    msg = _channel_message(OTHER, "intruder message")
    db_session.add(msg)
    await db_session.commit()

    listed = await client.get("/api/v1/channel-gateway/messages")
    assert listed.status_code == 200
    assert all(m["message_text"] != "intruder message" for m in listed.json()["messages"])

    assert (
        await client.get(f"/api/v1/channel-gateway/messages/{msg.id}")
    ).status_code == 404


@pytest.mark.asyncio
async def test_channel_configs_and_identities_are_tenant_scoped(client, db_session):
    config = ChannelConfig(
        id=str(uuid.uuid4()),
        tenant_id=OTHER,
        channel_type="slack",
        channel_id="C-INTRUDER",
        channel_name="intruder-channel",
        webhook_url="https://hooks.example.com/intruder",
        signing_secret="s3cr3t",
    )
    identity = ChannelIdentity(
        tenant_id=OTHER,
        channel_type="slack",
        platform_user_id="U-INTRUDER",
        platform_email="intruder@example.com",
        is_trusted=True,
    )
    db_session.add_all([config, identity])
    await db_session.commit()

    configs = await client.get("/api/v1/channel-gateway/configs")
    assert configs.status_code == 200
    assert all(c["channel_id"] != "C-INTRUDER" for c in configs.json())

    identities = await client.get("/api/v1/channel-gateway/identities")
    assert identities.status_code == 200
    assert all(
        i["platform_user_id"] != "U-INTRUDER" for i in identities.json()
    )

    # Webhook URLs and signing secrets are credentials; a foreign config must
    # not be editable by id.
    assert (
        await client.patch(
            f"/api/v1/channel-gateway/configs/{config.id}",
            json={"webhook_url": "https://attacker.example.com"},
        )
    ).status_code == 404


@pytest.mark.asyncio
async def test_upsert_identity_cannot_claim_another_tenant(client, db_session):
    """A tenant_id in the body must not let the caller adopt a foreign mapping."""
    identity = ChannelIdentity(
        tenant_id=OTHER,
        channel_type="slack",
        platform_user_id="U-VICTIM",
        platform_email="victim@example.com",
        is_trusted=False,
        trust_score=10,
    )
    db_session.add(identity)
    await db_session.commit()

    resp = await client.post(
        "/api/v1/channel-gateway/identities",
        json={
            "channel_type": "slack",
            "platform_user_id": "U-VICTIM",
            "tenant_id": OTHER,
            "is_trusted": True,
            "trust_score": 99,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["tenant_id"] != OTHER if "tenant_id" in resp.json() else True

    await db_session.refresh(identity)
    assert identity.is_trusted is False, "foreign identity must not be elevated"
    assert identity.trust_score == 10


@pytest.mark.asyncio
async def test_gateway_stats_do_not_count_other_tenants(client, db_session):
    db_session.add(_channel_message(OTHER, "intruder message"))
    await db_session.commit()

    resp = await client.get("/api/v1/channel-gateway/stats")
    assert resp.status_code == 200
    assert resp.json()["total_messages"] == 0


@pytest.mark.asyncio
async def test_unowned_ingress_message_is_hidden_from_tenant_callers(client, db_session):
    """Ingress for an unregistered channel stays unowned, not globally visible."""
    db_session.add(_channel_message(None, "unowned ingress"))
    await db_session.commit()

    listed = await client.get("/api/v1/channel-gateway/messages")
    assert listed.status_code == 200
    assert all(m["message_text"] != "unowned ingress" for m in listed.json()["messages"])
