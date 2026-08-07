"""Connected Enkstein Guard coverage and privacy contract."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from app.models.audit import AuditLog
from app.models.event import Event
from app.models.policy import Policy, PolicyAction, PolicyScope
from app.services.policy_engine import evaluate_policy_catalog


def _policy(index: int, *, field: str = "action", value: str = "never") -> Policy:
    return Policy(
        name=f"Catalog policy {index:03d}",
        priority=index,
        scope=(PolicyScope.GLOBAL if index % 3 == 0 else PolicyScope.MODULE),
        scope_target=(None if index % 3 == 0 else f"module_{index % 25}"),
        condition_json=json.dumps({"field": field, "op": "eq", "value": value}),
        action=PolicyAction.DENY,
        is_active=True,
    )


@pytest.mark.asyncio
async def test_guard_evaluates_all_270_active_policies(db_session):
    policies = [_policy(index) for index in range(1, 271)]
    policies[-1].condition_json = json.dumps({
        "field": "action", "op": "eq", "value": "guard_probe",
    })
    db_session.add_all(policies)
    await db_session.commit()

    result = await evaluate_policy_catalog(db_session, {"action": "guard_probe"})

    assert result.catalog_total == 270
    assert result.policies_evaluated == 270
    assert result.policies_matched == 1
    assert result.result.policy_name == "Catalog policy 270"
    assert result.result.action == PolicyAction.DENY


@pytest.mark.asyncio
async def test_guard_preserves_first_match_wins_across_scopes(db_session):
    db_session.add_all([
        Policy(
            name="First monitor",
            priority=1,
            scope=PolicyScope.CONNECTOR,
            scope_target="any",
            condition_json=json.dumps({"field": "action", "op": "contains", "value": "write"}),
            action=PolicyAction.MONITOR,
            is_active=True,
        ),
        Policy(
            name="Later deny",
            priority=2,
            scope=PolicyScope.MODULE,
            scope_target="devclaw",
            condition_json=json.dumps({"field": "action", "op": "contains", "value": "write"}),
            action=PolicyAction.DENY,
            is_active=True,
        ),
    ])
    await db_session.commit()

    result = await evaluate_policy_catalog(db_session, {"action": "write_file"})

    assert result.policies_evaluated == 2
    assert result.policies_matched == 2
    assert result.result.policy_name == "First monitor"
    assert result.result.action == PolicyAction.MONITOR


@pytest.mark.asyncio
async def test_guard_endpoint_never_accepts_raw_content(client):
    payload = _guard_payload()
    for forbidden in ("prompt", "content", "command", "path", "workspace", "tool_input"):
        response = await client.post(
            "/api/v1/trust-fabric/guard/evaluate",
            json={**payload, forbidden: "AKIA3ZK7QWERTYUIOPAS"},
        )
        assert response.status_code == 422, forbidden


@pytest.mark.asyncio
async def test_guard_endpoint_persists_only_safe_evidence(client, db_session):
    db_session.add(_policy(1, field="action", value="write_file"))
    await db_session.commit()

    response = await client.post(
        "/api/v1/trust-fabric/guard/evaluate",
        json=_guard_payload(),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["policy_coverage"] == {
        "catalog_total": 1,
        "policies_evaluated": 1,
        "policies_matched": 1,
        "invalid_conditions": 0,
    }

    event = (await db_session.execute(select(Event))).scalar_one()
    audit = (await db_session.execute(select(AuditLog))).scalar_one()
    persisted = " ".join(filter(None, (
        event.target,
        event.metadata_json,
        event.description,
        audit.resource_id,
        audit.detail_json,
    )))
    for forbidden in (
        "AKIA3ZK7QWERTYUIOPAS",
        "src/customer-a/config.ts",
        "npm publish --token",
        "/Users/private/project",
    ):
        assert forbidden not in persisted
    assert event.tenant_id == "global"


@pytest.mark.asyncio
async def test_guard_signal_map_cannot_override_trusted_context(client, db_session):
    payload = _guard_payload()
    payload["risk_score"] = 80
    payload["signals"] = {
        "tenant_id": False,
        "risk_score": 0,
        "actor_type": False,
        "safe_custom_signal": True,
    }

    response = await client.post(
        "/api/v1/trust-fabric/guard/evaluate",
        json=payload,
    )
    assert response.status_code == 200, response.text

    event = (await db_session.execute(select(Event))).scalar_one()
    metadata = json.loads(event.metadata_json)
    assert event.tenant_id == "global"
    assert event.actor_type == "agent"
    assert metadata["context"]["risk_score"] == 80
    assert metadata["context"]["safe_custom_signal"] is True


def _guard_payload() -> dict:
    return {
        "surface": "write",
        "tool": "Write",
        "operation": "write_file",
        "target_kind": "workspace_file",
        "target_labels": ["config", "ext_ts"],
        "target_digest": "a" * 64,
        "content_digest": "b" * 64,
        "content_length": 128,
        "local_decision": "allow",
        "local_policy_ids": [],
        "local_findings_count": 0,
        "risk_score": 0,
        "risk_level": "none",
        "is_sensitive": False,
        "prompt_injection_risk": False,
        "signals": {"secret_in_repo_commit": False},
    }
