import json

import pytest

from app.models.audit import AuditLog


BASE = "/api/v1/complianceclaw/evidence/export"


@pytest.mark.asyncio
async def test_compliance_evidence_export_returns_chain_of_custody(client, db_session):
    db_session.add(
        AuditLog(
            actor="compliance-admin",
            actor_type="human",
            action="control.review",
            resource_type="control",
            resource_name="SOC2 CC6.2",
            outcome="allowed",
            policy_applied="baseline",
            reason="unit-test evidence",
            module="complianceclaw",
            compliance_relevant=True,
            frameworks="SOC2,ISO27001",
        )
    )
    await db_session.commit()

    response = await client.post(
        BASE,
        json={
            "requested_by": "compliance-admin",
            "frameworks": ["SOC 2", "ISO 27001"],
            "include_findings": True,
            "include_audit_logs": True,
            "max_audit_logs": 10,
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["summary"]["framework_count"] == 2
    assert body["summary"]["audit_log_count"] >= 1
    assert body["summary"]["finding_count"] >= 1
    assert body["policy_decision"]["outcome"] in {"allowed", "flagged"}
    assert body["chain_of_custody"]["hash_algorithm"] == "sha256"
    assert len(body["chain_of_custody"]["bundle_hash"]) == 64
    assert body["controls"]["SOC 2"]["evidence_state"] == "collected"


@pytest.mark.asyncio
async def test_compliance_evidence_export_blocked_by_policy(client):
    deny_policy = {
        "name": "Block evidence exports",
        "description": "test deny",
        "priority": 1,
        "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "export_compliance_evidence"}),
        "action": "deny",
        "created_by": "test",
    }
    policy_resp = await client.post("/api/v1/policies", json=deny_policy)
    assert policy_resp.status_code == 201, policy_resp.text

    response = await client.post(BASE, json={"requested_by": "compliance-admin"})
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert "blocked by Trust Fabric policy" in detail["message"]
    assert detail["outcome"] == "blocked"
