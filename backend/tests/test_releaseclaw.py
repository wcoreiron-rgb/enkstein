import pytest


BASE = "/api/v1/releaseclaw"


def _release_payload(**overrides):
    payload = {
        "requested_by": "release-owner",
        "source": "github_actions",
        "environment": "staging",
        "application": "customer-api",
        "change_ref": "release-2026.06.02",
        "deployment_type": "container",
        "mode": "DRY_RUN",
        "template_id": "github-actions-prod",
        "artifacts": [{"name": "customer-api:release-2026.06.02", "type": "image", "digest": "sha256:abc"}],
        "execution_plan": [{"step": 1, "command": "workflow_dispatch customer-api staging"}],
        "rollback_plan": [{"step": 1, "command": "restore previous artifact"}],
        "classification": "internal",
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_releaseclaw_catalog_endpoints(client):
    stats = await client.get(f"{BASE}/stats")
    assert stats.status_code == 200
    assert stats.json()["adapters"] >= 10

    providers = await client.get(f"{BASE}/providers")
    assert providers.status_code == 200
    assert any(p["provider"] == "github_actions" for p in providers.json())

    templates = await client.get(f"{BASE}/templates")
    assert templates.status_code == 200
    assert any(t["id"] == "ai-service-stack" for t in templates.json())


@pytest.mark.asyncio
async def test_releaseclaw_preflight_allows_low_risk_dry_run(client):
    resp = await client.post(BASE + "/preflight", json=_release_payload())
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in {"allowed", "conditional"}
    assert data["execution_handoff"]["direct_script_execution"] is False
    assert data["evidence"]["chain_of_custody"]["bundle_hash"]


@pytest.mark.asyncio
async def test_releaseclaw_blocks_ai_stack_without_model_profile(client):
    resp = await client.post(
        BASE + "/preflight",
        json=_release_payload(
            source="custom",
            environment="prod",
            deployment_type="ai_stack",
            mode="AI_STACK_DEPLOY",
            template_id="ai-service-stack",
            model_profile=None,
        ),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "blocked"
    assert "model_profile_required_for_ai_stack" in data["blockers"]


@pytest.mark.asyncio
async def test_releaseclaw_self_approval_is_blocked(client):
    created = await client.post(
        BASE + "/preflight",
        json=_release_payload(environment="prod", mode="APPROVAL_REQUIRED"),
    )
    assert created.status_code == 200
    deployment_id = created.json()["id"]

    denied = await client.post(
        f"{BASE}/deployments/{deployment_id}/approve",
        json={},
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_releaseclaw_approval_required_status_cannot_execute_without_approval(client):
    created = await client.post(
        BASE + "/preflight",
        json=_release_payload(
            source="custom",
            environment="prod",
            mode="FULL_STACK_PROVISION",
            deployment_type="full_stack",
            template_id="full-stack-app",
            rollback_plan=[{"step": 1, "command": "restore previous artifact"}],
            classification="confidential",
        ),
    )
    assert created.status_code == 200
    data = created.json()
    assert data["status"] == "approval_required"

    execute = await client.post(f"{BASE}/deployments/{data['id']}/execute")
    assert execute.status_code == 403


@pytest.mark.asyncio
async def test_releaseclaw_task_contract(client):
    resp = await client.post(
        BASE + "/task",
        json={
            "swarm_job_id": "job_release",
            "task_type": "deployment_preflight",
            "input": {
                "source": "terraform_cloud",
                "environment": "prod",
                "application": "network-stack",
                "deployment_type": "terraform",
                "mode": "PLAN_ONLY",
                "template_id": "terraform-cloud-apply",
            },
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["claw"] == "releaseclaw"
    assert data["data_source"] == "release_plan"
    assert "SOC2 CC8" in data["compliance_mappings"]


@pytest.mark.asyncio
async def test_releaseclaw_redacts_secret_like_execution_plan(client):
    resp = await client.post(
        BASE + "/preflight",
        json=_release_payload(
            execution_plan=[{"step": 1, "command": "deploy --token=super-sensitive"}],
        ),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "possible_secret_in_execution_plan" in data["blockers"]
    assert data["request"]["execution_plan"][0]["command"] == "[redacted]"


@pytest.mark.asyncio
async def test_releaseclaw_deployments_are_tenant_filtered(client):
    tenant_a = await client.post(BASE + "/preflight", json=_release_payload(tenant_id="tenant-a"))
    assert tenant_a.status_code == 200
    deployment_id = tenant_a.json()["id"]

    default_list = await client.get(BASE + "/deployments")
    assert default_list.status_code == 200
    assert all(row["id"] != deployment_id for row in default_list.json())

    tenant_list = await client.get(BASE + "/deployments", params={"tenant_id": "tenant-a"})
    assert tenant_list.status_code == 200
    assert any(row["id"] == deployment_id for row in tenant_list.json())
