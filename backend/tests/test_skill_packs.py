import json

import pytest


BASE = "/api/v1/skill-packs"


def _pack_payload(slug: str, name: str) -> dict:
    manifest = {
        "skills": [{"id": "s1", "name": "Investigate", "claw": "identityclaw", "action": "investigate"}],
        "scope_permissions": ["read:findings"],
    }
    return {
        "name": name,
        "slug": slug,
        "version": "1.0.0",
        "description": "test pack",
        "manifest_json": json.dumps(manifest),
        "risk_level": "medium",
        "requires_approval": False,
    }


def _manifest(skill_id: str = "s1", scope: str = "read:findings") -> str:
    return json.dumps(
        {
            "skills": [{"id": skill_id, "name": "Investigate", "claw": "identityclaw", "action": "investigate"}],
            "required_connectors": ["entra_id"],
            "required_claws": ["identityclaw"],
            "scope_permissions": [scope],
        }
    )


@pytest.mark.asyncio
async def test_install_skill_pack_blocked_by_policy(client):
    create_resp = await client.post(f"{BASE}", json=_pack_payload("deny-install-pack", "Deny Install Pack"))
    assert create_resp.status_code == 200, create_resp.text
    pack_id = create_resp.json()["id"]

    deny_policy = {
        "name": "Block skill pack installs",
        "description": "test deny",
        "priority": 1,
        "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "install_skill_pack"}),
        "action": "deny",
        "created_by": "test",
    }
    policy_resp = await client.post("/api/v1/policies", json=deny_policy)
    assert policy_resp.status_code == 201, policy_resp.text

    install_resp = await client.post(f"{BASE}/{pack_id}/install", json={"installed_by": "tester"})
    assert install_resp.status_code == 403, install_resp.text
    detail = install_resp.json()["detail"]
    assert "blocked by Trust Fabric policy" in detail["message"]
    assert detail["outcome"] == "blocked"


@pytest.mark.asyncio
async def test_install_skill_pack_blocked_by_gateway_scan(client, monkeypatch):
    create_resp = await client.post(f"{BASE}", json=_pack_payload("gateway-fail-pack", "Gateway Fail Pack"))
    assert create_resp.status_code == 200, create_resp.text
    pack_id = create_resp.json()["id"]

    class _FakeFlags:
        enable_mcp_gateway = True

    class _FakeAdapter:
        flags = _FakeFlags()

        def scan_path(self, path: str):
            return {
                "is_safe": False,
                "risk_score": 90.0,
                "critical_count": 1,
                "high_count": 2,
                "findings": [{"severity": "critical", "message": "hidden instruction payload"}],
                "path": path,
            }

    from app.api.routes import skill_packs_v2 as skill_pack_routes

    monkeypatch.setattr(skill_pack_routes, "get_agt_adapter", lambda: _FakeAdapter())

    install_resp = await client.post(
        f"{BASE}/{pack_id}/install",
        json={"installed_by": "tester", "scan_path": "backend/app/claws/identityclaw"},
    )
    assert install_resp.status_code == 400, install_resp.text
    detail = install_resp.json()["detail"]
    assert "blocked by MCP Security Gateway scan" in detail["message"]
    assert detail["scan"]["critical_count"] == 1


@pytest.mark.asyncio
async def test_skill_pack_preview_upgrade_and_rollback(client):
    create_resp = await client.post(
        f"{BASE}",
        json={**_pack_payload("upgrade-pack", "Upgrade Pack"), "manifest_json": _manifest("s1")},
    )
    assert create_resp.status_code == 200, create_resp.text
    pack_id = create_resp.json()["id"]

    install_resp = await client.post(f"{BASE}/{pack_id}/install", json={"installed_by": "tester"})
    assert install_resp.status_code == 200, install_resp.text

    target_manifest = json.dumps(
        {
            "skills": [
                {"id": "s1", "name": "Investigate", "claw": "identityclaw", "action": "investigate"},
                {"id": "s2", "name": "Contain", "claw": "automationclaw", "action": "contain"},
            ],
            "required_connectors": ["entra_id", "jira"],
            "required_claws": ["identityclaw", "automationclaw"],
            "scope_permissions": ["read:findings", "write:tickets"],
        }
    )

    preview = await client.post(
        f"{BASE}/{pack_id}/preview-update",
        json={"version": "1.1.0", "manifest_json": target_manifest, "upgraded_by": "tester"},
    )
    assert preview.status_code == 200, preview.text
    diff = preview.json()["diff"]
    assert diff["skills_added"] == ["s2"]
    assert diff["field_changes"]["scope_permissions"]["added"] == ["write:tickets"]

    upgrade = await client.post(
        f"{BASE}/{pack_id}/upgrade",
        json={
            "version": "1.1.0",
            "manifest_json": target_manifest,
            "changelog": "Added ticket containment",
            "upgraded_by": "tester",
        },
    )
    assert upgrade.status_code == 200, upgrade.text
    upgraded = upgrade.json()
    assert upgraded["version"] == "1.1.0"
    assert upgraded["rollback_available"] is True
    assert upgraded["skill_count"] == 2

    rollback = await client.post(
        f"{BASE}/{pack_id}/rollback",
        json={"rolled_back_by": "tester", "reason": "validation failed"},
    )
    assert rollback.status_code == 200, rollback.text
    rolled = rollback.json()
    assert rolled["version"] == "1.0.0"
    assert rolled["skill_count"] == 1
    assert rolled["rollback_available"] is False


@pytest.mark.asyncio
async def test_skill_pack_rollback_requires_previous_version(client):
    create_resp = await client.post(f"{BASE}", json=_pack_payload("no-rollback-pack", "No Rollback Pack"))
    assert create_resp.status_code == 200, create_resp.text
    pack_id = create_resp.json()["id"]
    rollback = await client.post(
        f"{BASE}/{pack_id}/rollback",
        json={"rolled_back_by": "tester", "reason": "no previous version"},
    )
    assert rollback.status_code == 400, rollback.text
    assert "No rollback version available" in rollback.text
