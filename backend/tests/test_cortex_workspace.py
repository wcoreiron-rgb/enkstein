from __future__ import annotations

from uuid import UUID

import pytest
from sqlalchemy import select

from app.core.deps import get_current_user
from app.core.marcellus import workspace
from app.core.swarm.dispatcher import _hydrate_cortex_context
from app.models.marcellus import CortexArtifact, CortexConversationMessage
from app.models.swarm import SwarmJob, SwarmJobStatus
from main import app


BASE = "/api/v1/marcellus/workspace"


def _identity(sub: str = "workspace-owner", tenant_id: str = "tenant-a", role: str = "admin") -> dict:
    return {
        "id": sub,
        "sub": sub,
        "email": f"{sub}@example.invalid",
        "role": role,
        "tenant_id": tenant_id,
    }


def _use_identity(identity: dict) -> None:
    app.dependency_overrides[get_current_user] = lambda: identity


def _gateway_response(text: str = "Governed answer") -> dict:
    return {
        "status": "completed",
        "response": text,
        "source": "codex_subscription",
        "provider": "openai_chatgpt_subscription",
        "model": "subscription-default",
        "mode": "cowork",
        "governance": {
            "outcome": "allowed",
            "policy_name": "Test policy",
            "reason": "Allowed",
            "risk_score": 0,
            "data_classification": "internal",
            "input_redacted": False,
            "output_redacted": False,
            "injection_risk": False,
            "injection_vectors": [],
        },
        "votes": [],
        "confidence": 0.9,
        "agreement": "high",
        "latency_ms": 2,
    }


async def _create_project(client, name: str = "Security platform") -> dict:
    response = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": name, "classification": "internal"},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _create_conversation(client, project_id: str | None = None, mode: str = "cowork") -> dict:
    response = await client.post(
        f"{BASE}/conversations",
        json={
            "tenant_id": "tenant-a",
            "project_id": project_id,
            "title": "New conversation",
            "mode": mode,
            "classification": "internal",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_workspace_turn_persists_encrypted_history(client, db_session, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, project["id"])

    async def fake_gateway(db, payload):
        assert payload.tenant_id == "tenant-a"
        assert payload.workspace_id == project["id"]
        return _gateway_response("The project is ready for review.")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Review project alpha"},
    )
    assert turn.status_code == 200, turn.text
    assert turn.json()["assistant_message"]["content"] == "The project is ready for review."
    assert turn.json()["conversation"]["message_count"] == 2

    stored_result = await db_session.execute(
        select(CortexConversationMessage).where(
            CortexConversationMessage.conversation_id == UUID(conversation["id"]),
            CortexConversationMessage.role == "user",
        )
    )
    stored = stored_result.scalar_one()
    assert "Review project alpha" not in stored.content_ciphertext

    detail = await client.get(
        f"{BASE}/conversations/{conversation['id']}",
        params={"tenant_id": "tenant-a"},
    )
    assert detail.status_code == 200
    assert [item["role"] for item in detail.json()["messages"]] == ["user", "assistant"]
    assert detail.json()["title"].startswith("Review project alpha")


@pytest.mark.asyncio
async def test_folder_artifacts_are_encrypted_versioned_and_reusable(client, db_session, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, project["id"])
    first = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "classification": "confidential",
            "files": [{"path": "src/policy.md", "content": "Internal policy source", "mime_type": "text/markdown"}],
        },
    )
    assert first.status_code == 200, first.text
    artifact = first.json()[0]
    assert artifact["version"] == 1

    second = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "classification": "confidential",
            "files": [{"path": "src/policy.md", "content": "Updated policy source", "mime_type": "text/markdown"}],
        },
    )
    assert second.status_code == 200
    assert second.json()[0]["version"] == 2

    stored = (await db_session.execute(select(CortexArtifact))).scalars().all()
    assert all("policy source" not in item.content_ciphertext for item in stored)
    active = await client.get(
        f"{BASE}/projects/{project['id']}/artifacts",
        params={"tenant_id": "tenant-a"},
    )
    assert len(active.json()) == 1
    assert active.json()[0]["version"] == 2

    captured = {}

    async def fake_gateway(db, payload):
        captured["prompt"] = payload.messages[-1].content
        return _gateway_response()

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Review the attached policy",
            "artifact_ids": [second.json()[0]["id"]],
        },
    )
    assert turn.status_code == 200, turn.text
    assert "Updated policy source" in captured["prompt"]


@pytest.mark.asyncio
async def test_explicit_script_attachment_is_sent_complete_without_silent_truncation(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Complete script review")
    conversation = await _create_conversation(client, project["id"])
    script = "# PowerShell review target\n" + "Write-Output 'complete-line'\n" * 1400
    created = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "files": [{"path": "scripts/review.ps1", "content": script, "mime_type": "text/x-powershell"}],
        },
    )
    assert created.status_code == 200, created.text
    captured = {}

    async def fake_gateway(db, payload):
        captured["prompt"] = payload.messages[-1].content
        return _gateway_response("Complete review")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "How can I improve the attached script?",
            "artifact_ids": [created.json()[0]["id"]],
        },
    )
    assert turn.status_code == 200, turn.text
    assert script in captured["prompt"]
    assert captured["prompt"].endswith(script)


@pytest.mark.asyncio
async def test_oversized_explicit_attachment_fails_instead_of_sending_partial_code(client):
    _use_identity(_identity())
    project = await _create_project(client, "Oversized review")
    conversation = await _create_conversation(client, project["id"])
    created = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "files": [{"path": "scripts/large.ps1", "content": "x" * 100001}],
        },
    )
    assert created.status_code == 200, created.text
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Review all of this file",
            "artifact_ids": [created.json()[0]["id"]],
        },
    )
    assert turn.status_code == 413
    assert "without truncation" in turn.json()["detail"]


@pytest.mark.asyncio
async def test_cowork_automatically_reads_active_project_files(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, project["id"])
    artifact = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "files": [{"path": "docs/context.md", "content": "Project codename is Lantern."}],
        },
    )
    assert artifact.status_code == 200, artifact.text
    captured = {}

    async def fake_gateway(db, payload):
        captured["prompt"] = payload.messages[-1].content
        captured["artifact_count"] = payload.context["artifact_count"]
        return _gateway_response("The codename is Lantern.")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "What is the project codename?"},
    )
    assert turn.status_code == 200, turn.text
    assert "Project codename is Lantern" in captured["prompt"]
    assert captured["artifact_count"] == 1


@pytest.mark.asyncio
async def test_cowork_file_delete_and_conversation_move_are_tenant_scoped(client):
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, mode="chat")
    moved = await client.post(
        f"{BASE}/conversations/{conversation['id']}/move",
        json={"tenant_id": "tenant-a", "project_id": project["id"]},
    )
    assert moved.status_code == 200, moved.text
    assert moved.json()["project_id"] == project["id"]
    assert moved.json()["mode"] == "cowork"

    created = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "conversation_id": conversation["id"],
            "files": [{"path": "plans/change.md", "content": "Versioned change"}],
        },
    )
    assert created.status_code == 200, created.text
    deleted = await client.delete(
        f"{BASE}/artifacts/{created.json()[0]['id']}",
        params={"tenant_id": "tenant-a"},
    )
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["status"] == "deleted"
    active = await client.get(
        f"{BASE}/projects/{project['id']}/artifacts",
        params={"tenant_id": "tenant-a"},
    )
    assert active.status_code == 200
    assert active.json() == []


@pytest.mark.asyncio
async def test_recoverable_workspace_actions_use_archive_policy_names(client, monkeypatch):
    _use_identity(_identity())
    actions: list[str] = []

    async def allow(db, request, ip_address=None):
        actions.append(request.action)
        return type("Decision", (), {"allowed": True, "policy_name": "test"})()

    monkeypatch.setattr(workspace, "enforce", allow)
    conversation = await _create_conversation(client, mode="chat")
    archived = await client.delete(f"{BASE}/conversations/{conversation['id']}", params={"tenant_id": "tenant-a"})
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "archived"
    assert actions[-1] == "workspace_conversation_archive"


@pytest.mark.asyncio
async def test_cowork_edit_and_move_mirror_to_native_workspace(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    created = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "files": [{"path": "notes/old.md", "content": "first"}],
        },
    )
    assert created.status_code == 200, created.text
    calls: list[tuple[str, str]] = []

    async def mirror_write(tenant_id, project_id, *, path, content):
        calls.append(("write", path))

    async def mirror_trash(tenant_id, project_id, *, path):
        calls.append(("trash", path))

    monkeypatch.setattr(workspace, "mirror_write", mirror_write)
    monkeypatch.setattr(workspace, "mirror_trash", mirror_trash)
    updated = await client.patch(
        f"{BASE}/artifacts/{created.json()[0]['id']}",
        json={"tenant_id": "tenant-a", "path": "notes/new.md", "content": "second"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["path"] == "notes/new.md"
    assert updated.json()["content"] == "second"
    assert calls == [("write", "notes/new.md"), ("trash", "notes/old.md")]


@pytest.mark.asyncio
async def test_native_folder_binding_syncs_only_validated_bridge_files(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    binding: dict[str, str] = {}

    def set_binding(tenant_id, project_id, *, token, name):
        binding.update({"token": token, "name": name})

    async def list_files(tenant_id, project_id):
        return [{"path": "src/main.py", "content": "print('ready')", "mime_type": "text/plain"}]

    monkeypatch.setattr(workspace, "set_binding", set_binding)
    monkeypatch.setattr(workspace, "list_native_files", list_files)
    connected = await client.post(
        f"{BASE}/projects/{project['id']}/native-workspace",
        json={
            "tenant_id": "tenant-a",
            "token": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "Local project",
        },
    )
    assert connected.status_code == 200, connected.text
    assert connected.json()["connected"] is True
    assert connected.json()["synced_files"] == 1
    assert binding["name"] == "Local project"


@pytest.mark.asyncio
async def test_workspace_rejects_path_traversal_and_cross_project_context(client, monkeypatch):
    _use_identity(_identity())
    first_project = await _create_project(client, "First")
    second_project = await _create_project(client, "Second")
    conversation = await _create_conversation(client, first_project["id"])
    traversal = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": first_project["id"],
            "files": [{"path": "../../.secrets/key", "content": "blocked"}],
        },
    )
    assert traversal.status_code == 422

    artifact = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": second_project["id"],
            "files": [{"path": "readme.md", "content": "Other project"}],
        },
    )
    assert artifact.status_code == 200

    async def fail_gateway(*args, **kwargs):
        raise AssertionError("cross-project context must be rejected before inference")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fail_gateway)
    denied = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Read it",
            "artifact_ids": [artifact.json()[0]["id"]],
        },
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_conversation_branch_and_encrypted_search(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    async def fake_gateway(db, payload):
        return _gateway_response("Rotate the exposed credential.")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Investigate credential exposure"},
    )
    assert turn.status_code == 200
    message_id = turn.json()["assistant_message"]["id"]

    branch = await client.post(
        f"{BASE}/conversations/{conversation['id']}/branches",
        json={"tenant_id": "tenant-a", "message_id": message_id, "title": "Alternative response"},
    )
    assert branch.status_code == 200, branch.text
    assert branch.json()["branch_of_id"] == conversation["id"]
    assert len(branch.json()["messages"]) == 2

    search = await client.get(
        f"{BASE}/search",
        params={"tenant_id": "tenant-a", "q": "credential exposure"},
    )
    assert search.status_code == 200
    assert search.json()[0]["conversation"]["id"] == turn.json()["conversation"]["id"]


@pytest.mark.asyncio
async def test_tenant_bound_identity_cannot_cross_workspace_tenant(client):
    _use_identity(_identity(tenant_id="tenant-a"))
    response = await client.get(f"{BASE}/projects", params={"tenant_id": "tenant-b"})
    assert response.status_code == 403
    assert response.json()["detail"] == "Cross-tenant access denied"


@pytest.mark.asyncio
async def test_cortex_security_handoff_is_redacted_and_approval_gated(client, db_session, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    async def fake_gateway(db, payload):
        return _gateway_response("Review the evidence before taking action.")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Investigate owner@example.com access"},
    )
    assert turn.status_code == 200
    captured = {}

    async def fake_create_swarm(db, payload):
        captured["payload"] = payload
        job = SwarmJob(
            name=payload.name,
            profile=payload.profile,
            status=SwarmJobStatus.PENDING,
            requested_by=payload.requested_by,
            trigger_type=payload.trigger_type,
            input_json="{}",
            classification=payload.classification,
            participants_json="[]",
            parallelism=payload.parallelism,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        return job

    monkeypatch.setattr(workspace, "create_swarm_job", fake_create_swarm)
    handoff = await client.post(
        f"{BASE}/conversations/{conversation['id']}/security-investigation",
        json={"tenant_id": "tenant-a", "requires_approval": True},
    )
    assert handoff.status_code == 200, handoff.text
    body = handoff.json()
    assert body["status"] == "requires_approval"
    assert body["requires_approval"] is True
    assert "redacted_context" not in captured["payload"].input
    assert "owner@example.com" not in str(captured["payload"].input)
    assert captured["payload"].input["context_redaction_required"] is True
    assert captured["payload"].input["tenant_id"] == "tenant-a"
    assert captured["payload"].task_type == "investigate_cortex_context"

    hydrated = await _hydrate_cortex_context(db_session, captured["payload"].input)
    assert hydrated["cortex_context_status"] == "loaded"
    assert hydrated["cortex_context_redacted"] is True
    assert "owner@example.com" not in hydrated["cortex_context"]

    denied = await _hydrate_cortex_context(
        db_session,
        {**captured["payload"].input, "tenant_id": "tenant-b"},
    )
    assert denied["cortex_context_status"] == "not_found"
    assert "cortex_context" not in denied


@pytest.mark.asyncio
async def test_agent_file_change_requires_review_before_native_write(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Governed agent changes")
    conversation = await _create_conversation(client, project["id"])
    original = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "files": [{"path": "src/config.py", "content": "ENABLED = False"}],
        },
    )
    assert original.status_code == 200, original.text

    async def fake_gateway(db, payload):
        assert payload.context["agent_mode"] is True
        return _gateway_response(
            "I prepared the requested update.\n"
            "```marcellus_changes\n"
            '[{"operation":"update","path":"src/config.py","content":"ENABLED = True","mime_type":"text/x-python"}]\n'
            "```"
        )

    writes: list[tuple[str, str]] = []

    async def mirror_write(tenant_id, project_id, *, path, content):
        writes.append((path, content))

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    monkeypatch.setattr(workspace, "mirror_write", mirror_write)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Enable this setting", "agent_mode": True},
    )
    assert turn.status_code == 200, turn.text
    assert "Prepared 1 governed file change" in turn.json()["assistant_message"]["content"]
    assert writes == []

    pending = await client.get(
        f"{BASE}/projects/{project['id']}/change-proposals",
        params={"tenant_id": "tenant-a"},
    )
    assert pending.status_code == 200, pending.text
    proposal = pending.json()[0]
    assert proposal["operation"] == "update"
    assert proposal["current_content"] == "ENABLED = False"
    assert proposal["proposed_content"] == "ENABLED = True"

    applied = await client.post(
        f"{BASE}/change-proposals/{proposal['id']}/review",
        json={"tenant_id": "tenant-a", "decision": "approve"},
    )
    assert applied.status_code == 200, applied.text
    assert applied.json()["status"] == "applied"
    assert writes == [("src/config.py", "ENABLED = True")]
    active = await client.get(f"{BASE}/projects/{project['id']}/artifacts", params={"tenant_id": "tenant-a"})
    assert active.json()[0]["version"] == 2


@pytest.mark.asyncio
async def test_agent_change_rejects_stale_file_and_unsafe_path(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Change conflicts")
    conversation = await _create_conversation(client, project["id"])
    original = await client.post(
        f"{BASE}/artifacts",
        json={"tenant_id": "tenant-a", "project_id": project["id"], "files": [{"path": "readme.md", "content": "v1"}]},
    )
    assert original.status_code == 200

    async def fake_gateway(db, payload):
        return _gateway_response(
            "Review changes.\n```marcellus_changes\n"
            '[{"operation":"update","path":"readme.md","content":"agent v2"},'
            '{"operation":"create","path":"../../.secrets/token","content":"unsafe"}]\n```'
        )

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Update files", "agent_mode": True},
    )
    assert turn.status_code == 200
    pending = await client.get(f"{BASE}/projects/{project['id']}/change-proposals", params={"tenant_id": "tenant-a"})
    assert [item["path"] for item in pending.json()] == ["readme.md"]

    changed = await client.patch(
        f"{BASE}/artifacts/{original.json()[0]['id']}",
        json={"tenant_id": "tenant-a", "path": "readme.md", "content": "human v2"},
    )
    assert changed.status_code == 200
    conflict = await client.post(
        f"{BASE}/change-proposals/{pending.json()[0]['id']}/review",
        json={"tenant_id": "tenant-a", "decision": "approve"},
    )
    assert conflict.status_code == 409


@pytest.mark.asyncio
async def test_streamed_turn_emits_lifecycle_brain_and_completion_events(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    async def fake_gateway(db, payload):
        result = _gateway_response("Streamed governed answer")
        result["votes"] = [{"source": "codex_subscription", "counted": True, "latency_ms": 4}]
        return result

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={"tenant_id": "tenant-a", "content": "Stream this"},
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    assert "event: turn_started" in body
    assert "event: brain_completed" in body
    assert "event: response_delta" in body
    assert "event: turn_completed" in body


@pytest.mark.asyncio
async def test_change_apply_fails_closed_when_trust_fabric_denies(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Denied agent change")
    conversation = await _create_conversation(client, project["id"])

    async def fake_gateway(db, payload):
        return _gateway_response(
            "Proposed.\n```marcellus_changes\n"
            '[{"operation":"create","path":"safe.txt","content":"pending"}]\n```'
        )

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Create safe.txt", "agent_mode": True},
    )
    assert turn.status_code == 200
    pending = await client.get(f"{BASE}/projects/{project['id']}/change-proposals", params={"tenant_id": "tenant-a"})
    proposal_id = pending.json()[0]["id"]

    async def deny_apply(db, request, ip_address=None):
        return type("Decision", (), {"allowed": False, "policy_name": "Agent writes denied"})()

    wrote = False

    async def fail_write(*args, **kwargs):
        nonlocal wrote
        wrote = True

    monkeypatch.setattr(workspace, "enforce", deny_apply)
    monkeypatch.setattr(workspace, "mirror_write", fail_write)
    denied = await client.post(
        f"{BASE}/change-proposals/{proposal_id}/review",
        json={"tenant_id": "tenant-a", "decision": "approve"},
    )
    assert denied.status_code == 403
    assert wrote is False
