from __future__ import annotations

from uuid import UUID

import pytest
from sqlalchemy import select

from app.core.deps import get_current_user
from app.core.marcellus import codex_workspace, workspace
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
async def test_workspace_turn_passes_runtime_group_to_gateway(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")
    captured = {}

    async def fake_gateway(db, payload):
        captured["runtime_group"] = payload.runtime_group
        return _gateway_response("Local-only answer")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Summarize this", "runtime_group": "local"},
    )
    assert turn.status_code == 200, turn.text
    assert captured["runtime_group"] == "local"
    # The runtime group and gateway latency are surfaced in the persisted
    # assistant governance so the workspace UI can show accurate provenance.
    assistant_governance = turn.json()["assistant_message"]["governance"]
    assert assistant_governance["runtime_group"] == "local"
    assert assistant_governance["latency_ms"] == 2

    legacy_conversation = await _create_conversation(client, mode="chat")
    legacy_turn = await client.post(
        f"{BASE}/conversations/{legacy_conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Summarize this"},
    )
    assert legacy_turn.status_code == 200, legacy_turn.text
    assert captured["runtime_group"] == "hybrid"


@pytest.mark.asyncio
async def test_switching_answering_brain_mid_conversation_flags_engine_switch(client, monkeypatch):
    """The Gateway needs to know when this turn is being answered by a
    different Brain than the one that answered the previous turn, because a
    Browser Companion turn normally sends only the current message (assuming
    the paired provider tab already holds prior history) -- an assumption
    that only holds if the same engine is still answering."""
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")
    captured: list[dict] = []

    async def fake_gateway(db, payload):
        captured.append(dict(payload.context))
        response = _gateway_response("Answer")
        # The persisted assistant message's `source` is what the next turn's
        # brain_switched_engine check compares against, so it must reflect
        # the Brain this turn actually requested (never the literal string
        # "auto", which is not a real answering source).
        response["source"] = payload.source if payload.source != "auto" else "codex_subscription"
        return response

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)

    first_turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "First question", "source": "codex_subscription"},
    )
    assert first_turn.status_code == 200, first_turn.text
    assert captured[0]["brain_switched_engine"] is False

    second_turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Continue with a different Brain", "source": "gemini_browser"},
    )
    assert second_turn.status_code == 200, second_turn.text
    assert captured[1]["brain_switched_engine"] is True

    third_turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Stay on the same Brain", "source": "gemini_browser"},
    )
    assert third_turn.status_code == 200, third_turn.text
    assert captured[2]["brain_switched_engine"] is False


@pytest.mark.asyncio
async def test_conversation_rename_is_owner_and_tenant_scoped(client):
    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    conversation = await _create_conversation(client, mode="chat")

    renamed = await client.post(
        f"{BASE}/conversations/{conversation['id']}/rename",
        json={"tenant_id": "tenant-a", "title": "Renamed by owner"},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["title"] == "Renamed by owner"

    _use_identity(_identity(sub="other-user", tenant_id="tenant-a", role="analyst"))
    denied = await client.post(
        f"{BASE}/conversations/{conversation['id']}/rename",
        json={"tenant_id": "tenant-a", "title": "Hijacked title"},
    )
    assert denied.status_code == 403

    _use_identity(_identity(sub="owner-a", tenant_id="tenant-b"))
    cross_tenant = await client.post(
        f"{BASE}/conversations/{conversation['id']}/rename",
        json={"tenant_id": "tenant-b", "title": "Cross tenant title"},
    )
    assert cross_tenant.status_code in {403, 404}


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
    assert f"{script}\n=== END FILE scripts/review.ps1 ===" in captured["prompt"]


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
async def test_projects_are_scoped_by_kind_between_chat_and_cowork(client):
    """Chat's project/folder concept must be entirely separate from Cowork's:
    creating a Chat folder must never appear in Cowork's project picker, and
    vice versa, even though both share the same underlying table."""
    _use_identity(_identity())
    cowork_project = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": "Cowork folder", "classification": "internal", "kind": "cowork"},
    )
    assert cowork_project.status_code == 200, cowork_project.text
    assert cowork_project.json()["kind"] == "cowork"

    chat_project = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": "Chat folder", "classification": "internal", "kind": "chat"},
    )
    assert chat_project.status_code == 200, chat_project.text
    assert chat_project.json()["kind"] == "chat"

    cowork_list = await client.get(f"{BASE}/projects", params={"tenant_id": "tenant-a", "kind": "cowork"})
    assert cowork_list.status_code == 200
    cowork_names = {item["name"] for item in cowork_list.json()}
    assert "Cowork folder" in cowork_names
    assert "Chat folder" not in cowork_names

    chat_list = await client.get(f"{BASE}/projects", params={"tenant_id": "tenant-a", "kind": "chat"})
    assert chat_list.status_code == 200
    chat_names = {item["name"] for item in chat_list.json()}
    assert "Chat folder" in chat_names
    assert "Cowork folder" not in chat_names


@pytest.mark.asyncio
async def test_projects_default_to_cowork_kind_for_existing_callers(client):
    """A caller that omits kind entirely (every pre-existing create-project
    call in this codebase) must keep creating a Cowork project, preserving
    the pre-Chat-folder behavior exactly."""
    _use_identity(_identity())
    project = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": "Legacy default project", "classification": "internal"},
    )
    assert project.status_code == 200, project.text
    assert project.json()["kind"] == "cowork"


@pytest.mark.asyncio
async def test_same_name_is_allowed_across_different_project_kinds(client):
    """A Chat folder and a Cowork project may share the same display name --
    they are different rows in different kind namespaces, not a collision."""
    _use_identity(_identity())
    cowork = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": "Shared name", "classification": "internal", "kind": "cowork"},
    )
    assert cowork.status_code == 200, cowork.text
    chat = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": "Shared name", "classification": "internal", "kind": "chat"},
    )
    assert chat.status_code == 200, chat.text
    assert cowork.json()["id"] != chat.json()["id"]


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

    async def mirror_rename(tenant_id, project_id, *, path, new_path):
        calls.append(("rename", f"{path}->{new_path}"))

    monkeypatch.setattr(workspace, "mirror_write", mirror_write)
    monkeypatch.setattr(workspace, "mirror_trash", mirror_trash)
    monkeypatch.setattr(workspace, "mirror_rename", mirror_rename)
    updated = await client.patch(
        f"{BASE}/artifacts/{created.json()[0]['id']}",
        json={"tenant_id": "tenant-a", "path": "notes/new.md", "content": "second"},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["path"] == "notes/new.md"
    assert updated.json()["content"] == "second"
    assert calls == [
        ("rename", "notes/old.md->notes/new.md"),
        ("write", "notes/new.md"),
    ]


@pytest.mark.asyncio
async def test_native_folder_binding_syncs_only_validated_bridge_files(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    binding: dict[str, str] = {}

    def set_binding(tenant_id, project_id, *, token, name, path_alias=None):
        binding.update({"token": token, "name": name, "path_alias": path_alias})

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
async def test_switching_native_folder_removes_files_from_the_previous_folder(client, monkeypatch):
    """Picking a different local folder for the same project must make the
    right-side file panel mirror only that folder's files -- a previously
    synced file whose path is no longer reported by the host bridge is
    marked deleted (recoverable) rather than staying listed forever, which
    was the bug: switching folders kept showing every earlier folder's files."""
    _use_identity(_identity())
    project = await _create_project(client)
    current_files: list[dict] = [
        {"path": "src/main.py", "content": "print('folder-a')", "mime_type": "text/plain"},
        {"path": "README.md", "content": "folder a docs", "mime_type": "text/plain"},
    ]

    def set_binding(tenant_id, project_id, *, token, name, path_alias=None):
        pass

    async def list_files(tenant_id, project_id):
        return current_files

    monkeypatch.setattr(workspace, "set_binding", set_binding)
    monkeypatch.setattr(workspace, "list_native_files", list_files)

    first = await client.post(
        f"{BASE}/projects/{project['id']}/native-workspace",
        json={"tenant_id": "tenant-a", "token": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "name": "Folder A"},
    )
    assert first.status_code == 200, first.text
    assert first.json()["synced_files"] == 2
    assert first.json()["removed_files"] == 0

    active = await client.get(f"{BASE}/projects/{project['id']}/artifacts", params={"tenant_id": "tenant-a"})
    assert sorted(item["path"] for item in active.json()) == ["README.md", "src/main.py"]

    # Operator picks a completely different local folder for the same project.
    current_files = [{"path": "app/index.ts", "content": "export {}", "mime_type": "text/plain"}]
    second = await client.post(
        f"{BASE}/projects/{project['id']}/native-workspace",
        json={"tenant_id": "tenant-a", "token": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "name": "Folder B"},
    )
    assert second.status_code == 200, second.text
    assert second.json()["synced_files"] == 1
    assert second.json()["removed_files"] == 2

    active_after = await client.get(f"{BASE}/projects/{project['id']}/artifacts", params={"tenant_id": "tenant-a"})
    assert [item["path"] for item in active_after.json()] == ["app/index.ts"]


@pytest.mark.asyncio
async def test_native_sync_never_removes_files_a_user_created_directly(client, monkeypatch):
    """A file created or uploaded by the operator inside Enkstein (not
    produced by a folder sync) must survive a native sync even if the bound
    folder doesn't happen to contain a file at that same path."""
    _use_identity(_identity())
    project = await _create_project(client)

    manual = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "files": [{"path": "notes/manual.md", "content": "written directly in Enkstein"}],
        },
    )
    assert manual.status_code == 200, manual.text

    def set_binding(tenant_id, project_id, *, token, name, path_alias=None):
        pass

    async def list_files(tenant_id, project_id):
        return [{"path": "src/main.py", "content": "print('synced')", "mime_type": "text/plain"}]

    monkeypatch.setattr(workspace, "set_binding", set_binding)
    monkeypatch.setattr(workspace, "list_native_files", list_files)
    connected = await client.post(
        f"{BASE}/projects/{project['id']}/native-workspace",
        json={"tenant_id": "tenant-a", "token": "cccccccc-cccc-cccc-cccc-cccccccccccc", "name": "Folder A"},
    )
    assert connected.status_code == 200, connected.text
    assert connected.json()["removed_files"] == 0

    active = await client.get(f"{BASE}/projects/{project['id']}/artifacts", params={"tenant_id": "tenant-a"})
    assert sorted(item["path"] for item in active.json()) == ["notes/manual.md", "src/main.py"]


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
async def test_conversation_branch_is_trust_fabric_gated(client, monkeypatch):
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

    actions: list[str] = []

    async def allow(db, request, ip_address=None):
        actions.append(request.action)
        return type("Decision", (), {"allowed": True, "policy_name": "test"})()

    monkeypatch.setattr(workspace, "enforce", allow)
    allowed = await client.post(
        f"{BASE}/conversations/{conversation['id']}/branches",
        json={"tenant_id": "tenant-a", "message_id": message_id, "title": "Allowed branch"},
    )
    assert allowed.status_code == 200, allowed.text
    assert actions[-1] == "workspace_conversation_branch"

    async def deny(db, request, ip_address=None):
        return type("Decision", (), {"allowed": False, "policy_name": "Branching denied"})()

    monkeypatch.setattr(workspace, "enforce", deny)
    denied = await client.post(
        f"{BASE}/conversations/{conversation['id']}/branches",
        json={"tenant_id": "tenant-a", "message_id": message_id, "title": "Denied branch"},
    )
    assert denied.status_code == 403


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


def test_change_extraction_recovers_complete_objects_from_a_truncated_block():
    """A response cut off mid-generation (browser timeout, provider
    truncation, dropped connection) leaves a change block that opens but
    never closes. Complete objects before the cutoff must still be
    recovered instead of the whole change set silently vanishing."""
    truncated = (
        "Here are the changes.\n"
        "```marcellus_changes\n"
        '[{"operation":"create","path":"a.py","content":"print(1)"},'
        ' {"operation":"create","path":"b.py","content":"still gener'
    )
    cleaned, changes = workspace._extract_change_requests(truncated)
    assert [item["path"] for item in changes] == ["a.py"]
    assert changes[0]["content"] == "print(1)"
    assert "cut off" in cleaned
    assert "1 complete change was recovered" in cleaned
    # The unclosed fence marker itself must not leak into the cleaned text
    # shown to the operator.
    assert "marcellus_changes" not in cleaned


def test_change_extraction_handles_a_brace_inside_recovered_content():
    """A literal '{' or '}' inside a quoted content string (e.g. generated
    Python/JSON source) must not be mistaken for a JSON object boundary
    while recovering a truncated block."""
    truncated = (
        "```marcellus_changes\n"
        '[{"operation":"create","path":"a.py","content":"def f(): return {1: 2}"},'
        ' {"operation":"create","path":"b.py","content":"still gener'
    )
    _cleaned, changes = workspace._extract_change_requests(truncated)
    assert [item["path"] for item in changes] == ["a.py"]
    assert changes[0]["content"] == "def f(): return {1: 2}"


def test_change_extraction_unchanged_for_a_complete_block():
    """A normal, fully-generated change block keeps its exact prior
    behavior: no truncation note, every change recovered."""
    complete = (
        "Here are the changes.\n"
        "```marcellus_changes\n"
        '[{"operation":"create","path":"a.py","content":"print(1)"},'
        ' {"operation":"create","path":"b.py","content":"print(2)"}]\n'
        "```\n"
        "Done."
    )
    cleaned, changes = workspace._extract_change_requests(complete)
    assert [item["path"] for item in changes] == ["a.py", "b.py"]
    assert "cut off" not in cleaned
    assert "Prepared 2 governed file changes for review." in cleaned


def test_change_extraction_with_no_block_is_unaffected():
    plain = "Just a normal answer with no proposed changes."
    cleaned, changes = workspace._extract_change_requests(plain)
    assert changes == []
    assert cleaned == plain


def test_change_extraction_empty_cutoff_reports_no_recovery_without_crashing():
    """The fence opened but generation stopped before any object body was
    produced at all -- this must still report the truncation clearly rather
    than raising or silently returning an empty, unexplained answer."""
    empty_cutoff = "Here we go.\n```marcellus_changes\n["
    cleaned, changes = workspace._extract_change_requests(empty_cutoff)
    assert changes == []
    assert "cut off" in cleaned


@pytest.mark.asyncio
async def test_agent_file_change_recovers_from_a_truncated_browser_response(client, monkeypatch):
    """End-to-end: a response that was cut off mid-change-block (the shape
    the browser-timeout bug produced) must still yield an approvable
    proposal for the change that completed before the cutoff, with a clear
    note about the truncation, instead of the operator seeing zero changes
    with no explanation."""
    _use_identity(_identity())
    project = await _create_project(client, "Recovered truncated changes")
    conversation = await _create_conversation(client, project["id"])

    async def truncated_gateway(db, payload):
        assert payload.context["agent_mode"] is True
        return _gateway_response(
            "I prepared the requested files.\n"
            "```marcellus_changes\n"
            '[{"operation":"create","path":"src/app.py","content":"print(\\"hello\\")"},'
            ' {"operation":"create","path":"src/util.py","content":"def helper(): retur'
        )

    monkeypatch.setattr(workspace, "execute_cortex_gateway", truncated_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Create these files", "agent_mode": True},
    )
    assert turn.status_code == 200, turn.text
    body = turn.json()["assistant_message"]["content"]
    assert "Prepared 1 governed file change" in body
    assert "cut off" in body

    pending = await client.get(
        f"{BASE}/projects/{project['id']}/change-proposals",
        params={"tenant_id": "tenant-a"},
    )
    assert pending.status_code == 200
    paths = [item["path"] for item in pending.json()]
    assert paths == ["src/app.py"]


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


def _sse_events(body: str) -> list[str]:
    return [line[len("event: ") :] for line in body.splitlines() if line.startswith("event: ")]


def _sse_deltas(body: str) -> str:
    import json as _json

    frames = body.split("\n\n")
    parts: list[str] = []
    for frame in frames:
        lines = frame.split("\n")
        event = next((line[len("event: ") :] for line in lines if line.startswith("event: ")), None)
        if event != "response_delta":
            continue
        encoded = "".join(line[len("data: ") :] for line in lines if line.startswith("data: "))
        parts.append(_json.loads(encoded)["delta"])
    return "".join(parts)


@pytest.mark.asyncio
async def test_streamed_turn_emits_heartbeats_while_running(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    from app.core.config import settings

    monkeypatch.setattr(settings, "WORKSPACE_STREAM_HEARTBEAT_SECONDS", 0.02)
    monkeypatch.setattr(settings, "WORKSPACE_STREAM_DEADLINE_SECONDS", 30.0)

    async def slow_gateway(db, payload):
        import asyncio as _asyncio

        await _asyncio.sleep(0.15)
        return _gateway_response("Answer after a slow governed Brain")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", slow_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={"tenant_id": "tenant-a", "content": "Take your time"},
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    events = _sse_events(body)
    # A heartbeat must be delivered before the terminal event so proxies and the
    # browser never observe an idle connection during a long turn.
    assert "heartbeat" in events
    assert events.index("heartbeat") < events.index("turn_completed")


@pytest.mark.asyncio
async def test_streamed_turn_deadline_yields_terminal_timeout(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    from app.core.config import settings

    monkeypatch.setattr(settings, "WORKSPACE_STREAM_HEARTBEAT_SECONDS", 0.02)
    monkeypatch.setattr(settings, "WORKSPACE_STREAM_DEADLINE_SECONDS", 0.1)

    async def stalled_gateway(db, payload):
        import asyncio as _asyncio

        await _asyncio.sleep(5)
        return _gateway_response("never reached")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", stalled_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={"tenant_id": "tenant-a", "content": "Stall forever"},
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    events = _sse_events(body)
    # The stream must terminate rather than hang: exactly one terminal event, and
    # it is the timeout — never turn_completed.
    assert "turn_timeout" in events
    assert "turn_completed" not in events
    assert events[-1] == "turn_timeout"


@pytest.mark.asyncio
async def test_streamed_turn_uses_the_longer_browser_deadline(client, monkeypatch):
    """A turn whose source is a Browser Companion session must survive a
    delay that would already exceed the normal (non-browser) deadline,
    proving the stream picks the browser-specific budget rather than the
    default one whenever a browser source is requested."""
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    from app.core.config import settings

    monkeypatch.setattr(settings, "WORKSPACE_STREAM_HEARTBEAT_SECONDS", 0.02)
    # The normal deadline is far shorter than the delay below; only picking
    # the browser deadline lets this turn complete instead of timing out.
    monkeypatch.setattr(settings, "WORKSPACE_STREAM_DEADLINE_SECONDS", 0.05)
    monkeypatch.setattr(settings, "WORKSPACE_STREAM_BROWSER_DEADLINE_SECONDS", 5.0)

    async def slow_browser_gateway(db, payload):
        import asyncio as _asyncio

        assert payload.source == "chatgpt_browser"
        await _asyncio.sleep(0.15)
        return _gateway_response("A long answer that streamed slowly from the browser tab")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", slow_browser_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={"tenant_id": "tenant-a", "content": "Ask the browser tab", "source": "chatgpt_browser"},
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    events = _sse_events(body)
    assert "turn_completed" in events
    assert "turn_timeout" not in events


@pytest.mark.asyncio
async def test_streamed_turn_uses_the_browser_deadline_for_a_custom_swarm(client, monkeypatch):
    """A consensus turn whose custom consensus_sources includes a browser
    session also gets the longer deadline, not just a direct single-source
    browser request."""
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    from app.core.config import settings

    monkeypatch.setattr(settings, "WORKSPACE_STREAM_HEARTBEAT_SECONDS", 0.02)
    monkeypatch.setattr(settings, "WORKSPACE_STREAM_DEADLINE_SECONDS", 0.05)
    monkeypatch.setattr(settings, "WORKSPACE_STREAM_BROWSER_DEADLINE_SECONDS", 5.0)

    async def slow_swarm_gateway(db, payload):
        import asyncio as _asyncio

        assert payload.consensus_sources == ["codex_subscription", "chatgpt_browser"]
        await _asyncio.sleep(0.15)
        return _gateway_response("Swarm answer")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", slow_swarm_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={
            "tenant_id": "tenant-a",
            "content": "Ask my custom swarm",
            "source": "consensus",
            "consensus_sources": ["codex_subscription", "chatgpt_browser"],
        },
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    events = _sse_events(body)
    assert "turn_completed" in events
    assert "turn_timeout" not in events


@pytest.mark.asyncio
async def test_streamed_turn_failure_yields_terminal_failed(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    async def broken_gateway(db, payload):
        raise RuntimeError("gateway exploded")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", broken_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={"tenant_id": "tenant-a", "content": "Break it"},
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    events = _sse_events(body)
    assert events[-1] == "turn_failed"
    assert "turn_completed" not in events
    # The failure detail must not leak the underlying exception text.
    assert "gateway exploded" not in body


@pytest.mark.asyncio
async def test_streamed_turn_preserves_large_multiline_script(client, monkeypatch):
    _use_identity(_identity())
    conversation = await _create_conversation(client, mode="chat")

    script_lines = [f"print('governed line {index:04d} with padding to force chunk splits')" for index in range(400)]
    script = "```python\n" + "\n".join(script_lines) + "\n```"

    async def script_gateway(db, payload):
        return _gateway_response(script)

    monkeypatch.setattr(workspace, "execute_cortex_gateway", script_gateway)
    async with client.stream(
        "POST",
        f"{BASE}/conversations/{conversation['id']}/turns/stream",
        json={"tenant_id": "tenant-a", "content": "Generate a long script"},
    ) as response:
        body = (await response.aread()).decode()
    assert response.status_code == 200
    # The bounded chunked deltas must reconstruct the full script byte-for-byte —
    # nothing is dropped or truncated by the chunk boundary.
    assert _sse_deltas(body) == script
    assert _sse_events(body)[-1] == "turn_completed"


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


@pytest.mark.asyncio
async def test_reopen_conversation_restores_active_status_and_is_owner_scoped(client, monkeypatch):
    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    conversation = await _create_conversation(client, mode="chat")
    archived = await client.delete(f"{BASE}/conversations/{conversation['id']}", params={"tenant_id": "tenant-a"})
    assert archived.status_code == 200, archived.text
    assert archived.json()["status"] == "archived"

    async def fake_gateway(db, payload):
        return _gateway_response("Should not run while archived")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    blocked_turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Hello while archived"},
    )
    assert blocked_turn.status_code == 409

    _use_identity(_identity(sub="other-user", tenant_id="tenant-a", role="analyst"))
    denied = await client.post(f"{BASE}/conversations/{conversation['id']}/reopen", params={"tenant_id": "tenant-a"})
    assert denied.status_code == 403

    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    reopened = await client.post(f"{BASE}/conversations/{conversation['id']}/reopen", params={"tenant_id": "tenant-a"})
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "active"

    allowed_turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Hello after reopen"},
    )
    assert allowed_turn.status_code == 200, allowed_turn.text


@pytest.mark.asyncio
async def test_permanent_delete_is_tenant_and_owner_scoped(client):
    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    conversation = await _create_conversation(client, mode="chat")

    _use_identity(_identity(sub="other-user", tenant_id="tenant-a", role="analyst"))
    denied = await client.delete(f"{BASE}/conversations/{conversation['id']}/permanent", params={"tenant_id": "tenant-a"})
    assert denied.status_code == 403

    _use_identity(_identity(sub="owner-b", tenant_id="tenant-b"))
    cross_tenant = await client.delete(
        f"{BASE}/conversations/{conversation['id']}/permanent", params={"tenant_id": "tenant-b"}
    )
    assert cross_tenant.status_code == 404

    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    still_readable = await client.get(f"{BASE}/conversations/{conversation['id']}", params={"tenant_id": "tenant-a"})
    assert still_readable.status_code == 200

    deleted = await client.delete(f"{BASE}/conversations/{conversation['id']}/permanent", params={"tenant_id": "tenant-a"})
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["status"] == "deleted"

    gone = await client.get(f"{BASE}/conversations/{conversation['id']}", params={"tenant_id": "tenant-a"})
    assert gone.status_code == 404


@pytest.mark.asyncio
async def test_permanent_delete_cleans_dependent_data_without_touching_other_tenants(client, db_session, monkeypatch):
    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    project = await _create_project(client, "Deletable project")
    conversation = await _create_conversation(client, project["id"])

    active_artifact = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "conversation_id": conversation["id"],
            "files": [{"path": "docs/keep.md", "content": "Stays in the project"}],
        },
    )
    assert active_artifact.status_code == 200, active_artifact.text
    active_artifact_id = active_artifact.json()[0]["id"]

    async def fake_gateway(db, payload):
        return _gateway_response(
            "Proposed.\n```marcellus_changes\n"
            '[{"operation":"create","path":"pending.txt","content":"proposed"}]\n```'
        )

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Propose a file", "agent_mode": True},
    )
    assert turn.status_code == 200, turn.text
    proposals = await client.get(f"{BASE}/projects/{project['id']}/change-proposals", params={"tenant_id": "tenant-a"})
    assert len(proposals.json()) == 1
    proposal_id = proposals.json()[0]["id"]

    branch = await client.post(
        f"{BASE}/conversations/{conversation['id']}/branches",
        json={"tenant_id": "tenant-a", "message_id": turn.json()["user_message"]["id"]},
    )
    assert branch.status_code == 200, branch.text
    branch_id = branch.json()["id"]

    # An identical conversation in a different tenant must be unaffected by the delete below.
    _use_identity(_identity(sub="owner-b", tenant_id="tenant-b"))
    other_tenant_project_response = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-b", "name": "Deletable project", "classification": "internal"},
    )
    assert other_tenant_project_response.status_code == 200, other_tenant_project_response.text
    other_tenant_conversation_response = await client.post(
        f"{BASE}/conversations",
        json={
            "tenant_id": "tenant-b",
            "project_id": other_tenant_project_response.json()["id"],
            "title": "New conversation",
            "mode": "cowork",
            "classification": "internal",
        },
    )
    assert other_tenant_conversation_response.status_code == 200, other_tenant_conversation_response.text
    other_tenant_conversation = other_tenant_conversation_response.json()
    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))

    deleted = await client.delete(f"{BASE}/conversations/{conversation['id']}/permanent", params={"tenant_id": "tenant-a"})
    assert deleted.status_code == 200, deleted.text

    message_rows = (
        await db_session.execute(
            select(CortexConversationMessage).where(CortexConversationMessage.conversation_id == UUID(conversation["id"]))
        )
    ).scalars().all()
    assert message_rows == []

    proposal_row = (
        await db_session.execute(select(CortexArtifact).where(CortexArtifact.id == UUID(proposal_id)))
    ).scalar_one_or_none()
    assert proposal_row is None

    kept_artifact = (
        await db_session.execute(select(CortexArtifact).where(CortexArtifact.id == UUID(active_artifact_id)))
    ).scalar_one()
    assert kept_artifact.status == "active"
    assert kept_artifact.conversation_id is None
    assert kept_artifact.project_id == UUID(project["id"])

    branch_detail = await client.get(f"{BASE}/conversations/{branch_id}", params={"tenant_id": "tenant-a"})
    assert branch_detail.status_code == 200, branch_detail.text
    assert branch_detail.json()["branch_of_id"] is None
    assert branch_detail.json()["branch_message_id"] is None
    assert len(branch_detail.json()["messages"]) == 1

    _use_identity(_identity(sub="owner-b", tenant_id="tenant-b"))
    other_tenant_still_there = await client.get(
        f"{BASE}/conversations/{other_tenant_conversation['id']}", params={"tenant_id": "tenant-b"}
    )
    assert other_tenant_still_there.status_code == 200


# --- Codex App Server control plane ----------------------------------------

async def _make_awaitable(value):
    return value


def _allow_decision():
    return type("Decision", (), {"allowed": True, "policy_name": "test", "reason": "ok"})()


def _deny_decision(policy_name: str = "Codex denied"):
    return type("Decision", (), {"allowed": False, "policy_name": policy_name, "reason": "denied"})()


def _bind_codex(monkeypatch, token: str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") -> None:
    monkeypatch.setattr(codex_workspace, "get_binding", lambda tenant_id, project_id: {"token": token, "name": "Local"})


async def _codex_conversation(client, classification: str = "internal") -> tuple[dict, dict]:
    project = await _create_project(client, f"Codex {classification}")
    response = await client.post(
        f"{BASE}/conversations",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "title": "New conversation",
            "mode": "cowork",
            "classification": classification,
        },
    )
    assert response.status_code == 200, response.text
    return project, response.json()


@pytest.mark.asyncio
async def test_codex_start_and_turn_scope_server_side_without_leaking_token_or_digest(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    calls: list[tuple[str, dict]] = []

    async def fake_bridge(operation, payload):
        calls.append((operation, payload))
        if operation == "start":
            return {"status": "running", "sandbox": payload["sandbox"], "resumed": False, "threadId": "th-secret"}
        return {"status": "running", "cursor": 7, "turnId": "tn-1", "threadId": "th-secret"}

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fake_bridge)

    started = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/start",
        json={"tenant_id": "tenant-a", "sandbox": "workspace-write"},
    )
    assert started.status_code == 200, started.text
    assert started.json() == {"status": "running", "sandbox": "workspace-write", "resumed": False}

    turned = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/turn",
        json={"tenant_id": "tenant-a", "prompt": "Refactor the module"},
    )
    assert turned.status_code == 200, turned.text
    body = turned.json()
    assert body["status"] == "running"
    assert body["cursor"] == 7
    assert body["turn_active"] is True

    # The derived digest and opaque token cross the bridge, never the client.
    start_payload = calls[0][1]
    assert start_payload["token"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert len(start_payload["scope_digest"]) == 64
    assert all(character in "0123456789abcdef" for character in start_payload["scope_digest"])
    assert start_payload["scope_digest"] == calls[1][1]["scope_digest"]
    assert calls[1][1]["prompt"] == "Refactor the module"

    for response_body in (started.json(), turned.json()):
        serialized = str(response_body)
        assert "th-secret" not in serialized
        assert "scope_digest" not in serialized
        assert start_payload["token"] not in serialized
        assert start_payload["scope_digest"] not in serialized


@pytest.mark.asyncio
async def test_codex_rejects_local_only_runtime_group_before_bridge(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)

    async def fail_bridge(operation, payload):
        raise AssertionError("local-only runtime must never invoke Codex")

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fail_bridge)

    start_local = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/start",
        json={"tenant_id": "tenant-a", "sandbox": "read-only", "runtime_group": "local"},
    )
    assert start_local.status_code == 422

    turn_local = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/turn",
        json={"tenant_id": "tenant-a", "prompt": "hi", "runtime_group": "local"},
    )
    assert turn_local.status_code == 422


@pytest.mark.asyncio
async def test_codex_denies_restricted_turn_before_bridge(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client, classification="restricted")
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    async def fail_bridge(operation, payload):
        raise AssertionError("restricted data must never reach the external Codex CLI")

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fail_bridge)

    requests = [
        ("post", f"{BASE}/conversations/{conversation['id']}/codex/start", {"tenant_id": "tenant-a"}),
        ("post", f"{BASE}/conversations/{conversation['id']}/codex/turn", {"tenant_id": "tenant-a", "prompt": "Investigate"}),
        ("get", f"{BASE}/conversations/{conversation['id']}/codex/status?tenant_id=tenant-a", None),
        ("post", f"{BASE}/conversations/{conversation['id']}/codex/approvals/apr-safe", {"tenant_id": "tenant-a", "decision": "decline"}),
        ("post", f"{BASE}/conversations/{conversation['id']}/codex/cancel", {"tenant_id": "tenant-a"}),
    ]
    for method, url, body in requests:
        denied = await client.request(method, url, json=body)
        assert denied.status_code == 403, (method, url, denied.text)
        assert "restricted" in denied.json()["detail"].lower()


@pytest.mark.asyncio
async def test_codex_is_owner_and_tenant_scoped(client, monkeypatch):
    _use_identity(_identity(sub="owner-a", tenant_id="tenant-a"))
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    async def fail_bridge(operation, payload):
        raise AssertionError("isolation must be enforced before the bridge")

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fail_bridge)

    _use_identity(_identity(sub="other-user", tenant_id="tenant-a", role="analyst"))
    other_owner = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/start",
        json={"tenant_id": "tenant-a", "sandbox": "read-only"},
    )
    assert other_owner.status_code == 403

    _use_identity(_identity(sub="owner-a", tenant_id="tenant-b"))
    cross_tenant = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/start",
        json={"tenant_id": "tenant-b", "sandbox": "read-only"},
    )
    assert cross_tenant.status_code in {403, 404}


@pytest.mark.asyncio
async def test_codex_turn_fails_closed_on_policy_denial(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_deny_decision()))

    async def fail_bridge(operation, payload):
        raise AssertionError("a denied turn must not reach the bridge")

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fail_bridge)
    denied = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/turn",
        json={"tenant_id": "tenant-a", "prompt": "Refactor"},
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_codex_denied_accept_sends_native_decline(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    decisions = iter([_deny_decision("Approvals denied"), _allow_decision()])
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(next(decisions)))

    calls: list[tuple[str, dict]] = []

    async def fake_bridge(operation, payload):
        calls.append((operation, payload))
        return {"status": "ok", "decision": payload["decision"]}

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fake_bridge)
    approval_id = "apr-" + "0" * 8 + "-0000-0000-0000-000000000000"
    denied = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/approvals/{approval_id}",
        json={"tenant_id": "tenant-a", "decision": "accept"},
    )
    assert denied.status_code == 403
    # The operator's accept was overridden with a governed native decline so the
    # turn cannot hang on the pending approval.
    assert calls == [("approve", calls[0][1])]
    assert calls[0][1]["decision"] == "decline"
    assert calls[0][1]["approval_id"] == approval_id


@pytest.mark.asyncio
async def test_codex_status_is_bounded_and_sanitized(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    async def fake_bridge(operation, payload):
        assert operation == "status"
        return {
            "status": "running",
            "transport": "running",
            "session": "active",
            "turn": "running",
            "cursor": 120,
            "events": [
                {"cursor": index, "channel": "notification", "fields": {"text": "x" * 9000}}
                for index in range(120)
            ],
            "pending_approvals": [
                {"approval_id": "apr-1", "method": "item/permissions/requestApproval", "detail": {"command": "rm -rf /"}}
            ],
        }

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fake_bridge)
    status_response = await client.get(
        f"{BASE}/conversations/{conversation['id']}/codex/status",
        params={"tenant_id": "tenant-a", "cursor": 0},
    )
    assert status_response.status_code == 200, status_response.text
    body = status_response.json()
    assert len(body["events"]) == 50
    assert all(len(event["fields"]["text"]) <= 4000 for event in body["events"])
    assert body["pending_approvals"] == [
        {
            "approval_id": "apr-1",
            "method": "item/permissions/requestApproval",
            "detail": {},
            "deny_only": True,
        }
    ]
    assert "rm -rf" not in str(body)


@pytest.mark.asyncio
async def test_codex_maps_unavailable_bridge_to_503(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    async def unavailable_bridge(operation, payload):
        raise RuntimeError("Codex App Server bridge is not configured")

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", unavailable_bridge)
    started = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/start",
        json={"tenant_id": "tenant-a", "sandbox": "read-only"},
    )
    assert started.status_code == 503


@pytest.mark.asyncio
async def test_codex_cancel_is_governed_and_normalized(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    calls: list[tuple[str, dict]] = []

    async def fake_bridge(operation, payload):
        calls.append((operation, payload))
        return {"status": "interrupted"}

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fake_bridge)
    cancelled = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/cancel",
        json={"tenant_id": "tenant-a"},
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json() == {"status": "interrupted"}
    assert calls[0][0] == "cancel"
    assert len(calls[0][1]["scope_digest"]) == 64


@pytest.mark.asyncio
async def test_codex_denies_turn_when_project_block_is_restricted(client, monkeypatch):
    _use_identity(_identity())
    project, conversation = await _codex_conversation(client)  # conversation is internal
    # A single restricted artifact block escalates the whole project's effective
    # classification, so the external Codex CLI must be denied even though the
    # conversation itself is only internal.
    restricted = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "classification": "restricted",
            "files": [{"path": "secrets/keys.txt", "content": "top secret material"}],
        },
    )
    assert restricted.status_code == 200, restricted.text
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    async def fail_bridge(operation, payload):
        raise AssertionError("restricted project data must never reach the external Codex CLI")

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fail_bridge)
    denied = await client.post(
        f"{BASE}/conversations/{conversation['id']}/codex/turn",
        json={"tenant_id": "tenant-a", "prompt": "Investigate"},
    )
    assert denied.status_code == 403
    assert "restricted" in denied.json()["detail"].lower()


@pytest.mark.asyncio
async def test_codex_status_redacts_streamed_free_text_and_preserves_ids(client, monkeypatch):
    _use_identity(_identity())
    _, conversation = await _codex_conversation(client)
    _bind_codex(monkeypatch)
    monkeypatch.setattr(codex_workspace, "enforce", lambda *a, **k: _make_awaitable(_allow_decision()))

    secret_key = "AKIA" + "IOSFODNN7EXAMPLE"
    fixture_value = "Hunter2Secret"

    async def fake_bridge(operation, payload):
        assert operation == "status"
        return {
            "status": "running",
            "transport": "running",
            "session": "active",
            "turn": "running",
            "cursor": 42,
            "events": [
                {
                    "cursor": 1,
                    "channel": "notification",
                    "fields": {
                        "type": "agent_message",
                        "itemId": "item-42",
                        "delta": f"here is the aws key {secret_key} from /Users/alice/private-repo do not share",
                    },
                },
                {
                    "cursor": 2,
                    "channel": "notification",
                    "fields": {
                        "type": "plan",
                        "turnId": "turn-9",
                        "plan": [f"step uses password={fixture_value} now"],
                    },
                },
                {
                    "cursor": 3,
                    "channel": "notification",
                    "fields": {"type": "diff", "diff": f"+ password={fixture_value}\n- old line"},
                },
            ],
            "pending_approvals": [
                {
                    "approval_id": "apr-1",
                    "method": "item/commands/requestApproval",
                    "detail": {
                        "command": f"deploy --token {secret_key}",
                        "reason": f"needs password={fixture_value}",
                        "cwd": "/srv/app",
                        "itemId": "item-77",
                        "turnId": "turn-3",
                    },
                }
            ],
        }

    monkeypatch.setattr(codex_workspace, "invoke_codex_bridge", fake_bridge)
    status_response = await client.get(
        f"{BASE}/conversations/{conversation['id']}/codex/status",
        params={"tenant_id": "tenant-a", "cursor": 0},
    )
    assert status_response.status_code == 200, status_response.text
    body = status_response.json()
    serialized = str(body)
    # Every streamed secret is redacted out of delta, plan, diff, command, reason.
    assert secret_key not in serialized
    assert "Hunter2Secret" not in serialized
    assert "[REDACTED]" in serialized
    # Cursor, method, lifecycle, and opaque correlation IDs survive intact.
    assert body["cursor"] == 42
    assert body["events"][0]["fields"]["itemId"] == "item-42"
    assert body["events"][1]["fields"]["turnId"] == "turn-9"
    approval = body["pending_approvals"][0]
    assert approval["approval_id"] == "apr-1"
    assert approval["method"] == "item/commands/requestApproval"
    assert approval["detail"]["itemId"] == "item-77"
    assert approval["detail"]["turnId"] == "turn-3"
    assert approval["detail"]["cwd"] == "app"
    assert "/srv/app" not in serialized
    assert "/Users/alice/private-repo" not in serialized
    assert "[LOCAL_PATH]" in serialized
    # Only safe aggregate scan metadata is emitted; no raw streamed text.
    assert body["scan"]["output_redacted"] is True
    assert body["scan"]["fields_redacted"] >= 3
    assert body["scan"]["sensitive_findings"] >= 3


@pytest.mark.asyncio
async def test_cowork_scanner_summarizes_project_before_heavy_brain(client, monkeypatch):
    """With enough project files and a non-local runtime group, a bounded
    local-only scanner pre-pass runs first (pinned to source=profile:gemma_scanner
    and runtime_group=local regardless of the turn's own runtime group), and its
    summary is folded into the prompt the heavy Brain actually receives."""
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, project["id"])
    files = [{"path": f"src/module_{index}.py", "content": f"# module {index}\ndef handler_{index}():\n    return {index}\n"} for index in range(8)]
    artifact = await client.post(
        f"{BASE}/artifacts",
        json={"tenant_id": "tenant-a", "project_id": project["id"], "files": files},
    )
    assert artifact.status_code == 200, artifact.text

    calls: list[dict] = []

    async def fake_gateway(db, payload):
        calls.append({
            "source": payload.source,
            "runtime_group": payload.runtime_group,
            "prompt": payload.messages[-1].content,
        })
        if payload.source == "profile:gemma_scanner":
            return _gateway_response("Scanner index: 8 handler modules, no notable risk.")
        return _gateway_response("The project has 8 handler modules.")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Summarize this project.",
            "runtime_group": "hybrid",
            "include_project_files": True,
        },
    )
    assert turn.status_code == 200, turn.text
    assert len(calls) == 2
    scanner_call = next(call for call in calls if call["source"] == "profile:gemma_scanner")
    heavy_call = next(call for call in calls if call["source"] != "profile:gemma_scanner")
    # The scanner call is pinned to the local boundary even though the turn's
    # own runtime_group is hybrid.
    assert scanner_call["runtime_group"] == "local"
    assert "module_0" in scanner_call["prompt"]
    # The heavy Brain sees the scanner's summary folded into its own prompt,
    # clearly labeled as untrusted reference material rather than instructions.
    assert "LOCAL SCANNER SUMMARY" in heavy_call["prompt"]
    assert "Scanner index: 8 handler modules" in heavy_call["prompt"]


@pytest.mark.asyncio
async def test_cowork_scanner_skips_below_threshold_and_when_local(client, monkeypatch):
    """The scanner pre-pass only engages once there is real navigation value
    (enough selected files) and never for an already-local turn, where the
    full local capsule is already safe and a second local call would only add
    latency without benefit."""
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, project["id"])
    few_files = [{"path": f"src/module_{index}.py", "content": f"# module {index}\n"} for index in range(2)]
    artifact = await client.post(
        f"{BASE}/artifacts",
        json={"tenant_id": "tenant-a", "project_id": project["id"], "files": few_files},
    )
    assert artifact.status_code == 200, artifact.text

    calls: list[str] = []

    async def fake_gateway(db, payload):
        calls.append(payload.source)
        return _gateway_response("Answer without a scanner pass.")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)

    below_threshold = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Summarize this project.",
            "runtime_group": "hybrid",
            "include_project_files": True,
        },
    )
    assert below_threshold.status_code == 200, below_threshold.text
    assert "profile:gemma_scanner" not in calls

    calls.clear()
    many_files = [{"path": f"src/extra_{index}.py", "content": f"# extra {index}\n"} for index in range(8)]
    extra = await client.post(
        f"{BASE}/artifacts",
        json={"tenant_id": "tenant-a", "project_id": project["id"], "files": many_files},
    )
    assert extra.status_code == 200, extra.text

    local_turn_conversation = await _create_conversation(client, project["id"])
    local_turn = await client.post(
        f"{BASE}/conversations/{local_turn_conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Summarize this project.",
            "runtime_group": "local",
            "include_project_files": True,
        },
    )
    assert local_turn.status_code == 200, local_turn.text
    assert "profile:gemma_scanner" not in calls
