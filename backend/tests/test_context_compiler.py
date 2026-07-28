from __future__ import annotations

import pytest

from app.core.deps import get_current_user
from app.core.marcellus import workspace
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


async def _create_project(client, name: str = "Context compiler project", classification: str = "internal") -> dict:
    response = await client.post(
        f"{BASE}/projects",
        json={"tenant_id": "tenant-a", "name": name, "classification": classification},
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


async def _create_artifact(
    client,
    project_id: str,
    path: str,
    content: str,
    *,
    classification: str = "internal",
    tenant_id: str = "tenant-a",
) -> dict:
    response = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": tenant_id,
            "project_id": project_id,
            "classification": classification,
            "files": [{"path": path, "content": content}],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()[0]


@pytest.mark.asyncio
async def test_explicit_under_limit_artifact_is_sent_full_with_manifest(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client)
    conversation = await _create_conversation(client, project["id"])
    content = "# review target\n" + "Write-Output 'complete-line'\n" * 50
    artifact = await _create_artifact(client, project["id"], "scripts/review.ps1", content)

    captured = {}

    async def fake_gateway(db, payload, **_kwargs):
        captured["prompt"] = payload.messages[-1].content
        return _gateway_response("Reviewed")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Review the attached script",
            "artifact_ids": [artifact["id"]],
        },
    )
    assert turn.status_code == 200, turn.text
    assert content in captured["prompt"]

    manifest = turn.json()["assistant_message"]["governance"]["context_manifest"]
    assert manifest["explicit"] is True
    assert manifest["budget_characters"] == 100_000
    assert len(manifest["entries"]) == 1
    entry = manifest["entries"][0]
    assert entry["disposition"] == "sent_full"
    assert entry["characters_sent"] == len(content)
    assert entry["estimated_tokens"] == -(-len(content) // 4)
    assert entry["citations"][0]["path"] == "scripts/review.ps1"
    assert entry["citations"][0]["line_start"] == 1
    assert entry["destination_brain"] == "codex_subscription/openai_chatgpt_subscription/subscription-default"
    assert manifest["selected_destination"] == entry["destination_brain"]
    assert manifest["effective_classification"] == "internal"
    assert manifest["destination"] == "adaptive"


@pytest.mark.asyncio
async def test_artifact_secret_is_redacted_and_final_provenance_preserves_identity(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Redacted provenance project")
    conversation = await _create_conversation(client, project["id"])
    secret = "AKIA" + "1234567890ABCDEF"
    artifact = await _create_artifact(
        client, project["id"], "config/local.env", f"PUBLIC=value\nAWS_KEY={secret}\n"
    )
    captured = {}

    async def fake_gateway(db, payload, **_kwargs):
        captured["prompt"] = payload.messages[-1].content
        response = _gateway_response("Reviewed")
        response["votes"] = [{
            "source": "claude_subscription", "provider": "anthropic", "model": "opus",
            "available": False, "counted": False, "policy_outcome": "allowed", "reason": "unavailable",
        }, {
            "source": "codex_subscription", "provider": "openai_chatgpt_subscription",
            "model": "subscription-default", "available": True, "counted": True,
            "policy_outcome": "allowed", "reason": "completed",
        }]
        response["routing"] = {"attempted_sources": ["claude_subscription", "codex_subscription"]}
        return response

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Inspect config", "artifact_ids": [artifact["id"]]},
    )
    assert turn.status_code == 200, turn.text
    assert secret not in captured["prompt"]
    manifest = turn.json()["assistant_message"]["governance"]["context_manifest"]
    entry = manifest["entries"][0]
    assert entry["artifact_id"] == artifact["id"]
    assert entry["content_digest"] == artifact["content_digest"]
    assert entry["redacted"] is True
    assert entry["destination_brain"].startswith("codex_subscription/")
    assert [attempt["source"] for attempt in manifest["attempts"]] == [
        "claude_subscription", "codex_subscription",
    ]
    assert manifest["attempts"][0]["policy_outcome"] == "allowed"
    assert manifest["fallback_reason"] == "unavailable"


@pytest.mark.asyncio
async def test_oversized_explicit_attachment_returns_413_before_gateway(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Oversized review")
    conversation = await _create_conversation(client, project["id"])
    artifact = await _create_artifact(client, project["id"], "scripts/large.ps1", "x" * 100_001)

    async def fail_gateway(*args, **kwargs):
        raise AssertionError("gateway must not be invoked when the explicit budget is exceeded")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fail_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Review all of this file",
            "artifact_ids": [artifact["id"]],
        },
    )
    assert turn.status_code == 413
    assert "100,000-character" in turn.json()["detail"]


@pytest.mark.asyncio
async def test_automatic_context_shows_truncation_and_omission_in_manifest(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Automatic ranking project")
    conversation = await _create_conversation(client, project["id"])

    # Each file is uploaded twice so version > 1 ("changed"), ranking them ahead
    # of stable-path fallbacks; stable path order breaks the tie among them.
    # Each file uses a distinct fill character so leakage between files is detectable.
    sizes = {"a-first.txt": ("a", 25_000), "b-second.txt": ("b", 25_000), "c-third.txt": ("c", 25_000), "d-fourth.txt": ("d", 5_000)}
    artifacts = {}
    for path, (fill, size) in sizes.items():
        content = fill * size
        await _create_artifact(client, project["id"], path, "placeholder")
        artifacts[path] = await _create_artifact(client, project["id"], path, content)

    captured = {}

    async def fake_gateway(db, payload, **_kwargs):
        captured["prompt"] = payload.messages[-1].content
        return _gateway_response("Summarized")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fake_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Give me an overview of unrelated topics"},
    )
    assert turn.status_code == 200, turn.text

    manifest = turn.json()["assistant_message"]["governance"]["context_manifest"]
    assert manifest["explicit"] is False
    assert manifest["budget_characters"] == 60_000
    dispositions = {entry["path"]: entry["disposition"] for entry in manifest["entries"]}
    assert dispositions["a-first.txt"] == "sent_full"
    assert dispositions["b-second.txt"] == "sent_full"
    assert dispositions["c-third.txt"] == "truncated"
    assert dispositions["d-fourth.txt"] == "omitted"
    assert manifest["total_characters_sent"] <= 60_000

    # Omitted content must never reach the gateway prompt.
    assert "d" * 5_000 not in captured["prompt"]
    assert "=== BEGIN FILE d-fourth.txt" not in captured["prompt"]


@pytest.mark.asyncio
async def test_restricted_explicit_artifact_to_cloud_destination_returns_403(client, monkeypatch):
    _use_identity(_identity())
    project = await _create_project(client, "Restricted review", classification="restricted")
    conversation = await _create_conversation(client, project["id"])
    artifact = await _create_artifact(
        client, project["id"], "secrets/keys.txt", "top secret material", classification="restricted"
    )

    async def fail_gateway(*args, **kwargs):
        raise AssertionError("gateway must not be invoked when restricted content targets an external destination")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fail_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Summarize the attached secrets",
            "artifact_ids": [artifact["id"]],
            "source": "claude_subscription",
            "runtime_group": "cloud",
        },
    )
    assert turn.status_code == 403


@pytest.mark.asyncio
async def test_cross_tenant_artifact_never_enters_capsule(client, monkeypatch):
    _use_identity(_identity(tenant_id="tenant-a"))
    project = await _create_project(client, "Tenant scoped project")
    conversation = await _create_conversation(client, project["id"])
    artifact = await _create_artifact(client, project["id"], "notes/plan.md", "tenant-a-only content")

    _use_identity(_identity(sub="intruder", tenant_id="tenant-b"))

    async def fail_gateway(*args, **kwargs):
        raise AssertionError("gateway must not be invoked for a cross-tenant artifact reference")

    monkeypatch.setattr(workspace, "execute_cortex_gateway", fail_gateway)
    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-b",
            "content": "Read it",
            "artifact_ids": [artifact["id"]],
        },
    )
    assert turn.status_code in {403, 404}


LOCAL_SOURCE = "profile:ollama_local_fallback"


def _local_vote(source: str, *, response: str = "Local-only governed answer", counted: bool = True, available: bool = True) -> dict:
    return {
        "source": source,
        "kind": "local",
        "available": available,
        "counted": counted,
        "provider": "test-provider",
        "model": "test-model",
        "response": response if counted else None,
        "reason": None if counted else "Local Brain unavailable",
        "latency_ms": 3,
        "token_count": 5,
    }


def test_classification_lattice_orders_and_fails_closed():
    from app.core.marcellus.context_compiler import (
        UnknownClassification,
        highest_classification,
        is_external_denied,
    )

    assert highest_classification("public", "internal", "confidential") == "confidential"
    assert highest_classification("internal", "restricted") == "restricted"
    assert highest_classification("restricted", "top_secret", "public") == "top_secret"
    assert is_external_denied("restricted") is True
    assert is_external_denied("top_secret") is True
    assert is_external_denied("confidential") is False
    assert is_external_denied("internal") is False
    # Unknown values fail closed for the egress decision and are rejected by the
    # escalation helper so callers never silently downgrade.
    assert is_external_denied("moon_secret") is True
    with pytest.raises(UnknownClassification):
        highest_classification("internal", "moon_secret")


@pytest.mark.asyncio
async def test_restricted_artifact_in_internal_conversation_pins_local_no_external(client, monkeypatch):
    from app.core.modelclaw import gateway

    _use_identity(_identity())
    project = await _create_project(client, "Effective escalation project")  # internal
    conversation = await _create_conversation(client, project["id"])  # internal
    artifact = await _create_artifact(
        client, project["id"], "secrets/keys.txt", "top secret material", classification="restricted"
    )

    async def fake_profile(db, source, prompt, **kwargs):
        return _local_vote(source)

    async def fail_subscription(*args, **kwargs):
        raise AssertionError("effective-restricted context must never reach a subscription Brain")

    monkeypatch.setattr(gateway, "invoke_profile_brain", fake_profile)
    monkeypatch.setattr(gateway, "invoke_subscription_brain", fail_subscription)

    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={
            "tenant_id": "tenant-a",
            "content": "Summarize the attached file",
            "artifact_ids": [artifact["id"]],
            "runtime_group": "hybrid",
        },
    )
    assert turn.status_code == 200, turn.text
    body = turn.json()
    gw = body["gateway"]
    # A single restricted artifact escalates internal -> restricted, and that
    # effective value is what the Gateway sees, routes on, and reports. Hybrid
    # therefore stays local-only; no subscription/external Brain is attempted.
    assert gw["governance"]["data_classification"] == "restricted"
    assert gw["routing"]["candidate_sources"] == [LOCAL_SOURCE]
    assert gw["source"] == LOCAL_SOURCE
    # Governance/audit and the persisted message both report the effective value.
    assert body["assistant_message"]["governance"]["effective_classification"] == "restricted"
    assert body["assistant_message"]["classification"] == "restricted"


@pytest.mark.asyncio
async def test_restricted_automatic_context_with_local_unavailable_blocks_cloud(client, monkeypatch):
    from app.core.modelclaw import gateway

    _use_identity(_identity())
    project = await _create_project(client, "Restricted automatic project", classification="restricted")
    conversation = await _create_conversation(client, project["id"])
    await _create_artifact(
        client, project["id"], "notes/plan.md", "restricted planning content", classification="restricted"
    )

    async def unavailable_profile(db, source, prompt, **kwargs):
        return _local_vote(source, counted=False, available=False)

    async def fail_subscription(*args, **kwargs):
        raise AssertionError("no cloud Brain may be attempted when local is the only pinned boundary")

    monkeypatch.setattr(gateway, "invoke_profile_brain", unavailable_profile)
    monkeypatch.setattr(gateway, "invoke_subscription_brain", fail_subscription)

    turn = await client.post(
        f"{BASE}/conversations/{conversation['id']}/turns",
        json={"tenant_id": "tenant-a", "content": "Give me an overview", "runtime_group": "hybrid"},
    )
    assert turn.status_code == 200, turn.text
    body = turn.json()
    # Restricted automatic context stays on the local boundary; when local is
    # unavailable the turn is honestly unavailable rather than falling back to
    # any cloud Brain.
    assert body["gateway"]["status"] == "unavailable"
    assert body["gateway"]["routing"]["candidate_sources"] == [LOCAL_SOURCE]
    assert body["assistant_message"]["governance"]["effective_classification"] == "restricted"
