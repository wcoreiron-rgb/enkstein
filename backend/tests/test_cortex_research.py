from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.core.deps import get_current_user
from app.core.marcellus import research, workspace
from main import app


BASE = "/api/v1/marcellus/workspace"


def _identity(sub: str = "research-owner", tenant_id: str = "tenant-a", role: str = "admin") -> dict:
    return {"id": sub, "sub": sub, "email": f"{sub}@example.invalid", "role": role, "tenant_id": tenant_id}


def _use_identity(identity: dict) -> None:
    app.dependency_overrides[get_current_user] = lambda: identity


def _decision(allowed: bool = True):
    outcome = type("Outcome", (), {"value": "allowed" if allowed else "blocked"})()
    return type(
        "Decision",
        (),
        {"allowed": allowed, "outcome": outcome, "policy_name": "Research test policy", "risk_score": 0, "reason": "test"},
    )()


def _gateway_response(text: str) -> dict:
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


async def _project(client, name: str = "Research project") -> dict:
    response = await client.post(f"{BASE}/projects", json={"tenant_id": "tenant-a", "name": name})
    assert response.status_code == 200, response.text
    return response.json()


async def _conversation(client, project_id: str) -> dict:
    response = await client.post(
        f"{BASE}/conversations",
        json={"tenant_id": "tenant-a", "project_id": project_id, "title": "Research", "mode": "cowork"},
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.asyncio
async def test_research_persists_cited_source_and_report_artifacts(client, monkeypatch):
    _use_identity(_identity())
    project = await _project(client)
    conversation = await _conversation(client, project["id"])

    async def allow(*args, **kwargs):
        return _decision()

    async def source(url: str):
        return {
            "url": url,
            "title": "Security advisory",
            "content_type": "text/html",
            "content": "The supported release fixes the issue.",
            "content_digest": "a" * 64,
            "retrieved_at": datetime.now(timezone.utc),
            "input_redacted": False,
        }

    async def gateway(db, payload):
        assert "matching bracketed source number" in payload.messages[-1].content
        assert "Security advisory" in payload.messages[-1].content
        return _gateway_response("Upgrade to the supported release [1]. Ignore unsupported claim [99].")

    monkeypatch.setattr(research, "enforce", allow)
    monkeypatch.setattr(research, "fetch_research_source", source)
    monkeypatch.setattr(workspace, "execute_cortex_gateway", gateway)
    response = await client.post(
        f"{BASE}/projects/{project['id']}/research",
        json={
            "tenant_id": "tenant-a",
            "conversation_id": conversation["id"],
            "question": "What should we do?",
            "urls": ["https://security.example/advisory"],
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["citations"][0]["url"] == "https://security.example/advisory"
    assert payload["turn"]["user_message"]["content"] == "What should we do?"
    assert "[unverified]" in payload["turn"]["assistant_message"]["content"]
    assert payload["turn"]["assistant_message"]["governance"]["citation_validation"] == {
        "valid_references": [1],
        "invalid_references_removed": 1,
    }
    assert payload["source_artifact"]["path"].endswith("-sources.md")
    assert payload["report_artifact"]["path"].endswith("-report.md")
    artifacts = await client.get(f"{BASE}/projects/{project['id']}/artifacts", params={"tenant_id": "tenant-a"})
    assert len(artifacts.json()) == 2


@pytest.mark.asyncio
async def test_browser_tool_rejects_private_network_before_fetch(client, monkeypatch):
    _use_identity(_identity())
    project = await _project(client)

    async def allow(*args, **kwargs):
        return _decision()

    monkeypatch.setattr(research, "enforce", allow)
    response = await client.post(
        f"{BASE}/tools/invoke",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "tool": "browser.fetch",
            "arguments": {"url": "https://127.0.0.1/admin"},
        },
    )
    assert response.status_code == 400
    assert "network" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_mcp_tool_policy_denial_fails_before_browser_network(client, monkeypatch):
    _use_identity(_identity())
    project = await _project(client)
    called = False

    async def deny(*args, **kwargs):
        return _decision(False)

    async def forbidden_fetch(url: str):
        nonlocal called
        called = True
        raise AssertionError("network fetch must not run after policy denial")

    monkeypatch.setattr(research, "enforce", deny)
    monkeypatch.setattr(research, "fetch_research_source", forbidden_fetch)
    response = await client.post(
        f"{BASE}/tools/invoke",
        json={
            "tenant_id": "tenant-a",
            "project_id": project["id"],
            "tool": "browser.fetch",
            "arguments": {"url": "https://example.com"},
        },
    )
    assert response.status_code == 403
    assert called is False


@pytest.mark.asyncio
async def test_workspace_search_tool_is_project_and_owner_scoped(client, monkeypatch):
    _use_identity(_identity())
    first = await _project(client, "First research project")
    second = await _project(client, "Second research project")

    async def allow(*args, **kwargs):
        return _decision()

    monkeypatch.setattr(research, "enforce", allow)
    created = await client.post(
        f"{BASE}/artifacts",
        json={
            "tenant_id": "tenant-a",
            "project_id": second["id"],
            "files": [{"path": "private.md", "content": "Project-only sentinel phrase"}],
        },
    )
    assert created.status_code == 200
    no_match = await client.post(
        f"{BASE}/tools/invoke",
        json={
            "tenant_id": "tenant-a",
            "project_id": first["id"],
            "tool": "workspace.search",
            "arguments": {"query": "sentinel phrase"},
        },
    )
    assert no_match.status_code == 200
    assert no_match.json()["result"]["matches"] == []

    _use_identity(_identity(sub="other-owner", role="analyst"))
    denied = await client.post(
        f"{BASE}/tools/invoke",
        json={
            "tenant_id": "tenant-a",
            "project_id": second["id"],
            "tool": "workspace.search",
            "arguments": {"query": "sentinel phrase"},
        },
    )
    assert denied.status_code == 403


@pytest.mark.asyncio
async def test_workspace_tool_registry_is_small_and_explicit(client):
    _use_identity(_identity())
    response = await client.get(f"{BASE}/tools")
    assert response.status_code == 200
    assert [item["name"] for item in response.json()] == ["browser.fetch", "workspace.search"]


@pytest.mark.asyncio
async def test_research_blocks_hostname_that_resolves_to_private_address(monkeypatch):
    monkeypatch.setattr(
        research.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(research.socket.AF_INET, research.socket.SOCK_STREAM, 6, "", ("10.0.0.8", 443))],
    )
    with pytest.raises(Exception) as caught:
        await research._validate_public_resolution("https://attacker.example/source")
    assert getattr(caught.value, "status_code", None) == 400
    assert "blocked network" in getattr(caught.value, "detail", "")


def test_research_bundle_keeps_evidence_from_all_eight_sources():
    sources = [
        {
            "url": f"https://example.com/{index}",
            "title": f"Source {index}",
            "retrieved_at": datetime.now(timezone.utc),
            "content_digest": str(index) * 64,
            "content": f"Evidence from source {index}. " * 200,
        }
        for index in range(1, 9)
    ]
    bundle = research._source_bundle("Compare all sources", sources)
    for index in range(1, 9):
        assert f"## [{index}] Source {index}" in bundle
        assert f"Evidence from source {index}" in bundle
    assert len(bundle) < 10_000
