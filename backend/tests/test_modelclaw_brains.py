import pytest

from app.core.modelclaw import brain_bridge, routes


BASE = "/api/v1/modelclaw"


@pytest.mark.asyncio
async def test_subscription_brain_status_is_explicit(client, monkeypatch):
    async def fake_status():
        return [
            {
                "brain": "codex_subscription",
                "kind": "subscription",
                "available": True,
                "authenticated": True,
                "runtime": "Codex CLI",
                "account_type": "ChatGPT subscription",
                "detail": "Ready",
            }
        ]

    monkeypatch.setattr(routes, "bridge_status", fake_status)
    response = await client.get(f"{BASE}/brains/status")
    assert response.status_code == 200
    assert response.json()[0]["authenticated"] is True


@pytest.mark.asyncio
async def test_desktop_brain_access_request_is_explicit(client, monkeypatch):
    async def fake_request():
        return {"granted": True, "detail": "Desktop Brain access is ready."}

    monkeypatch.setattr(routes, "request_desktop_brain_access", fake_request)
    response = await client.post(f"{BASE}/brains/desktop-access")
    assert response.status_code == 200
    assert response.json() == {"granted": True, "detail": "Desktop Brain access is ready."}


@pytest.mark.asyncio
async def test_browser_brain_pairing_is_started_by_authenticated_api(client, monkeypatch):
    async def fake_pairing():
        return {
            "available": True,
            "setup_url": "http://127.0.0.1:47831/v1/browser/setup?code=one-time",
            "opened": True,
            "expires_in_seconds": 300,
        }

    monkeypatch.setattr(routes, "create_browser_brain_pairing", fake_pairing)
    response = await client.post(f"{BASE}/brains/browser-pair")
    assert response.status_code == 200
    assert response.json()["available"] is True
    assert response.json()["setup_url"].startswith("http://127.0.0.1:")


@pytest.mark.asyncio
async def test_subscription_brain_invocation_is_audited(client, monkeypatch):
    async def fake_invoke(brain, prompt, *, model=None):
        return {
            "source": brain,
            "kind": "subscription",
            "available": True,
            "counted": True,
            "provider": "openai_chatgpt_subscription",
            "model": model or "subscription-default",
            "response": "Governed answer",
            "latency_ms": 25,
            "token_count": 8,
        }

    monkeypatch.setattr(routes, "invoke_subscription_brain", fake_invoke)
    response = await client.post(
        f"{BASE}/brains/invoke",
        json={
            "brain": "codex_subscription",
            "prompt": "Assess this finding",
            "claw": "executive",
            "data_classification": "internal",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["counted"] is True
    calls = await client.get(f"{BASE}/calls")
    assert any(row["model_profile"] == "codex_subscription" for row in calls.json())


@pytest.mark.asyncio
async def test_chatgpt_desktop_invocation_uses_same_governed_audit_path(client, monkeypatch):
    async def fake_invoke(brain, prompt, *, model=None):
        assert brain == "chatgpt_desktop"
        return {
            "source": brain,
            "kind": "desktop_session",
            "available": True,
            "counted": True,
            "provider": "openai_chatgpt_desktop",
            "model": "desktop-selected",
            "response": "Visible desktop response",
            "latency_ms": 40,
        }

    monkeypatch.setattr(routes, "invoke_subscription_brain", fake_invoke)
    response = await client.post(
        f"{BASE}/brains/invoke",
        json={
            "brain": "chatgpt_desktop",
            "prompt": "Review this architecture",
            "claw": "executive",
            "data_classification": "internal",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["provider"] == "openai_chatgpt_desktop"
    calls = await client.get(f"{BASE}/calls")
    assert any(row["model_profile"] == "chatgpt_desktop" for row in calls.json())


@pytest.mark.asyncio
async def test_subscription_brain_rejects_restricted_data(client):
    response = await client.post(
        f"{BASE}/brains/invoke",
        json={
            "brain": "codex_subscription",
            "prompt": "Analyze restricted material",
            "claw": "executive",
            "data_classification": "restricted",
        },
    )
    assert response.status_code == 403
    assert "approved local profile" in response.json()["detail"]

    desktop = await client.post(
        f"{BASE}/brains/invoke",
        json={
            "brain": "claude_desktop",
            "prompt": "Analyze restricted material",
            "claw": "executive",
            "data_classification": "restricted",
        },
    )
    assert desktop.status_code == 403

    browser = await client.post(
        f"{BASE}/brains/invoke",
        json={
            "brain": "chatgpt_browser",
            "prompt": "Analyze restricted material",
            "claw": "executive",
            "data_classification": "restricted",
        },
    )
    assert browser.status_code == 403


@pytest.mark.asyncio
async def test_consensus_excludes_unavailable_brains(client, monkeypatch):
    async def fake_collect(db, sources, prompt, *, tenant_id, claw, data_classification):
        return [
            {
                "source": "codex_subscription",
                "kind": "subscription",
                "available": True,
                "counted": True,
                "provider": "openai_chatgpt_subscription",
                "model": "subscription-default",
                "response": "Rotate the exposed credential and review its audit history.",
                "latency_ms": 20,
                "token_count": 10,
            },
            {
                "source": "claude_subscription",
                "kind": "subscription",
                "available": False,
                "counted": False,
                "reason": "Runtime unavailable.",
            },
        ]

    monkeypatch.setattr(routes, "collect_votes", fake_collect)
    response = await client.post(
        f"{BASE}/consensus",
        json={
            "prompt": "What should we do?",
            "sources": ["codex_subscription", "claude_subscription"],
            "claw": "executive",
            "data_classification": "internal",
            "minimum_votes": 2,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "insufficient_votes"
    assert body["counted_votes"] == 1
    assert body["confidence"] == 0.35
    assert body["votes"][1]["counted"] is False


def test_deterministic_consensus_reports_agreement_without_hidden_reasoning():
    votes = [
        {"source": "codex_subscription", "response": "Rotate credential and inspect audit evidence immediately."},
        {"source": "profile:nim_fast_reasoning", "response": "Inspect audit evidence and rotate the credential immediately."},
    ]
    answer, confidence, agreement = routes._deterministic_consensus(votes, 2)
    assert answer == votes[0]["response"]
    assert 0.0 < confidence <= 0.95
    assert agreement in {"low", "moderate", "high"}


def test_browser_session_affinity_is_opaque_and_tenant_scoped():
    context = {"conversation_id": "conversation-123"}
    first = brain_bridge.derive_brain_session_id("tenant-a", context)
    repeated = brain_bridge.derive_brain_session_id("tenant-a", context)
    other_tenant = brain_bridge.derive_brain_session_id("tenant-b", context)

    assert first == repeated
    assert first != other_tenant
    assert len(first or "") == 64
    assert "conversation-123" not in (first or "")


@pytest.mark.asyncio
async def test_subscription_bridge_redacts_sensitive_input(monkeypatch):
    captured = {}

    async def fake_request(method, path, payload=None):
        captured.update(payload or {})
        return {
            "success": True,
            "provider": "openai_chatgpt_subscription",
            "model": "subscription-default",
            "response": "Completed safely",
            "latency_ms": 5,
        }

    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_bridge_request", fake_request)
    vote = await brain_bridge.invoke_subscription_brain(
        "codex_subscription",
        "Contact owner@example.com about the alert",
    )
    assert "owner@example.com" not in captured["prompt"]
    assert vote["counted"] is True
    assert "input was redacted" in vote["reason"].lower()


@pytest.mark.asyncio
async def test_profile_brain_redacts_sensitive_input_when_required(monkeypatch):
    captured = {}

    monkeypatch.setattr(
        brain_bridge,
        "get_profile",
        lambda name, tenant_id: {
            "name": name,
            "provider": "ollama",
            "model": "local-test",
            "allowed_models": [],
            "allowed_claws": ["executive"],
            "allowed_data_classes": ["internal"],
            "requires_redaction": True,
        },
    )

    async def fake_call(provider, prompt, **kwargs):
        captured["prompt"] = prompt
        return type(
            "Result",
            (),
            {"success": True, "content": "Evidence-aware response", "model": "local-test", "tokens_used": 5},
        )()

    monkeypatch.setattr(brain_bridge, "call_llm", fake_call)
    async def fake_ollama_models():
        return ["local-test"], True

    monkeypatch.setattr(brain_bridge, "fetch_ollama_models", fake_ollama_models)
    vote = await brain_bridge.invoke_profile_brain(
        object(),
        "profile:local-test",
        "Investigate owner@example.com",
        tenant_id="global",
        claw="executive",
        data_classification="internal",
    )
    assert "owner@example.com" not in captured["prompt"]
    assert vote["counted"] is True
    assert "input was redacted" in vote["reason"].lower()


@pytest.mark.asyncio
async def test_ollama_profile_selects_an_installed_fallback_when_default_is_missing(monkeypatch):
    captured = {}
    monkeypatch.delenv("MARCELLUS_OLLAMA_MODEL", raising=False)
    monkeypatch.setattr(
        brain_bridge,
        "get_profile",
        lambda name, tenant_id: {
            "name": name,
            "provider": "ollama",
            "model": "qwen2.5:14b-instruct",
            "allowed_models": [],
            "allowed_claws": ["executive"],
            "allowed_data_classes": ["internal"],
            "requires_redaction": True,
        },
    )

    async def fake_models():
        return ["llama3.2:latest", "qwen2.5:7b", "regent-aegis:bc"], True

    async def fake_call(provider, prompt, **kwargs):
        captured.update(provider=provider, model=kwargs["model"])
        return type("Result", (), {"success": True, "content": "Local answer", "model": kwargs["model"], "tokens_used": 4})()

    monkeypatch.setattr(brain_bridge, "fetch_ollama_models", fake_models)
    monkeypatch.setattr(brain_bridge, "call_llm", fake_call)
    vote = await brain_bridge.invoke_profile_brain(
        object(),
        "profile:ollama_local_fallback",
        "Review this policy",
        tenant_id="global",
        claw="executive",
        data_classification="internal",
    )
    assert captured == {"provider": "ollama", "model": "regent-aegis:bc"}
    assert vote["counted"] is True


@pytest.mark.asyncio
async def test_ollama_profile_accepts_latest_alias_but_rejects_missing_explicit_model(monkeypatch):
    async def fake_models():
        return ["llama3.2:latest"], True

    monkeypatch.setattr(brain_bridge, "fetch_ollama_models", fake_models)
    monkeypatch.setattr(
        brain_bridge,
        "get_profile",
        lambda name, tenant_id: {
            "name": name,
            "provider": "ollama",
            "model": "llama3.2",
            "allowed_models": [],
            "allowed_claws": ["executive"],
            "allowed_data_classes": ["internal"],
            "requires_redaction": True,
        },
    )
    prepared = await brain_bridge._prepare_profile_brain(
        object(),
        "profile:ollama_local_fallback",
        tenant_id="global",
        claw="executive",
        data_classification="internal",
        model="llama3.2",
    )
    assert prepared["model"] == "llama3.2:latest"

    denied = await brain_bridge._prepare_profile_brain(
        object(),
        "profile:ollama_local_fallback",
        tenant_id="global",
        claw="executive",
        data_classification="internal",
        model="missing-model",
    )
    assert denied["unavailable_vote"]["counted"] is False
    assert "not installed" in denied["unavailable_vote"]["reason"].lower()


@pytest.mark.asyncio
async def test_profile_brain_rejects_model_outside_profile_allowlist(monkeypatch):
    called = False

    monkeypatch.setattr(
        brain_bridge,
        "get_profile",
        lambda name, tenant_id: {
            "name": name,
            "provider": "gemini",
            "model": "approved-model",
            "allowed_models": ["approved-model"],
            "allowed_claws": ["executive"],
            "allowed_data_classes": ["internal"],
            "requires_redaction": True,
        },
    )

    async def fake_call(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("Provider must not be called for a denied model")

    monkeypatch.setattr(brain_bridge, "call_llm", fake_call)
    vote = await brain_bridge.invoke_profile_brain(
        object(),
        "profile:restricted-profile",
        "Review this finding",
        tenant_id="global",
        claw="executive",
        data_classification="internal",
        model="unapproved-model",
    )

    assert vote["counted"] is False
    assert "not allowed" in vote["reason"].lower()
    assert called is False
