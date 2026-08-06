import asyncio

import pytest

from app.core.deps import get_current_user
from app.core.modelclaw import brain_bridge, gateway, routes, service
from app.core.modelclaw.schemas import ModelProfileCreate
from main import app


BASE = "/api/v1/modelclaw"


def test_same_profile_name_is_isolated_between_tenants(monkeypatch):
    monkeypatch.setattr(service, "_persist_state", lambda: None)
    name = "shared-profile-name"
    keys = [f"tenant-a:{name}", f"tenant-b:{name}"]
    try:
        service.upsert_profile(
            ModelProfileCreate(name=name, provider="ollama", model="tenant-a-model", tenant_id="tenant-a")
        )
        service.upsert_profile(
            ModelProfileCreate(name=name, provider="ollama", model="tenant-b-model", tenant_id="tenant-b")
        )

        assert service.get_profile(name, "tenant-a")["model"] == "tenant-a-model"
        assert service.get_profile(name, "tenant-b")["model"] == "tenant-b-model"
    finally:
        for key in keys:
            service._PROFILES.pop(key, None)


@pytest.mark.asyncio
async def test_subscription_brain_status_is_explicit(client, monkeypatch):
    async def fake_status(db, *, force=False, tenant_id="global", actor_id="brain-status-discovery"):
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
async def test_brain_status_route_passes_force_query_param_through(client, monkeypatch):
    captured = {}

    async def fake_status(db, *, force=False, tenant_id="global", actor_id="brain-status-discovery"):
        captured["force"] = force
        captured["tenant_id"] = tenant_id
        captured["actor_id"] = actor_id
        return []

    monkeypatch.setattr(routes, "bridge_status", fake_status)
    default_response = await client.get(f"{BASE}/brains/status")
    assert default_response.status_code == 200
    assert captured["force"] is False
    assert captured["tenant_id"] == "global"
    assert captured["actor_id"] != "brain-status-discovery"

    forced_response = await client.get(f"{BASE}/brains/status?force=true")
    assert forced_response.status_code == 200
    assert captured["force"] is True

    refreshed_response = await client.get(f"{BASE}/brains/status?refresh=true")
    assert refreshed_response.status_code == 200
    assert captured["force"] is True


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
async def test_cli_login_launch_is_started_by_authenticated_api(client, monkeypatch):
    async def fake_launch(brain):
        assert brain == "codex_subscription"
        return {"launched": True, "detail": "Complete sign-in in the opened Terminal window, then return here and refresh."}

    monkeypatch.setattr(routes, "launch_cli_login", fake_launch)
    response = await client.post(f"{BASE}/brains/cli-login", json={"brain": "codex_subscription"})
    assert response.status_code == 200
    assert response.json()["launched"] is True


@pytest.mark.asyncio
async def test_cli_login_launch_rejects_unsupported_brain(client):
    response = await client.post(f"{BASE}/brains/cli-login", json={"brain": "gemini_browser"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_cli_login_launch_requests_the_native_bridge_endpoint(monkeypatch):
    async def fake_request(method, path, payload=None):
        assert method == "POST"
        assert path == "/v1/cli/launch-login"
        assert payload == {"brain": "claude_subscription"}
        return {"launched": True, "detail": "Complete sign-in in the opened Terminal window, then return here and refresh."}

    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_bridge_request", fake_request)
    result = await brain_bridge.launch_cli_login("claude_subscription")
    assert result["launched"] is True


@pytest.mark.asyncio
async def test_cli_login_launch_fails_closed_without_bridge(monkeypatch):
    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: False)
    result = await brain_bridge.launch_cli_login("codex_subscription")
    assert result["launched"] is False


@pytest.mark.asyncio
async def test_browser_brain_pairing_accepts_explicit_loopback_url(monkeypatch):
    async def fake_request(method, path, payload=None):
        return {
            "setup_url": "http://127.0.0.1:47831/v1/browser/setup?code=one-time",
            "opened": True,
            "expires_in_seconds": 300,
        }

    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_bridge_request", fake_request)
    result = await brain_bridge.create_browser_brain_pairing()
    assert result["available"] is True
    assert result["setup_url"] == "http://127.0.0.1:47831/v1/browser/setup?code=one-time"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "setup_url",
    [
        "http://user:pass@127.0.0.1:47831/v1/browser/setup",
        "http://127.0.0.1:47831@evil.example/v1/browser/setup",
        "http://evil.example/v1/browser/setup?code=one-time",
        "http://127.0.0.1/v1/browser/setup",
        "https://127.0.0.1:47831/v1/browser/setup",
        "http://127.0.0.1:47831.evil.example/v1/browser/setup",
    ],
)
async def test_browser_brain_pairing_rejects_userinfo_and_non_loopback_urls(monkeypatch, setup_url):
    async def fake_request(method, path, payload=None):
        return {"setup_url": setup_url, "opened": True, "expires_in_seconds": 300}

    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_bridge_request", fake_request)
    result = await brain_bridge.create_browser_brain_pairing()
    assert result["available"] is False


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


@pytest.mark.asyncio
async def test_consensus_local_runtime_group_excludes_subscription_and_api_sources(client, monkeypatch):
    called: list[str] = []

    async def fake_collect(db, sources, prompt, *, tenant_id, claw, data_classification):
        called.extend(sources)
        return [
            {
                "source": source,
                "kind": "local",
                "available": True,
                "counted": True,
                "provider": "ollama",
                "model": "local-default",
                "response": "Local-only evidence.",
                "latency_ms": 5,
                "token_count": 6,
            }
            for source in sources
        ]

    monkeypatch.setattr(routes, "collect_votes", fake_collect)
    response = await client.post(
        f"{BASE}/consensus",
        json={
            "prompt": "What should we do?",
            "sources": ["codex_subscription", "claude_subscription", "profile:ollama_local_fallback"],
            "runtime_group": "local",
            "minimum_votes": 1,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert called == ["profile:ollama_local_fallback"]
    assert body["requested_votes"] == 1
    assert all(vote["source"] != "codex_subscription" and vote["source"] != "claude_subscription" for vote in body["votes"])


@pytest.mark.asyncio
async def test_consensus_local_runtime_group_fails_closed_without_a_local_source(client, monkeypatch):
    async def empty_collect(db, sources, prompt, *, tenant_id, claw, data_classification):
        assert sources == [], "Local runtime group must not invoke any Brain when no local source was requested"
        return []

    monkeypatch.setattr(routes, "collect_votes", empty_collect)
    response = await client.post(
        f"{BASE}/consensus",
        json={
            "prompt": "What should we do?",
            "sources": ["codex_subscription", "claude_subscription"],
            "runtime_group": "local",
            "minimum_votes": 1,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["requested_votes"] == 0
    assert body["votes"] == []
    assert body["status"] == "insufficient_votes"


@pytest.mark.asyncio
async def test_consensus_cloud_runtime_group_excludes_browser_desktop_and_local(client, monkeypatch):
    called: list[str] = []

    async def fake_collect(db, sources, prompt, *, tenant_id, claw, data_classification):
        called.extend(sources)
        return [
            {
                "source": source,
                "kind": "subscription",
                "available": True,
                "counted": True,
                "provider": "openai_chatgpt_subscription",
                "model": "subscription-default",
                "response": "Cloud evidence.",
                "latency_ms": 5,
                "token_count": 6,
            }
            for source in sources
        ]

    monkeypatch.setattr(routes, "collect_votes", fake_collect)
    response = await client.post(
        f"{BASE}/consensus",
        json={
            "prompt": "What should we do?",
            "sources": ["codex_subscription", "chatgpt_browser", "claude_desktop", "profile:ollama_local_fallback"],
            "runtime_group": "cloud",
            "minimum_votes": 1,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert called == ["codex_subscription"]
    assert body["requested_votes"] == 1


def test_deterministic_consensus_reports_agreement_without_hidden_reasoning():
    votes = [
        {"source": "codex_subscription", "response": "Rotate credential and inspect audit evidence immediately."},
        {"source": "profile:nim_fast_reasoning", "response": "Inspect audit evidence and rotate the credential immediately."},
    ]
    answer, confidence, agreement = routes._deterministic_consensus(votes, 2)
    assert answer == votes[0]["response"]
    assert 0.0 < confidence <= 0.95
    assert agreement in {"low", "moderate", "high"}


def test_cortex_unavailable_reason_preserves_actionable_provider_failure():
    votes = [
        {
            "source": "chatgpt_browser",
            "available": False,
            "counted": False,
            "reason": "The provider message field rejected the prompt.",
        }
    ]

    assert gateway._best_failure_reason(votes) == "The provider message field rejected the prompt."
    assert gateway._best_failure_reason([]) == "No governed Brain returned a usable response."


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


@pytest.mark.asyncio
async def test_multibrain_calls_are_bounded_per_tenant(monkeypatch):
    active = 0
    peak = 0

    async def fake_invoke(source, prompt, **kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return {
            "source": source,
            "kind": "subscription",
            "available": True,
            "counted": True,
            "response": source,
        }

    monkeypatch.setattr(brain_bridge, "_MAX_TENANT_BRAIN_CALLS", 2)
    brain_bridge._TENANT_SEMAPHORES.clear()
    brain_bridge._SOURCE_SEMAPHORES.clear()
    votes = await brain_bridge.collect_votes(
        object(),
        ["codex_subscription", "claude_subscription", "chatgpt_desktop", "claude_desktop"],
        "Review concurrently",
        tenant_id="bounded-tenant",
        claw="executive",
        data_classification="internal",
        subscription_invoker=fake_invoke,
    )

    assert len(votes) == 4
    assert peak == 2


@pytest.mark.asyncio
async def test_multibrain_timeout_returns_safe_unavailable_vote(monkeypatch):
    async def slow_invoke(source, prompt, **kwargs):
        await asyncio.sleep(1)

    monkeypatch.setattr(brain_bridge, "_BRAIN_TIMEOUT_SECONDS", 0.01)
    # codex_subscription is CLI-driven and now carries the longer local budget,
    # so the timeout under test is that one, not the hosted-API budget.
    monkeypatch.setattr(brain_bridge, "_LOCAL_BRAIN_TIMEOUT_SECONDS", 0.01)
    brain_bridge._TENANT_SEMAPHORES.clear()
    brain_bridge._SOURCE_SEMAPHORES.clear()
    votes = await brain_bridge.collect_votes(
        object(),
        ["codex_subscription"],
        "Timeout safely",
        tenant_id="timeout-tenant",
        claw="executive",
        data_classification="internal",
        subscription_invoker=slow_invoke,
    )

    assert votes[0]["counted"] is False
    assert "timed out" in votes[0]["reason"].lower()


@pytest.mark.asyncio
async def test_browser_brain_survives_beyond_the_direct_call_timeout(monkeypatch):
    """A browser Companion source must not be cut off by the same short
    budget used for a direct API/CLI call: it needs to survive a delay that
    would already have failed a codex_subscription/claude_subscription call,
    proving the two timeouts are genuinely independent."""
    calls: list[str] = []

    async def slow_browser_invoke(source, prompt, **kwargs):
        calls.append(source)
        await asyncio.sleep(0.05)
        return {
            "source": source,
            "kind": "browser_session",
            "available": True,
            "counted": True,
            "provider": "openai_chatgpt_browser",
            "model": "browser-selected",
            "response": "A long response that took a while to stream.",
            "reason": None,
            "latency_ms": 50,
            "token_count": None,
        }

    monkeypatch.setattr(brain_bridge, "_BRAIN_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(brain_bridge, "_BROWSER_BRAIN_TIMEOUT_SECONDS", 5.0)
    brain_bridge._TENANT_SEMAPHORES.clear()
    brain_bridge._SOURCE_SEMAPHORES.clear()
    votes = await brain_bridge.collect_votes(
        object(),
        ["chatgpt_browser"],
        "Ask something that takes a while to answer",
        tenant_id="browser-timeout-tenant",
        claw="executive",
        data_classification="internal",
        subscription_invoker=slow_browser_invoke,
    )

    assert calls == ["chatgpt_browser"]
    assert votes[0]["counted"] is True
    assert votes[0]["response"] == "A long response that took a while to stream."


def test_locally_executed_brains_get_more_time_than_a_hosted_api_call():
    """A local Ollama profile and a CLI-driven subscription both run on this
    machine and were being cut off by a budget tuned for a hosted API round
    trip, so most of a swarm reported itself as timed out."""
    hosted = brain_bridge._brain_timeout_seconds("openai_api")
    local_profile = brain_bridge._brain_timeout_seconds("profile:ollama_local_fallback")
    codex_cli = brain_bridge._brain_timeout_seconds("codex_subscription")
    claude_cli = brain_bridge._brain_timeout_seconds("claude_subscription")
    browser = brain_bridge._brain_timeout_seconds("chatgpt_browser")

    assert local_profile > hosted
    assert codex_cli == local_profile
    assert claude_cli == local_profile
    assert browser > local_profile


def test_a_local_brain_budget_stays_under_the_outer_turn_deadline():
    """The per-Brain timeout must resolve before the streaming turn deadline,
    otherwise the turn dies first and the Brain's reason is never reported."""
    from app.core.config import settings

    assert brain_bridge._LOCAL_BRAIN_TIMEOUT_SECONDS < settings.WORKSPACE_STREAM_DEADLINE_SECONDS
    assert brain_bridge._BROWSER_BRAIN_TIMEOUT_SECONDS < settings.WORKSPACE_STREAM_BROWSER_DEADLINE_SECONDS


def test_a_file_writing_turn_is_never_told_to_be_concise():
    """Enkstein's own system prompt was telling a file-authoring Brain to be
    concise, so it answered that the file was too large to reproduce instead
    of writing it."""
    reasoning = brain_bridge._profile_system_prompt("What does this project do?")
    authoring = brain_bridge._profile_system_prompt(
        "Return exactly one fenced `marcellus_changes` JSON array and no prose."
    )

    assert "concise" in reasoning
    assert "concise" not in authoring
    assert "complete file contents" in authoring
    assert "Length is not a constraint" in authoring


@pytest.mark.asyncio
async def test_browser_status_poll_recovers_after_transient_bridge_failure(monkeypatch):
    """One failed status request must not become an immediate false timeout
    while the provider tab continues generating its response."""
    calls = 0
    progress: list[tuple[str, str | None]] = []

    async def fake_request(method, path, payload=None, **_kwargs):
        nonlocal calls
        if path == "/v1/browser-invoke/start":
            return {"task_id": "browser-task-1"}
        assert path == "/v1/browser-invoke/status"
        calls += 1
        if calls == 1:
            raise OSError("transient host bridge interruption")
        if calls == 2:
            return {"state": "streaming", "provider": "chatgpt"}
        return {
            "state": "completed",
            "provider": "chatgpt",
            "response": "The complete browser response.",
        }

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(brain_bridge, "_bridge_request", fake_request)
    monkeypatch.setattr(brain_bridge.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(brain_bridge, "_BROWSER_BRAIN_TIMEOUT_SECONDS", 5.0)
    vote = await brain_bridge._invoke_browser_polled(
        "chatgpt_browser",
        "Build the application",
        session_id="a" * 64,
        started=brain_bridge.perf_counter(),
        input_scan=brain_bridge.scan_text("Build the application", redact=True),
        on_progress=lambda state, label: progress.append((state, label)),
    )

    assert vote["counted"] is True
    assert vote["response"] == "The complete browser response."
    assert calls == 3
    assert any(state == "reconnecting" for state, _label in progress)
    assert any(state == "streaming" for state, _label in progress)


@pytest.mark.asyncio
async def test_browser_brain_still_times_out_eventually(monkeypatch):
    """The browser budget is longer, not unbounded: a browser session that
    never returns must still fail safely rather than hang the turn."""
    async def never_returns(source, prompt, **kwargs):
        await asyncio.sleep(1)

    monkeypatch.setattr(brain_bridge, "_BROWSER_BRAIN_TIMEOUT_SECONDS", 0.01)
    brain_bridge._TENANT_SEMAPHORES.clear()
    brain_bridge._SOURCE_SEMAPHORES.clear()
    votes = await brain_bridge.collect_votes(
        object(),
        ["claude_browser"],
        "Timeout safely",
        tenant_id="browser-timeout-tenant-2",
        claw="executive",
        data_classification="internal",
        subscription_invoker=never_returns,
    )

    assert votes[0]["counted"] is False
    assert "timed out" in votes[0]["reason"].lower()


@pytest.mark.asyncio
async def test_modelclaw_rejects_cross_tenant_reads_and_execution(client):
    app.dependency_overrides[get_current_user] = lambda: {
        "sub": "tenant-a-user",
        "role": "analyst",
        "tenant_id": "tenant-a",
    }

    profiles = await client.get(f"{BASE}/profiles?tenant_id=tenant-b")
    calls = await client.get(f"{BASE}/calls?tenant_id=tenant-b")
    invocation = await client.post(
        f"{BASE}/brains/invoke",
        json={
            "brain": "codex_subscription",
            "prompt": "Cross tenant request",
            "tenant_id": "tenant-b",
        },
    )
    profile_update = await client.post(
        f"{BASE}/profiles",
        json={
            "name": "tenant-a-profile",
            "provider": "ollama",
            "model": "llama3.2",
            "tenant_id": "tenant-a",
        },
    )

    assert profiles.status_code == 403
    assert calls.status_code == 403
    assert invocation.status_code == 403
    assert profile_update.status_code == 403


@pytest.mark.asyncio
async def test_bridge_status_marks_installed_but_unauthenticated_as_needs_setup(monkeypatch, db_session):
    async def fake_request(method, path):
        return {
            "brains": [
                {
                    "brain": "codex_subscription",
                    "kind": "subscription",
                    "available": True,
                    "authenticated": False,
                    "detail": "Run codex login on this host.",
                },
                {
                    "brain": "claude_subscription",
                    "kind": "subscription",
                    "available": True,
                    "authenticated": True,
                    "detail": "Ready",
                },
            ]
        }

    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_bridge_request", fake_request)
    brain_bridge._stale_status_cache = None
    rows = await brain_bridge.bridge_status(db_session)
    by_name = {row["brain"]: row for row in rows}
    assert by_name["codex_subscription"]["status"] == "needs_setup"
    assert by_name["codex_subscription"]["last_checked"] is not None
    assert by_name["claude_subscription"]["status"] == "ready"


@pytest.mark.asyncio
async def test_bridge_status_recovers_from_stale_unreachable_cache_to_ready(monkeypatch, db_session):
    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_STALE_STATUS_CACHE_SECONDS", 0.0)
    brain_bridge._stale_status_cache = None

    async def failing_request(method, path):
        raise ConnectionError("bridge offline")

    monkeypatch.setattr(brain_bridge, "_bridge_request", failing_request)
    down = await brain_bridge.bridge_status(db_session)
    assert all(row["status"] == "unavailable" for row in down)
    assert brain_bridge._stale_status_cache is not None

    async def recovered_request(method, path):
        return {
            "brains": [
                {"brain": "codex_subscription", "kind": "subscription", "available": True, "authenticated": True, "detail": "Ready"},
            ]
        }

    monkeypatch.setattr(brain_bridge, "_bridge_request", recovered_request)
    recovered = await brain_bridge.bridge_status(db_session)
    assert recovered[0]["status"] == "ready"
    brain_bridge._stale_status_cache = None


@pytest.mark.asyncio
async def test_bridge_status_caches_unreachable_failure_briefly(monkeypatch, db_session):
    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_STALE_STATUS_CACHE_SECONDS", 30.0)
    brain_bridge._stale_status_cache = None
    calls = 0

    async def failing_request(method, path):
        nonlocal calls
        calls += 1
        raise ConnectionError("bridge offline")

    monkeypatch.setattr(brain_bridge, "_bridge_request", failing_request)
    first = await brain_bridge.bridge_status(db_session)
    second = await brain_bridge.bridge_status(db_session)
    assert calls == 1
    assert first == second
    brain_bridge._stale_status_cache = None


@pytest.mark.asyncio
async def test_bridge_status_force_bypasses_and_clears_negative_cache(monkeypatch, db_session):
    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    monkeypatch.setattr(brain_bridge, "_STALE_STATUS_CACHE_SECONDS", 30.0)
    brain_bridge._stale_status_cache = None
    calls = 0

    async def failing_request(method, path):
        nonlocal calls
        calls += 1
        raise ConnectionError("bridge offline")

    monkeypatch.setattr(brain_bridge, "_bridge_request", failing_request)
    stale = await brain_bridge.bridge_status(db_session)
    assert all(row["status"] == "unavailable" for row in stale)
    assert calls == 1

    async def recovered_request(method, path):
        return {
            "brains": [
                {"brain": "codex_subscription", "kind": "subscription", "available": True, "authenticated": True, "detail": "Ready"},
            ]
        }

    monkeypatch.setattr(brain_bridge, "_bridge_request", recovered_request)
    # Without force, the negative cache would still be replayed here since
    # _STALE_STATUS_CACHE_SECONDS is 30s; force must bypass and clear it.
    forced = await brain_bridge.bridge_status(db_session, force=True)
    assert forced[0]["status"] == "ready"
    assert brain_bridge._stale_status_cache is None
    brain_bridge._stale_status_cache = None


@pytest.mark.asyncio
async def test_bridge_status_blocked_by_trust_fabric_returns_policy_blocked_without_probing(monkeypatch, db_session):
    monkeypatch.setattr(brain_bridge, "bridge_configured", lambda: True)
    brain_bridge._stale_status_cache = None
    probed = False

    async def probing_request(method, path):
        nonlocal probed
        probed = True
        return {"brains": []}

    class DeniedDecision:
        allowed = False
        reason = "Brain status discovery is denied for this tenant."

    async def deny(db, request):
        return DeniedDecision()

    monkeypatch.setattr(brain_bridge, "_bridge_request", probing_request)
    monkeypatch.setattr(brain_bridge, "enforce", deny)
    rows = await brain_bridge.bridge_status(db_session, force=True)
    assert probed is False
    assert all(row["status"] == "policy_blocked" for row in rows)
    assert rows[0]["detail"] == "Brain status discovery is denied for this tenant."


def test_macos_claude_invocation_sends_prompt_via_stdin_not_argv() -> None:
    """The prompt must never appear in the Claude CLI argument list: process
    argument lists are visible to other local users (ps) and to crash/audit
    logs, unlike stdin. Codex and the Windows bridge already use stdin."""
    from pathlib import Path

    source = Path(__file__).resolve().parents[2].joinpath(
        "packaging", "macos", "MarcellusBrainBridge.swift"
    ).read_text(encoding="utf-8")
    start = source.index("private func invokeClaude(")
    end = source.index("private func run(", start)
    body = source[start:end]
    assert 'arguments.append(' not in body
    assert "input: governedPrompt" in body
    assert "run(executable, arguments: arguments, input: governedPrompt" in body


def test_windows_claude_invocation_sends_prompt_via_stdin_not_arguments() -> None:
    """$governedPrompt must be Invoke-Process's third (stdin) positional
    argument, never concatenated into the second (Arguments) string."""
    from pathlib import Path

    source = Path(__file__).resolve().parents[2].joinpath(
        "packaging", "windows", "BrainBridge.ps1"
    ).read_text(encoding="utf-8")
    start = source.index('$Payload.brain -eq "claude_subscription"')
    end = source.index('throw "Unknown Brain."', start)
    body = source[start:end]
    invocation_line = next(line for line in body.splitlines() if "Invoke-Process $runtime" in line)
    arguments_expr, stdin_expr = invocation_line.split("Invoke-Process $runtime", 1)[1].rsplit(")", 1)
    assert "governedPrompt" not in arguments_expr
    assert stdin_expr.strip() == "$governedPrompt"


@pytest.mark.asyncio
async def test_browser_companion_downloads_as_a_loadable_zip(client):
    """Revealing a folder only helps someone sitting at the host.

    A tester on another machine needs the bytes, so the companion is served as
    a zip that Chrome/Edge can load unpacked.
    """
    import io
    import zipfile

    response = await client.get(f"{BASE}/brains/browser-companion/download")

    # A source checkout has the extension; a stripped runtime honestly 404s.
    if response.status_code == 404:
        pytest.skip("browser-extension is not present in this runtime")

    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"
    assert "attachment;" in response.headers["content-disposition"]

    archive = zipfile.ZipFile(io.BytesIO(response.content))
    names = archive.namelist()
    # A manifest is what makes the folder loadable at all.
    assert "enkstein-browser-companion/manifest.json" in names
    assert any(name.endswith("background.js") for name in names)
    # Dotfiles and OS metadata make Chrome reject an unpacked load.
    assert not any("/." in name for name in names)
