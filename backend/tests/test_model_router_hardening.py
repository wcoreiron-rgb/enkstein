import types

import pytest
from fastapi import HTTPException

import app.api.routes.model_router as model_router_api
from app.services import model_router


@pytest.mark.asyncio
async def test_model_router_output_rescan_redacts_sensitive_response(monkeypatch):
    async def fake_backend(prompt: str, model: str = "", **_):
        return {
            "provider": model_router.Provider.MOCK,
            "model": model or "mock-v1",
            "response": "Here is token=abcd1234secretvalue and password=supersecret123",
            "usage": {},
            "latency_ms": 1,
        }

    monkeypatch.setitem(
        model_router._PROVIDER_BACKENDS,  # noqa: SLF001 - targeted hardening test
        model_router.Provider.MOCK,
        fake_backend,
    )

    routed = await model_router.route_and_call(
        prompt="summarize",
        provider_override=model_router.Provider.MOCK,
        model_override="mock-v1",
        caller="test",
        override_reason="unit-test",
    )

    assert routed["output_scan"]["is_sensitive"] is True
    assert routed["output_scan"]["redacted"] is True
    assert "[REDACTED]" in routed["response"]
    assert routed["routing"]["override_used"] is True
    assert routed["routing"]["override_reason"] == "unit-test"

    audit = model_router.get_routing_audit(limit=1)[0]
    assert audit["output_sensitive"] is True
    assert audit["override_used"] is True
    assert audit["override_reason"] == "unit-test"


def test_model_route_rate_limit_blocks_after_threshold(monkeypatch):
    monkeypatch.setattr(model_router_api, "_MODEL_ROUTE_MAX", 2)
    monkeypatch.setattr(model_router_api, "_MODEL_ROUTE_WINDOW", 60)
    model_router_api._model_route_store.clear()  # noqa: SLF001 - test setup

    request = types.SimpleNamespace(client=types.SimpleNamespace(host="127.0.0.1"))
    model_router_api._model_route_rate_limit(request)
    model_router_api._model_route_rate_limit(request)
    with pytest.raises(HTTPException) as exc:
        model_router_api._model_route_rate_limit(request)
    assert exc.value.status_code == 429
