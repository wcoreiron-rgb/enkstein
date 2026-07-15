from __future__ import annotations

import httpx
import pytest

from app.claws.arcclaw import llm_proxy


class _Response:
    status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {
            "candidates": [{"content": {"parts": [{"text": "Governed Gemini response"}]}}],
            "usageMetadata": {"totalTokenCount": 17},
        }


class _Client:
    captured = {}

    def __init__(self, **_: object) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def post(self, url: str, **kwargs: object) -> _Response:
        self.captured["url"] = url
        self.captured.update(kwargs)
        return _Response()


@pytest.mark.asyncio
async def test_gemini_provider_uses_supported_generate_content_api(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = await llm_proxy.call_llm(
        "gemini",
        "Review this architecture",
        model="gemini-2.5-flash",
        api_key="test-key",
    )

    assert result.success is True
    assert result.content == "Governed Gemini response"
    assert result.tokens_used == 17
    assert _Client.captured["url"].endswith("/models/gemini-2.5-flash:generateContent")
    assert _Client.captured["headers"]["x-goog-api-key"] == "test-key"
    assert "test-key" not in str(_Client.captured["json"])

