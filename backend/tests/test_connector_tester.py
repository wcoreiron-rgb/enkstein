import httpx
import pytest

from app.services import connector_tester


class _Response:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


class _Client:
    response = _Response(500)

    def __init__(self, **_: object) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def get(self, *_: object, **__: object) -> _Response:
        return self.response

    async def post(self, *_: object, **__: object) -> _Response:
        return self.response


@pytest.mark.asyncio
async def test_nvidia_rejects_fake_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _Client.response = _Response(401)
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = await connector_tester.test_connector(
        "nvidia_nim",
        {"api_key": "definitely-not-a-real-key"},
    )

    assert result.success is False
    assert result.verification_level == "none"
    assert "rejected" in result.message.lower()


@pytest.mark.asyncio
async def test_nvidia_requires_authenticated_model_response(monkeypatch: pytest.MonkeyPatch) -> None:
    _Client.response = _Response(200, {"choices": [{"message": {"content": "OK"}}]})
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = await connector_tester.test_connector(
        "nvidia_nim",
        {"api_key": "valid-test-key"},
    )

    assert result.success is True
    assert result.verification_level == "credential"


@pytest.mark.asyncio
async def test_gemini_rejects_fake_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    _Client.response = _Response(403)
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = await connector_tester.test_connector("gemini", {"api_key": "fake-key"})

    assert result.success is False
    assert "rejected" in result.message.lower()


@pytest.mark.asyncio
async def test_gemini_requires_authenticated_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    _Client.response = _Response(200, {"candidates": [{"content": {"parts": [{"text": "OK"}]}}]})
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = await connector_tester.test_connector("gemini", {"api_key": "valid-test-key"})

    assert result.success is True
    assert result.verification_level == "credential"


@pytest.mark.asyncio
async def test_generic_reachability_does_not_establish_trust(monkeypatch: pytest.MonkeyPatch) -> None:
    _Client.response = _Response(200)
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = await connector_tester.test_connector(
        "unsupported_provider",
        {"api_key": "unverified"},
        endpoint="https://example.com/health",
    )

    assert result.success is True
    assert result.verification_level == "reachability"


@pytest.mark.asyncio
async def test_email_rejects_incomplete_credentials() -> None:
    result = await connector_tester.test_connector(
        "email",
        {"smtp_host": "smtp.example.com", "smtp_port": "587", "from_addr": "security@example.com", "username": "mailer@example.com"},
    )

    assert result.success is False
    assert "together" in result.message


@pytest.mark.asyncio
async def test_email_uses_dedicated_smtp_verifier(monkeypatch: pytest.MonkeyPatch) -> None:
    async def verified(_: dict) -> connector_tester.TestResult:
        return connector_tester.TestResult(True, "SMTP verified", verification_level="credential")

    monkeypatch.setitem(connector_tester.TEST_MAP, "email", verified)
    result = await connector_tester.test_connector(
        "email",
        {
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "from_addr": "security@example.com",
            "username": "mailer@example.com",
            "password": "app-password",
        },
    )

    assert result.success is True
    assert result.verification_level == "credential"
