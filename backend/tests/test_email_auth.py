import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.api.routes import auth as auth_routes
from app.core.deps import get_current_user
from app.core.security import create_access_token, decode_access_token


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.counts = {}

    async def ping(self):
        return True

    async def incr(self, key):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key, ttl):
        return True

    async def set(self, key, value, ex=None, keepttl=False, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def get(self, key):
        return self.values.get(key)

    async def getdel(self, key):
        return self.values.pop(key, None)

    async def delete(self, key):
        self.values.pop(key, None)
        return 1

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_email_code_proves_mailbox_and_is_single_use(client, monkeypatch):
    redis = FakeRedis()
    delivered = []

    async def _redis():
        return redis

    async def _config(db):
        return {
            "smtp_host": "smtp.test",
            "smtp_port": 587,
            "username": "mailer",
            "password": "secret",
            "from_addr": "security@test.invalid",
        }

    async def _send(**kwargs):
        delivered.append(kwargs)
        return True

    monkeypatch.setattr(auth_routes, "_redis_client", _redis)
    monkeypatch.setattr(auth_routes, "_email_config", _config)
    monkeypatch.setattr(auth_routes, "send_email", _send)
    monkeypatch.setattr(auth_routes.secrets, "randbelow", lambda maximum: 123456)

    requested = await client.post("/api/v1/auth/email/request", json={"email": "User@Example.com"})
    assert requested.status_code == 202, requested.text
    assert requested.json()["accepted"] is True
    assert delivered[0]["to_addrs"] == ["user@example.com"]
    assert "123456" in delivered[0]["body"]

    verified = await client.post(
        "/api/v1/auth/email/verify",
        json={"email": "user@example.com", "code": "123456"},
    )
    assert verified.status_code == 200, verified.text
    claims = decode_access_token(verified.json()["access_token"])
    assert claims["email"] == "user@example.com"
    assert claims["email_verified"] is True
    assert claims["role"] == "viewer"

    replay = await client.post(
        "/api/v1/auth/email/verify",
        json={"email": "user@example.com", "code": "123456"},
    )
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_email_request_fails_closed_without_delivery(client, monkeypatch):
    async def _config(db):
        return None

    monkeypatch.setattr(auth_routes, "_email_config", _config)
    response = await client.post("/api/v1/auth/email/request", json={"email": "user@example.com"})
    assert response.status_code == 503
    assert "Email connector" in response.json()["detail"]


@pytest.mark.asyncio
async def test_verified_email_viewer_is_read_only():
    token = create_access_token({
        "sub": "email:test",
        "role": "viewer",
        "email": "user@example.com",
        "email_verified": True,
    })
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/connectors",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1234),
        "scheme": "http",
    })
    with pytest.raises(HTTPException) as error:
        await get_current_user(request)
    assert error.value.status_code == 403


@pytest.mark.asyncio
async def test_verified_email_viewer_can_read():
    token = create_access_token({"sub": "email:test", "role": "viewer", "email": "user@example.com"})
    request = Request({
        "type": "http",
        "method": "GET",
        "path": "/api/v1/findings",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
        "query_string": b"",
        "server": ("test", 80),
        "client": ("127.0.0.1", 1234),
        "scheme": "http",
    })
    user = await get_current_user(request)
    assert user["role"] == "viewer"
