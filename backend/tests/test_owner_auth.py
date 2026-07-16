import time

import pytest

from app.api.routes import auth as auth_routes
from app.core.security import decode_access_token, hash_password
from app.services import owner_auth


class FakeRedis:
    def __init__(self):
        self.values = {}

    async def set(self, key, value, ex=None, keepttl=False, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def get(self, key):
        return self.values.get(key)

    async def getdel(self, key):
        return self.values.pop(key, None)

    async def aclose(self):
        return None


def test_totp_accepts_current_window_and_rejects_bad_code() -> None:
    secret = owner_auth.generate_totp_secret()
    now = 1_750_000_000.0
    counter = int(now // owner_auth.TOTP_PERIOD_SECONDS)
    code = owner_auth._totp_at(secret, counter)

    assert owner_auth.verify_totp(secret, code, now=now) == counter
    assert owner_auth.verify_totp(secret, "000000", now=now) is None
    assert "issuer=Enkstein" in owner_auth.enrollment_uri("owner", secret)


@pytest.mark.asyncio
async def test_first_run_setup_issues_mfa_owner_and_recovery_codes(client, monkeypatch) -> None:
    redis = FakeRedis()
    persisted = {}

    async def fake_redis():
        return redis

    monkeypatch.setattr(auth_routes, "_redis_client", fake_redis)
    monkeypatch.setattr(owner_auth, "owner_is_configured", lambda: bool(persisted))
    monkeypatch.setattr(
        owner_auth,
        "persist_owner_hash",
        lambda username, password_hash, totp_secret: persisted.update(
            username=username, password_hash=password_hash, totp_secret=totp_secret
        ) or ["ABCD-1234"] * 10,
    )

    started = await client.post(
        "/api/v1/auth/owner/setup",
        json={"username": "owner", "password": "a-strong-local-password"},
    )
    assert started.status_code == 200, started.text
    enrollment = started.json()
    counter = int(time.time() // owner_auth.TOTP_PERIOD_SECONDS)
    code = owner_auth._totp_at(enrollment["secret"], counter)

    confirmed = await client.post(
        "/api/v1/auth/owner/setup/confirm",
        json={"enrollment_token": enrollment["enrollment_token"], "code": code},
    )
    assert confirmed.status_code == 200, confirmed.text
    assert len(confirmed.json()["recovery_codes"]) == 10
    claims = decode_access_token(confirmed.json()["access_token"])
    assert claims["role"] == "admin"
    assert claims["mfa_verified"] is True


@pytest.mark.asyncio
async def test_totp_login_blocks_code_replay(client, monkeypatch) -> None:
    redis = FakeRedis()
    secret = owner_auth.generate_totp_secret()
    owner = {
        "username": "owner",
        "password_hash": hash_password("a-strong-local-password"),
        "totp_secret": secret,
        "recovery_hashes": "[]",
    }

    async def fake_redis():
        return redis

    monkeypatch.setattr(auth_routes, "_redis_client", fake_redis)
    monkeypatch.setattr(owner_auth, "get_owner", lambda: owner)
    code = owner_auth._totp_at(secret, int(time.time() // owner_auth.TOTP_PERIOD_SECONDS))
    payload = {"username": "owner", "password": "a-strong-local-password", "code": code}

    first = await client.post("/api/v1/auth/owner/login", json=payload)
    replay = await client.post("/api/v1/auth/owner/login", json=payload)

    assert first.status_code == 200, first.text
    assert replay.status_code == 401
    assert "already used" in replay.json()["detail"]


@pytest.mark.asyncio
async def test_configured_owner_disables_legacy_password_only_login(client, monkeypatch) -> None:
    monkeypatch.setattr(owner_auth, "get_owner", lambda: {
        "username": "owner",
        "password_hash": hash_password("a-strong-local-password"),
        "totp_secret": owner_auth.generate_totp_secret(),
        "recovery_hashes": "[]",
    })

    response = await client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "regentclaw-admin"},
    )

    assert response.status_code == 428
    assert "Authenticator" in response.json()["detail"]
