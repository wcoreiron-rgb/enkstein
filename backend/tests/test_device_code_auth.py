"""
Tests for OAuth device-code connector sign-in.

The behaviours that matter:

  * only providers that genuinely publish a device endpoint are offered
  * a pending approval is not mistaken for a failure
  * refusal, expiry, and denial produce clear errors rather than silent success
  * expired access tokens refresh transparently
  * non-device credentials are left entirely alone
"""
import time

import pytest

from app.services import device_code_auth as dca


def test_microsoft_connectors_are_device_code_capable():
    assert dca.supports_device_code("entra_id") is True
    assert dca.supports_device_code("azure") is True
    assert dca.provider_for_connector("entra_id").label == "Microsoft Entra ID"


def test_providers_without_a_device_endpoint_are_not_offered():
    assert dca.supports_device_code("okta") is False
    assert dca.supports_device_code("splunk") is False
    assert dca.provider_for_connector("splunk") is None


def test_github_is_disabled_until_an_oauth_client_id_is_configured():
    # GitHub has no first-party public client, so the flow must stay off
    # rather than sending an operator to a page that cannot succeed.
    github = dca.PROVIDERS["github"]
    assert dca.provider_for_connector("github") is github
    if not github.client_id:
        assert dca.supports_device_code("github") is False


def test_pending_and_slow_down_are_not_treated_as_errors(monkeypatch):
    assert "authorization_pending" in dca._PENDING
    assert "slow_down" in dca._PENDING


def test_is_expired_respects_skew():
    assert dca.is_expired({"expires_at": str(time.time() - 10)}) is True
    assert dca.is_expired({"expires_at": str(time.time() + 3600)}) is False
    # No expiry recorded means the caller cannot conclude it is stale.
    assert dca.is_expired({}) is False
    assert dca.is_expired({"expires_at": "not-a-number"}) is False


def test_is_device_code_only_matches_interactive_credentials():
    assert dca.is_device_code({"auth_method": "device_code", "access_token": "t"}) is True
    assert dca.is_device_code({"auth_method": "device_code"}) is False
    assert dca.is_device_code({"client_secret": "s"}) is False


@pytest.mark.asyncio
async def test_resolve_ignores_client_credential_connectors():
    # Client-credential adapters must fall through to their own token flow.
    assert await dca.resolve_access_token({"client_id": "a", "client_secret": "b"}) is None


@pytest.mark.asyncio
async def test_resolve_returns_a_valid_token_without_refreshing(monkeypatch):
    async def _fail(_):
        raise AssertionError("should not refresh a valid token")

    monkeypatch.setattr(dca, "refresh_access_token", _fail)
    creds = {
        "auth_method": "device_code",
        "access_token": "good",
        "expires_at": str(time.time() + 3600),
    }
    assert await dca.resolve_access_token(creds) == "good"


@pytest.mark.asyncio
async def test_resolve_refreshes_an_expired_token(monkeypatch):
    async def _refresh(credentials):
        return {**credentials, "access_token": "fresh", "expires_at": str(time.time() + 3600)}

    monkeypatch.setattr(dca, "refresh_access_token", _refresh)
    creds = {
        "auth_method": "device_code",
        "device_provider": "microsoft_graph",
        "access_token": "stale",
        "refresh_token": "r",
        "expires_at": str(time.time() - 5),
    }
    assert await dca.resolve_access_token(creds) == "fresh"
    # The caller's dict is updated so one scan does not refresh twice.
    assert creds["access_token"] == "fresh"


@pytest.mark.asyncio
async def test_resolve_returns_none_when_the_grant_cannot_be_renewed(monkeypatch):
    async def _refresh(_):
        return None

    monkeypatch.setattr(dca, "refresh_access_token", _refresh)
    creds = {
        "auth_method": "device_code",
        "access_token": "stale",
        "expires_at": str(time.time() - 5),
    }
    assert await dca.resolve_access_token(creds) is None


@pytest.mark.asyncio
async def test_start_requires_a_client_id():
    provider = dca.DeviceCodeProvider(
        key="x", label="Example", device_endpoint="https://e/d",
        token_endpoint="https://e/t", client_id="", scope="s",
        connector_types=("x",),
    )
    with pytest.raises(dca.DeviceCodeError):
        await dca.start_device_authorization(provider)


def test_tenant_placeholder_defaults_to_organizations():
    url = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    assert dca._resolve(url, None).endswith("/organizations/oauth2/v2.0/token")
    assert "/my-tenant/" in dca._resolve(url, "my-tenant")


def test_microsoft_scopes_request_a_refresh_token():
    # Without offline_access the grant expires in about an hour and every
    # scheduled scan would silently stop working.
    for key in ("microsoft_graph", "azure_management"):
        assert "offline_access" in dca.PROVIDERS[key].scope
