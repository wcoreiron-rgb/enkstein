"""
Browser sign-in (OAuth authorization code + PKCE).

This is a credential path, so the tests assert the properties that keep it safe
rather than just that it produces a URL: PKCE is real, the redirect stays on
loopback, an operator-supplied host cannot rewrite the authorization URL, and a
code cannot be replayed or redeemed into a different connector.
"""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest

from app.services import browser_auth
from app.services.browser_auth import BrowserAuthError
from app.services import device_code_auth

OKTA = browser_auth.PROVIDERS["okta"]
OKTA_CREDS = {"oauth_client_id": "0oaTEST"}


def _query(url: str) -> dict:
    return {key: value[0] for key, value in parse_qs(urlparse(url).query).items()}


def test_authorization_url_uses_real_pkce():
    started = browser_auth.start_authorization(
        OKTA, connector_id="c-1", host="acme.okta.com", credentials=OKTA_CREDS
    )
    params = _query(started["authorization_url"])
    assert params["code_challenge_method"] == "S256"

    verifier = browser_auth._PENDING[started["state"]]["verifier"]
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode()
        .rstrip("=")
    )
    # A challenge that does not derive from the verifier would let an
    # intercepted code be redeemed by someone else.
    assert params["code_challenge"] == expected


def test_redirect_target_never_leaves_this_machine():
    started = browser_auth.start_authorization(
        OKTA, connector_id="c-1", host="acme.okta.com", credentials=OKTA_CREDS
    )
    redirect = urlparse(_query(started["authorization_url"])["redirect_uri"])
    assert redirect.hostname == "127.0.0.1"
    assert redirect.scheme == "http"


def test_no_client_secret_is_ever_sent():
    started = browser_auth.start_authorization(
        OKTA, connector_id="c-1", host="acme.okta.com", credentials=OKTA_CREDS
    )
    assert "client_secret" not in _query(started["authorization_url"])


@pytest.mark.parametrize(
    "host",
    ["evil.com/../x", "a.com?x=1", "a com", "", "https://x.com/y", "a.com#f"],
)
def test_operator_supplied_host_cannot_rewrite_the_authorization_url(host):
    with pytest.raises(BrowserAuthError):
        browser_auth.start_authorization(
            OKTA, connector_id="c-2", host=host, credentials=OKTA_CREDS
        )


def test_valid_host_is_used_verbatim():
    started = browser_auth.start_authorization(
        OKTA, connector_id="c-2", host="acme.okta.com", credentials=OKTA_CREDS
    )
    assert urlparse(started["authorization_url"]).hostname == "acme.okta.com"


@pytest.mark.asyncio
async def test_code_cannot_be_redeemed_into_a_different_connector():
    started = browser_auth.start_authorization(
        OKTA, connector_id="c-owner", host="acme.okta.com", credentials=OKTA_CREDS
    )
    with pytest.raises(BrowserAuthError):
        await browser_auth.complete_authorization(
            OKTA, connector_id="c-attacker", state=started["state"], code="x"
        )


@pytest.mark.asyncio
async def test_a_sign_in_request_is_single_use():
    started = browser_auth.start_authorization(
        OKTA, connector_id="c-1", host="acme.okta.com", credentials=OKTA_CREDS
    )
    try:
        await browser_auth.complete_authorization(
            OKTA, connector_id="c-1", state=started["state"], code="x"
        )
    except Exception:
        # The token exchange itself is expected to fail without a live
        # provider; what matters is that the request is consumed.
        pass
    with pytest.raises(BrowserAuthError):
        await browser_auth.complete_authorization(
            OKTA, connector_id="c-1", state=started["state"], code="x"
        )


def test_provider_without_a_public_client_says_what_is_missing():
    state = browser_auth.readiness("okta")
    assert state["supported"] is True
    assert state["ready"] is False
    assert state["requires_client_id"] is True
    # The operator must be told what to register, not shown a dead button.
    assert "127.0.0.1" in state["unavailable_reason"]


def test_salesforce_browser_signin_retains_the_instance_host_for_later_scans():
    provider = browser_auth.PROVIDERS["salesforce"]
    started = browser_auth.start_authorization(
        provider,
        connector_id="salesforce-1",
        host="acme.my.salesforce.com",
        credentials={"oauth_client_id": "salesforce-client"},
    )
    pending = browser_auth._PENDING[started["state"]]
    assert pending["host"] == "acme.my.salesforce.com"
    assert pending["host_field"] == "base_url"


def test_microsoft_is_not_offered_browser_auth():
    # The Azure CLI public client does not register a redirect URI carrying
    # our /connector-callback path, so an authorization-code attempt fails
    # with AADSTS50011 before the operator can consent. Microsoft is served
    # by the device grant instead, which needs no redirect registration.
    for connector_type in (
        "entra_id", "azure_ad", "azure", "azure_arm",
        "sentinel", "defender_endpoint", "mcas", "purview", "azure_defender",
    ):
        assert browser_auth.supports_browser_auth(connector_type) is False
        assert device_code_auth.provider_for_connector(connector_type) is not None


def test_connectors_without_an_oauth_endpoint_are_not_offered():
    # Pretending a provider supports interactive sign-in would strand the
    # operator on a screen that can never succeed.
    assert browser_auth.readiness("tenable") == {"supported": False}
    assert browser_auth.supports_browser_auth("cisa_kev") is False


def test_redirect_listener_only_records_states_this_process_started():
    browser_auth._REDIRECT_RESULTS.clear()
    assert browser_auth.take_redirect_result("not-a-real-state") is None
