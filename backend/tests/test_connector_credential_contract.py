"""
The Configure form and the provider adapters must agree.

Two failures motivated these tests, both reported by an operator as "the
connector says my credentials are wrong" when the credentials were fine:

  * The Okta form stored ``domain`` while the adapter read ``org_url``, so a
    correctly configured connector raised before it ever reached Okta.
  * A Microsoft connector was tested by asking for findings, so a healthy
    tenant with nothing to report was indistinguishable from a bad token.
"""
from __future__ import annotations

import importlib
import inspect
import re

import pytest

from app.api.routes.connectors import CREDENTIAL_FIELDS
from app.claws import credential_aliases
from app.claws.adapters import registry
from app.services import connector_tester


# Fields supplied by an interactive sign-in rather than typed into the form.
_SIGN_IN_FIELDS = {
    "auth_method",
    "access_token",
    "refresh_token",
    "expires_at",
    "device_provider",
}

# connector type -> module implementing a hand-written adapter.
_NATIVE = {
    "aws_security_hub": "app.claws.cloudclaw.providers.aws",
    "aws_iam": "app.claws.cloudclaw.providers.aws",
    "gcp_scc": "app.claws.cloudclaw.providers.gcp",
    "gcp_iam": "app.claws.cloudclaw.providers.gcp",
    "okta": "app.claws.accessclaw.providers.okta",
    "entra_id": "app.claws.accessclaw.providers.entra",
    "splunk": "app.claws.logclaw.providers.splunk",
    "crowdstrike": "app.claws.endpointclaw.providers.crowdstrike",
    "sentinelone": "app.claws.endpointclaw.providers.sentinelone",
    "defender_endpoint": "app.claws.endpointclaw.providers.defender",
}


def _fields_read_by(module_path: str) -> set[str]:
    module = importlib.import_module(module_path)
    src = inspect.getsource(module)
    return set(re.findall(r"credentials\[[\"'](\w+)[\"']\]", src)) | set(
        re.findall(r"credentials\.get\([\"'](\w+)[\"']", src)
    )


@pytest.mark.parametrize("connector_type,module_path", sorted(_NATIVE.items()))
def test_native_adapter_fields_are_reachable(connector_type, module_path):
    """Every field a native adapter reads is either on the form or aliased."""
    form = {f["name"] for f in CREDENTIAL_FIELDS.get(connector_type, [])}
    reachable = set(
        credential_aliases.resolve(
            connector_type, {name: "value" for name in form}
        )
    )
    unreachable = _fields_read_by(module_path) - reachable - _SIGN_IN_FIELDS
    assert not unreachable, (
        f"{connector_type} adapter reads {sorted(unreachable)}, which the "
        f"Configure form never supplies and no alias derives"
    )


@pytest.mark.parametrize("connector_type", sorted(registry.SPECS))
def test_declarative_spec_required_fields_are_on_the_form(connector_type):
    """A declarative adapter cannot require a field the operator can't enter."""
    spec = registry.SPECS[connector_type]
    form = {f["name"] for f in CREDENTIAL_FIELDS.get(connector_type, [])}
    missing = set(spec.required_fields or []) - form - _SIGN_IN_FIELDS
    assert not missing, (
        f"{connector_type} requires {sorted(missing)} but the Configure form "
        f"offers {sorted(form)}"
    )


def test_okta_domain_resolves_to_org_url():
    """The form stores a bare domain; the adapter needs a URL."""
    resolved = credential_aliases.resolve(
        "okta", {"domain": "acme.okta.com", "api_token": "t"}
    )
    assert resolved["org_url"] == "https://acme.okta.com"


def test_alias_never_overrides_an_explicit_value():
    resolved = credential_aliases.resolve(
        "okta", {"org_url": "https://explicit.example", "domain": "other.okta.com"}
    )
    assert resolved["org_url"] == "https://explicit.example"


def test_microsoft_probe_audience_matches_sign_in_scope():
    """A Graph token cannot verify an ARM connector, or the reverse."""
    from app.services import device_code_auth

    for connector_type, (_url, _label, audience) in (
        connector_tester._MICROSOFT_IDENTITY_PROBES.items()
    ):
        provider = device_code_auth.provider_for_connector(connector_type)
        if provider is None:
            continue
        expected = "arm" if "management.azure.com" in provider.scope else "graph"
        assert audience == expected, (
            f"{connector_type} signs in for {expected} but is probed as {audience}"
        )


@pytest.mark.asyncio
async def test_microsoft_connector_with_valid_token_and_no_findings_passes(monkeypatch):
    """An empty-but-healthy tenant is a connected tenant, not a bad credential."""
    import httpx

    async def _token(_creds):
        return "valid-token"

    monkeypatch.setattr(
        "app.services.device_code_auth.resolve_access_token", _token
    )

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def get(self, *_a, **_k):
            return httpx.Response(200, json={"value": []})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_k: _Client())

    result = await connector_tester.test_connector(
        "entra_id", {"auth_method": "device_code", "access_token": "valid-token"}
    )
    assert result.success is True
    assert result.verification_level == "credential"


@pytest.mark.asyncio
async def test_microsoft_connector_with_rejected_token_fails(monkeypatch):
    import httpx

    async def _token(_creds):
        return "stale-token"

    monkeypatch.setattr(
        "app.services.device_code_auth.resolve_access_token", _token
    )

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def get(self, *_a, **_k):
            return httpx.Response(401, json={"error": "invalid_token"})

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_k: _Client())

    result = await connector_tester.test_connector(
        "entra_id", {"auth_method": "device_code", "access_token": "stale"}
    )
    assert result.success is False
    assert "401" in result.message


@pytest.mark.asyncio
async def test_native_adapter_with_no_findings_is_connected(monkeypatch):
    """A provider that answers with an empty list still accepted the credential."""
    module = importlib.import_module("app.claws.accessclaw.providers.okta")

    async def _empty(_creds):
        return []

    monkeypatch.setattr(module, "fetch_findings", _empty)
    result = await connector_tester.test_connector(
        "okta", {"domain": "acme.okta.com", "api_token": "t"}
    )
    assert result.success is True
    assert "no findings" in result.message.lower()


@pytest.mark.asyncio
async def test_native_adapter_unreachable_host_is_not_a_credential_error(monkeypatch):
    """A network failure must not be reported as a rejected credential."""
    import httpx

    module = importlib.import_module("app.claws.accessclaw.providers.okta")

    async def _unreachable(_creds):
        raise httpx.ConnectError("no route to host")

    monkeypatch.setattr(module, "fetch_findings", _unreachable)
    result = await connector_tester.test_connector(
        "okta", {"domain": "acme.okta.com", "api_token": "t"}
    )
    assert result.success is False
    assert "could not be reached" in result.message
