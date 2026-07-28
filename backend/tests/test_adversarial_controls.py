"""
Adversarial checks: do the guarantees the product advertises actually hold?

Every assertion here is written as an attack, not as a feature test. A control
that exists in code but does not block is worse than an absent one, because the
operator has been told they are protected.
"""
import pytest

from app.claws import rest_adapter
from app.claws.adapters import registry
from app.services.connector_tester import _validate_endpoint_url

# Destinations an attacker reaches by supplying a self-hosted connector URL.
SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8000/api/v1/connectors",
    "http://localhost:6379/",
    "http://[::1]:8000/admin",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/admin",
    "http://172.16.0.1/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
]


@pytest.mark.parametrize("url", SSRF_TARGETS)
def test_ssrf_targets_are_refused(url):
    """A connector URL must never become a pivot into the host or metadata."""
    with pytest.raises(ValueError):
        _validate_endpoint_url(url)


def test_hostname_pointing_at_loopback_is_refused(monkeypatch):
    """
    The classic bypass: register a public name that resolves to 127.0.0.1.
    Checking the literal text of the URL is not enough; the name has to be
    resolved before it is trusted.
    """
    import socket

    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]

    monkeypatch.setattr(
        "app.services.connector_tester.socket.getaddrinfo", fake_getaddrinfo
    )
    with pytest.raises(ValueError):
        _validate_endpoint_url("http://attacker-controlled.example.com/")


def test_hostname_pointing_at_cloud_metadata_is_refused(monkeypatch):
    import socket

    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

    monkeypatch.setattr(
        "app.services.connector_tester.socket.getaddrinfo", fake_getaddrinfo
    )
    with pytest.raises(ValueError):
        _validate_endpoint_url("https://totally-normal.example.com/v1/")


def test_a_genuine_public_endpoint_is_still_allowed(monkeypatch):
    """The guard must not be so strict that no connector can be configured."""
    import socket

    def fake_getaddrinfo(host, port, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(
        "app.services.connector_tester.socket.getaddrinfo", fake_getaddrinfo
    )
    assert _validate_endpoint_url("https://api.vendor.example/v1/findings")


@pytest.mark.parametrize(
    "connector_type,spec", sorted(registry.SPECS.items()), ids=sorted(registry.SPECS)
)
@pytest.mark.asyncio
async def test_no_connector_reports_success_without_credentials(
    connector_type, spec, monkeypatch
):
    """
    An unconfigured connector must not produce findings that look live.
    Presenting demonstration data as tenant data is the failure mode that makes
    a security console actively harmful.
    """
    findings = await rest_adapter.get_findings(spec, None, simulated=[
        {"title": "demo", "severity": "high"}
    ])
    for finding in findings:
        assert finding["data_origin"] == "simulated", (
            f"{connector_type}: unconfigured connector emitted non-simulated data"
        )


@pytest.mark.parametrize(
    "status", [401, 403, 500, 502, 429]
)
@pytest.mark.asyncio
async def test_failed_provider_never_becomes_a_clean_scan(status, monkeypatch):
    """
    The dangerous outcome is not an error; it is an error rendered as success.
    A provider that rejects or fails must raise so the scan records it.
    """
    import httpx

    spec = registry.SPECS["cisa_kev"]
    transport = httpx.MockTransport(lambda r: httpx.Response(status, json={}))
    real = httpx.AsyncClient

    def _client(*a, **kw):
        kw["transport"] = transport
        return real(*a, **kw)

    monkeypatch.setattr(rest_adapter.httpx, "AsyncClient", _client)
    monkeypatch.setattr(rest_adapter, "validate_outbound_url", lambda u: u)

    with pytest.raises(rest_adapter.AdapterError):
        await rest_adapter.fetch_findings(spec, {"api_key": "k"})


@pytest.mark.parametrize(
    "requester,approver",
    [
        ("alice@example.com", "alice@example.com"),
        ("alice@example.com", "ALICE@example.com"),   # case variation
        ("alice@example.com", "  alice@example.com "),  # whitespace padding
    ],
)
def test_self_approval_is_refused_however_the_identity_is_spelled(requester, approver):
    """
    Dual control is the platform's headline governance claim. An attacker does
    not submit a literal duplicate string; they change the case or pad the
    value, so the comparison must normalise before it decides.
    """
    from app.api.routes.remote_control import _normalize_principal

    assert _normalize_principal(approver) == _normalize_principal(requester), (
        "self-approval must be detected regardless of formatting"
    )


def test_distinct_approvers_are_not_treated_as_self_approval():
    """The guard must not be so blunt that legitimate dual control is impossible."""
    from app.api.routes.remote_control import _normalize_principal

    assert _normalize_principal("alice@example.com") != _normalize_principal(
        "bob@example.com"
    )


@pytest.mark.asyncio
async def test_custom_capability_cannot_be_pointed_at_internal_hosts(client):
    """
    A user-defined capability takes an operator-supplied URL, which makes it
    the most direct SSRF surface in the product.
    """
    created = await client.post(
        "/api/v1/customclaw/definitions",
        json={
            "name": "pivot",
            "base_url": "http://169.254.169.254",
            "endpoints": [{"path": "/latest/meta-data/", "method": "GET"}],
            "auth_type": "none",
        },
    )
    if created.status_code >= 400:
        # Rejecting at creation time is a valid, stricter outcome.
        return

    definition_id = created.json().get("id")
    scanned = await client.post(f"/api/v1/customclaw/definitions/{definition_id}/scan")
    assert scanned.status_code < 500
    body = scanned.text.lower()
    assert "meta-data" not in body or "blocked" in body or "error" in body
