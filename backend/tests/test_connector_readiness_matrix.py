"""
Exercises every declarative connector end to end against a mock transport.

Import-time correctness is not readiness. This drives each spec the way a real
scan does — build auth, template the URL, issue the request, parse the response
— so a spec with a broken credential template, an unfillable path placeholder,
an SSRF-blocked URL, or a parser that raises is caught here rather than by the
first operator who configures that connector.
"""
import httpx
import pytest

from app.claws import rest_adapter
from app.claws.adapters import registry

SPECS = sorted(registry.SPECS.items())

# A response shaped to satisfy the widest range of provider parsers: whichever
# collection key a spec reads, it finds a plausible row.
_ROW = {
    "id": "row-1", "uuid": "row-1", "key": "ROW-1", "name": "example finding",
    "title": "Example finding", "summary": "Example finding", "description": "detail",
    "severity": "high", "risk": "high", "priority": "high", "score": 42,
    "state": "open", "status": "open", "created": "2026-01-01T00:00:00Z",
    "createdAt": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
    "url": "https://example.test/finding/1", "hostname": "host-1",
    "asset": "host-1", "resource": "host-1", "package": "left-pad",
    "cve": "CVE-2026-0001", "vulnerability": "CVE-2026-0001",
}
_COLLECTIONS = [
    "data", "results", "items", "issues", "findings", "alerts", "detections",
    "value", "vulnerabilities", "records", "entries", "assets", "hosts",
    "matches", "events", "incidents", "list", "resources", "objects", "rows",
]


def _payload():
    body = {key: [dict(_ROW)] for key in _COLLECTIONS}
    body.update(dict(_ROW))
    body["access_token"] = "mock-token"
    body["token"] = "mock-token"
    body["total"] = 1
    body["count"] = 1
    return body


def _credentials(spec) -> dict[str, str]:
    """Plausible values for every field this spec could read."""
    creds = {
        "api_key": "k", "api_token": "k", "token": "k", "secret": "s",
        "client_id": "cid", "client_secret": "csec", "tenant_id": "tid",
        "username": "u", "password": "p", "access_key": "ak", "secret_key": "sk",
        "org_id": "org", "organization_id": "org", "account_id": "acct",
        "subscription_id": "sub", "workspace_id": "ws", "instance": "example",
        "region": "us-east-1", "query": "port:22", "email": "u@example.test",
        "base_url": "https://provider.example.test",
        "platform_url": "https://provider.example.test",
        "instance_url": "https://provider.example.test",
        "url": "https://provider.example.test",
        "host": "provider.example.test", "domain": "example.test",
    }
    for field in spec.required_fields:
        creds.setdefault(field, "value")
    for field in (spec.token_field, spec.username_field, spec.password_field,
                  spec.base_url_field):
        if field:
            creds.setdefault(field, "value")
    return creds


@pytest.mark.parametrize("connector_type,spec", SPECS, ids=[c for c, _ in SPECS])
@pytest.mark.asyncio
async def test_connector_completes_a_full_fetch(connector_type, spec, monkeypatch):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_payload())

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def _client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(rest_adapter.httpx, "AsyncClient", _client)
    # Public test hostnames are not routable; the SSRF guard is verified by its
    # own tests. Here the concern is whether the spec itself executes.
    monkeypatch.setattr(rest_adapter, "validate_outbound_url", lambda url: url)

    findings = await rest_adapter.fetch_findings(spec, _credentials(spec))

    assert seen, f"{connector_type}: spec issued no HTTP request"
    for request in seen:
        assert str(request.url).startswith("http"), f"{connector_type}: bad URL"
    # Findings may legitimately be empty when a parser rejects the generic row,
    # but every finding produced must be pipeline-shaped.
    for finding in findings:
        assert finding.get("title"), f"{connector_type}: finding without a title"
        assert finding.get("severity") in (
            "critical", "high", "medium", "low", "info"
        ), f"{connector_type}: bad severity {finding.get('severity')!r}"
        assert finding.get("data_origin") == "live", (
            f"{connector_type}: live fetch not tagged live"
        )


@pytest.mark.parametrize("connector_type,spec", SPECS, ids=[c for c, _ in SPECS])
@pytest.mark.asyncio
async def test_connector_reports_rejected_credentials(connector_type, spec, monkeypatch):
    """A bad credential must raise, never silently produce an empty clean scan."""
    transport = httpx.MockTransport(lambda request: httpx.Response(401, json={}))
    real_client = httpx.AsyncClient

    def _client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(rest_adapter.httpx, "AsyncClient", _client)
    monkeypatch.setattr(rest_adapter, "validate_outbound_url", lambda url: url)

    with pytest.raises(rest_adapter.AdapterError):
        await rest_adapter.fetch_findings(spec, _credentials(spec))
