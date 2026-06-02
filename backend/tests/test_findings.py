"""
Tests for Finding endpoints and CloudClaw scan integration.

Endpoints under test:
  GET  /api/v1/findings                  — list findings (filterable)
  POST /api/v1/cloudclaw/scan            — trigger CloudClaw scan
  GET  /api/v1/findings?claw=cloudclaw   — filter findings by claw
"""
import pytest
import asyncio


FINDINGS_BASE  = "/api/v1/findings"
CLOUDCLAW_SCAN = "/api/v1/cloudclaw/scan"


@pytest.mark.asyncio
async def test_list_findings_empty(client):
    """GET /api/v1/findings on an empty DB should return an empty list."""
    resp = await client.get(FINDINGS_BASE)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    # The endpoint may return a list or a dict with a 'findings' key
    if isinstance(data, list):
        assert data == []
    elif isinstance(data, dict):
        items = data.get("findings", data.get("items", data.get("results", [])))
        assert isinstance(items, list)
        assert len(items) == 0


@pytest.mark.asyncio
async def test_cloudclaw_scan_returns_findings(client):
    """
    POST /api/v1/cloudclaw/scan should trigger a scan and return a result dict.
    In the test environment no real connectors are configured so we accept
    a scan that returns 0 new findings — we just assert the response shape.
    """
    resp = await client.post(CLOUDCLAW_SCAN)
    # Scan may return 200 OK or 202 Accepted
    assert resp.status_code in (200, 201, 202), resp.text
    data = resp.json()
    # Should include some indication of scan results
    assert isinstance(data, dict), "Scan response should be a JSON object"
    # Accept any of these common response keys
    has_result_key = any(k in data for k in (
        "message", "findings", "total_created", "status",
        "scan_id", "results", "summary",
    ))
    assert has_result_key, f"Unexpected scan response shape: {data}"


@pytest.mark.asyncio
async def test_findings_by_claw(client):
    """GET /api/v1/findings?claw=cloudclaw should accept the filter without error."""
    resp = await client.get(FINDINGS_BASE, params={"claw": "cloudclaw"})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    if isinstance(data, list):
        # Every returned finding should belong to cloudclaw
        for finding in data:
            if "claw" in finding:
                assert finding["claw"].lower() == "cloudclaw"
    elif isinstance(data, dict):
        items = data.get("findings", data.get("items", []))
        for finding in items:
            if "claw" in finding:
                assert finding["claw"].lower() == "cloudclaw"


@pytest.mark.asyncio
async def test_findings_filter_by_severity(client):
    """GET /api/v1/findings with severity filter should not error."""
    resp = await client.get(FINDINGS_BASE, params={"severity": "high"})
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_findings_support_recent_sort_for_last_run_visibility(client):
    older = await client.post(
        FINDINGS_BASE,
        json={
            "claw": "legacyclaw",
            "provider": "seed",
            "title": "Older critical backlog finding",
            "severity": "critical",
            "risk_score": 99,
        },
    )
    assert older.status_code == 201, older.text
    await asyncio.sleep(0.01)
    newer = await client.post(
        FINDINGS_BASE,
        json={
            "claw": "devclaw",
            "provider": "github",
            "title": "Latest GitHub run finding",
            "severity": "medium",
            "risk_score": 45,
        },
    )
    assert newer.status_code == 201, newer.text

    recent = await client.get(FINDINGS_BASE, params={"sort": "recent", "limit": "2"})
    assert recent.status_code == 200, recent.text
    recent_rows = recent.json()
    assert recent_rows[0]["title"] == "Latest GitHub run finding"

    risk = await client.get(FINDINGS_BASE, params={"sort": "risk", "limit": "2"})
    assert risk.status_code == 200, risk.text
    risk_rows = risk.json()
    assert risk_rows[0]["title"] == "Older critical backlog finding"


@pytest.mark.asyncio
async def test_findings_invalid_severity_returns_400(client):
    """GET /api/v1/findings with an invalid severity should be a client error, not a 500."""
    resp = await client.get(FINDINGS_BASE, params={"severity": "notreal"})
    assert resp.status_code == 400, resp.text
    assert "Invalid severity" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_update_finding_invalid_id_returns_400(client):
    """PATCH /api/v1/findings/{id} with a malformed UUID should not crash."""
    resp = await client.patch(f"{FINDINGS_BASE}/not-a-uuid", json={"status": "open"})
    assert resp.status_code == 400, resp.text
    assert resp.json()["detail"] == "Invalid finding id"
