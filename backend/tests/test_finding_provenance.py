"""
Tests for finding data-origin provenance.

A beta tenant typically has one or two live connectors configured while the
rest of the platform still emits realistic demonstration findings.  The origin
marker is what lets an operator tell those apart, so the rules that matter are:

  * an adapter that says nothing is never presented as live
  * a simulated provider is labelled simulated
  * an authenticated provider is labelled live and names its connector
  * a simulated finding later confirmed against live data records the change
"""
import pytest

from app.claws import provenance
from app.services.finding_pipeline import _build_finding, _update_finding

FINDINGS_BASE = "/api/v1/findings"


def _payload(**overrides):
    base = {
        "claw": "cloudclaw",
        "provider": "aws",
        "title": "Public S3 bucket",
        "severity": "high",
        "risk_score": 70.0,
    }
    base.update(overrides)
    return base


def test_untagged_adapter_is_not_presented_as_live():
    finding = _build_finding("cloudclaw", _payload(), tenant_id="tenant-test")
    assert finding.data_origin == "unknown"
    assert finding.source_connector is None


def test_unrecognised_origin_falls_back_to_unknown():
    finding = _build_finding("cloudclaw", _payload(data_origin="verified"), tenant_id="tenant-test")
    assert finding.data_origin == "unknown"


def test_simulated_provider_output_is_labelled_simulated():
    tagged = provenance.simulated([{"title": "Demo"}], provider="aws")
    assert tagged[0]["data_origin"] == provenance.SIMULATED
    assert "source_connector" not in tagged[0]

    finding = _build_finding("cloudclaw", _payload(**tagged[0]), tenant_id="tenant-test")
    assert finding.data_origin == "simulated"


def test_live_provider_output_names_its_connector():
    tagged = provenance.live(
        [{"title": "Real"}], provider="aws", connector="aws_security_hub"
    )
    assert tagged[0]["data_origin"] == provenance.LIVE
    assert tagged[0]["source_connector"] == "aws_security_hub"

    finding = _build_finding("cloudclaw", _payload(**tagged[0]), tenant_id="tenant-test")
    assert finding.data_origin == "live"
    assert finding.source_connector == "aws_security_hub"


def test_live_tag_defaults_connector_to_provider_name():
    tagged = provenance.live([{"title": "Real"}], provider="okta")
    assert tagged[0]["source_connector"] == "okta"


def test_origin_transition_to_live_is_recorded():
    existing = _build_finding("cloudclaw", _payload(data_origin="simulated"), tenant_id="tenant-test")
    changes = _update_finding(
        existing,
        _payload(data_origin="live", source_connector="aws_security_hub"),
    )
    assert changes["data_origin_changed"] == {"from": "simulated", "to": "live"}
    assert existing.data_origin == "live"
    assert existing.source_connector == "aws_security_hub"


def test_untagged_rescan_does_not_downgrade_a_live_finding():
    existing = _build_finding(
        "cloudclaw", _payload(data_origin="live", source_connector="aws_security_hub"), tenant_id="tenant-test"
    )
    changes = _update_finding(existing, _payload())
    assert "data_origin_changed" not in changes
    assert existing.data_origin == "live"


def test_source_connector_is_truncated_to_column_width():
    finding = _build_finding(
        "cloudclaw", _payload(data_origin="live", source_connector="x" * 200), tenant_id="tenant-test"
    )
    assert len(finding.source_connector) == 64


@pytest.mark.asyncio
async def test_findings_reject_unknown_data_origin_filter(client):
    resp = await client.get(f"{FINDINGS_BASE}?data_origin=totally_real")
    assert resp.status_code == 400, resp.text
    assert "data_origin" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_findings_accept_valid_data_origin_filter(client):
    for origin in ("live", "simulated", "unknown"):
        resp = await client.get(f"{FINDINGS_BASE}?data_origin={origin}")
        assert resp.status_code == 200, resp.text
        assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_findings_stats_expose_origin_breakdown(client):
    resp = await client.get(f"{FINDINGS_BASE}/stats")
    assert resp.status_code == 200, resp.text
    by_origin = resp.json()["by_origin"]
    assert set(by_origin) == {"live", "simulated", "unknown"}
