"""
Tests for shared Claw scan execution.

The behaviours that matter to a beta tenant:

  * configuring a connector must not blank a module that has no live adapter
  * a configured adapter is actually called, and its output is tagged live
  * a failing connector keeps demonstration data rather than showing nothing
  * demonstration fallback is always labelled simulated
"""
import pytest

from app.services.claw_scan import _prepare, has_live_adapter, run_claw_scan


class _Adapter:
    """Minimal stand-in for a provider module exposing get_findings."""

    def __init__(self, findings=None, error=None):
        self.findings = findings or []
        self.error = error
        self.called_with = None

    async def get_findings(self, credentials=None):
        self.called_with = credentials
        if self.error:
            raise self.error
        return list(self.findings)


DEMO = [{"title": "Demo finding", "severity": "HIGH", "risk_score": 60.0}]


def test_has_live_adapter_detects_adapter_backed_providers():
    assert has_live_adapter([{"provider": "okta", "adapter": _Adapter()}]) is True
    assert has_live_adapter([{"provider": "okta"}]) is False
    assert has_live_adapter([]) is False


def test_prepare_labels_and_normalises_demo_findings():
    prepared = _prepare(DEMO, claw="accessclaw", provider=None, origin="simulated")
    assert prepared[0]["claw"] == "accessclaw"
    assert prepared[0]["severity"] == "high"
    assert prepared[0]["data_origin"] == "simulated"
    assert "source_connector" not in prepared[0]


def test_prepare_does_not_overwrite_an_adapter_supplied_origin():
    prepared = _prepare(
        [{"title": "Real", "data_origin": "live", "source_connector": "okta"}],
        claw="accessclaw",
        provider="okta",
        origin="simulated",
        connector="okta",
    )
    assert prepared[0]["data_origin"] == "live"
    assert prepared[0]["source_connector"] == "okta"


def test_prepare_never_attaches_a_connector_to_simulated_data():
    prepared = _prepare(
        DEMO, claw="accessclaw", provider="okta", origin="simulated", connector="okta"
    )
    assert "source_connector" not in prepared[0]


@pytest.mark.asyncio
async def test_scan_without_connectors_falls_back_to_labelled_demo_data(db_session):
    result = await run_claw_scan(
        db_session,
        claw="accessclaw",
        provider_config=[{"provider": "okta", "connector_type": "okta", "adapter": _Adapter()}],
        demo_findings=DEMO,
        tenant_id="tenant-test",
    )
    assert result["mode"] == "simulated"
    assert result["providers"]["okta"]["status"] == "not_configured"
    assert result["findings_created"] >= 1


@pytest.mark.asyncio
async def test_configured_adapter_output_is_ingested_as_live(db_session, monkeypatch):
    adapter = _Adapter([{"title": "Okta admin without MFA", "severity": "critical"}])
    monkeypatch.setattr(
        "app.services.claw_scan.resolve_credentials",
        _fake_credentials,
    )
    result = await run_claw_scan(
        db_session,
        claw="accessclaw",
        provider_config=[{"provider": "okta", "connector_type": "okta", "adapter": adapter}],
        demo_findings=DEMO,
        tenant_id="tenant-test",
    )
    assert adapter.called_with == {"token": "x"}
    assert result["mode"] == "live"
    assert result["providers"]["okta"] == {"status": "success", "findings": 1}


@pytest.mark.asyncio
async def test_failing_connector_keeps_demonstration_data(db_session, monkeypatch):
    adapter = _Adapter(error=RuntimeError("upstream 503"))
    monkeypatch.setattr(
        "app.services.claw_scan.resolve_credentials",
        _fake_credentials,
    )
    result = await run_claw_scan(
        db_session,
        claw="accessclaw",
        provider_config=[{"provider": "okta", "connector_type": "okta", "adapter": adapter}],
        demo_findings=DEMO,
        tenant_id="tenant-test",
    )
    assert result["mode"] == "simulated"
    assert result["providers"]["okta"]["status"] == "error"
    assert result["providers"]["okta"]["error"] == "RuntimeError"


@pytest.mark.asyncio
async def test_configured_provider_without_adapter_is_reported_honestly(
    db_session, monkeypatch
):
    monkeypatch.setattr(
        "app.services.claw_scan.resolve_credentials",
        _fake_credentials,
    )
    # A deliberately unsupported provider exercises the honest
    # "configured but inert" path rather than a provider that can actually scan.
    result = await run_claw_scan(
        db_session,
        claw="appclaw",
        provider_config=[{"provider": "unsupported", "connector_type": "unsupported_test_provider"}],
        demo_findings=DEMO,
        tenant_id="tenant-test",
    )
    assert result["mode"] == "simulated"
    assert result["providers"]["unsupported"]["status"] == "no_adapter"
    assert "no live adapter is available yet" in result["message"]


async def _fake_credentials(db, connector_type, *, tenant_id):
    return {"token": "x"}


class _MaskingAdapter:
    """
    A bespoke provider module in its original shape: ``get_findings`` catches
    its own failures and returns demonstration data so a standalone page is
    never blank, while ``fetch_findings`` is the authenticated path that lets
    the failure surface.
    """

    def __init__(self, error):
        self.error = error
        self.masked_path_used = False

    async def fetch_findings(self, credentials):
        raise self.error

    async def get_findings(self, credentials=None):
        self.masked_path_used = True
        return list(DEMO)


@pytest.mark.asyncio
async def test_provider_failure_is_not_reported_as_a_successful_scan(
    db_session, monkeypatch
):
    """
    The failure mode this guards against: an operator configures a credential,
    the vendor call fails, the adapter quietly substitutes demonstration
    findings, and the scan reports success. The operator then reads demo data
    as their own estate. A provider that failed must say so.
    """
    monkeypatch.setattr(
        "app.services.claw_scan.resolve_credentials", _fake_credentials
    )
    adapter = _MaskingAdapter(RuntimeError("vendor 500"))

    result = await run_claw_scan(
        db_session,
        claw="endpointclaw",
        provider_config=[
            {"provider": "crowdstrike", "connector_type": "crowdstrike", "adapter": adapter}
        ],
        demo_findings=DEMO,
        tenant_id="tenant-test",
    )

    assert adapter.masked_path_used is False, (
        "a configured provider must use the authenticated path that raises"
    )
    assert result["providers"]["crowdstrike"]["status"] == "error"
    assert result["providers"]["crowdstrike"]["error"] == "RuntimeError"
    # Demonstration data still populates the module, but it is labelled.
    assert result["mode"] == "simulated"


@pytest.mark.asyncio
async def test_authenticated_path_output_is_used_when_the_provider_succeeds(
    db_session, monkeypatch
):
    monkeypatch.setattr(
        "app.services.claw_scan.resolve_credentials", _fake_credentials
    )

    class _Working(_MaskingAdapter):
        async def fetch_findings(self, credentials):
            return [{"title": "Live detection", "severity": "HIGH", "risk_score": 80.0}]

    adapter = _Working(RuntimeError("unused"))
    result = await run_claw_scan(
        db_session,
        claw="endpointclaw",
        provider_config=[
            {"provider": "crowdstrike", "connector_type": "crowdstrike", "adapter": adapter}
        ],
        demo_findings=DEMO,
        tenant_id="tenant-test",
    )

    assert adapter.masked_path_used is False
    assert result["mode"] == "live"
    assert result["providers"]["crowdstrike"]["status"] == "success"
