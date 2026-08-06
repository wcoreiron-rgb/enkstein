"""A connector's control scope must be answerable and honestly bounded."""
from __future__ import annotations

import pytest

from app.services import connector_control_scope as scope_mod


def test_alias_resolves_to_the_same_collectors():
    # A tenant that configures azure_ad must get the Entra collectors, not an
    # empty scope, since the adapter registry treats them as one provider.
    assert scope_mod.evaluators_for_connector("azure_ad") == \
        scope_mod.evaluators_for_connector("entra_id")


def test_identity_provider_is_bound_to_privilege_collectors():
    keys = scope_mod.evaluators_for_connector("entra_id")
    assert "identity.privilege" in keys
    assert "identity.entra" in keys


def test_unbound_connector_reports_no_scope_rather_than_guessing():
    assert scope_mod.evaluators_for_connector("pagerduty") == []


@pytest.mark.asyncio
async def test_scope_endpoint_returns_controls_and_counts(client):
    res = await client.get("/api/v1/controls/connector-scope/entra_id")
    assert res.status_code == 200
    body = res.json()
    assert body["canonical_type"] == "entra_id"
    assert body["collectors"], "identity provider must expose collectors"
    counts = body["counts"]
    assert counts["in_scope"] == len(body["controls"])
    assert counts["in_scope"] == counts["pass"] + counts["fail"] + counts["not_assessed"]


@pytest.mark.asyncio
async def test_action_only_connector_says_why_it_assesses_nothing(client):
    res = await client.get("/api/v1/controls/connector-scope/pagerduty")
    assert res.status_code == 200
    body = res.json()
    assert body["controls"] == []
    assert body["counts"]["in_scope"] == 0
    assert body["reason"]


@pytest.mark.asyncio
async def test_catalog_lists_every_collector_bound_connector(client):
    res = await client.get("/api/v1/controls/connector-scope")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == len(body["connectors"])
    assert body["total"] > 0
    types = {item["connector_type"] for item in body["connectors"]}
    assert "entra_id" in types


def test_every_reporting_adapter_has_a_collector():
    """A connector with a working read adapter must not show an empty scope.

    An adapter that can return findings but is bound to no collector is a
    silent gap: the connector looks functional and assesses nothing. Only
    action-only connectors and non-reporting providers may be unbound.
    """
    from app.claws.adapters.registry import ACTION_ONLY, NATIVE_ADAPTERS, SPECS

    unbound = [
        connector
        for connector in set(SPECS) | set(NATIVE_ADAPTERS)
        if not scope_mod.evaluators_for_connector(connector)
        and connector not in ACTION_ONLY
        and scope_mod.non_assessing_reason(connector) == "unbound"
    ]
    assert unbound == [], f"reporting adapters without a collector: {sorted(unbound)}"


def test_every_baseline_evaluator_names_a_real_collector():
    from app.services.control_collectors import BASELINE_EVALUATORS, COLLECTORS

    missing = sorted(
        {key for key in BASELINE_EVALUATORS.values() if key not in COLLECTORS}
    )
    assert missing == [], f"evaluators naming an undefined collector: {missing}"


def test_model_providers_are_distinguished_from_unbound_connectors():
    # "No collector bound yet" implies a gap that will close. A Brain provider
    # has no security posture to assess, so it must say so instead.
    assert scope_mod.non_assessing_reason("openai") == "model_provider"
    assert scope_mod.non_assessing_reason("ollama") == "model_provider"
    assert scope_mod.non_assessing_reason("email") == "notification_channel"
    assert scope_mod.non_assessing_reason("pagerduty") == "action_only"


@pytest.mark.asyncio
async def test_model_provider_scope_explains_itself(client):
    res = await client.get("/api/v1/controls/connector-scope/openai")
    assert res.status_code == 200
    body = res.json()
    assert body["assesses_controls"] is False
    assert body["reason_code"] == "model_provider"
    assert "Model Cortex" in body["reason"]


@pytest.mark.asyncio
async def test_previously_unevaluated_nodes_now_have_collectors(client):
    """Vendor, threat, release, and recovery connectors report real scope."""
    for connector in ("servicenow", "virustotal", "tenable", "wiz", "jenkins"):
        res = await client.get(f"/api/v1/controls/connector-scope/{connector}")
        assert res.status_code == 200
        body = res.json()
        assert body["assesses_controls"] is True, connector
        assert body["collectors"], connector


@pytest.mark.asyncio
async def test_bootstrap_binds_collectors_so_a_fresh_install_is_assessable(client):
    """Installing the pack without binding leaves every control unassessable."""
    res = await client.post("/api/v1/controls/bootstrap")
    assert res.status_code == 200
    body = res.json()
    assert "evaluators_attached" in body
    assert "remediation_linked" in body
