"""
Marketplace connector coverage.

These tests are the contract that keeps "56 connectors" from quietly becoming
"56 icons". Every connector offered in the marketplace must have an adapter (or
an honest documented reason it has none), credential fields that match what its
adapter actually reads, and a credential test that proves the key works rather
than that the vendor's website is up.
"""
from __future__ import annotations

import importlib
import os

import pytest

from app.api.routes.connectors import CREDENTIAL_FIELDS
from app.claws.adapters import registry
from app.services import connector_tester

_CLAW_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "app", "claws")


def _node_connector_types(node: str) -> list[str]:
    module = importlib.import_module(f"app.claws.{node}.routes")
    provider_map = getattr(module, "PROVIDER_MAP", None) or getattr(module, "PROVIDER_CONFIG", None)
    if not isinstance(provider_map, (list, dict)):
        return []
    entries = provider_map if isinstance(provider_map, list) else [
        {"connector_type": key} for key in provider_map
    ]
    types: list[str] = []
    for entry in entries:
        value = entry.get("connector_type") if isinstance(entry, dict) else entry
        if isinstance(value, list):
            types.extend(item for item in value if isinstance(item, str))
        elif isinstance(value, str):
            types.append(value)
    return types


def _nodes() -> list[str]:
    return sorted(
        name
        for name in os.listdir(_CLAW_ROOT)
        if os.path.exists(os.path.join(_CLAW_ROOT, name, "routes.py"))
    )


def _marketplace_types() -> set[str]:
    return (
        set(registry.SPECS)
        | set(registry.NATIVE_ADAPTERS)
        | set(registry.ACTION_ONLY)
    )


def _verification_kind(connector_type: str) -> str:
    if connector_type in connector_tester.TEST_MAP:
        return "handwritten"
    if connector_type in connector_tester._LOCAL_TOOLING:
        return "local"
    if connector_type in connector_tester._NATIVE_TEST_MODULES:
        return "native"
    if registry.spec_for(connector_type) is not None:
        return "declarative"
    return "generic"


def test_every_marketplace_connector_has_credential_fields():
    missing = sorted(t for t in _marketplace_types() if t not in CREDENTIAL_FIELDS)
    assert not missing, (
        "These connectors would show a generic 'API Key' form that their adapter "
        f"cannot use: {missing}"
    )


def test_every_marketplace_connector_verifies_credentials():
    generic = sorted(t for t in _marketplace_types() if _verification_kind(t) == "generic")
    assert not generic, (
        "These connectors would report Connected on reachability alone, which "
        f"tells an operator nothing about their credentials: {generic}"
    )


def test_declarative_specs_only_require_fields_the_form_collects():
    mismatches: list[str] = []
    for connector_type, spec in registry.SPECS.items():
        collected = {f["name"] for f in CREDENTIAL_FIELDS.get(connector_type, [])}
        for required in spec.required_fields:
            if required not in collected:
                mismatches.append(f"{connector_type}.{required}")
    assert not mismatches, (
        "Adapters require fields the configure form never asks for, so the "
        f"connector can never be configured successfully: {sorted(mismatches)}"
    )


def test_action_only_connectors_state_why_they_produce_no_findings():
    for connector_type, reason in registry.ACTION_ONLY.items():
        assert reason.strip(), f"{connector_type} must explain why it has no adapter"
        assert registry.spec_for(connector_type) is None


def test_aliases_resolve_to_a_real_adapter():
    unresolved = sorted(
        alias
        for alias, target in registry.ALIASES.items()
        if target not in registry.SPECS and target not in registry.NATIVE_ADAPTERS
    )
    assert not unresolved, f"Aliases point at connectors with no adapter: {unresolved}"


def test_every_capability_node_has_at_least_one_live_provider():
    """
    A node whose every provider lacks an adapter can only ever show
    demonstration data, no matter what a tenant configures. That is the failure
    mode that makes the product look broken, so it is asserted rather than
    assumed.
    """
    inert: list[str] = []
    for node in _nodes():
        types = _node_connector_types(node)
        if not types:
            continue
        live = [
            connector_type
            for connector_type in types
            if registry.coverage_state(connector_type) not in ("missing", "action_only")
        ]
        if not live:
            inert.append(f"{node} ({', '.join(sorted(set(types)))})")
    assert not inert, f"Capability Nodes with no live provider path: {inert}"


def test_every_declared_capability_provider_has_a_live_adapter():
    """
    A partial node is still a production gap: an operator should not be able to
    configure a provider named by a Capability Node only to discover that it
    will never be queried. Aliases count because they intentionally resolve to
    an adapter-backed canonical connector.
    """
    missing: list[str] = []
    for node in _nodes():
        for connector_type in _node_connector_types(node):
            if registry.coverage_state(connector_type) == "missing":
                missing.append(f"{node}.{connector_type}")
    assert not missing, f"Capability Node providers with no live adapter: {sorted(missing)}"


@pytest.mark.asyncio
async def test_provider_status_declares_whether_it_can_return_live_data(db_session):
    """
    An operator has to be able to tell an unconfigured provider apart from one
    that has no adapter at all, otherwise they connect a credential and
    reasonably conclude the product is broken when nothing changes.
    """
    from app.services.connector_check import check_providers

    statuses = await check_providers(
        db_session,
        [
            {"provider": "cisa_kev", "label": "CISA KEV", "connector_type": "cisa_kev"},
            {"provider": "unsupported", "label": "Unsupported", "connector_type": "unsupported_test_provider"},
        ],
    )
    by_provider = {entry["provider"]: entry for entry in statuses}

    assert by_provider["cisa_kev"]["live_capable"] is True
    assert by_provider["cisa_kev"]["coverage"] == "declarative"
    # No adapter: the pill must say so rather than implying a credential is all
    # that is missing.
    assert by_provider["unsupported"]["live_capable"] is False
    assert by_provider["unsupported"]["coverage"] == "missing"
