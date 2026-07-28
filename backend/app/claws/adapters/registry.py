"""
Connector adapter registry.

Single source of truth for which connector types can return live tenant data.
A Capability Node consults this to decide whether it can execute a real scan,
and coverage tests assert against it so a connector cannot be advertised in the
marketplace without either an adapter or an honest statement that it has none.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.adapters import community, enterprise, exposure, identity, platform, telemetry, vendor
from app.claws.rest_adapter import AdapterSpec
from app.claws.rest_adapter import fetch_findings as _spec_fetch_findings

# Declarative REST adapters.
SPECS: dict[str, AdapterSpec] = {
    spec.connector_type: spec
    for module in (community, enterprise, exposure, identity, telemetry, platform, vendor)
    for spec in module.SPECS
}

# Connector types served by a hand-written adapter module, kept where the
# provider needs bespoke logic (multi-step auth, pagination, or aggregation)
# that a declarative spec should not try to express.
NATIVE_ADAPTERS: dict[str, str] = {
    "aws_security_hub": "cloudclaw.providers.aws",
    "azure_defender": "cloudclaw.providers.azure",
    "azure_arm": "cloudclaw.providers.azure",
    "gcp_scc": "cloudclaw.providers.gcp",
    "gcp_iam": "cloudclaw.providers.gcp",
    "aws_iam": "cloudclaw.providers.aws",
    "entra_id": "accessclaw.providers.entra",
    "okta": "accessclaw.providers.okta",
    "splunk": "logclaw.providers.splunk",
    "crowdstrike": "endpointclaw.providers.crowdstrike",
    "defender_endpoint": "endpointclaw.providers.defender",
    "sentinelone": "endpointclaw.providers.sentinelone",
    "github": "devclaw.github_scanner",
    "prowler": "cloudclaw.providers.prowler",
}

# Connector types that are deliberately not finding sources. These are action
# or notification targets; presenting them as scannable would be misleading.
ACTION_ONLY: dict[str, str] = {
    "pagerduty": "Notification target — used to page on-call, not to produce findings.",
    "terraform_mcp": "Local Terraform tooling driven by TerraClaw, not a remote API.",
    "tfsec": "Local IaC scanner invoked during TerraClaw analysis.",
    "checkov": "Local IaC scanner invoked during TerraClaw analysis.",
    "infracost": "Cost estimation for Terraform plans, not a security finding source.",
}

# Capability Nodes were authored at different times and refer to the same
# provider by different names. Mapping the aliases here means a tenant that
# configures "azure_ad" gets the Entra adapter rather than an inert connector.
ALIASES: dict[str, str] = {
    "azure_ad": "entra_id",
    "microsoft_sentinel": "sentinel",
    "microsoft_purview": "purview",
    "mcas": "purview",
    "palo_alto": "paloalto",
    "azure_security_center": "azure_defender",
    "microsoft_defender_xdr": "defender_endpoint",
    "gitlab_ci": "gitlab",
    "aws_config": "aws_security_hub",
    "aws_macie": "aws_security_hub",
    "aws_vpc": "aws_security_hub",
    "azure_policy": "azure_defender",
    "gcp_org_policy": "gcp_scc",
    "google_dlp": "gcp_scc",
    "prowler_cloud": "prowler",
}


def canonical(connector_type: str) -> str:
    """Resolve a Capability Node's connector name to its adapter's name."""
    return ALIASES.get(connector_type, connector_type)


def has_adapter(connector_type: str) -> bool:
    """True when this connector type can return live tenant data."""
    key = canonical(connector_type)
    return key in SPECS or key in NATIVE_ADAPTERS


def is_action_only(connector_type: str) -> bool:
    """True for connectors that act rather than report."""
    return connector_type in ACTION_ONLY


def coverage_state(connector_type: str) -> str:
    """One of: declarative, native, action_only, missing."""
    key = canonical(connector_type)
    if key in SPECS:
        return "declarative"
    if key in NATIVE_ADAPTERS:
        return "native"
    if key in ACTION_ONLY:
        return "action_only"
    return "missing"


def spec_for(connector_type: str) -> Optional[AdapterSpec]:
    return SPECS.get(canonical(connector_type))


def adapter_for(connector_type: str):
    """
    Return an object exposing ``get_findings(credentials=...)`` for this
    connector type, or None when it has no live adapter.
    """
    spec = SPECS.get(canonical(connector_type))
    if spec is None:
        return None
    return _SpecAdapter(spec)


class _SpecAdapter:
    """Adapts an AdapterSpec to the get_findings contract Claws expect."""

    __slots__ = ("spec",)

    def __init__(self, spec: AdapterSpec):
        self.spec = spec

    async def get_findings(self, credentials: Optional[dict] = None) -> list[dict[str, Any]]:
        # A shared scan must be able to distinguish a provider failure from an
        # empty but valid result. ``rest_adapter.get_findings`` is designed for
        # standalone presentation and deliberately returns demo data on error;
        # that made run_claw_scan report a failed provider as success. Propagate
        # adapter errors here so the scan records ``error`` and keeps its own
        # clearly labelled demo fallback.
        if credentials is None:
            return []
        return await _spec_fetch_findings(self.spec, credentials)


def specs_for_claw(claw: str) -> list[AdapterSpec]:
    """Every declarative adapter belonging to a Capability Node."""
    return [spec for spec in SPECS.values() if spec.claw == claw]
