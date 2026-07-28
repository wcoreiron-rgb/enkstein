"""
Adapters for the Security Capability Node providers that were still only names
in a provider map.  Each adapter is read-only, credential-scoped, bounded by
the shared timeout/SSRF layer, and returns normalised live findings.

Several of these products are tenant-hosted.  Their base URL is therefore a
required connector field instead of being guessed from a company name.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, normalize_severity


def _first(row: dict, *names: str) -> Any:
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return None


def _generic_finding(category: str, prefix: str):
    def parse(row: dict, _creds: dict) -> Optional[dict]:
        title = _first(row, "title", "name", "summary", "message", "rule_name", "policy_name")
        if not title:
            return None
        severity = normalize_severity(_first(row, "severity", "severity_level", "risk_level", "priority"))
        resource = _first(row, "resource_name", "asset_name", "hostname", "user_name", "email", "entity") or "unknown resource"
        identifier = _first(row, "id", "uuid", "alert_id", "issue_id", "external_id") or f"{prefix}-{title}"
        return {
            "title": f"{prefix}: {title}"[:200],
            "description": str(_first(row, "description", "details", "message", "summary") or title)[:600],
            "category": category,
            "severity": severity,
            "resource_id": str(identifier)[:200],
            "resource_type": str(_first(row, "resource_type", "type", "entity_type") or "asset")[:100],
            "resource_name": str(resource)[:200],
            "external_id": f"{prefix}-{identifier}"[:120],
            "remediation": str(_first(row, "remediation", "recommendation", "resolution") or "Review the finding and remediate according to the provider guidance.")[:600],
        }
    return parse


# Application and release security -------------------------------------------

VERACODE = AdapterSpec(
    provider="veracode", connector_type="veracode", label="Veracode",
    claw="appclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("api_key", "base_url"),
    base_url_field="base_url",
    endpoints=(Endpoint(path="/api/authn/v2/applications", items_key="_embedded.applications", parse=_generic_finding("application_security", "Veracode")),),
)

JENKINS = AdapterSpec(
    provider="jenkins", connector_type="jenkins", label="Jenkins",
    claw="automationclaw", auth="basic", username_field="username", password_field="api_token",
    required_fields=("base_url", "username", "api_token"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/json", params={"tree": "jobs[name,url,color,lastBuild[number,result,timestamp]]"}, items_key="jobs", parse=_generic_finding("pipeline_security", "Jenkins")),),
)

# Cloud, network, and endpoint ------------------------------------------------

ORCA = AdapterSpec(
    provider="orca", connector_type="orca", label="Orca Security",
    claw="attackpathclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("api_key", "base_url"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/v1/alerts", items_key="data", parse=_generic_finding("attack_path", "Orca")),),
)

FORTINET = AdapterSpec(
    provider="fortinet", connector_type="fortinet", label="Fortinet FortiGate",
    claw="netclaw", auth="query", auth_name="access_token", token_field="api_token",
    required_fields=("base_url", "api_token"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/v2/monitor/log/fortianalyzer/alert", items_key="results", parse=_generic_finding("network_security", "Fortinet")),),
)

DTEX = AdapterSpec(
    provider="dtex", connector_type="dtex", label="DTEX Systems",
    claw="insiderclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("base_url", "api_key"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/v1/alerts", items_key="data", parse=_generic_finding("insider_risk", "DTEX")),),
)

CODE42 = AdapterSpec(
    provider="code42", connector_type="code42", label="Code42 Incydr",
    claw="insiderclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("base_url", "api_key"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/v1/alerts", items_key="alerts", parse=_generic_finding("insider_risk", "Code42")),),
)

# Privacy, SaaS, and user behaviour -------------------------------------------

ONETRUST = AdapterSpec(
    provider="onetrust", connector_type="onetrust", label="OneTrust",
    claw="privacyclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("base_url", "api_key"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/risk/v1/risks", items_key="items", parse=_generic_finding("privacy", "OneTrust")),),
)

TRANSCEND = AdapterSpec(
    provider="transcend", connector_type="transcend", label="Transcend",
    claw="privacyclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("base_url", "api_key"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/v1/data-map", items_key="data", parse=_generic_finding("privacy", "Transcend")),),
)

GOOGLE_WORKSPACE = AdapterSpec(
    provider="google_workspace", connector_type="google_workspace", label="Google Workspace Security",
    claw="saasclaw", auth="device", token_field="access_token",
    required_fields=(), base_url="https://admin.googleapis.com",
    endpoints=(Endpoint(path="/admin/reports/v1/activity/users/all/applications/login", items_key="items", parse=_generic_finding("saas_security", "Google Workspace")),),
)

SALESFORCE = AdapterSpec(
    provider="salesforce", connector_type="salesforce", label="Salesforce Shield",
    claw="saasclaw", auth="device", token_field="access_token",
    required_fields=("base_url",), base_url_field="base_url",
    endpoints=(Endpoint(path="/services/data/v59.0/query", params={"q": "SELECT Id, EventType, LogDate, UserId FROM EventLogFile ORDER BY LogDate DESC LIMIT 100"}, items_key="records", parse=_generic_finding("saas_security", "Salesforce")),),
)

EXABEAM = AdapterSpec(
    provider="exabeam", connector_type="exabeam", label="Exabeam",
    claw="userclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("base_url", "api_key"), base_url_field="base_url",
    endpoints=(Endpoint(path="/api/v1/alerts", items_key="alerts", parse=_generic_finding("user_risk", "Exabeam")),),
)

SECURONIX = AdapterSpec(
    provider="securonix", connector_type="securonix", label="Securonix",
    claw="userclaw", auth="header", auth_name="Authorization", auth_prefix="Bearer",
    token_field="api_key", required_fields=("base_url", "api_key"), base_url_field="base_url",
    endpoints=(Endpoint(path="/Snypr/rs/incident/list", items_key="data", parse=_generic_finding("user_risk", "Securonix")),),
)


SPECS = (
    VERACODE, ORCA, JENKINS, DTEX, CODE42, FORTINET, ONETRUST, TRANSCEND,
    GOOGLE_WORKSPACE, SALESFORCE, EXABEAM, SECURONIX,
)
