"""
Data protection, developer, IaC, compliance, endpoint, and cloud adapters.

The remaining connector estate. Data-protection providers report classification
and policy posture; developer and ITSM providers report the state of the change
pipeline; compliance providers report control drift. Each is described with the
shared spec so behaviour stays uniform across the whole marketplace.
"""
from __future__ import annotations

from typing import Any, Optional

from app.claws.rest_adapter import AdapterSpec, Endpoint, as_mapping, normalize_severity


# ── Microsoft Purview ─────────────────────────────────────────────────────────

def _summarize_purview(payload: Any, _creds: dict) -> list[dict]:
    policies = as_mapping(payload).get("value") or []
    disabled = [p for p in policies if str(p.get("mode", "")).lower() in ("test", "disable")]
    if not disabled:
        return []
    return [{
        "title": f"Purview: {len(disabled)} DLP policies not enforcing",
        "description": (
            f"{len(disabled)} data loss prevention policies are in test or disabled "
            "mode, so they report matches without actually blocking exfiltration."
        ),
        "category": "data_protection",
        "severity": "high",
        "resource_id": "purview-dlp-not-enforcing",
        "resource_type": "policy_set",
        "external_id": f"PURVIEW-DLP-TEST-{len(disabled)}",
        "remediation": "Move validated DLP policies from test mode into enforcement.",
    }]


PURVIEW = AdapterSpec(
    provider="purview",
    connector_type="purview",
    label="Microsoft Purview",
    claw="dataclaw",
    auth="device",
    base_url="https://graph.microsoft.com",
    token_field="access_token",
    endpoints=(
        Endpoint(path="/beta/security/dataLossPreventionPolicies", summarize=_summarize_purview),
    ),
)


# ── Varonis ───────────────────────────────────────────────────────────────────

def _parse_varonis(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("Name") or row.get("name")
    if not name:
        return None
    return {
        "title": f"Varonis: {name}",
        "description": (row.get("Description") or row.get("description") or "")[:600],
        "category": "data_protection",
        "severity": normalize_severity(row.get("Severity") or row.get("severity")),
        "resource_id": str(row.get("ID") or row.get("id") or name)[:120],
        "resource_type": "data_asset",
        "resource_name": name,
        "external_id": f"VARONIS-{row.get('ID') or row.get('id')}"[:120],
        "remediation": "Review the exposed data set and reduce its access scope.",
    }


VARONIS = AdapterSpec(
    provider="varonis",
    connector_type="varonis",
    label="Varonis",
    claw="dataclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url_field="host",
    token_field="api_key",
    required_fields=("host", "api_key"),
    endpoints=(
        Endpoint(path="/api/alert/alert/GetAlerts", items_key="Alerts", parse=_parse_varonis, limit=50),
    ),
)


# ── Nightfall ─────────────────────────────────────────────────────────────────

def _parse_nightfall(row: dict, _creds: dict) -> Optional[dict]:
    detector = row.get("detectorName") or row.get("detector")
    if not detector:
        return None
    return {
        "title": f"Nightfall: sensitive data detected — {detector}",
        "description": (
            f"Nightfall matched the {detector} detector, indicating sensitive data "
            "present in a monitored location."
        ),
        "category": "data_protection",
        "severity": normalize_severity(row.get("confidence"), default="high"),
        "resource_id": str(row.get("id") or detector)[:120],
        "resource_type": "data_finding",
        "external_id": f"NIGHTFALL-{row.get('id')}"[:120],
        "remediation": "Remove or tokenise the sensitive value and rotate anything exposed.",
    }


NIGHTFALL = AdapterSpec(
    provider="nightfall",
    connector_type="nightfall",
    label="Nightfall",
    claw="dataclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://api.nightfall.ai",
    token_field="api_key",
    required_fields=("api_key",),
    endpoints=(
        Endpoint(path="/v3/findings", items_key="findings", parse=_parse_nightfall, limit=50),
    ),
)


# ── BigID ─────────────────────────────────────────────────────────────────────

def _parse_bigid(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or row.get("objectName")
    if not name:
        return None
    return {
        "title": f"BigID: sensitive data discovered in {name}",
        "description": (
            f"BigID classified {name} as containing sensitive or regulated data "
            "that must be governed under the applicable retention policy."
        ),
        "category": "privacy",
        "severity": normalize_severity(row.get("risk"), default="medium"),
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "data_source",
        "resource_name": name,
        "external_id": f"BIGID-{row.get('id')}"[:120],
        "remediation": "Apply the correct retention and access policy to this data source.",
    }


BIGID = AdapterSpec(
    provider="bigid",
    connector_type="bigid",
    label="BigID",
    claw="privacyclaw",
    auth="header",
    auth_name="Authorization",
    base_url_field="host",
    token_field="token",
    required_fields=("host", "token"),
    endpoints=(
        Endpoint(path="/api/v1/data-catalog", items_key="results", parse=_parse_bigid, limit=50),
    ),
)


# ── GitLab ────────────────────────────────────────────────────────────────────

def _parse_gitlab(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or (row.get("vulnerability") or {}).get("name")
    if not name:
        return None
    return {
        "title": f"GitLab: {name}",
        "description": (row.get("description") or "")[:600],
        "category": "dependency",
        "severity": normalize_severity(row.get("severity")),
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "project",
        "resource_name": (row.get("location") or {}).get("file"),
        "external_id": f"GITLAB-{row.get('id')}"[:120],
        "remediation": (row.get("solution") or "Apply the GitLab-recommended remediation.")[:600],
    }


GITLAB = AdapterSpec(
    provider="gitlab",
    connector_type="gitlab",
    label="GitLab",
    claw="devclaw",
    auth="header",
    auth_name="PRIVATE-TOKEN",
    base_url="https://gitlab.com",
    token_field="personal_access_token",
    required_fields=("personal_access_token",),
    endpoints=(
        Endpoint(
            path="/api/v4/vulnerabilities",
            params={"per_page": 50, "state": "detected"},
            parse=_parse_gitlab,
            limit=50,
        ),
    ),
)


# ── Jira ──────────────────────────────────────────────────────────────────────

def _summarize_jira(payload: Any, _creds: dict) -> list[dict]:
    issues = as_mapping(payload).get("issues") or []
    total = as_mapping(payload).get("total", len(issues))
    if not total:
        return []
    return [{
        "title": f"Jira: {total} security issues open past their due date",
        "description": (
            f"{total} security-labelled Jira issues are open and overdue. Remediation "
            "that slips past its own deadline is where risk quietly accumulates."
        ),
        "category": "remediation_backlog",
        "severity": "high" if total > 20 else "medium",
        "resource_id": "jira-overdue-security",
        "resource_type": "issue_queue",
        "external_id": f"JIRA-OVERDUE-{total}",
        "remediation": "Triage the overdue security backlog and re-baseline the due dates.",
    }]


JIRA = AdapterSpec(
    provider="jira",
    connector_type="jira",
    label="Jira",
    claw="vendorclaw",
    auth="basic",
    username_field="email",
    password_field="api_token",
    base_url_field="domain",
    required_fields=("domain", "email", "api_token"),
    endpoints=(
        Endpoint(
            path="/rest/api/3/search",
            params={"jql": "labels = security AND duedate < now() AND statusCategory != Done", "maxResults": 50},
            summarize=_summarize_jira,
        ),
    ),
)


# ── ServiceNow ────────────────────────────────────────────────────────────────

def _parse_servicenow(row: dict, _creds: dict) -> Optional[dict]:
    short = row.get("short_description")
    if not short:
        return None
    return {
        "title": f"ServiceNow: {short}",
        "description": (row.get("description") or "")[:600],
        "category": "remediation_backlog",
        "severity": normalize_severity(row.get("priority"), default="medium"),
        "resource_id": str(row.get("sys_id") or short)[:120],
        "resource_type": "incident",
        "external_id": f"SNOW-{row.get('number') or row.get('sys_id')}"[:120],
        "remediation": "Progress the ServiceNow record to closure.",
    }


SERVICENOW = AdapterSpec(
    provider="servicenow",
    connector_type="servicenow",
    label="ServiceNow",
    claw="vendorclaw",
    auth="basic",
    username_field="username",
    password_field="password",
    base_url_field="instance",
    required_fields=("instance", "username", "password"),
    endpoints=(
        Endpoint(
            path="/api/now/table/sn_si_incident",
            items_key="result",
            params={"sysparm_limit": 50, "sysparm_query": "active=true"},
            parse=_parse_servicenow,
            limit=50,
        ),
    ),
)


# ── Terraform Cloud ───────────────────────────────────────────────────────────

def _summarize_terraform(payload: Any, _creds: dict) -> list[dict]:
    workspaces = as_mapping(payload).get("data") or []
    drifted = [
        w for w in workspaces
        if (w.get("attributes") or {}).get("structured-run-output-enabled") is False
        or (w.get("attributes") or {}).get("auto-apply") is True
    ]
    if not drifted:
        return []
    return [{
        "title": f"Terraform Cloud: {len(drifted)} workspaces with auto-apply enabled",
        "description": (
            f"{len(drifted)} workspaces apply infrastructure changes without a human "
            "review step, so a bad plan reaches production unreviewed."
        ),
        "category": "infrastructure_as_code",
        "severity": "high",
        "resource_id": "tfc-auto-apply",
        "resource_type": "workspace_set",
        "external_id": f"TFC-AUTOAPPLY-{len(drifted)}",
        "remediation": "Disable auto-apply for production workspaces and require plan approval.",
    }]


TERRAFORM_CLOUD = AdapterSpec(
    provider="terraform_cloud",
    connector_type="terraform_cloud",
    label="Terraform Cloud",
    claw="terraclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://app.terraform.io",
    token_field="api_token",
    required_fields=("api_token", "organization"),
    endpoints=(
        Endpoint(path="/api/v2/organizations/{organization}/workspaces", summarize=_summarize_terraform),
    ),
)


# ── Drata ─────────────────────────────────────────────────────────────────────

def _parse_drata(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name")
    if not name or row.get("status") == "PASSING":
        return None
    return {
        "title": f"Drata: failing control — {name}",
        "description": (row.get("description") or "")[:600],
        "category": "compliance",
        "severity": "high",
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "control",
        "resource_name": name,
        "external_id": f"DRATA-{row.get('id')}"[:120],
        "remediation": "Remediate the failing control and re-collect its evidence.",
    }


DRATA = AdapterSpec(
    provider="drata",
    connector_type="drata",
    label="Drata",
    claw="complianceclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://public-api.drata.com",
    token_field="api_key",
    required_fields=("api_key",),
    endpoints=(
        Endpoint(path="/public/controls", items_key="data", parse=_parse_drata, limit=100),
    ),
)


# ── Vanta ─────────────────────────────────────────────────────────────────────

def _parse_vanta(row: dict, _creds: dict) -> Optional[dict]:
    name = row.get("name") or row.get("title")
    if not name:
        return None
    return {
        "title": f"Vanta: failing test — {name}",
        "description": (row.get("description") or "")[:600],
        "category": "compliance",
        "severity": "high",
        "resource_id": str(row.get("id") or name)[:120],
        "resource_type": "control",
        "resource_name": name,
        "external_id": f"VANTA-{row.get('id')}"[:120],
        "remediation": "Resolve the failing Vanta test before the next audit window.",
    }


VANTA = AdapterSpec(
    provider="vanta",
    connector_type="vanta",
    label="Vanta",
    claw="complianceclaw",
    auth="bearer",
    auth_prefix="Bearer",
    base_url="https://api.vanta.com",
    token_field="api_token",
    required_fields=("api_token",),
    endpoints=(
        Endpoint(
            path="/v1/tests",
            items_key="results.data",
            params={"statusFilter": "FAILING", "pageSize": 50},
            parse=_parse_vanta,
            limit=50,
        ),
    ),
)


# ── Carbon Black ──────────────────────────────────────────────────────────────

def _parse_carbonblack(row: dict, _creds: dict) -> Optional[dict]:
    reason = row.get("reason") or row.get("threat_cause_actor_name")
    if not reason:
        return None
    return {
        "title": f"Carbon Black: {str(reason)[:120]}",
        "description": (row.get("reason") or "")[:600],
        "category": "endpoint_threat",
        "severity": normalize_severity(row.get("severity"), default="high"),
        "resource_id": str(row.get("device_id") or row.get("id"))[:120],
        "resource_type": "endpoint",
        "resource_name": row.get("device_name"),
        "external_id": f"CBC-{row.get('id')}"[:120],
        "remediation": "Isolate the endpoint and complete incident response.",
    }


CARBONBLACK = AdapterSpec(
    provider="carbonblack",
    connector_type="carbonblack",
    label="VMware Carbon Black",
    claw="endpointclaw",
    auth="header",
    auth_name="X-Auth-Token",
    base_url_field="base_url",
    token_field="_cbc_header",
    required_fields=("org_key", "api_id", "api_key"),
    transform=lambda c: {
        "_cbc_header": f"{c.get('api_key', '')}/{c.get('api_id', '')}",
        "base_url": c.get("base_url") or "https://defense.conferdeploy.net",
    },
    endpoints=(
        Endpoint(path="/appservices/v6/orgs/{org_key}/alerts", items_key="results", parse=_parse_carbonblack, limit=50),
    ),
)


# ── Tanium ────────────────────────────────────────────────────────────────────

def _summarize_tanium(payload: Any, _creds: dict) -> list[dict]:
    data = as_mapping(as_mapping(payload).get("data"))
    endpoints = data.get("endpoints") or data.get("items") or []
    unmanaged = [
        e for e in endpoints
        if isinstance(e, dict) and not e.get("isManaged", True)
    ]
    if not unmanaged:
        return []
    return [{
        "title": f"Tanium: {len(unmanaged)} unmanaged endpoints discovered",
        "description": (
            f"Tanium discovered {len(unmanaged)} endpoints on the network without a "
            "management agent, so they receive no patching or detection coverage."
        ),
        "category": "endpoint_coverage",
        "severity": "high",
        "resource_id": "tanium-unmanaged",
        "resource_type": "endpoint_group",
        "external_id": f"TANIUM-UNMANAGED-{len(unmanaged)}",
        "remediation": "Deploy the management agent or remove the devices from the network.",
    }]


TANIUM = AdapterSpec(
    provider="tanium",
    connector_type="tanium",
    label="Tanium",
    claw="endpointclaw",
    auth="header",
    auth_name="session",
    base_url_field="host",
    token_field="api_key",
    required_fields=("host", "api_key"),
    endpoints=(
        Endpoint(path="/plugin/products/asset/v1/assets", summarize=_summarize_tanium),
    ),
)


SPECS = (
    PURVIEW, VARONIS, NIGHTFALL, BIGID,
    GITLAB, JIRA, SERVICENOW, TERRAFORM_CLOUD,
    DRATA, VANTA, CARBONBLACK, TANIUM,
)
